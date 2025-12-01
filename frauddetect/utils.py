import hashlib
import requests
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
from django.db import models


def calculate_device_fingerprint(request):
    """
    Request থেকে Device Fingerprint তৈরি করে
    একই ডিভাইস থেকে আসা request গুলো identify করতে সাহায্য করে
    """
    components = [
        request.META.get('HTTP_USER_AGENT', ''),
        request.META.get('HTTP_ACCEPT_LANGUAGE', ''),
        request.META.get('HTTP_ACCEPT_ENCODING', ''),
    ]
    fingerprint = '|'.join(components)
    return hashlib.sha256(fingerprint.encode()).hexdigest()


def get_client_ip(request):
    """
    Request থেকে সঠিক Client IP Address বের করে
    Proxy/Load Balancer এর পেছনে থাকলেও কাজ করে
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        # Multiple proxies থাকলে প্রথমটি হলো actual client IP
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def get_country_risk_level(country_code):
    """
    দেশের কোড থেকে ঝুঁকি স্তর নির্ধারণ করে
    
    Returns:
        dict: level, score, reason
    """
    if not country_code:
        return {'level': 'medium', 'score': 20, 'reason': 'Unknown Country'}
    
    country = country_code.upper()
    
    if country in settings.HIGH_RISK_COUNTRIES:
        return {
            'level': 'high', 
            'score': 30, 
            'reason': f'High-Risk Country ({country})'
        }
    elif country in settings.MEDIUM_RISK_COUNTRIES:
        return {
            'level': 'medium', 
            'score': 15, 
            'reason': f'Medium-Risk Country ({country})'
        }
    elif country in settings.LOW_RISK_COUNTRIES:
        return {
            'level': 'low', 
            'score': 5, 
            'reason': f'Low-Risk Country ({country})'
        }
    else:
        return {
            'level': 'medium', 
            'score': 20, 
            'reason': f'Unknown Country ({country})'
        }


def get_geo_location(ip_address):
    """
    IP Address থেকে Geographic Location বের করে
    Free API ব্যবহার করে (ipapi.co)
    """
    try:
        response = requests.get(
            f'https://ipapi.co/{ip_address}/json/', 
            timeout=3
        )
        if response.status_code == 200:
            data = response.json()
            return {
                'country_code': data.get('country_code', 'SA'),
                'city': data.get('city', 'Unknown'),
                'latitude': data.get('latitude'),
                'longitude': data.get('longitude'),
            }
    except Exception as e:
        print(f"Geo location error: {e}")
    
    # Default return যদি API কাজ না করে
    return {
        'country_code': 'SA', 
        'city': 'Unknown',
        'latitude': None,
        'longitude': None
    }


def check_velocity(user, check_type='login', window_minutes=60):
    """
    Velocity Check - নির্দিষ্ট সময়ে কতগুলো action হয়েছে তা চেক করে
    
    যেমন: ১ ঘণ্টায় ১০টির বেশি transaction হলে suspicious
    
    Args:
        user: User object
        check_type: 'login' বা 'transaction'
        window_minutes: কত মিনিটের মধ্যে চেক করতে হবে
    
    Returns:
        bool: True যদি limit exceed করে
    """
    from .models import LoginEvent, Transaction
    
    time_threshold = timezone.now() - timedelta(minutes=window_minutes)
    
    if check_type == 'login':
        count = LoginEvent.objects.filter(
            user=user,
            attempt_time__gte=time_threshold
        ).count()
    else:
        count = Transaction.objects.filter(
            user=user,
            created_at__gte=time_threshold
        ).count()
    
    max_allowed = settings.FRAUD_SETTINGS['MAX_TRANSACTIONS_PER_HOUR']
    
    return count >= max_allowed


def is_business_hours():
    """
    বর্তমান সময় business hours এর মধ্যে কিনা চেক করে
    Office hours এর বাইরে transaction সন্দেহজনক হতে পারে
    
    Returns:
        bool: True যদি business hours এর মধ্যে থাকে
    """
    current_hour = timezone.now().hour
    start = settings.FRAUD_SETTINGS['BUSINESS_HOURS_START']
    end = settings.FRAUD_SETTINGS['BUSINESS_HOURS_END']
    
    return start <= current_hour <= end


def check_ip_blocklist(ip_address):
    """
    IP Address ব্লকলিস্টে আছে কিনা চেক করে
    
    Returns:
        bool: True যদি ব্লক করা থাকে
    """
    from .models import IPBlocklist
    
    blocked = IPBlocklist.objects.filter(
        ip_address=ip_address,
        is_active=True
    ).filter(
        # মেয়াদ শেষ হয়নি বা মেয়াদ নেই
        models.Q(expires_at__isnull=True) | models.Q(expires_at__gt=timezone.now())
    ).exists()
    
    return blocked


def calculate_transaction_risk(transaction):
    """
    🔥 মূল Fraud Detection Logic
    
    Transaction এর ঝুঁকি স্কোর এবং level নির্ধারণ করে
    বিভিন্ন নিয়ম প্রয়োগ করে মোট স্কোর বের করে
    
    Args:
        transaction: Transaction object
    
    Returns:
        dict: risk_score, risk_level, triggered_rules
    """
    risk_score = 0
    triggered_rules = []
    
    # ============================================
    # Rule FR-01: High Amount Transaction
    # ১ লাখ টাকার বেশি হলে সন্দেহজনক
    # ============================================
    if transaction.amount > settings.FRAUD_SETTINGS['HIGH_AMOUNT_THRESHOLD']:
        risk_score += 40
        triggered_rules.append('FR-01: High Amount Transaction (>100,000)')
    
    # ============================================
    # Rule FR-02: Outside Business Hours
    # অফিস সময়ের বাইরে লেনদেন
    # ============================================
    if not is_business_hours():
        risk_score += 20
        triggered_rules.append('FR-02: Outside Business Hours')
    
    # ============================================
    # Rule FR-03: Velocity Check
    # ঘণ্টায় অনেক বেশি transaction
    # ============================================
    if check_velocity(transaction.user, 'transaction', 60):
        risk_score += 30
        triggered_rules.append('FR-03: Too Many Transactions in Short Time')
    
    # ============================================
    # Rule FR-04: Untrusted Device
    # অপরিচিত ডিভাইস থেকে লেনদেন
    # ============================================
    if transaction.device and not transaction.device.is_trusted:
        risk_score += 15
        triggered_rules.append('FR-04: Untrusted Device')
    
    # ============================================
    # Determine Risk Level
    # ============================================
    if risk_score >= 70:
        risk_level = 'high'
    elif risk_score >= 40:
        risk_level = 'medium'
    else:
        risk_level = 'low'
    
    return {
        'risk_score': risk_score,
        'risk_level': risk_level,
        'triggered_rules': triggered_rules
    }


def calculate_login_risk(request, user=None):
    """
    Login এর ঝুঁকি মূল্যায়ন করে
    """
    risk_score = 0
    risk_reasons = []
    
    ip = get_client_ip(request)
    geo = get_geo_location(ip)
    
    # Country risk
    country_risk = get_country_risk_level(geo['country_code'])
    risk_score += country_risk['score']
    if country_risk['level'] != 'low':
        risk_reasons.append(country_risk['reason'])
    
    # IP blocklist check
    if check_ip_blocklist(ip):
        risk_score += 50
        risk_reasons.append('Blocked IP Address')
    
    # Velocity check
    if user and check_velocity(user, 'login', 60):
        risk_score += 25
        risk_reasons.append('Too Many Login Attempts')
    
    return {
        'risk_score': risk_score,
        'risk_reasons': risk_reasons,
        'is_suspicious': risk_score >= 30,
        'geo': geo
    }