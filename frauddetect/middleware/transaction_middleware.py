"""
🔍 Transaction Fraud Detection Middleware
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Simple middleware for transaction fraud detection.

Usage:
    from frauddetect.middleware import check_transaction_fraud
    
    result = check_transaction_fraud(request, user, transaction_data)
    if not result['allowed']:
        return error_response(result['error'])
"""

from django.utils import timezone
from datetime import timedelta
from django.db.models import Sum, Count, Avg, StdDev
import hashlib


def get_client_ip(request):
    """Get client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def get_geo_location(ip_address):
    """
    Get geolocation from IP address using free API
    Uses ipapi.co (free tier: 1000 requests/day)
    """
    import requests
    
    # Local/Private IPs - return LOCAL
    if ip_address.startswith(('127.', '10.', '172.', '192.168.', 'localhost')) or ip_address == '::1':
        return {
            'country_code': 'LOCAL',
            'country_name': 'Local Network',
            'city': 'Local',
            'region': 'Local',
        }
    
    # Try ipapi.co (free API)
    try:
        response = requests.get(
            f'https://ipapi.co/{ip_address}/json/',
            timeout=3,
            headers={'User-Agent': 'FraudDetection/1.0'}
        )
        if response.status_code == 200:
            data = response.json()
            if 'error' not in data:
                return {
                    'country_code': data.get('country_code', 'Unknown'),
                    'country_name': data.get('country_name', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'region': data.get('region', 'Unknown'),
                }
    except Exception as e:
        print(f"⚠️ Geo API error: {e}")
    
    # Fallback - try ip-api.com (free, no key needed)
    try:
        response = requests.get(
            f'http://ip-api.com/json/{ip_address}',
            timeout=3
        )
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                return {
                    'country_code': data.get('countryCode', 'Unknown'),
                    'country_name': data.get('country', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'region': data.get('regionName', 'Unknown'),
                }
    except Exception as e:
        print(f"⚠️ Fallback Geo API error: {e}")
    
    return {
        'country_code': 'Unknown',
        'country_name': 'Unknown',
        'city': 'Unknown',
        'region': 'Unknown',
    }


def get_user_device(request, user):
    """Get or create user device"""
    from frauddetect.models import Device
    
    user_agent = request.META.get('HTTP_USER_AGENT', '')
    ip_address = get_client_ip(request)
    
    # Generate fingerprint
    fingerprint_data = f"{user_agent}|{ip_address}"
    fingerprint_hash = hashlib.sha256(fingerprint_data.encode()).hexdigest()
    
    # Get or create device
    device = Device.objects.filter(
        user=user,
        fingerprint_hash=fingerprint_hash
    ).first()
    
    return device


def check_transaction_fraud(request, user, transaction_data):
    """
    🔍 Main Transaction Fraud Detection Function
    
    Args:
        request: Django request object
        user: User object
        transaction_data: Dict with transaction details
    
    Returns:
        dict: Fraud check result
    """
    from frauddetect.models import FraudConfig, Transaction, IPBlocklist, Device
    
    # Get configuration
    try:
        config = FraudConfig.get_active_config()
    except:
        config = None
    
    # Extract transaction details
    amount = transaction_data.get('amount', 0)
    currency = transaction_data.get('currency', 'SAR')
    beneficiary = transaction_data.get('beneficiary', '')
    transaction_type = transaction_data.get('transaction_type', 'transfer')
    
    # Get IP and location
    ip_address = get_client_ip(request)
    geo_data = get_geo_location(ip_address)
    country_code = geo_data['country_code']
    country_name = geo_data['country_name']
    city = geo_data['city']
    
    # Get device
    device = get_user_device(request, user)
    
    # Risk tracking
    total_risk = 0
    risk_reasons = []
    triggered_patterns = []
    
    # Track if superuser (will run all checks but never block)
    is_superuser = user.is_superuser
    
    # CHECK 1: IP BLACKLIST
    if IPBlocklist.objects.filter(ip_address=ip_address, is_active=True).exists():
        total_risk += 100
        risk_reasons.append('Blacklisted IP')
        triggered_patterns.append('blacklisted_ip')
        
        if not is_superuser:
            return {
                'allowed': False,
                'error': {
                    'error': 'Transaction Blocked',
                    'reason': 'blacklisted_ip',
                    'message': 'Your IP address has been blocked',
                    'ip_address': ip_address
                },
                'risk_score': 100,
                'risk_reasons': risk_reasons,
                'triggered_patterns': triggered_patterns,
            }
    
    # CHECK 2: COUNTRY RESTRICTION
    if config and config.geo_restriction_enabled:
        allowed_countries = config.allowed_countries or ['SA']
        
        if country_code not in allowed_countries:
            total_risk += 60
            risk_reasons.append(f'Transaction from non-allowed country: {country_code}')
            triggered_patterns.append('non_allowed_country')
            
            if not is_superuser:
                return {
                    'allowed': False,
                    'error': {
                        'error': 'Transaction Blocked',
                        'reason': 'non_allowed_country',
                        'message': f'Transactions from {country_name} are not allowed',
                        'your_country': country_name,
                        'allowed_countries': allowed_countries
                    },
                    'risk_score': total_risk,
                    'risk_reasons': risk_reasons,
                    'triggered_patterns': triggered_patterns,
                }
    
    # CHECK 3: DEVICE TRUST
    if device and not device.is_trusted:
        total_risk += 50
        risk_reasons.append('Transaction from untrusted device')
        triggered_patterns.append('untrusted_device')
        
        if not is_superuser:
            return {
                'allowed': False,
                'error': {
                    'error': 'Transaction Blocked',
                    'reason': 'untrusted_device',
                    'message': 'This device is not trusted for transactions',
                    'device_name': device.device_name if device else 'Unknown'
                },
                'risk_score': total_risk,
                'risk_reasons': risk_reasons,
                'triggered_patterns': triggered_patterns,
            }
    
    # CHECK 4: AMOUNT THRESHOLD
    if config:
        threshold = config.high_amount_threshold or 100000
        
        if amount > threshold:
            total_risk += 30
            risk_reasons.append(f'Amount {amount} exceeds threshold {threshold}')
            triggered_patterns.append('amount_exceeds_threshold')
    
    # CHECK 5: VELOCITY (HIGH FREQUENCY)
    if config:
        max_per_hour = config.max_transactions_per_hour or 10
        
        one_hour_ago = timezone.now() - timedelta(hours=1)
        recent_count = Transaction.objects.filter(
            user=user,
            created_at__gte=one_hour_ago,
            status__in=['approved', 'pending']
        ).count()
        
        if recent_count >= max_per_hour:
            total_risk += 50
            risk_reasons.append(f'High velocity: {recent_count} transactions in 1 hour')
            triggered_patterns.append('high_velocity')
            
            if not is_superuser:
                return {
                    'allowed': False,
                    'error': 'Transaction Blocked',
                    'message': f'Too many transactions. Maximum {max_per_hour} per hour allowed.',
                    'transaction_count': recent_count,
                    'max_allowed': max_per_hour,
                    'risk_score': total_risk,
                    'risk_reasons': risk_reasons,
                    'triggered_patterns': triggered_patterns,
                }
    
    # CHECK 6: DAILY LIMITS
    if config:
        max_daily_count = config.max_daily_transactions or 50
        max_daily_amount = config.max_transaction_amount_daily or 500000
        
        today_start = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
        today_txns = Transaction.objects.filter(
            user=user,
            created_at__gte=today_start,
            status__in=['approved', 'pending']
        )
        
        today_count = today_txns.count()
        today_amount = today_txns.aggregate(Sum('amount'))['amount__sum'] or 0
        today_amount += amount
        
        if today_count >= max_daily_count:
            total_risk += 40
            risk_reasons.append(f'Daily limit exceeded: {today_count}/{max_daily_count} transactions')
            triggered_patterns.append('daily_limit_count')
        
        if today_amount > max_daily_amount:
            total_risk += 40
            risk_reasons.append(f'Daily amount limit exceeded: {today_amount}/{max_daily_amount}')
            triggered_patterns.append('daily_limit_amount')
            
            return {
                'allowed': False,
                'error': {
                    'error': 'Transaction Blocked',
                    'reason': 'daily_limit_exceeded',
                    'message': 'Daily transaction limit exceeded',
                    'today_amount': float(today_amount),
                    'max_amount': max_daily_amount
                },
                'risk_score': total_risk,
                'risk_reasons': risk_reasons,
                'triggered_patterns': triggered_patterns,
            }
    
    # CHECK 7: BUSINESS HOURS
    if config and config.flag_outside_business_hours:
        current_hour = timezone.now().hour
        business_start = config.business_hours_start or 8
        business_end = config.business_hours_end or 18
        
        if current_hour < 6 or current_hour > 22:
            total_risk += 20
            risk_reasons.append(f'Transaction at high-risk hour: {current_hour}:00')
            triggered_patterns.append('high_risk_hours')
        elif current_hour < business_start or current_hour >= business_end:
            total_risk += 10
            risk_reasons.append(f'Transaction outside business hours: {current_hour}:00')
            triggered_patterns.append('outside_business_hours')
    
    # CHECK 8: USER AVERAGE COMPARISON
    historical = Transaction.objects.filter(
        user=user,
        status='approved',
        created_at__gte=timezone.now() - timedelta(days=90)
    ).aggregate(
        avg_amount=Avg('amount'),
        count=Count('id')
    )
    
    if historical['count'] and historical['count'] >= 5:
        avg_amount = historical['avg_amount'] or 0
        
        if avg_amount > 0 and amount > avg_amount * 3:
            deviation_pct = ((amount - avg_amount) / avg_amount) * 100
            total_risk += 40
            risk_reasons.append(f'Amount {deviation_pct:.0f}% above user average')
            triggered_patterns.append('amount_exceeds_user_average')
    
    # CHECK 9: DORMANT ACCOUNT
    last_txn = Transaction.objects.filter(
        user=user,
        status='approved'
    ).order_by('-created_at').first()
    
    if last_txn:
        days_since_last = (timezone.now() - last_txn.created_at).days
        
        if days_since_last >= 90:
            total_risk += 45
            risk_reasons.append(f'Dormant account active after {days_since_last} days')
            triggered_patterns.append('dormant_account')
    
    # CHECK 10: NEW ACCOUNT
    account_age_days = (timezone.now() - user.date_joined).days
    
    if account_age_days < 30 and amount > 50000:
        total_risk += 50
        risk_reasons.append(f'New account ({account_age_days} days) with high-value transaction')
        triggered_patterns.append('new_account_high_value')
    
    # CHECK 11: TRANSACTION TYPE RISK
    if transaction_type == 'international':
        total_risk += 35
        risk_reasons.append('International transfer')
        triggered_patterns.append('international_transfer')
    elif transaction_type == 'crypto':
        total_risk += 40
        risk_reasons.append('Cryptocurrency transaction')
        triggered_patterns.append('crypto_transaction')
    elif transaction_type == 'p2p' and amount > 100000:
        total_risk += 30
        risk_reasons.append('High-value P2P transfer')
        triggered_patterns.append('p2p_high_value')
    
    # CHECK 12: NEW DEVICE HIGH AMOUNT
    if device:
        device_age_hours = (timezone.now() - device.first_seen_at).total_seconds() / 3600
        
        if device_age_hours < 24 and amount > 50000:
            total_risk += 40
            risk_reasons.append(f'High amount from new device (age: {device_age_hours:.1f} hours)')
            triggered_patterns.append('new_device_high_amount')
    
    # CALCULATE RISK LEVEL
    total_risk = min(total_risk, 100)
    
    if total_risk >= 80:
        risk_level = 'critical'
        action = 'block'
    elif total_risk >= 60:
        risk_level = 'high'
        action = 'hold'
    elif total_risk >= 40:
        risk_level = 'medium'
        action = 'flag'
    elif total_risk >= 20:
        risk_level = 'low'
        action = 'allow'
    else:
        risk_level = 'safe'
        action = 'allow'
    
    # Block if critical
    if action == 'block':
        return {
            'allowed': False,
            'error': {
                'error': 'Transaction Blocked',
                'reason': 'high_risk',
                'message': 'Transaction blocked due to high fraud risk',
                'risk_score': total_risk,
                'risk_reasons': risk_reasons
            },
            'risk_score': total_risk,
            'risk_level': risk_level,
            'risk_reasons': risk_reasons,
            'triggered_patterns': triggered_patterns,
        }
    
    # RETURN RESULT
    return {
        'allowed': True,
        'risk_score': total_risk,
        'risk_level': risk_level,
        'risk_reasons': risk_reasons,
        'triggered_patterns': triggered_patterns,
        'requires_manual_review': total_risk >= 60,
        'action': action,
        'location_info': {
            'ip_address': ip_address,
            'country': country_name,
            'country_code': country_code,
            'city': city,
        }
    }
