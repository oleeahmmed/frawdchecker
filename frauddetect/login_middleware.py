"""
🛡️ Login Security Middleware - ALL IN ONE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

সব কিছু এক file এ। কোনো dependency নেই।

Settings.py তে add করো:
    MIDDLEWARE = [
        ...
        'frauddetect.login_middleware.LoginSecurityMiddleware',
    ]
"""

import hashlib
import requests
from django.http import JsonResponse
from django.utils import timezone
from django.conf import settings


# ═══════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS (সব এখানে)
# ═══════════════════════════════════════════════════════════════════════════════

def get_client_ip(request):
    """Request থেকে IP address বের করে"""
    headers = ['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'REMOTE_ADDR']
    
    for header in headers:
        ip = request.META.get(header)
        if ip:
            if ',' in ip:
                ip = ip.split(',')[0].strip()
            return ip.strip()
    
    return request.META.get('REMOTE_ADDR', '127.0.0.1')


def get_geo_location(ip_address):
    """IP থেকে location বের করে"""
    # Local IP
    if ip_address.startswith(('127.', '10.', '172.', '192.168.', 'localhost')):
        return {
            'country_code': 'LOCAL',
            'country_name': 'Local Network',
            'city': 'Local',
        }
    
    # Try API
    try:
        response = requests.get(f'https://ipapi.co/{ip_address}/json/', timeout=3)
        if response.status_code == 200:
            data = response.json()
            return {
                'country_code': data.get('country_code', 'Unknown'),
                'country_name': data.get('country_name', 'Unknown'),
                'city': data.get('city', 'Unknown'),
            }
    except:
        pass
    
    return {
        'country_code': 'Unknown',
        'country_name': 'Unknown',
        'city': 'Unknown',
    }


def is_ip_blocked(ip_address):
    """IP blocked কিনা check করে"""
    from .models import IPBlocklist
    
    entry = IPBlocklist.objects.filter(
        ip_address=ip_address,
        is_active=True
    ).first()
    
    return (entry is not None, entry)


def is_superuser_request(request):
    """
    Check if request is from a superuser
    Superusers should NEVER be blocked
    """
    from .superuser_protection import is_superuser_username
    
    # Check if user is authenticated and is superuser
    if hasattr(request, 'user') and request.user.is_authenticated:
        if request.user.is_superuser:
            return True
    
    # Check from POST data (during login)
    username = None
    
    # Try POST data
    if request.POST:
        username = request.POST.get('username') or request.POST.get('email')
    
    # Try JSON body
    if not username:
        try:
            import json
            if request.body:
                body = json.loads(request.body.decode('utf-8'))
                username = body.get('username') or body.get('email')
        except:
            pass
    
    if username:
        return is_superuser_username(username)
    
    return False


def is_ip_whitelisted(ip_address):
    """
    IP whitelisted কিনা check করে
    দুই জায়গায় check করে:
    1. IPWhitelist model (detailed management)
    2. FraudConfig.quick_whitelist_ips (quick access)
    """
    # Check IPWhitelist model
    try:
        from .models import IPWhitelist
        if IPWhitelist.is_whitelisted(ip_address):
            return True
    except:
        pass
    
    # Check FraudConfig quick whitelist
    try:
        from .models import FraudConfig
        config = FraudConfig.objects.filter(is_active=True).first()
        if config and config.quick_whitelist_ips:
            if ip_address in config.quick_whitelist_ips:
                return True
    except:
        pass
    
    return False


def get_allowed_countries():
    """Allowed countries list return করে"""
    try:
        from .models import FraudConfig
        config = FraudConfig.objects.filter(is_active=True).first()
        if config:
            return config.allowed_countries or ['SA']
    except:
        pass
    
    return getattr(settings, 'ALLOWED_COUNTRIES', ['SA'])


def create_login_event(username, status, ip_address, country_code, city, risk_score, risk_reasons, user_agent):
    """Login event তৈরি করে"""
    from .models import LoginEvent
    
    return LoginEvent.objects.create(
        user=None,
        username=username,
        device=None,
        status=status,
        ip_address=ip_address,
        country_code=country_code,
        city=city,
        is_suspicious=risk_score >= 40,
        risk_score=risk_score,
        risk_reasons=risk_reasons,
        user_agent=user_agent
    )


def create_system_log(log_type, level, message, ip_address, metadata):
    """System log তৈরি করে"""
    from .models import SystemLog
    
    return SystemLog.objects.create(
        log_type=log_type,
        level=level,
        message=message,
        user=None,
        ip_address=ip_address,
        metadata=metadata
    )


def auto_block_ip(ip_address, reason):
    """IP automatically block করে"""
    from .models import IPBlocklist
    from django.contrib.auth.models import User
    
    # Already blocked check
    if IPBlocklist.objects.filter(ip_address=ip_address).exists():
        return None
    
    # Get admin
    admin = User.objects.filter(is_superuser=True).order_by('id').first()
    
    # Create block entry
    return IPBlocklist.objects.create(
        ip_address=ip_address,
        reason=reason,
        is_active=True,
        blocked_by=admin
    )


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN MIDDLEWARE CLASS
# ═══════════════════════════════════════════════════════════════════════════════

class LoginSecurityMiddleware:
    """
    🛡️ Login Security Middleware - ALL IN ONE
    
    Features:
    ✅ IP Blocklist Check
    ✅ Country Restriction (Saudi Arabia only)
    ✅ Auto IP Blocking
    ✅ Login Event Logging
    ✅ System Logging
    ✅ NO DEPENDENCIES - সব কিছু এখানে
    
    Applies to:
    - /api/auth/login/
    - /api/token/
    - /admin/login/
    """
    
    # Login endpoints
    LOGIN_ENDPOINTS = [
        '/api/auth/login/',
        '/api/token/',
        '/api/auth/token/',
        '/admin/login/',
    ]
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        """
        Main middleware logic
        """
        # ─────────────────────────────────────────────────────────────────────
        # Only check login endpoints (POST only)
        # ─────────────────────────────────────────────────────────────────────
        if request.method == 'POST' and request.path in self.LOGIN_ENDPOINTS:
            
            # Get IP and location
            ip_address = get_client_ip(request)
            geo_data = get_geo_location(ip_address)
            country_code = geo_data['country_code']
            country_name = geo_data['country_name']
            city = geo_data['city']
            user_agent = request.META.get('HTTP_USER_AGENT', '')
            
            # Get username from request
            username = 'Unknown'
            
            # Try to get from POST data
            if request.POST:
                username = request.POST.get('username') or request.POST.get('email') or 'Unknown'
            
            # Try to get from JSON body
            if username == 'Unknown':
                try:
                    import json
                    if request.body:
                        body = json.loads(request.body.decode('utf-8'))
                        username = body.get('username') or body.get('email') or 'Unknown'
                except:
                    pass
            
            print(f"🔍 LOGIN CHECK: {username} from {ip_address} ({country_code})")
            
            # ═════════════════════════════════════════════════════════════════
            # CHECK 0: SUPERUSER PROTECTION (Never block superusers)
            # ═════════════════════════════════════════════════════════════════
            if is_superuser_request(request):
                print(f"👑 SUPERUSER: {username} - Bypassing all checks (Admin Protection)")
                
                # Log superuser access
                create_system_log(
                    log_type='security',
                    level='info',
                    message=f"Superuser {username} accessed login from {ip_address} ({country_code})",
                    ip_address=ip_address,
                    metadata={
                        'username': username,
                        'country_code': country_code,
                        'superuser': True,
                        'protection': 'admin_never_blocked'
                    }
                )
                
                # Continue to login view (bypass all checks)
                response = self.get_response(request)
                return response
            
            # ═════════════════════════════════════════════════════════════════
            # CHECK 1: IP WHITELIST (Bypass all checks)
            # ═════════════════════════════════════════════════════════════════
            if is_ip_whitelisted(ip_address):
                print(f"✅ WHITELISTED IP: {ip_address} - Bypassing all checks")
                
                # Log whitelisted access
                create_system_log(
                    log_type='security',
                    level='info',
                    message=f"Whitelisted IP {ip_address} accessed login as {username}",
                    ip_address=ip_address,
                    metadata={
                        'username': username,
                        'country_code': country_code,
                        'whitelisted': True
                    }
                )
                
                # Continue to login view (bypass all checks)
                response = self.get_response(request)
                return response
            
            # ═════════════════════════════════════════════════════════════════
            # CHECK 1: IP BLOCKLIST
            # ═════════════════════════════════════════════════════════════════
            is_blocked_flag, blocked_entry = is_ip_blocked(ip_address)
            
            if is_blocked_flag:
                print(f"🚫 BLOCKED: IP Blocklist - {ip_address}")
                
                # Create login event
                create_login_event(
                    username=username,
                    status='blocked',
                    ip_address=ip_address,
                    country_code=country_code,
                    city=city,
                    risk_score=100,
                    risk_reasons=['IP address is blocked'],
                    user_agent=user_agent
                )
                
                # Create system log
                create_system_log(
                    log_type='security',
                    level='critical',
                    message=f"Blocked IP {ip_address} attempted login as {username}",
                    ip_address=ip_address,
                    metadata={
                        'username': username,
                        'country_code': country_code,
                        'reason': 'ip_blocked'
                    }
                )
                
                return JsonResponse({
                    'error': 'Access Denied',
                    'blocked': True,
                    'reason': 'ip_blocked',
                    'message': 'Your IP address has been blocked',
                    'details': {
                        'your_ip': ip_address,
                        'block_reason': blocked_entry.reason if blocked_entry else 'Security violation',
                    },
                    'contact': 'Please contact support if you believe this is an error.'
                }, status=403)
            
            # ═════════════════════════════════════════════════════════════════
            # CHECK 2: COUNTRY RESTRICTION
            # ═════════════════════════════════════════════════════════════════
            allowed_countries = get_allowed_countries()
            
            if country_code not in allowed_countries:
                print(f"🚫 BLOCKED: Country - {country_code} ({country_name})")
                
                # Auto-block IP
                auto_block_ip(
                    ip_address=ip_address,
                    reason=f"Auto-block: Login from non-allowed country {country_code} ({country_name})"
                )
                
                # Create login event
                create_login_event(
                    username=username,
                    status='blocked',
                    ip_address=ip_address,
                    country_code=country_code,
                    city=city,
                    risk_score=100,
                    risk_reasons=[f'Non-allowed country: {country_code}'],
                    user_agent=user_agent
                )
                
                # Create system log
                create_system_log(
                    log_type='security',
                    level='critical',
                    message=f"Blocked login from {country_name} ({country_code}) - User: {username}, IP: {ip_address}",
                    ip_address=ip_address,
                    metadata={
                        'username': username,
                        'country_code': country_code,
                        'country_name': country_name,
                        'city': city,
                        'reason': 'non_allowed_country'
                    }
                )
                
                return JsonResponse({
                    'error': 'Access Denied',
                    'blocked': True,
                    'reason': 'non_allowed_country',
                    'message': 'Access to this service is restricted to Saudi Arabia only',
                    'details': {
                        'your_country': country_name,
                        'your_country_code': country_code,
                        'your_city': city,
                        'your_ip': ip_address,
                        'allowed_countries': ['Saudi Arabia (SA)'],
                        'ip_blocked': True,
                    },
                    'contact': 'Please contact support if you believe this is an error.'
                }, status=403)
            
            # ✅ All checks passed
            print(f"✅ ALLOWED: {username} from {country_code}")
        
        # ─────────────────────────────────────────────────────────────────────
        # Continue to next middleware/view
        # ─────────────────────────────────────────────────────────────────────
        response = self.get_response(request)
        return response
