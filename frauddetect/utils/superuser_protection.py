"""
👑 Superuser Protection Module
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Superusers should NEVER be blocked from the system.
This module provides protection mechanisms.

Rules:
1. ✅ Superuser IPs can NEVER be blocked
2. ✅ Superuser devices can NEVER be blocked
3. ✅ Superuser devices are automatically trusted
4. ✅ Superusers bypass ALL fraud checks
5. ✅ Superusers bypass country restrictions
"""

from django.contrib.auth.models import User


def is_superuser_username(username):
    """
    Check if username belongs to a superuser
    
    Args:
        username (str): Username to check
        
    Returns:
        bool: True if user is superuser, False otherwise
    """
    try:
        user = User.objects.filter(username=username).first()
        if user and user.is_superuser:
            return True
    except Exception as e:
        print(f"⚠️ Error checking superuser: {e}")
    
    return False


def is_superuser_ip(ip_address):
    """
    Check if IP address belongs to any superuser
    
    Args:
        ip_address (str): IP address to check
        
    Returns:
        bool: True if IP belongs to superuser, False otherwise
    """
    try:
        from frauddetect.models import Device
        
        # Check if any superuser has used this IP
        superuser_devices = Device.objects.filter(
            user__is_superuser=True,
            last_ip=ip_address
        )
        
        return superuser_devices.exists()
    except Exception as e:
        print(f"⚠️ Error checking superuser IP: {e}")
    
    return False


def is_superuser_device(device):
    """
    Check if device belongs to a superuser
    
    Args:
        device: Device object
        
    Returns:
        bool: True if device belongs to superuser, False otherwise
    """
    try:
        if device and device.user and device.user.is_superuser:
            return True
    except Exception as e:
        print(f"⚠️ Error checking superuser device: {e}")
    
    return False


def protect_superuser_device(device):
    """
    Apply protection to superuser device
    - Auto-trust
    - Prevent blocking
    
    Args:
        device: Device object
        
    Returns:
        bool: True if protection applied, False otherwise
    """
    try:
        if not device or not device.user:
            return False
        
        if device.user.is_superuser:
            # Auto-trust
            if not device.is_trusted:
                device.is_trusted = True
                print(f"✅ Auto-trusted superuser device: {device.device_name}")
            
            # Prevent blocking
            if device.is_blocked:
                device.is_blocked = False
                print(f"⚠️ Prevented blocking of superuser device: {device.device_name}")
            
            device.save()
            return True
    except Exception as e:
        print(f"⚠️ Error protecting superuser device: {e}")
    
    return False


def can_block_ip(ip_address):
    """
    Check if IP can be blocked
    Superuser IPs cannot be blocked
    
    Args:
        ip_address (str): IP address to check
        
    Returns:
        tuple: (can_block: bool, reason: str)
    """
    if is_superuser_ip(ip_address):
        return False, "IP belongs to superuser - cannot block"
    
    return True, "OK"


def can_block_device(device):
    """
    Check if device can be blocked
    Superuser devices cannot be blocked
    
    Args:
        device: Device object
        
    Returns:
        tuple: (can_block: bool, reason: str)
    """
    if is_superuser_device(device):
        return False, "Device belongs to superuser - cannot block"
    
    return True, "OK"


def get_superuser_protection_status(user=None, ip_address=None, device=None):
    """
    Get comprehensive protection status
    
    Args:
        user: User object (optional)
        ip_address: IP address (optional)
        device: Device object (optional)
        
    Returns:
        dict: Protection status details
    """
    status = {
        'is_protected': False,
        'protection_type': None,
        'can_be_blocked': True,
        'reason': None
    }
    
    # Check user
    if user and user.is_superuser:
        status['is_protected'] = True
        status['protection_type'] = 'superuser'
        status['can_be_blocked'] = False
        status['reason'] = 'User is superuser'
        return status
    
    # Check IP
    if ip_address and is_superuser_ip(ip_address):
        status['is_protected'] = True
        status['protection_type'] = 'superuser_ip'
        status['can_be_blocked'] = False
        status['reason'] = 'IP belongs to superuser'
        return status
    
    # Check device
    if device and is_superuser_device(device):
        status['is_protected'] = True
        status['protection_type'] = 'superuser_device'
        status['can_be_blocked'] = False
        status['reason'] = 'Device belongs to superuser'
        return status
    
    return status


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DECORATOR FOR VIEWS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def superuser_bypass(func):
    """
    Decorator to bypass fraud checks for superusers
    
    Usage:
        @superuser_bypass
        def my_view(request):
            ...
    """
    def wrapper(request, *args, **kwargs):
        # Check if user is superuser
        if hasattr(request, 'user') and request.user.is_authenticated:
            if request.user.is_superuser:
                print(f"👑 SUPERUSER BYPASS: {request.user.username}")
                # Set flag to bypass checks
                request.superuser_bypass = True
        
        return func(request, *args, **kwargs)
    
    return wrapper
