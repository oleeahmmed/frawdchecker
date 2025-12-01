from django.utils.deprecation import MiddlewareMixin
from django.utils import timezone
from django.http import JsonResponse
from .models import Device, IPBlocklist
from .utils import calculate_device_fingerprint, get_client_ip


class IPBlocklistMiddleware(MiddlewareMixin):
    """
    IP Blocklist Check - Runs BEFORE authentication
    
    Purpose:
    1. Check if IP is blocked
    2. Block request immediately if IP is blacklisted
    3. No authentication needed - security first!
    """
    
    def process_request(self, request):
        # Get client IP
        ip_address = get_client_ip(request)
        
        # Check if IP is blocked
        is_blocked = IPBlocklist.objects.filter(
            ip_address=ip_address,
            is_active=True
        ).exists()
        
        if is_blocked:
            # Return 403 Forbidden immediately
            return JsonResponse(
                {
                    'error': 'Access Denied',
                    'message': 'Your IP address has been blocked due to suspicious activity.',
                    'ip_address': ip_address,
                    'contact': 'Please contact support if you believe this is an error.'
                },
                status=403
            )
        
        # IP is not blocked, continue processing
        return None


class DeviceFingerprintMiddleware(MiddlewareMixin):
    """
    Device Fingerprint Tracking - Runs AFTER authentication
    
    Purpose:
    1. Extract device fingerprint from request
    2. Update device in database if exists
    3. Create new device if not exists
    4. Attach device object to request
    """
    
    def process_request(self, request):
        # Get IP address (always needed)
        ip_address = get_client_ip(request)
        request.client_ip = ip_address
        
        # Only track devices for authenticated users
        if request.user.is_authenticated:
            # Calculate fingerprint
            fingerprint_hash = calculate_device_fingerprint(request)
            request.device_fingerprint = fingerprint_hash
            
            # Get or create device
            device, created = Device.objects.get_or_create(
                user=request.user,
                fingerprint_hash=fingerprint_hash,
                defaults={
                    'last_ip': ip_address,
                    'device_fingerprint': fingerprint_hash,
                }
            )
            
            # Check if device is blocked
            if device.is_blocked:
                return JsonResponse(
                    {
                        'error': 'Device Blocked',
                        'message': 'This device has been blocked due to suspicious activity.',
                        'device_id': device.id,
                        'contact': 'Please contact support for assistance.'
                    },
                    status=403
                )
            
            # Update existing device
            if not created:
                device.last_seen_at = timezone.now()
                device.last_ip = ip_address
                device.save(update_fields=['last_seen_at', 'last_ip'])
            
            # Attach device to request
            request.device = device
        else:
            # Anonymous user
            request.device = None
            request.device_fingerprint = None
        
        return None