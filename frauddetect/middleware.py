from django.utils.deprecation import MiddlewareMixin
from django.utils import timezone
from .models import Device
from .utils import calculate_device_fingerprint, get_client_ip


class DeviceFingerprintMiddleware(MiddlewareMixin):
    """
    প্রতিটি Request এ Device Fingerprint ট্র্যাক করে
    
    কাজ:
    1. Request থেকে device fingerprint বের করে
    2. Device ডাটাবেসে থাকলে update করে
    3. নতুন হলে create করে
    4. Request object এ device attach করে
    """
    
    def process_request(self, request):
        # শুধুমাত্র authenticated user দের জন্য
        if request.user.is_authenticated:
            # Fingerprint বের করা
            fingerprint_hash = calculate_device_fingerprint(request)
            ip_address = get_client_ip(request)
            
            # Request এ attach করা (পরে ব্যবহারের জন্য)
            request.device_fingerprint = fingerprint_hash
            request.client_ip = ip_address
            
            # Device খোঁজা বা তৈরি করা
            device, created = Device.objects.get_or_create(
                user=request.user,
                fingerprint_hash=fingerprint_hash,
                defaults={
                    'last_ip': ip_address,
                    'device_fingerprint': fingerprint_hash,
                }
            )
            
            if not created:
                # যদি আগে থেকে থাকে, তাহলে update করা
                device.last_seen_at = timezone.now()
                device.last_ip = ip_address
                device.save(update_fields=['last_seen_at', 'last_ip'])
            
            # Request এ device attach করা
            request.device = device
        else:
            request.device = None
            request.device_fingerprint = None
            request.client_ip = get_client_ip(request)
        
        return None