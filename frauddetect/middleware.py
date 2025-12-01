from django.utils.deprecation import MiddlewareMixin
from django.utils import timezone
from django.http import JsonResponse
from django.conf import settings
from .models import Device, IPBlocklist
from .utils import calculate_device_fingerprint, get_client_ip, get_geo_location
import ipaddress


class GeoRestrictionMiddleware(MiddlewareMixin):
    """
    Geo-Restriction Middleware - KSA Compliance
    
    Purpose:
    1. Enforce geographic access restrictions
    2. Only allow access from Saudi Arabia (and other specified countries)
    3. Ensure data residency compliance
    4. Block/flag access from non-allowed countries
    
    Runs BEFORE authentication for maximum security
    
    BYPASS: Superusers (staff) are never blocked
    """
    
    def process_request(self, request):
        # Skip if geo-restriction is disabled
        if not getattr(settings, 'GEO_RESTRICTION_ENABLED', False):
            return None
        
        # Skip for admin panel and static files
        if request.path.startswith('/admin/') or request.path.startswith('/static/'):
            return None
        
        # BYPASS: Allow ONLY superusers unrestricted access (not regular staff)
        # Check if user is authenticated (user attribute may not exist yet)
        if hasattr(request, 'user') and request.user.is_authenticated and request.user.is_superuser:
            print(f"✓ Geo-restriction bypassed: Superuser {request.user.username}")
            return None
        
        # Get client IP
        ip_address = get_client_ip(request)
        
        # Check if IP is in whitelist
        whitelist = getattr(settings, 'GEO_RESTRICTION_WHITELIST_IPS', [])
        if self._is_ip_whitelisted(ip_address, whitelist):
            print(f"✓ Geo-restriction bypassed: Whitelisted IP {ip_address}")
            return None
        
        # Skip for local/private IPs (development)
        if self._is_private_ip(ip_address):
            print(f"⚠️  Geo-restriction skipped: Local IP {ip_address}")
            return None
        
        # Get geolocation
        geo_data = get_geo_location(ip_address)
        country_code = geo_data.get('country_code', 'Unknown')
        
        # Get allowed countries
        allowed_countries = getattr(settings, 'ALLOWED_COUNTRIES', ['SA'])
        
        # Check if country is allowed
        if country_code not in allowed_countries:
            action = getattr(settings, 'GEO_RESTRICTION_ACTION', 'block')
            
            if action == 'block':
                # Block access
                print(f"🚫 GEO-BLOCKED: Access from {country_code} ({geo_data.get('country_name')}) - IP: {ip_address}")
                
                # AUTOMATICALLY ADD IP TO BLOCKLIST (if enabled)
                from .models import SystemLog, IPBlocklist
                
                auto_block_enabled = getattr(settings, 'AUTO_BLOCK_NON_ALLOWED_COUNTRY_IPS', True)
                ip_already_blocked = False
                
                if auto_block_enabled:
                    # Check if IP is already in blocklist
                    ip_already_blocked = IPBlocklist.objects.filter(
                        ip_address=ip_address
                    ).exists()
                    
                    if not ip_already_blocked:
                        # Get first superuser (system admin) for blocked_by field
                        from django.contrib.auth.models import User
                        system_admin = User.objects.filter(is_superuser=True).order_by('id').first()
                        
                        # Add IP to blocklist
                        IPBlocklist.objects.create(
                            ip_address=ip_address,
                            reason=f"Automatic block: Access attempt from non-allowed country {country_code} ({geo_data.get('country_name')})",
                            is_active=True,
                            blocked_by=system_admin  # Set to first superuser
                        )
                        blocked_by_username = system_admin.username if system_admin else 'System'
                        print(f"🚫 IP AUTO-BLOCKED: {ip_address} added to blocklist (Country: {country_code}, Blocked by: {blocked_by_username})")
                        
                        # Log the auto-block
                        SystemLog.objects.create(
                            log_type='security',
                            level='critical',
                            message=f"IP {ip_address} automatically added to blocklist (Country: {country_code}, Blocked by: {blocked_by_username})",
                            user=system_admin,
                            ip_address=ip_address,
                            metadata={
                                'country_code': country_code,
                                'country_name': geo_data.get('country_name'),
                                'city': geo_data.get('city'),
                                'action': 'auto_blocked',
                                'blocked_by': blocked_by_username
                            }
                        )
                    else:
                        print(f"⚠️  IP already in blocklist: {ip_address}")
                
                # Log the blocked attempt
                SystemLog.objects.create(
                    log_type='security',
                    level='critical',
                    message=f"Geo-restriction: Blocked access from {country_code} ({geo_data.get('country_name')})",
                    ip_address=ip_address,
                    metadata={
                        'country_code': country_code,
                        'country_name': geo_data.get('country_name'),
                        'city': geo_data.get('city'),
                        'allowed_countries': allowed_countries,
                        'ip_auto_blocked': not ip_already_blocked
                    }
                )
                
                return JsonResponse(
                    {
                        'error': 'Access Denied',
                        'message': 'Access to this service is restricted to Saudi Arabia only.',
                        'details': 'This application complies with Saudi Arabia data residency requirements.',
                        'country_detected': geo_data.get('country_name', 'Unknown'),
                        'country_code': country_code,
                        'contact': 'Please contact support if you believe this is an error.'
                    },
                    status=403
                )
            else:
                # Flag but allow (for monitoring)
                print(f"⚠️  GEO-FLAGGED: Access from {country_code} - IP: {ip_address}")
                request.geo_flagged = True
                request.geo_country = country_code
        else:
            # Allowed country
            print(f"✓ Geo-check passed: {country_code} ({geo_data.get('country_name')}) - IP: {ip_address}")
            request.geo_allowed = True
            request.geo_country = country_code
        
        return None
    
    def _is_private_ip(self, ip_address):
        """Check if IP is private/local"""
        try:
            ip = ipaddress.ip_address(ip_address)
            return ip.is_private or ip.is_loopback or ip.is_link_local
        except:
            return False
    
    def _is_ip_whitelisted(self, ip_address, whitelist):
        """Check if IP is in whitelist"""
        try:
            ip = ipaddress.ip_address(ip_address)
            for whitelisted in whitelist:
                if '/' in whitelisted:
                    # CIDR notation
                    network = ipaddress.ip_network(whitelisted, strict=False)
                    if ip in network:
                        return True
                else:
                    # Single IP
                    if str(ip) == whitelisted:
                        return True
            return False
        except:
            return False


class IPBlocklistMiddleware(MiddlewareMixin):
    """
    IP Blocklist Check - Runs BEFORE authentication
    
    Purpose:
    1. Check if IP is blocked
    2. Block request immediately if IP is blacklisted
    3. No authentication needed - security first!
    
    BYPASS: Superusers (staff) are never blocked
    """
    
    def process_request(self, request):
        # BYPASS: Allow ONLY superusers unrestricted access (not regular staff)
        # Check if user is authenticated (user attribute may not exist yet)
        if hasattr(request, 'user') and request.user.is_authenticated and request.user.is_superuser:
            print(f"✓ IP blocklist bypassed: Superuser {request.user.username}")
            return None
        
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
    Device Fingerprint Tracking with Country-Based Trust - Runs AFTER authentication
    
    Purpose:
    1. Extract device fingerprint from request
    2. Check if device exists in database
    3. Create new device with country-based trust:
       - From ALLOWED_COUNTRIES → is_trusted = True
       - From other countries → is_blocked = True
    4. Block login if device is blocked
    5. Attach device object to request
    
    BYPASS: Superusers (staff) are never blocked and always trusted
    
    NOTE: This middleware does NOT block - it only tracks devices.
    Blocking is handled in the login view after all records are created.
    """
    
    def process_request(self, request):
        # Get IP address (always needed)
        ip_address = get_client_ip(request)
        request.client_ip = ip_address
        
        # Only track devices for authenticated users
        if request.user.is_authenticated:
            # BYPASS: ONLY superusers always have trusted devices (not regular staff)
            if request.user.is_superuser:
                print(f"✓ Device check bypassed: Superuser {request.user.username}")
                # Create a virtual trusted device for superusers
                request.device = type('obj', (object,), {
                    'id': 0,
                    'is_trusted': True,
                    'is_blocked': False,
                    'status': 'superuser'
                })()
                request.device_fingerprint = 'superuser'
                return None
            
            # Calculate fingerprint
            fingerprint_hash = calculate_device_fingerprint(request)
            request.device_fingerprint = fingerprint_hash
            
            # Get geolocation to determine country
            geo_data = get_geo_location(ip_address)
            country_code = geo_data.get('country_code', 'Unknown')
            
            # Get allowed countries from settings
            allowed_countries = getattr(settings, 'ALLOWED_COUNTRIES', ['SA'])
            
            # Determine if device should be trusted or blocked based on country
            is_from_allowed_country = country_code in allowed_countries
            
            # Calculate initial risk score
            from .utils import calculate_device_risk_score
            
            # Get or create device
            device, created = Device.objects.get_or_create(
                user=request.user,
                fingerprint_hash=fingerprint_hash,
                defaults={
                    'last_ip': ip_address,
                    'device_fingerprint': fingerprint_hash,
                    'is_trusted': is_from_allowed_country,  # Auto-trust if from allowed country
                    'is_blocked': not is_from_allowed_country,  # Auto-block if not from allowed country
                    'status': 'normal' if is_from_allowed_country else 'blocked',
                    'last_country_code': country_code,
                    'risk_score': 0 if is_from_allowed_country else 70  # Initial risk score
                }
            )
            
            # Calculate and update device risk score
            device_risk_score = calculate_device_risk_score(device, country_code)
            if device.risk_score != device_risk_score:
                device.risk_score = device_risk_score
                device.save(update_fields=['risk_score'])
            
            # Log device creation/detection
            if created:
                if is_from_allowed_country:
                    print(f"✓ NEW DEVICE TRUSTED: User={request.user.username}, Country={country_code}, Device={device.id}, Risk={device_risk_score}")
                else:
                    print(f"🚫 NEW DEVICE BLOCKED: User={request.user.username}, Country={country_code}, Device={device.id}, Risk={device_risk_score}")
                
                # Log to system
                from .models import SystemLog
                SystemLog.objects.create(
                    log_type='security',
                    level='info' if is_from_allowed_country else 'warning',
                    message=f"New device {'trusted' if is_from_allowed_country else 'blocked'} for {request.user.username} from {country_code}",
                    user=request.user,
                    ip_address=ip_address,
                    metadata={
                        'device_id': device.id,
                        'country_code': country_code,
                        'is_trusted': device.is_trusted,
                        'is_blocked': device.is_blocked,
                        'risk_score': device_risk_score
                    }
                )
            else:
                print(f"✓ EXISTING DEVICE: User={request.user.username}, Device={device.id}, Risk={device_risk_score}, Trusted={device.is_trusted}, Blocked={device.is_blocked}")
            
            # Update existing device
            if not created:
                device.last_seen_at = timezone.now()
                device.last_ip = ip_address
                device.last_country_code = country_code
                device.save(update_fields=['last_seen_at', 'last_ip', 'last_country_code'])
            
            # Attach device to request (even if blocked - let login view handle blocking)
            request.device = device
        else:
            # Anonymous user
            request.device = None
            request.device_fingerprint = None
        
        return None