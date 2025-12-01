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
        
        # Skip for admin panel, static files, and authentication endpoints
        # IMPORTANT: Allow login page access so admins can login to unblock IPs
        if (request.path.startswith('/admin/') or 
            request.path.startswith('/static/') or
            request.path.startswith('/media/') or
            request.path.startswith('/api/auth/')):  # Allow all auth endpoints
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
    
    BYPASS: Superusers are never blocked (but only AFTER they're authenticated)
    """
    
    def process_request(self, request):
        # Skip for static files and admin static assets
        if (request.path.startswith('/static/') or 
            request.path.startswith('/media/')):
            return None
        
        # BYPASS: Allow ONLY superusers unrestricted access (but only if already authenticated)
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
            print(f"🚫 IP BLOCKED: {ip_address} attempted to access {request.path}")
            
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
    2. Attach device info to request for authenticated users
    3. Track device usage
    
    BYPASS: Superusers always have trusted devices
    
    NOTE: This middleware ONLY tracks - does NOT block.
    Blocking happens in authentication layer BEFORE user is authenticated.
    """
    
    def process_request(self, request):
        # Get IP address (always needed)
        ip_address = get_client_ip(request)
        request.client_ip = ip_address
        
        # Only track devices for authenticated users
        if request.user.is_authenticated:
            # BYPASS: ONLY superusers always have trusted devices
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
            
            # Get geolocation
            geo_data = get_geo_location(ip_address)
            country_code = geo_data.get('country_code', 'Unknown')
            
            # Try to get existing device
            try:
                device = Device.objects.get(
                    user=request.user,
                    fingerprint_hash=fingerprint_hash
                )
                
                # Update last seen
                device.last_seen_at = timezone.now()
                device.last_ip = ip_address
                device.last_country_code = country_code
                device.save(update_fields=['last_seen_at', 'last_ip', 'last_country_code'])
                
                print(f"✓ EXISTING DEVICE: User={request.user.username}, Device={device.id}, Trusted={device.is_trusted}, Blocked={device.is_blocked}")
                
            except Device.DoesNotExist:
                # Device will be created during login - this shouldn't happen
                # but handle gracefully
                device = None
                print(f"⚠️  Device not found for authenticated user {request.user.username}")
            
            # Attach device to request
            request.device = device
        else:
            # Anonymous user
            request.device = None
            request.device_fingerprint = None
        
        return None