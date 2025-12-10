"""
🔐 Login Serializers - Complete Fraud Detection
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Complete login with:
✅ Device tracking
✅ Device trust check
✅ Success/Failed/Blocked login events
✅ IP blocking → Device blocking
✅ Device blocking → Login denied
✅ Untrusted device → Login denied
"""

from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.utils import timezone
import hashlib


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 🛡️ LOGIN PROTECTION ENGINE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class LoginProtectionEngine:
    """
    🛡️ Complete Login Protection Engine
    
    Security Checks:
    1. ✅ IP Blocklist Check
    2. ✅ Device Blocklist Check  
    3. ✅ Device Trust Check
    4. ✅ Country Restriction (SA only)
    5. ✅ Risk Assessment
    """
    
    def __init__(self, request, user=None, username=None):
        from frauddetect.middleware import get_client_ip, get_geo_location
        
        self.request = request
        self.user = user
        self.username = username or (user.username if user else 'unknown')
        
        # Get IP and location
        self.ip_address = get_client_ip(request)
        self.geo_data = get_geo_location(self.ip_address)
        self.country_code = self.geo_data['country_code']
        self.country_name = self.geo_data['country_name']
        self.city = self.geo_data['city']
        self.user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        # Device
        self.device = None
        
        # Risk tracking
        self.risk_score = 0
        self.risk_reasons = []
        self.is_suspicious = False
    
    def get_or_create_device(self):
        """Get or create device based on fingerprint"""
        from frauddetect.models import Device
        from frauddetect.utils import is_superuser_device
        
        # Generate fingerprint
        fingerprint_data = f"{self.user_agent}|{self.ip_address}"
        fingerprint_hash = hashlib.sha256(fingerprint_data.encode()).hexdigest()
        
        # Extract device details
        device_info = self._extract_device_info()
        
        # Get or create device
        device, created = Device.objects.get_or_create(
            user=self.user,
            fingerprint_hash=fingerprint_hash,
            defaults={
                'device_fingerprint': fingerprint_data,
                'device_name': device_info['device_name'],
                'device_type': device_info['device_type'],
                'os_name': device_info['os_name'],
                'os_version': device_info['os_version'],
                'browser_name': device_info['browser_name'],
                'browser_version': device_info['browser_version'],
                'last_ip': self.ip_address,
                'last_country_code': self.country_code,
                'last_city': self.city,
                'is_trusted': False,
                'is_blocked': False,
                'is_whitelisted': False,
                'status': 'normal',
                'risk_score': 0,
            }
        )
        
        # Update existing device
        if not created:
            device.last_ip = self.ip_address
            device.last_country_code = self.country_code
            device.last_city = self.city
            device.last_seen_at = timezone.now()
            device.device_name = device_info['device_name']
            device.device_type = device_info['device_type']
            device.os_name = device_info['os_name']
            device.browser_name = device_info['browser_name']
        
        # Apply automatic rules
        device = self._apply_device_rules(device, created)
        device.save()
        
        return device, created
    
    def _extract_device_info(self):
        """Extract detailed device information from user agent"""
        ua = self.user_agent.lower()
        
        info = {
            'device_name': 'Unknown Device',
            'device_type': 'unknown',
            'os_name': 'Unknown',
            'os_version': '',
            'browser_name': 'Unknown',
            'browser_version': '',
        }
        
        # Detect device type and OS
        if 'android' in ua:
            info['device_type'] = 'mobile'
            info['os_name'] = 'Android'
            info['device_name'] = 'Android Device'
        elif 'iphone' in ua or 'ipad' in ua:
            info['device_type'] = 'mobile' if 'iphone' in ua else 'tablet'
            info['os_name'] = 'iOS'
            info['device_name'] = 'iPhone' if 'iphone' in ua else 'iPad'
        elif 'windows' in ua:
            info['device_type'] = 'desktop'
            info['os_name'] = 'Windows'
            info['device_name'] = 'Windows PC'
        elif 'mac' in ua:
            info['device_type'] = 'desktop'
            info['os_name'] = 'macOS'
            info['device_name'] = 'Mac'
        elif 'linux' in ua:
            info['device_type'] = 'desktop'
            info['os_name'] = 'Linux'
            info['device_name'] = 'Linux PC'
        elif 'mobile' in ua:
            info['device_type'] = 'mobile'
            info['device_name'] = 'Mobile Device'
        
        # Detect browser
        if 'chrome' in ua and 'edg' not in ua:
            info['browser_name'] = 'Chrome'
        elif 'firefox' in ua:
            info['browser_name'] = 'Firefox'
        elif 'safari' in ua and 'chrome' not in ua:
            info['browser_name'] = 'Safari'
        elif 'edg' in ua:
            info['browser_name'] = 'Edge'
        elif 'opera' in ua or 'opr' in ua:
            info['browser_name'] = 'Opera'
        
        return info
    
    def _apply_device_rules(self, device, is_new):
        """Apply automatic rules to device based on conditions"""
        from frauddetect.models import FraudConfig, IPBlocklist
        from frauddetect.utils import is_superuser_device
        
        # Rule 1: Superuser protection
        if is_superuser_device(device):
            device.is_trusted = True
            device.is_blocked = False
            device.status = 'normal'
            device.risk_score = 0
            print(f"👑 SUPERUSER DEVICE: Auto-trusted {device.device_name}")
            return device
        
        # Rule 2: Check if IP is blocked
        ip_blocked = IPBlocklist.objects.filter(
            ip_address=self.ip_address,
            is_active=True
        ).exists()
        
        if ip_blocked:
            device.is_blocked = True
            device.is_trusted = False
            device.status = 'blocked'
            device.risk_score = 100
            print(f"🚫 BLOCKED DEVICE: IP {self.ip_address} is blocked")
            return device
        
        # Rule 3: Check country restriction
        try:
            config = FraudConfig.objects.filter(is_active=True).first()
            allowed_countries = config.allowed_countries if config else ['SA']
        except:
            allowed_countries = ['SA']
        
        if self.country_code not in allowed_countries:
            device.is_blocked = True
            device.is_trusted = False
            device.status = 'blocked'
            device.risk_score = 100
            print(f"🚫 BLOCKED DEVICE: Country {self.country_code} not allowed")
            return device
        
        # Rule 4: Allowed country - AUTO-TRUST
        if is_new:
            device.is_trusted = True
            device.is_blocked = False
            device.status = 'suspicious'
            device.risk_score = 20
            print(f"✅ AUTO-TRUSTED: New device {device.device_name} from {self.country_code}")
        else:
            if not device.is_blocked:
                device.status = 'normal'
                print(f"✅ EXISTING DEVICE: {device.device_name}")
        
        return device
    
    def check_ip_blocked(self):
        """Check if IP is blocked"""
        from frauddetect.models import IPBlocklist
        
        blocked = IPBlocklist.objects.filter(
            ip_address=self.ip_address,
            is_active=True
        ).first()
        
        if blocked:
            self.risk_score += 100
            self.risk_reasons.append('IP is blocked')
            return False, {
                'error': 'Access Denied',
                'blocked': True,
                'reason': 'ip_blocked',
                'message': f'Your IP address ({self.ip_address}) has been blocked',
                'details': {
                    'ip_address': self.ip_address,
                    'block_reason': blocked.reason,
                    'blocked_at': blocked.created_at.isoformat(),
                },
                'contact': 'Please contact support if you believe this is an error.'
            }
        
        return True, None
    
    def check_device_blocked(self):
        """Check if device is blocked"""
        if not self.device:
            return True, None
        
        if self.device.is_blocked:
            self.risk_score += 100
            self.risk_reasons.append('Device is blocked')
            return False, {
                'error': 'Access Denied',
                'blocked': True,
                'reason': 'device_blocked',
                'message': 'This device has been blocked',
                'details': {
                    'device_id': self.device.id,
                    'device_name': self.device.device_name,
                },
                'contact': 'Please contact support to unblock this device.'
            }
        
        return True, None
    
    def check_device_trusted(self):
        """Check if device is trusted"""
        if not self.device:
            return True, None
        
        if not self.device.is_trusted:
            self.risk_score += 50
            self.risk_reasons.append('Device not trusted')
            return False, {
                'error': 'Access Denied',
                'blocked': True,
                'reason': 'device_not_trusted',
                'message': 'This device is not trusted. Please contact administrator.',
                'details': {
                    'device_id': self.device.id,
                    'device_name': self.device.device_name,
                    'is_trusted': False,
                },
                'contact': 'Contact administrator to trust this device.'
            }
        
        return True, None
    
    def check_country_allowed(self):
        """Check if country is allowed"""
        from frauddetect.models import FraudConfig
        
        try:
            config = FraudConfig.objects.filter(is_active=True).first()
            allowed_countries = config.allowed_countries if config else ['SA']
        except:
            allowed_countries = ['SA']
        
        if self.country_code not in allowed_countries:
            self.risk_score += 100
            self.risk_reasons.append(f'Non-allowed country: {self.country_code}')
            return False, {
                'error': 'Access Denied',
                'blocked': True,
                'reason': 'non_allowed_country',
                'message': 'Access to this service is restricted to Saudi Arabia only',
                'details': {
                    'your_country': self.country_name,
                    'your_country_code': self.country_code,
                    'your_city': self.city,
                    'your_ip': self.ip_address,
                    'allowed_countries': ['Saudi Arabia (SA)'],
                },
                'contact': 'Please contact support if you believe this is an error.'
            }
        
        return True, None
    
    def check_device_whitelisted(self):
        """Check if device is whitelisted"""
        if not self.device:
            return False
        return self.device.is_whitelisted
    
    def check_user_superuser(self):
        """Check if user is superuser"""
        if not self.user:
            return False
        return self.user.is_superuser
    
    def check_login_velocity(self):
        """Check login velocity (rate limiting)"""
        from frauddetect.models import LoginEvent, FraudConfig, IPBlocklist
        from datetime import timedelta
        
        try:
            config = FraudConfig.objects.filter(is_active=True).first()
            max_attempts = config.max_login_attempts if config else 5
            window_minutes = config.login_attempt_window_minutes if config else 5
        except:
            max_attempts = 5
            window_minutes = 5
        
        time_threshold = timezone.now() - timedelta(minutes=window_minutes)
        
        failed_attempts = LoginEvent.objects.filter(
            username=self.username,
            status='failed',
            attempt_time__gte=time_threshold
        ).count()
        
        if failed_attempts >= max_attempts:
            self.risk_score += 100
            self.risk_reasons.append(f'Too many failed login attempts ({failed_attempts})')
            
            # Auto-block IP
            if not IPBlocklist.objects.filter(ip_address=self.ip_address).exists():
                admin = User.objects.filter(is_superuser=True).order_by('id').first()
                IPBlocklist.objects.create(
                    ip_address=self.ip_address,
                    reason=f"Auto-block: {failed_attempts} failed login attempts",
                    is_active=True,
                    blocked_by=admin
                )
                print(f"🚫 AUTO-BLOCKED IP: {self.ip_address}")
            
            return False, {
                'error': 'Access Denied',
                'blocked': True,
                'reason': 'too_many_attempts',
                'message': 'Too many failed login attempts. Your IP has been blocked.',
                'details': {
                    'failed_attempts': failed_attempts,
                    'time_window': f'{window_minutes} minutes',
                    'max_allowed': max_attempts,
                },
                'contact': 'Please contact support to unblock your IP.'
            }
        
        return True, None
    
    def run_all_checks(self):
        """Run all security checks"""
        
        # 0. Superuser bypass
        if self.check_user_superuser():
            print(f"👑 SUPERUSER: {self.username} - Bypassing all checks")
            return {
                'allowed': True,
                'bypassed': True,
                'bypass_reason': 'superuser_protection',
                'risk_score': 0,
                'risk_level': 'safe',
                'message': 'Superuser - Never blocked'
            }
        
        # 0.1. Whitelisted device bypass
        if self.check_device_whitelisted():
            print(f"✅ WHITELISTED DEVICE: {self.device.device_name}")
            return {
                'allowed': True,
                'bypassed': True,
                'bypass_reason': 'whitelisted_device',
                'risk_score': 0,
                'risk_level': 'safe'
            }
        
        # 1. Check IP blocked
        allowed, error = self.check_ip_blocked()
        if not allowed:
            return {'allowed': False, 'error': error}
        
        # 2. Check device blocked
        allowed, error = self.check_device_blocked()
        if not allowed:
            return {'allowed': False, 'error': error}
        
        # 3. Check device trusted
        allowed, error = self.check_device_trusted()
        if not allowed:
            return {'allowed': False, 'error': error}
        
        # 4. Check country allowed
        allowed, error = self.check_country_allowed()
        if not allowed:
            return {'allowed': False, 'error': error}
        
        # 5. Check login velocity
        allowed, error = self.check_login_velocity()
        if not allowed:
            return {'allowed': False, 'error': error}
        
        # Calculate risk level
        if self.risk_score >= 70:
            risk_level = 'high'
            self.is_suspicious = True
        elif self.risk_score >= 40:
            risk_level = 'medium'
            self.is_suspicious = True
        elif self.risk_score >= 20:
            risk_level = 'low'
            self.is_suspicious = False
        else:
            risk_level = 'safe'
            self.is_suspicious = False
        
        return {
            'allowed': True,
            'risk_score': self.risk_score,
            'risk_level': risk_level,
            'risk_reasons': self.risk_reasons,
            'is_suspicious': self.is_suspicious,
            'location_info': self._get_location_info(),
        }
    
    def _get_location_info(self):
        """Get location info"""
        return {
            'ip_address': self.ip_address,
            'country': self.country_name,
            'country_code': self.country_code,
            'city': self.city,
        }
    
    def create_login_event(self, status='success'):
        """Create login event"""
        from frauddetect.models import LoginEvent
        
        return LoginEvent.objects.create(
            user=self.user,
            username=self.username,
            device=self.device,
            status=status,
            ip_address=self.ip_address,
            country_code=self.country_code,
            city=self.city,
            is_suspicious=self.is_suspicious,
            risk_score=self.risk_score,
            risk_reasons=self.risk_reasons,
            user_agent=self.user_agent
        )
    
    def create_system_log(self, level='info'):
        """Create system log"""
        from frauddetect.models import SystemLog
        
        message = f"Login {level}: {self.username} from {self.ip_address}"
        
        return SystemLog.objects.create(
            log_type='login',
            level=level,
            message=message,
            user=self.user,
            ip_address=self.ip_address,
            metadata={
                'username': self.username,
                'country_code': self.country_code,
                'city': self.city,
                'risk_score': self.risk_score,
                'risk_reasons': self.risk_reasons,
            }
        )



class LoginSerializer(serializers.Serializer):
    """
    🔐 Complete Login Serializer with Fraud Detection
    """
    
    username_or_email = serializers.CharField(
        required=False,
        write_only=True,
        help_text="Username or Email"
    )
    username = serializers.CharField(required=False, write_only=True)
    email = serializers.EmailField(required=False, write_only=True)
    password = serializers.CharField(
        required=True,
        write_only=True,
        style={'input_type': 'password'}
    )
    
    # Response fields (read-only)
    access = serializers.CharField(read_only=True)
    refresh = serializers.CharField(read_only=True)
    user = serializers.DictField(read_only=True)
    device_id = serializers.IntegerField(read_only=True)
    device_trusted = serializers.BooleanField(read_only=True)
    device_new = serializers.BooleanField(read_only=True)
    security = serializers.DictField(read_only=True)
    login_info = serializers.DictField(read_only=True)
    
    def validate(self, attrs):
        """Complete Login Validation with Fraud Detection"""
        from rest_framework_simplejwt.tokens import RefreshToken
        from frauddetect.models import Device, LoginEvent, SystemLog, IPBlocklist
        from frauddetect.middleware import get_client_ip, get_geo_location
        
        request = self.context.get('request')
        if not request:
            raise serializers.ValidationError({'error': 'Request required'})
        
        # STEP 1: Extract Credentials
        username_or_email = attrs.get('username_or_email', '').strip()
        username = attrs.get('username', '').strip()
        email = attrs.get('email', '').strip()
        password = attrs.get('password', '')
        
        # Determine username
        final_username = None
        if username_or_email:
            if '@' in username_or_email:
                try:
                    user_obj = User.objects.get(email=username_or_email)
                    final_username = user_obj.username
                except User.DoesNotExist:
                    pass
            else:
                final_username = username_or_email
        elif username:
            final_username = username
        elif email:
            try:
                user_obj = User.objects.get(email=email)
                final_username = user_obj.username
            except User.DoesNotExist:
                pass
        
        if not final_username:
            raise serializers.ValidationError({'error': 'Must provide username or email'})
        
        # Get IP and location
        ip_address = get_client_ip(request)
        geo_data = get_geo_location(ip_address)
        country_code = geo_data['country_code']
        city = geo_data['city']
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        # STEP 2: AUTHENTICATE USER
        user = authenticate(request=request, username=final_username, password=password)
        
        if not user:
            # Failed login
            LoginEvent.objects.create(
                user=None,
                username=final_username,
                device=None,
                status='failed',
                ip_address=ip_address,
                country_code=country_code,
                city=city,
                is_suspicious=True,
                risk_score=10,
                risk_reasons=['Invalid credentials'],
                user_agent=user_agent
            )
            
            SystemLog.objects.create(
                log_type='security',
                level='warning',
                message=f"Failed login: {final_username} from {ip_address}",
                user=None,
                ip_address=ip_address,
                metadata={'username': final_username, 'country_code': country_code}
            )
            
            # UPDATE RISK PROFILE for existing user (if username exists)
            try:
                existing_user = User.objects.get(username=final_username)
                from frauddetect.utils import RiskProfileManager
                risk_manager = RiskProfileManager(existing_user)
                risk_manager.on_login_failed(ip_address, country_code)
            except User.DoesNotExist:
                pass
            
            print(f"❌ FAILED LOGIN: {final_username} from {ip_address}")
            raise serializers.ValidationError({'error': 'Invalid credentials'})
        
        if not user.is_active:
            raise serializers.ValidationError({'error': 'Account disabled'})
        
        # STEP 3: POST-AUTHENTICATION SECURITY CHECKS
        engine = LoginProtectionEngine(request, user=user, username=user.username)
        
        # Get or create device
        device, device_created = engine.get_or_create_device()
        engine.device = device
        
        # SUPERUSER BYPASS
        if user.is_superuser:
            print(f"✅ SUPERUSER LOGIN: {user.username}")
            engine.create_login_event(status='success')
            
            refresh = RefreshToken.for_user(user)
            
            return {
                'access': str(refresh.access_token),
                'refresh': str(refresh),
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'first_name': user.first_name,
                    'last_name': user.last_name,
                    'is_staff': user.is_staff,
                    'is_superuser': user.is_superuser,
                },
                'device_id': device.id if device else 0,
                'device_trusted': True,
                'device_new': device_created,
                'security': {
                    'risk_score': 0,
                    'risk_level': 'superuser',
                    'is_suspicious': False,
                    'requires_verification': False,
                },
                'login_info': engine._get_location_info(),
                'superuser': True,
            }
        
        # RUN ALL SECURITY CHECKS
        result = engine.run_all_checks()
        
        # IF BLOCKED - DENY LOGIN
        if not result['allowed']:
            engine.create_login_event(status='blocked')
            engine.create_system_log(level='critical')
            
            # UPDATE RISK PROFILE - Blocked login
            from frauddetect.utils import RiskProfileManager
            risk_manager = RiskProfileManager(user)
            risk_manager.on_login_blocked(
                reason=result.get('error', {}).get('reason', 'unknown'),
                ip_address=engine.ip_address,
                country_code=engine.country_code
            )
            
            print(f"🚫 LOGIN BLOCKED: {result.get('error', {}).get('message')}")
            raise serializers.ValidationError(result['error'])
        
        # SUCCESS
        engine.create_login_event(status='success')
        engine.create_system_log(
            level='warning' if result['is_suspicious'] else 'info'
        )
        
        # UPDATE RISK PROFILE
        from frauddetect.utils import RiskProfileManager
        risk_manager = RiskProfileManager(user)
        risk_update = risk_manager.on_login_success(
            ip_address=engine.ip_address,
            country_code=engine.country_code,
            city=engine.city,
            device=device
        )
        
        print(f"✅ LOGIN SUCCESS: {user.username} | Risk Profile Updated: {risk_update}")
        
        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        
        response_data = {
            'access': str(refresh.access_token),
            'refresh': str(refresh),
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'is_staff': user.is_staff,
                'is_superuser': user.is_superuser,
            },
            'device_id': device.id if device else None,
            'device_trusted': device.is_trusted if device else False,
            'device_new': device_created,
            'security': {
                'risk_score': result['risk_score'],
                'risk_level': result['risk_level'],
                'is_suspicious': result['is_suspicious'],
                'requires_verification': result['is_suspicious'],
            },
            'login_info': result['location_info'],
        }
        
        if result['is_suspicious']:
            response_data['warning'] = 'This login appears suspicious. Additional verification may be required.'
        
        return response_data


class UserInfoSerializer(serializers.ModelSerializer):
    """Basic User Information"""
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'is_staff', 'is_superuser', 'date_joined']
        read_only_fields = fields
