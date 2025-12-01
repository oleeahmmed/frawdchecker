from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.views import APIView
from django.contrib.auth import authenticate, login
from django.utils import timezone
from django.db.models import Sum, Count, Q
from datetime import timedelta
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter, OpenApiExample
from drf_spectacular.types import OpenApiTypes

from .models import (
    Device, 
    LoginEvent, 
    Transaction, 
    FraudEvent, 
    RiskProfile, 
    SystemLog,
    IPBlocklist
)
from .serializers import (
    DeviceSerializer, 
    LoginEventSerializer, 
    TransactionSerializer,
    TransactionCreateSerializer,
    FraudEventSerializer, 
    FraudEventResolveSerializer,
    RiskProfileSerializer, 
    SystemLogSerializer,
    IPBlocklistSerializer,
    IPBlocklistCreateSerializer,
    DashboardStatsSerializer
)
from .utils import (
    get_client_ip, 
    get_geo_location, 
    get_country_risk_level,
    calculate_transaction_risk, 
    check_velocity, 
    check_ip_blocklist
)


# ============================================
# 📱 DEVICE VIEW SET
# ============================================
@extend_schema_view(
    list=extend_schema(tags=['Devices'], description='List all devices for the authenticated user'),
    retrieve=extend_schema(tags=['Devices'], description='Retrieve a specific device'),
    trust=extend_schema(tags=['Devices'], description='Mark a device as trusted'),
    block=extend_schema(tags=['Devices'], description='Block a device (Admin only)'),
)
class DeviceViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ব্যবহারকারীর ডিভাইস দেখা এবং পরিচালনা করা
    
    Endpoints:
    - GET /api/devices/ - সব ডিভাইস দেখা
    - GET /api/devices/{id}/ - নির্দিষ্ট ডিভাইস
    - POST /api/devices/{id}/trust/ - ডিভাইস বিশ্বস্ত করা
    - POST /api/devices/{id}/block/ - ডিভাইস ব্লক করা
    """
    serializer_class = DeviceSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        # Admin সব দেখতে পারবে, সাধারণ user শুধু নিজের ডিভাইস
        if self.request.user.is_staff:
            return Device.objects.all().select_related('user')
        return Device.objects.filter(user=self.request.user)
    
    @action(detail=True, methods=['post'])
    def trust(self, request, pk=None):
        """ডিভাইস বিশ্বস্ত হিসেবে চিহ্নিত করা"""
        device = self.get_object()
        
        # শুধু নিজের ডিভাইস বা admin
        if device.user != request.user and not request.user.is_staff:
            return Response(
                {'error': 'Permission denied'}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        device.is_trusted = True
        device.status = 'normal'
        device.save()
        
        # Log
        SystemLog.objects.create(
            log_type='security',
            level='info',
            message=f"Device {device.id} marked as trusted",
            user=request.user,
            ip_address=get_client_ip(request)
        )
        
        return Response({
            'message': 'Device trusted successfully',
            'device': DeviceSerializer(device).data
        })
    
    @action(detail=True, methods=['post'])
    def block(self, request, pk=None):
        """ডিভাইস ব্লক করা (শুধু Admin)"""
        if not request.user.is_staff:
            return Response(
                {'error': 'Admin only'}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        device = self.get_object()
        device.is_blocked = True
        device.status = 'blocked'
        device.save()
        
        # Log
        SystemLog.objects.create(
            log_type='security',
            level='warning',
            message=f"Device {device.id} blocked by {request.user.username}",
            user=request.user,
            ip_address=get_client_ip(request)
        )
        
        return Response({
            'message': 'Device blocked successfully',
            'device': DeviceSerializer(device).data
        })


# ============================================
# 🔐 LOGIN EVENT VIEW SET
# ============================================
@extend_schema_view(
    list=extend_schema(tags=['Login Events'], description='List all login events'),
    retrieve=extend_schema(tags=['Login Events'], description='Retrieve a specific login event'),
    suspicious=extend_schema(tags=['Login Events'], description='List only suspicious login attempts'),
)
class LoginEventViewSet(viewsets.ReadOnlyModelViewSet):
    """
    লগইন ইতিহাস দেখা
    
    Endpoints:
    - GET /api/login-events/ - সব লগইন ইভেন্ট
    - GET /api/login-events/{id}/ - নির্দিষ্ট ইভেন্ট
    """
    serializer_class = LoginEventSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        queryset = LoginEvent.objects.select_related('user', 'device')
        
        if self.request.user.is_staff:
            return queryset
        return queryset.filter(user=self.request.user)
    
    @action(detail=False, methods=['get'])
    def suspicious(self, request):
        """শুধু সন্দেহজনক লগইন দেখা"""
        queryset = self.get_queryset().filter(is_suspicious=True)
        serializer = self.get_serializer(queryset[:50], many=True)
        return Response(serializer.data)


# ============================================
# 💰 TRANSACTION VIEW SET (🔥 মূল অংশ)
# ============================================
@extend_schema_view(
    list=extend_schema(tags=['Transactions'], description='List all transactions'),
    retrieve=extend_schema(tags=['Transactions'], description='Retrieve a specific transaction'),
    create=extend_schema(tags=['Transactions'], description='Create a new transaction with fraud detection'),
    approve=extend_schema(tags=['Transactions'], description='Approve a transaction (Admin only)'),
    reject=extend_schema(tags=['Transactions'], description='Reject a transaction (Admin only)'),
    flagged=extend_schema(tags=['Transactions'], description='List only flagged transactions'),
)
class TransactionViewSet(viewsets.ModelViewSet):
    """
    লেনদেন পরিচালনা - Fraud Detection এর মূল অংশ
    
    Endpoints:
    - GET /api/transactions/ - সব লেনদেন
    - POST /api/transactions/ - নতুন লেনদেন (Fraud Check সহ)
    - GET /api/transactions/{id}/ - নির্দিষ্ট লেনদেন
    - POST /api/transactions/{id}/approve/ - অনুমোদন করা
    - POST /api/transactions/{id}/reject/ - প্রত্যাখ্যান করা
    """
    serializer_class = TransactionSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        queryset = Transaction.objects.select_related('user', 'device')
        
        if self.request.user.is_staff:
            return queryset
        return queryset.filter(user=self.request.user)
    
    def get_serializer_class(self):
        if self.action == 'create':
            return TransactionCreateSerializer
        return TransactionSerializer
    
    def create(self, request, *args, **kwargs):
        """
        🔥 নতুন লেনদেন তৈরি - Fraud Detection সহ
        """
        # Step 1: Get IP (already checked by middleware)
        ip = get_client_ip(request)
        
        # Step 2: Validate Data
        serializer = TransactionCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # Step 3: Create Transaction
        transaction = serializer.save(
            user=request.user,
            device=getattr(request, 'device', None),
            ip_address=ip
        )
        
        # Step 4: 🔥 Run Fraud Detection
        risk_result = calculate_transaction_risk(transaction)
        
        # Step 5: Update Transaction with Risk Assessment
        transaction.risk_score = risk_result['risk_score']
        transaction.risk_level = risk_result['risk_level']
        transaction.is_suspicious = risk_result['risk_score'] >= 40
        
        # High risk হলে flagged করা
        if transaction.is_suspicious:
            transaction.status = 'flagged'
        else:
            transaction.status = 'pending'  # Normal হলে pending
        
        transaction.save()
        
        # Step 6: Create Fraud Event if Suspicious
        if risk_result['risk_score'] >= 40:
            severity = 'high' if risk_result['risk_score'] >= 70 else 'medium'
            
            FraudEvent.objects.create(
                transaction=transaction,
                user=request.user,
                triggered_rules=risk_result['triggered_rules'],
                risk_score=risk_result['risk_score'],
                severity=severity,
                description=f"Suspicious transaction detected. Amount: {transaction.amount}. Rules triggered: {', '.join(risk_result['triggered_rules'])}"
            )
        
        # Step 7: Create System Log
        SystemLog.objects.create(
            log_type='transaction',
            level='warning' if transaction.is_suspicious else 'info',
            message=f"Transaction {transaction.external_txn_id} created. Risk: {risk_result['risk_level']}",
            user=request.user,
            ip_address=ip,
            metadata={
                'amount': str(transaction.amount),
                'risk_score': risk_result['risk_score'],
                'triggered_rules': risk_result['triggered_rules']
            }
        )
        
        # Step 8: Return Response
        return Response(
            {
                'transaction': TransactionSerializer(transaction).data,
                'risk_assessment': risk_result,
                'message': 'Transaction flagged for review' if transaction.is_suspicious else 'Transaction pending'
            },
            status=status.HTTP_201_CREATED
        )
    
    @action(detail=True, methods=['post'])
    def approve(self, request, pk=None):
        """লেনদেন অনুমোদন করা (Admin Only)"""
        if not request.user.is_staff:
            return Response(
                {'error': 'Admin only'}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        transaction = self.get_object()
        transaction.status = 'approved'
        transaction.approved_at = timezone.now()
        transaction.save()
        
        # Log
        SystemLog.objects.create(
            log_type='transaction',
            level='info',
            message=f"Transaction {transaction.external_txn_id} approved by {request.user.username}",
            user=request.user,
            ip_address=get_client_ip(request)
        )
        
        return Response({
            'message': 'Transaction approved',
            'transaction': TransactionSerializer(transaction).data
        })
    
    @action(detail=True, methods=['post'])
    def reject(self, request, pk=None):
        """লেনদেন প্রত্যাখ্যান করা (Admin Only)"""
        if not request.user.is_staff:
            return Response(
                {'error': 'Admin only'}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        transaction = self.get_object()
        transaction.status = 'rejected'
        transaction.save()
        
        # Log
        SystemLog.objects.create(
            log_type='transaction',
            level='warning',
            message=f"Transaction {transaction.external_txn_id} rejected by {request.user.username}",
            user=request.user,
            ip_address=get_client_ip(request)
        )
        
        return Response({
            'message': 'Transaction rejected',
            'transaction': TransactionSerializer(transaction).data
        })
    
    @action(detail=False, methods=['get'])
    def flagged(self, request):
        """শুধু Flagged transactions"""
        queryset = self.get_queryset().filter(status='flagged')
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


# ============================================
# 🚨 FRAUD EVENT VIEW SET
# ============================================
@extend_schema_view(
    list=extend_schema(tags=['Fraud Events'], description='List all fraud events'),
    retrieve=extend_schema(tags=['Fraud Events'], description='Retrieve a specific fraud event'),
    resolve=extend_schema(tags=['Fraud Events'], description='Resolve a fraud event (Admin only)'),
    unresolved=extend_schema(tags=['Fraud Events'], description='List only unresolved fraud events'),
)
class FraudEventViewSet(viewsets.ReadOnlyModelViewSet):
    """
    জালিয়াতি ইভেন্ট দেখা ও সমাধান করা
    
    Endpoints:
    - GET /api/fraud-events/ - সব ইভেন্ট
    - GET /api/fraud-events/{id}/ - নির্দিষ্ট ইভেন্ট
    - POST /api/fraud-events/{id}/resolve/ - সমাধান করা
    """
    serializer_class = FraudEventSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        queryset = FraudEvent.objects.select_related(
            'user', 'transaction', 'resolved_by'
        )
        
        if self.request.user.is_staff:
            return queryset
        return queryset.filter(user=self.request.user)
    
    @action(detail=True, methods=['post'], permission_classes=[IsAdminUser])
    def resolve(self, request, pk=None):
        """জালিয়াতি ইভেন্ট সমাধান করা"""
        event = self.get_object()
        
        serializer = FraudEventResolveSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        event.is_resolved = True
        event.resolved_by = request.user
        event.resolved_at = timezone.now()
        event.resolution_notes = serializer.validated_data.get('notes', '')
        event.save()
        
        # Log
        SystemLog.objects.create(
            log_type='fraud_alert',
            level='info',
            message=f"Fraud event {event.id} resolved by {request.user.username}",
            user=request.user,
            ip_address=get_client_ip(request)
        )
        
        return Response({
            'message': 'Fraud event resolved',
            'event': FraudEventSerializer(event).data
        })
    
    @action(detail=False, methods=['get'])
    def unresolved(self, request):
        """শুধু অমীমাংসিত ইভেন্ট"""
        queryset = self.get_queryset().filter(is_resolved=False)
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


# ============================================
# 📊 RISK PROFILE VIEW SET
# ============================================
@extend_schema_view(
    list=extend_schema(tags=['Risk Profiles'], description='List all risk profiles'),
    retrieve=extend_schema(tags=['Risk Profiles'], description='Retrieve a specific risk profile'),
    high_risk=extend_schema(tags=['Risk Profiles'], description='List only high-risk users (Admin only)'),
)
class RiskProfileViewSet(viewsets.ReadOnlyModelViewSet):
    """
    ব্যবহারকারীর ঝুঁকি প্রোফাইল
    """
    serializer_class = RiskProfileSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        queryset = RiskProfile.objects.select_related('user')
        
        if self.request.user.is_staff:
            return queryset
        return queryset.filter(user=self.request.user)
    
    @action(detail=False, methods=['get'])
    def high_risk(self, request):
        """উচ্চ ঝুঁকির ব্যবহারকারী"""
        if not request.user.is_staff:
            return Response(
                {'error': 'Admin only'}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        queryset = RiskProfile.objects.filter(risk_level='high')
        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


# ============================================
# 📝 SYSTEM LOG VIEW SET
# ============================================
@extend_schema_view(
    list=extend_schema(
        tags=['System Logs'], 
        description='List all system logs (Admin only)',
        parameters=[
            OpenApiParameter(name='type', description='Filter by log type', required=False, type=str),
            OpenApiParameter(name='level', description='Filter by log level', required=False, type=str),
        ]
    ),
    retrieve=extend_schema(tags=['System Logs'], description='Retrieve a specific system log'),
)
class SystemLogViewSet(viewsets.ReadOnlyModelViewSet):
    """
    সিস্টেম লগ (শুধু Admin)
    """
    serializer_class = SystemLogSerializer
    permission_classes = [IsAdminUser]
    queryset = SystemLog.objects.select_related('user')
    
    def get_queryset(self):
        queryset = super().get_queryset()
        
        # Filter by log_type
        log_type = self.request.query_params.get('type')
        if log_type:
            queryset = queryset.filter(log_type=log_type)
        
        # Filter by level
        level = self.request.query_params.get('level')
        if level:
            queryset = queryset.filter(level=level)
        
        return queryset


# ============================================
# 🚫 IP BLOCKLIST VIEW SET
# ============================================
@extend_schema_view(
    list=extend_schema(tags=['IP Blocklist'], description='List all blocked IP addresses (Admin only)'),
    retrieve=extend_schema(tags=['IP Blocklist'], description='Retrieve a specific IP blocklist entry'),
    create=extend_schema(tags=['IP Blocklist'], description='Add an IP address to blocklist (Admin only)'),
    update=extend_schema(tags=['IP Blocklist'], description='Update an IP blocklist entry (Admin only)'),
    partial_update=extend_schema(tags=['IP Blocklist'], description='Partially update an IP blocklist entry (Admin only)'),
    destroy=extend_schema(tags=['IP Blocklist'], description='Remove an IP address from blocklist (Admin only)'),
)
class IPBlocklistViewSet(viewsets.ModelViewSet):
    """
    IP Blocklist পরিচালনা (Admin Only)
    """
    serializer_class = IPBlocklistSerializer
    permission_classes = [IsAdminUser]
    queryset = IPBlocklist.objects.all()
    
    def get_serializer_class(self):
        if self.action == 'create':
            return IPBlocklistCreateSerializer
        return IPBlocklistSerializer
    
    def perform_create(self, serializer):
        serializer.save(blocked_by=self.request.user)
        
        # Log
        SystemLog.objects.create(
            log_type='security',
            level='warning',
            message=f"IP {serializer.validated_data['ip_address']} blocked",
            user=self.request.user,
            ip_address=get_client_ip(self.request)
        )


# ============================================
# 📈 DASHBOARD VIEW
# ============================================
@extend_schema(
    tags=['Dashboard'],
    description='Get dashboard statistics including transactions, fraud events, and risk metrics',
    responses={200: DashboardStatsSerializer}
)
class DashboardView(APIView):
    """
    Dashboard Statistics
    """
    permission_classes = [IsAdminUser]
    
    def get(self, request):
        today = timezone.now().date()
        
        stats = {
            'total_transactions': Transaction.objects.count(),
            'suspicious_transactions': Transaction.objects.filter(is_suspicious=True).count(),
            'total_fraud_events': FraudEvent.objects.count(),
            'unresolved_fraud_events': FraudEvent.objects.filter(is_resolved=False).count(),
            'blocked_ips': IPBlocklist.objects.filter(is_active=True).count(),
            'high_risk_users': RiskProfile.objects.filter(risk_level='high').count(),
            'transactions_today': Transaction.objects.filter(
                created_at__date=today
            ).count(),
            'total_amount_today': Transaction.objects.filter(
                created_at__date=today
            ).aggregate(total=Sum('amount'))['total'] or 0,
        }
        
        serializer = DashboardStatsSerializer(stats)
        return Response(serializer.data)



# ============================================
# 🔐 CUSTOM AUTHENTICATION VIEWS
# ============================================
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework.permissions import AllowAny
from django.contrib.auth.signals import user_logged_in


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Custom JWT Token with Device Tracking and Fraud Detection
    Supports login with username OR email
    """
    username = serializers.CharField(required=False, allow_blank=True)
    email = serializers.EmailField(required=False, allow_blank=True)
    
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        
        # Add custom claims
        token['username'] = user.username
        token['email'] = user.email
        token['is_staff'] = user.is_staff
        
        return token
    
    def validate(self, attrs):
        # Support login with username OR email
        username = attrs.get('username', '').strip()
        email = attrs.get('email', '').strip()
        password = attrs.get('password')
        
        # Must provide either username or email
        if not username and not email:
            raise serializers.ValidationError({'error': 'Must provide either username or email'})
        
        # Try to find user by email if provided
        if email and not username:
            try:
                from django.contrib.auth.models import User
                user_obj = User.objects.get(email=email)
                attrs['username'] = user_obj.username
            except User.DoesNotExist:
                raise serializers.ValidationError({'error': 'Invalid credentials'})
        
        # Call parent validate
        data = super().validate(attrs)
        
        # Get request from context
        request = self.context.get('request')
        user = self.user
        
        # Track device and create login event with fraud detection
        if request:
            from .utils import (
                calculate_device_fingerprint, 
                get_client_ip, 
                get_geo_location,
                get_country_risk_level,
                check_velocity,
                check_ip_blocklist
            )
            from .models import Device, LoginEvent, SystemLog, IPBlocklist
            from django.utils import timezone
            
            fingerprint_hash = calculate_device_fingerprint(request)
            ip_address = get_client_ip(request)
            
            # Log IP detection
            print(f"🔍 Login attempt - User: {user.username}, IP: {ip_address}")
            
            # ═══════════════════════════════════════════════════════
            # FRAUD DETECTION RULES
            # ═══════════════════════════════════════════════════════
            risk_score = 0
            risk_reasons = []
            is_suspicious = False
            should_block = False
            
            # Rule 1: Check if IP is blocked
            if check_ip_blocklist(ip_address):
                should_block = True
                risk_score += 100
                risk_reasons.append('IP address is blocked')
                print(f"🚫 BLOCKED: IP {ip_address} is in blocklist")
            
            # Get geolocation
            geo_data = get_geo_location(ip_address)
            print(f"📍 Location: {geo_data.get('country_name', 'Unknown')} ({geo_data.get('country_code', 'Unknown')}) - {geo_data.get('city', 'Unknown')}")
            
            # Rule 2: Country risk assessment
            country_risk = get_country_risk_level(geo_data.get('country_code'))
            risk_score += country_risk['score']
            if country_risk['level'] == 'high':
                risk_reasons.append(country_risk['reason'])
                print(f"⚠️  High-risk country: {country_risk['reason']}")
            
            # Rule 3: Velocity check - too many login attempts
            if check_velocity(user, 'login', 60):
                risk_score += 25
                risk_reasons.append('Too many login attempts in short time')
                is_suspicious = True
                print(f"⚠️  Velocity check failed: Too many attempts")
            
            # Get or create device
            device, created = Device.objects.get_or_create(
                user=user,
                fingerprint_hash=fingerprint_hash,
                defaults={
                    'last_ip': ip_address,
                    'device_fingerprint': fingerprint_hash,
                    'is_trusted': False,
                    'status': 'normal'
                }
            )
            
            # Rule 4: New device detection
            if created:
                risk_score += 15
                risk_reasons.append('Login from new device')
                print(f"🆕 New device detected: {device.id}")
            else:
                # Update existing device
                device.last_seen_at = timezone.now()
                device.last_ip = ip_address
                device.save(update_fields=['last_seen_at', 'last_ip'])
                print(f"✓ Known device: {device.id}")
            
            # Rule 5: Check if device is blocked
            if device.is_blocked:
                should_block = True
                risk_score += 100
                risk_reasons.append('Device is blocked')
                print(f"🚫 BLOCKED: Device {device.id} is blocked")
            
            # Rule 6: Untrusted device
            if not device.is_trusted:
                risk_score += 10
                risk_reasons.append('Untrusted device')
            
            # Rule 7: IP change detection
            if not created and device.last_ip != ip_address:
                risk_score += 20
                risk_reasons.append(f'IP changed from {device.last_ip} to {ip_address}')
                print(f"⚠️  IP changed: {device.last_ip} → {ip_address}")
            
            # Determine if suspicious
            if risk_score >= 40:
                is_suspicious = True
            
            # Block if necessary
            if should_block:
                print(f"🚫 LOGIN BLOCKED: Risk score {risk_score}")
                SystemLog.objects.create(
                    log_type='security',
                    level='critical',
                    message=f"Blocked login attempt for {user.username} from {ip_address}",
                    user=user,
                    ip_address=ip_address,
                    metadata={
                        'risk_score': risk_score,
                        'risk_reasons': risk_reasons,
                        'device_id': device.id
                    }
                )
                raise serializers.ValidationError({
                    'error': 'Login blocked due to security concerns',
                    'risk_score': risk_score,
                    'reasons': risk_reasons
                })
            
            # Create login event with risk assessment
            login_event = LoginEvent.objects.create(
                user=user,
                username=user.username,
                device=device,
                status='success',
                ip_address=ip_address,
                country_code=geo_data.get('country_code', 'Unknown'),
                city=geo_data.get('city', 'Unknown'),
                is_suspicious=is_suspicious,
                risk_score=risk_score,
                risk_reasons=risk_reasons,
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            print(f"✓ Login event created: ID={login_event.id}, Risk={risk_score}, Suspicious={is_suspicious}")
            
            # Create system log
            SystemLog.objects.create(
                log_type='login',
                level='warning' if is_suspicious else 'info',
                message=f"User {user.username} logged in from {ip_address} ({geo_data.get('city')}, {geo_data.get('country_code')})",
                user=user,
                ip_address=ip_address,
                metadata={
                    'risk_score': risk_score,
                    'risk_reasons': risk_reasons,
                    'device_id': device.id,
                    'is_new_device': created
                }
            )
            
            # Add device and location info to response
            data['device_id'] = device.id
            data['device_trusted'] = device.is_trusted
            data['device_new'] = created
            data['security'] = {
                'risk_score': risk_score,
                'risk_level': 'high' if risk_score >= 70 else 'medium' if risk_score >= 40 else 'low',
                'is_suspicious': is_suspicious,
                'requires_verification': is_suspicious and not device.is_trusted,
            }
            data['login_info'] = {
                'ip_address': ip_address,
                'country': geo_data.get('country_name', 'Unknown'),
                'country_code': geo_data.get('country_code', 'Unknown'),
                'city': geo_data.get('city', 'Unknown'),
                'region': geo_data.get('region', 'Unknown'),
            }
            
            # Warning message if suspicious
            if is_suspicious:
                data['warning'] = 'This login appears suspicious. Additional verification may be required.'
                print(f"⚠️  SUSPICIOUS LOGIN: {', '.join(risk_reasons)}")
        
        # Add user info to response
        data['user'] = {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'is_staff': user.is_staff,
        }
        
        return data


@extend_schema(
    tags=['Authentication'],
    description='Login with username and password to get JWT tokens',
    request=CustomTokenObtainPairSerializer,
)
class CustomTokenObtainPairView(TokenObtainPairView):
    """
    Custom Login View with Device Tracking
    
    POST /api/auth/login/
    {
        "username": "your_username",
        "password": "your_password"
    }
    
    Response:
    {
        "access": "eyJ0eXAiOiJKV1QiLCJhbGc...",
        "refresh": "eyJ0eXAiOiJKV1QiLCJhbGc...",
        "user": {...},
        "device_id": 1,
        "device_trusted": true
    }
    """
    serializer_class = CustomTokenObtainPairSerializer
    permission_classes = [AllowAny]


@extend_schema(
    tags=['Authentication'],
    description='Refresh access token using refresh token',
)
class CustomTokenRefreshView(TokenRefreshView):
    """
    Refresh JWT Token
    
    POST /api/auth/token/refresh/
    {
        "refresh": "eyJ0eXAiOiJKV1QiLCJhbGc..."
    }
    """
    permission_classes = [AllowAny]
