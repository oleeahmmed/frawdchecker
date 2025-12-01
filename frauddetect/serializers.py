from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from dj_rest_auth.registration.serializers import RegisterSerializer
from dj_rest_auth.serializers import LoginSerializer
from .models import (
    Device, 
    LoginEvent, 
    Transaction, 
    FraudEvent, 
    RiskProfile, 
    SystemLog,
    IPBlocklist
)
from .utils import get_client_ip, calculate_device_fingerprint


# ============================================
# User Serializer
# ============================================
class UserSerializer(serializers.ModelSerializer):
    """Basic User Information"""
    
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name']


# ============================================
# Device Serializer
# ============================================
class DeviceSerializer(serializers.ModelSerializer):
    """Device Details with User Info"""
    user = UserSerializer(read_only=True)
    
    class Meta:
        model = Device
        fields = '__all__'


# ============================================
# Login Event Serializer
# ============================================
class LoginEventSerializer(serializers.ModelSerializer):
    """Login Event with Related Info"""
    user = UserSerializer(read_only=True)
    device = DeviceSerializer(read_only=True)
    
    class Meta:
        model = LoginEvent
        fields = '__all__'


# ============================================
# Transaction Serializer
# ============================================
class TransactionSerializer(serializers.ModelSerializer):
    """Transaction with Risk Assessment"""
    user = UserSerializer(read_only=True)
    device = DeviceSerializer(read_only=True)
    
    class Meta:
        model = Transaction
        fields = '__all__'
        # এই fields গুলো client পাঠাতে পারবে না, system generate করবে
        read_only_fields = [
            'risk_score', 
            'risk_level', 
            'is_suspicious',
            'status',
            'approved_at'
        ]


class TransactionCreateSerializer(serializers.ModelSerializer):
    """Transaction Creation (Limited Fields)"""
    
    class Meta:
        model = Transaction
        fields = [
            'external_txn_id',
            'amount',
            'currency',
            'description',
            'beneficiary',
            'raw_payload'
        ]


# ============================================
# Fraud Event Serializer
# ============================================
class FraudEventSerializer(serializers.ModelSerializer):
    """Fraud Event with Details"""
    user = UserSerializer(read_only=True)
    transaction = TransactionSerializer(read_only=True)
    resolved_by = UserSerializer(read_only=True)
    
    class Meta:
        model = FraudEvent
        fields = '__all__'


class FraudEventResolveSerializer(serializers.Serializer):
    """For Resolving Fraud Events"""
    notes = serializers.CharField(required=False, allow_blank=True)


# ============================================
# Risk Profile Serializer
# ============================================
class RiskProfileSerializer(serializers.ModelSerializer):
    """User Risk Profile"""
    user = UserSerializer(read_only=True)
    
    class Meta:
        model = RiskProfile
        fields = '__all__'


# ============================================
# System Log Serializer
# ============================================
class SystemLogSerializer(serializers.ModelSerializer):
    """System Activity Logs"""
    user = UserSerializer(read_only=True)
    
    class Meta:
        model = SystemLog
        fields = '__all__'


# ============================================
# IP Blocklist Serializer
# ============================================
class IPBlocklistSerializer(serializers.ModelSerializer):
    """Blocked IP Addresses"""
    blocked_by = UserSerializer(read_only=True)
    
    class Meta:
        model = IPBlocklist
        fields = '__all__'


class IPBlocklistCreateSerializer(serializers.ModelSerializer):
    """Create IP Block Entry"""
    
    class Meta:
        model = IPBlocklist
        fields = ['ip_address', 'reason', 'expires_at']


# ============================================
# Dashboard Statistics Serializer
# ============================================
class DashboardStatsSerializer(serializers.Serializer):
    """Dashboard Overview Statistics"""
    total_transactions = serializers.IntegerField()
    suspicious_transactions = serializers.IntegerField()
    total_fraud_events = serializers.IntegerField()
    unresolved_fraud_events = serializers.IntegerField()
    blocked_ips = serializers.IntegerField()
    high_risk_users = serializers.IntegerField()
    transactions_today = serializers.IntegerField()
    total_amount_today = serializers.DecimalField(max_digits=15, decimal_places=2)


# ============================================
# Authentication Serializers
# ============================================
class UserDetailsSerializer(serializers.ModelSerializer):
    """Extended User Details for Authentication"""
    
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name', 'is_staff', 'date_joined']
        read_only_fields = ['id', 'date_joined']


class CustomLoginSerializer(LoginSerializer):
    """
    Custom Login Serializer with Device Tracking
    Supports login with username OR email
    """
    username = serializers.CharField(required=False, allow_blank=True)
    email = serializers.EmailField(required=False, allow_blank=True)
    password = serializers.CharField(style={'input_type': 'password'}, write_only=True)
    
    def validate(self, attrs):
        username = attrs.get('username', '').strip()
        email = attrs.get('email', '').strip()
        password = attrs.get('password')
        
        # Must provide either username or email
        if not username and not email:
            raise serializers.ValidationError('Must provide either username or email.')
        
        if not password:
            raise serializers.ValidationError('Password is required.')
        
        # Try to find user by email if provided
        user = None
        if email:
            try:
                from django.contrib.auth.models import User
                user_obj = User.objects.get(email=email)
                username = user_obj.username
            except User.DoesNotExist:
                pass
        
        # Authenticate
        if username and password:
            user = authenticate(
                request=self.context.get('request'),
                username=username,
                password=password
            )
        
        if not user:
            raise serializers.ValidationError('Unable to log in with provided credentials.')
        
        if not user.is_active:
            raise serializers.ValidationError('User account is disabled.')
        
        attrs['user'] = user
        return attrs


class CustomRegisterSerializer(RegisterSerializer):
    """
    Custom Registration Serializer
    """
    first_name = serializers.CharField(required=False, max_length=150)
    last_name = serializers.CharField(required=False, max_length=150)
    
    def get_cleaned_data(self):
        data = super().get_cleaned_data()
        data['first_name'] = self.validated_data.get('first_name', '')
        data['last_name'] = self.validated_data.get('last_name', '')
        return data
    
    def save(self, request):
        user = super().save(request)
        user.first_name = self.validated_data.get('first_name', '')
        user.last_name = self.validated_data.get('last_name', '')
        user.save()
        return user
