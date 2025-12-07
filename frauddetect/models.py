from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta
import hashlib
import json


# ============================================
# 📱 MODEL 1: DEVICE (ডিভাইস ট্র্যাকিং)
# ============================================
class Device(models.Model):
    """
    ব্যবহারকারীর ডিভাইস ট্র্যাক করার জন্য
    একই ব্যক্তি বিভিন্ন ডিভাইস থেকে লগইন করলে ট্র্যাক করা যায়
    """
    STATUS_CHOICES = [
        ('normal', 'Normal'),
        ('suspicious', 'Suspicious'),
        ('blocked', 'Blocked'),
    ]
    
    # কোন ইউজারের ডিভাইস
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='devices')
    
    # ডিভাইসের Unique Fingerprint (Hash)
    fingerprint_hash = models.CharField(max_length=64, db_index=True)
    device_fingerprint = models.TextField(null=True, blank=True)
    
    # ডিভাইসের তথ্য
    device_type = models.CharField(max_length=50, null=True, blank=True)  # mobile/desktop/tablet
    device_name = models.CharField(max_length=100, null=True, blank=True)
    os_name = models.CharField(max_length=50, null=True, blank=True)      # Windows/Android/iOS
    os_version = models.CharField(max_length=50, null=True, blank=True)
    browser_name = models.CharField(max_length=50, null=True, blank=True)  # Chrome/Firefox
    browser_version = models.CharField(max_length=50, null=True, blank=True)
    
    # লোকেশন তথ্য
    last_ip = models.GenericIPAddressField(null=True, blank=True)
    last_country_code = models.CharField(max_length=2, null=True, blank=True)
    last_city = models.CharField(max_length=100, null=True, blank=True)
    
    # স্ট্যাটাস
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='normal')
    is_trusted = models.BooleanField(default=False)  # বিশ্বস্ত ডিভাইস কিনা
    is_blocked = models.BooleanField(default=False)  # ব্লক করা হয়েছে কিনা
    risk_score = models.IntegerField(default=0)      # ঝুঁকি স্কোর (0-100)
    
    # Whitelist functionality
    is_whitelisted = models.BooleanField(default=False, help_text="Whitelisted devices bypass all fraud checks")
    whitelisted_at = models.DateTimeField(null=True, blank=True, help_text="When this device was whitelisted")
    whitelisted_by = models.ForeignKey(
        User, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True, 
        related_name='whitelisted_devices',
        help_text="Admin who whitelisted this device"
    )
    whitelist_reason = models.CharField(max_length=200, blank=True, help_text="Reason for whitelisting")
    
    # সময়
    first_seen_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'devices'
        indexes = [
            models.Index(fields=['fingerprint_hash', 'user']),
            models.Index(fields=['last_ip']),
        ]
    
    def __str__(self):
        return f"{self.user.username} - {self.device_name or 'Unknown Device'}"
    
    def save(self, *args, **kwargs):
        """
        Override save to protect superuser devices
        Superuser devices can NEVER be blocked
        """
        if self.user and self.user.is_superuser:
            # Superuser protection
            if self.is_blocked:
                print(f"⚠️ WARNING: Attempted to block superuser device. Preventing block.")
                self.is_blocked = False
            
            # Auto-trust superuser devices
            if not self.is_trusted:
                self.is_trusted = True
                print(f"✅ Auto-trusted superuser device: {self.device_name}")
        
        super().save(*args, **kwargs)


# ============================================
# 🔐 MODEL 2: LOGIN EVENT (লগইন ইভেন্ট)
# ============================================
class LoginEvent(models.Model):
    """
    প্রতিটি লগইন চেষ্টা রেকর্ড করার জন্য
    সফল/ব্যর্থ উভয় লগইন ট্র্যাক করা হয়
    """
    STATUS_CHOICES = [
        ('success', 'Success'),
        ('failed', 'Failed'),
        ('blocked', 'Blocked'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    username = models.CharField(max_length=150)  # ব্যর্থ লগইনের জন্য username রাখা হয়
    device = models.ForeignKey(Device, on_delete=models.SET_NULL, null=True, blank=True)
    
    # লগইন ডিটেইলস
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    ip_address = models.GenericIPAddressField()
    country_code = models.CharField(max_length=2, null=True, blank=True)
    city = models.CharField(max_length=100, null=True, blank=True)
    
    # ঝুঁকি মূল্যায়ন
    is_suspicious = models.BooleanField(default=False)
    risk_score = models.IntegerField(default=0)
    risk_reasons = models.JSONField(default=list)  # কেন সন্দেহজনক তার কারণ
    
    # অতিরিক্ত তথ্য
    user_agent = models.TextField(null=True, blank=True)
    attempt_time = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'login_events'
        ordering = ['-attempt_time']
        indexes = [
            models.Index(fields=['username', 'attempt_time']),
            models.Index(fields=['ip_address']),
        ]
    
    def __str__(self):
        return f"{self.username} - {self.status} at {self.attempt_time}"


# ============================================
# 💰 MODEL 3: TRANSACTION (লেনদেন)
# ============================================
class Transaction(models.Model):
    """
    আর্থিক লেনদেন ট্র্যাক করার জন্য
    প্রতিটি লেনদেনের ঝুঁকি মূল্যায়ন করা হয়
    """
    STATUS_CHOICES = [
        ('pending', 'Pending'),      # অপেক্ষমাণ
        ('approved', 'Approved'),    # অনুমোদিত
        ('rejected', 'Rejected'),    # প্রত্যাখ্যাত
        ('flagged', 'Flagged'),      # সন্দেহজনক হিসেবে চিহ্নিত
        ('blocked', 'Blocked'),      # ব্লক করা
    ]
    
    TRANSACTION_TYPE_CHOICES = [
        ('transfer', 'Bank Transfer'),
        ('p2p', 'Peer-to-Peer'),
        ('international', 'International Transfer'),
        ('cash_withdrawal', 'Cash Withdrawal'),
        ('bill_payment', 'Bill Payment'),
        ('purchase', 'Purchase'),
        ('crypto', 'Cryptocurrency'),
        ('deposit', 'Deposit'),
        ('other', 'Other'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='transactions')
    device = models.ForeignKey(Device, on_delete=models.SET_NULL, null=True, blank=True)
    
    # লেনদেনের ডিটেইলস
    external_txn_id = models.CharField(max_length=100, unique=True)  # বাহ্যিক ট্রানজেকশন ID
    amount = models.DecimalField(max_digits=15, decimal_places=2)    # পরিমাণ
    currency = models.CharField(max_length=3, default='SAR')         # মুদ্রা
    description = models.TextField(null=True, blank=True)            # বিবরণ
    beneficiary = models.CharField(max_length=255, null=True, blank=True)  # প্রাপক
    
    # Transaction Type
    transaction_type = models.CharField(
        max_length=20,
        choices=TRANSACTION_TYPE_CHOICES,
        default='transfer',
        help_text="Type of transaction"
    )
    
    # স্ট্যাটাস
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    # ঝুঁকি মূল্যায়ন
    risk_score = models.IntegerField(default=0)           # ০-১০০
    risk_level = models.CharField(max_length=20, default='low')  # low/medium/high
    is_suspicious = models.BooleanField(default=False)
    risk_reasons = models.JSONField(default=list, help_text="List of reasons for risk score")
    triggered_patterns = models.JSONField(default=list, help_text="List of pattern IDs that triggered")
    
    # Geographic Information
    country_code = models.CharField(max_length=2, null=True, blank=True)
    city = models.CharField(max_length=100, null=True, blank=True)
    
    # Manual Review
    requires_manual_review = models.BooleanField(default=False)
    reviewed_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='reviewed_transactions'
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)
    review_notes = models.TextField(null=True, blank=True)
    
    # মেটাডেটা
    raw_payload = models.JSONField(null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    
    # সময়
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    approved_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'transactions'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'created_at']),
            models.Index(fields=['status']),
            models.Index(fields=['transaction_type']),
            models.Index(fields=['is_suspicious']),
            models.Index(fields=['requires_manual_review']),
        ]
    
    def __str__(self):
        return f"TXN-{self.external_txn_id} - {self.amount} {self.currency}"


# ============================================
# 🚨 MODEL 4: FRAUD EVENT (জালিয়াতি ইভেন্ট)
# ============================================
class FraudEvent(models.Model):
    """
    সন্দেহজনক কার্যকলাপ সনাক্ত হলে এখানে রেকর্ড করা হয়
    """
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    transaction = models.ForeignKey(Transaction, on_delete=models.CASCADE, null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    
    # জালিয়াতির ডিটেইলস
    rule_id = models.CharField(max_length=50, null=True, blank=True)  # কোন নিয়ম ভঙ্গ হয়েছে
    triggered_rules = models.JSONField(default=list)  # সব triggered নিয়মের তালিকা
    risk_score = models.IntegerField()
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    
    # বিবরণ
    description = models.TextField()
    recommendations = models.TextField(null=True, blank=True)  # কী করা উচিত
    
    # সমাধান স্ট্যাটাস
    is_resolved = models.BooleanField(default=False)
    resolved_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, 
        null=True, blank=True, 
        related_name='resolved_frauds'
    )
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolution_notes = models.TextField(null=True, blank=True)
    
    # সময়
    detected_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'fraud_events'
        ordering = ['-detected_at']
        indexes = [
            models.Index(fields=['user', 'detected_at']),
            models.Index(fields=['severity']),
        ]
    
    def __str__(self):
        return f"Fraud Event - {self.severity} - {self.user.username}"


# ============================================
# 📊 MODEL 5: RISK PROFILE (ঝুঁকি প্রোফাইল)
# ============================================
class RiskProfile(models.Model):
    """
    প্রতিটি ব্যবহারকারীর সামগ্রিক ঝুঁকি প্রোফাইল
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='risk_profile')
    
    # সামগ্রিক ঝুঁকি
    overall_risk_score = models.IntegerField(default=0)
    risk_level = models.CharField(max_length=20, default='low')
    
    # পরিসংখ্যান
    total_transactions = models.IntegerField(default=0)
    total_amount = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    suspicious_events_count = models.IntegerField(default=0)
    failed_login_count = models.IntegerField(default=0)
    
    # আচরণগত প্যাটার্ন
    avg_transaction_amount = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    usual_login_hours = models.JSONField(default=list)    # সাধারণত কোন সময় লগইন করে
    usual_countries = models.JSONField(default=list)       # সাধারণত কোন দেশ থেকে
    trusted_devices_count = models.IntegerField(default=0)
    
    # স্ট্যাটাস
    is_monitored = models.BooleanField(default=False)  # নজরদারিতে আছে কিনা
    is_blocked = models.BooleanField(default=False)    # ব্লক করা হয়েছে কিনা
    
    # সময়
    last_reviewed_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'risk_profiles'
    
    def __str__(self):
        return f"{self.user.username} - Risk: {self.risk_level}"


# ============================================
# ✅ MODEL 6: IP WHITELIST (অনুমোদিত IP)
# ============================================
class IPWhitelist(models.Model):
    """
    Whitelisted IP addresses যেগুলো সব check bypass করবে
    Admin/Development/Trusted locations এর জন্য
    """
    ip_address = models.GenericIPAddressField(unique=True, help_text="IP address to whitelist")
    description = models.CharField(max_length=200, blank=True, help_text="Purpose of this IP (e.g., 'Office IP', 'Admin Home')")
    
    # Metadata
    added_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='whitelisted_ips')
    is_active = models.BooleanField(default=True, help_text="Enable/disable this whitelist entry")
    
    # Timestamps
    added_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True, help_text="Optional expiry date for temporary whitelist")
    last_used_at = models.DateTimeField(null=True, blank=True, help_text="Last time this IP was used")
    
    class Meta:
        db_table = 'ip_whitelist'
        verbose_name = 'IP Whitelist'
        verbose_name_plural = 'IP Whitelist'
        ordering = ['-added_at']
    
    def __str__(self):
        status = "✅" if self.is_active else "❌"
        return f"{status} {self.ip_address} - {self.description or 'No description'}"
    
    def is_expired(self):
        """Check if whitelist entry has expired"""
        if self.expires_at:
            return timezone.now() > self.expires_at
        return False
    
    @classmethod
    def is_whitelisted(cls, ip_address):
        """Check if an IP is whitelisted and active"""
        try:
            entry = cls.objects.get(ip_address=ip_address, is_active=True)
            if entry.is_expired():
                entry.is_active = False
                entry.save()
                return False
            # Update last used
            entry.last_used_at = timezone.now()
            entry.save(update_fields=['last_used_at'])
            return True
        except cls.DoesNotExist:
            return False


# ============================================
# 🚫 MODEL 7: IP BLOCKLIST (ব্লক করা IP)
# ============================================
class IPBlocklist(models.Model):
    """
    ব্লক করা IP ঠিকানার তালিকা
    """
    ip_address = models.GenericIPAddressField(unique=True)
    reason = models.TextField()
    blocked_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    is_active = models.BooleanField(default=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)  # কখন মেয়াদ শেষ হবে
    
    class Meta:
        db_table = 'ip_blocklist'
    
    def __str__(self):
        return f"Blocked IP: {self.ip_address}"
    
    @classmethod
    def is_superuser_ip(cls, ip_address):
        """
        Check if IP belongs to any superuser
        Superuser IPs should NEVER be blocked
        """
        from .models import Device
        
        # Check if any superuser has used this IP
        superuser_devices = Device.objects.filter(
            user__is_superuser=True,
            last_ip=ip_address
        )
        
        return superuser_devices.exists()
    
    def save(self, *args, **kwargs):
        """
        Override save to protect superuser IPs
        """
        # Check if this IP belongs to a superuser
        if self.is_superuser_ip(self.ip_address):
            print(f"⚠️ WARNING: Attempted to block superuser IP {self.ip_address}. Preventing block.")
            # Don't save the block
            return
        
        super().save(*args, **kwargs)


# ============================================
# 📝 MODEL 7: SYSTEM LOG (সিস্টেম লগ)
# ============================================
class SystemLog(models.Model):
    """
    সব ধরনের সিস্টেম কার্যকলাপ লগ করার জন্য
    """
    LOG_TYPE_CHOICES = [
        ('login', 'Login'),
        ('transaction', 'Transaction'),
        ('fraud_alert', 'Fraud Alert'),
        ('security', 'Security'),
        ('system', 'System'),
    ]
    
    LEVEL_CHOICES = [
        ('info', 'Info'),
        ('warning', 'Warning'),
        ('error', 'Error'),
        ('critical', 'Critical'),
    ]
    
    log_type = models.CharField(max_length=50, choices=LOG_TYPE_CHOICES)
    level = models.CharField(max_length=20, choices=LEVEL_CHOICES, default='info')
    message = models.TextField()
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    metadata = models.JSONField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'system_logs'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['log_type', 'created_at']),
            models.Index(fields=['level']),
        ]
    
    def __str__(self):
        return f"{self.log_type} - {self.level} - {self.created_at}"


# ============================================
# ⚙️ MODEL 8: FRAUD CONFIG (জালিয়াতি কনফিগারেশন)
# ============================================
class FraudConfig(models.Model):
    """
    Fraud Detection এর সব configuration এক জায়গায়
    Admin panel থেকে সহজে পরিবর্তন করা যাবে
    """
    # Configuration Name
    name = models.CharField(max_length=100, unique=True, help_text="Configuration name (e.g., 'Production Config', 'Test Config')")
    description = models.TextField(blank=True, help_text="Description of this configuration")
    
    # Status
    is_active = models.BooleanField(default=False, help_text="Only one config can be active at a time")
    
    # ═══════════════════════════════════════════════════════
    # WHITELIST SETTINGS (Quick Access)
    # ═══════════════════════════════════════════════════════
    quick_whitelist_ips = models.JSONField(
        default=list,
        blank=True,
        help_text="Quick IP whitelist (e.g., ['127.0.0.1', '192.168.1.100']). For detailed management, use IPWhitelist model."
    )
    
    # ═══════════════════════════════════════════════════════
    # GEO-RESTRICTION SETTINGS
    # ═══════════════════════════════════════════════════════
    geo_restriction_enabled = models.BooleanField(
        default=True,
        help_text="Enable geographic restriction"
    )
    allowed_countries = models.JSONField(
        default=list,
        help_text="List of allowed country codes (e.g., ['SA', 'AE'])"
    )
    auto_block_non_allowed_ips = models.BooleanField(
        default=True,
        help_text="Automatically block IPs from non-allowed countries"
    )
    auto_trust_devices_from_allowed_countries = models.BooleanField(
        default=True,
        help_text="Automatically trust devices from allowed countries"
    )
    auto_block_devices_from_blocked_countries = models.BooleanField(
        default=True,
        help_text="Automatically block devices from non-allowed countries"
    )
    
    # ═══════════════════════════════════════════════════════
    # LOGIN SECURITY SETTINGS
    # ═══════════════════════════════════════════════════════
    max_login_attempts = models.IntegerField(
        default=5,
        help_text="Maximum login attempts before blocking"
    )
    login_attempt_window_minutes = models.IntegerField(
        default=5,
        help_text="Time window for login attempts (in minutes)"
    )
    require_trusted_device = models.BooleanField(
        default=True,
        help_text="Only allow login from trusted devices"
    )
    
    # ═══════════════════════════════════════════════════════
    # TRANSACTION FRAUD SETTINGS
    # ═══════════════════════════════════════════════════════
    high_amount_threshold = models.DecimalField(
        max_digits=15,
        decimal_places=2,
        default=100000,
        help_text="Amount above this is considered high-risk (in SAR)"
    )
    max_daily_transactions = models.IntegerField(
        default=50,
        help_text="Maximum transactions per day per user"
    )
    max_transaction_amount_daily = models.DecimalField(
        max_digits=15,
        decimal_places=2,
        default=500000,
        help_text="Maximum total transaction amount per day (in SAR)"
    )
    max_transactions_per_hour = models.IntegerField(
        default=10,
        help_text="Maximum transactions per hour per user"
    )
    
    # ═══════════════════════════════════════════════════════
    # BUSINESS HOURS
    # ═══════════════════════════════════════════════════════
    business_hours_start = models.IntegerField(
        default=8,
        help_text="Business hours start (0-23)"
    )
    business_hours_end = models.IntegerField(
        default=18,
        help_text="Business hours end (0-23)"
    )
    flag_outside_business_hours = models.BooleanField(
        default=True,
        help_text="Flag transactions outside business hours as suspicious"
    )
    
    # ═══════════════════════════════════════════════════════
    # RISK SCORING
    # ═══════════════════════════════════════════════════════
    risk_score_threshold_low = models.IntegerField(
        default=20,
        help_text="Risk score below this is considered low risk"
    )
    risk_score_threshold_medium = models.IntegerField(
        default=40,
        help_text="Risk score below this is considered medium risk"
    )
    risk_score_threshold_high = models.IntegerField(
        default=70,
        help_text="Risk score above this is considered high risk"
    )
    
    # ═══════════════════════════════════════════════════════
    # METADATA
    # ═══════════════════════════════════════════════════════
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='created_configs'
    )
    updated_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='updated_configs'
    )
    
    class Meta:
        db_table = 'fraud_configs'
        ordering = ['-is_active', '-updated_at']
        verbose_name = 'Fraud Configuration'
        verbose_name_plural = 'Fraud Configurations'
    
    def __str__(self):
        status = "✅ ACTIVE" if self.is_active else "⚪ Inactive"
        return f"{status} - {self.name}"
    
    def save(self, *args, **kwargs):
        """
        যখন একটা config active করা হয়, বাকি সব deactivate করা হয়
        """
        if self.is_active:
            # Deactivate all other configs
            FraudConfig.objects.filter(is_active=True).exclude(pk=self.pk).update(is_active=False)
        super().save(*args, **kwargs)
    
    @classmethod
    def get_active_config(cls):
        """
        Active configuration return করে
        যদি কোনো active না থাকে, default config তৈরি করে
        """
        try:
            return cls.objects.get(is_active=True)
        except cls.DoesNotExist:
            # Create default config if none exists
            return cls.create_default_config()
        except cls.MultipleObjectsReturned:
            # If multiple active configs (shouldn't happen), return first one
            return cls.objects.filter(is_active=True).first()
    
    @classmethod
    def create_default_config(cls):
        """
        Default configuration তৈরি করে
        """
        config = cls.objects.create(
            name='Default Configuration',
            description='Default fraud detection configuration for Saudi Arabia compliance',
            is_active=True,
            geo_restriction_enabled=True,
            allowed_countries=['SA'],
            auto_block_non_allowed_ips=True,
            auto_trust_devices_from_allowed_countries=True,
            auto_block_devices_from_blocked_countries=True,
            max_login_attempts=5,
            login_attempt_window_minutes=5,
            require_trusted_device=True,
            high_amount_threshold=100000,
            max_daily_transactions=50,
            max_transaction_amount_daily=500000,
            max_transactions_per_hour=10,
            business_hours_start=8,
            business_hours_end=18,
            flag_outside_business_hours=True,
            risk_score_threshold_low=20,
            risk_score_threshold_medium=40,
            risk_score_threshold_high=70,
        )
        print(f"✅ Created default fraud config: {config.name}")
        return config