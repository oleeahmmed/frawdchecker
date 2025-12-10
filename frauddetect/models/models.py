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
    device_type = models.CharField(max_length=50, null=True, blank=True)
    device_name = models.CharField(max_length=100, null=True, blank=True)
    os_name = models.CharField(max_length=50, null=True, blank=True)
    os_version = models.CharField(max_length=50, null=True, blank=True)
    browser_name = models.CharField(max_length=50, null=True, blank=True)
    browser_version = models.CharField(max_length=50, null=True, blank=True)
    
    # লোকেশন তথ্য
    last_ip = models.GenericIPAddressField(null=True, blank=True)
    last_country_code = models.CharField(max_length=2, null=True, blank=True)
    last_city = models.CharField(max_length=100, null=True, blank=True)
    
    # স্ট্যাটাস
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='normal')
    is_trusted = models.BooleanField(default=False)
    is_blocked = models.BooleanField(default=False)
    risk_score = models.IntegerField(default=0)
    
    # Whitelist functionality
    is_whitelisted = models.BooleanField(default=False, help_text="Whitelisted devices bypass all fraud checks")
    whitelisted_at = models.DateTimeField(null=True, blank=True)
    whitelisted_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='whitelisted_devices'
    )
    whitelist_reason = models.CharField(max_length=200, blank=True)
    
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
        if self.user and self.user.is_superuser:
            if self.is_blocked:
                print(f"⚠️ WARNING: Attempted to block superuser device. Preventing block.")
                self.is_blocked = False
            if not self.is_trusted:
                self.is_trusted = True
                print(f"✅ Auto-trusted superuser device: {self.device_name}")
        super().save(*args, **kwargs)


# ============================================
# 🔐 MODEL 2: LOGIN EVENT (লগইন ইভেন্ট)
# ============================================
class LoginEvent(models.Model):
    STATUS_CHOICES = [
        ('success', 'Success'),
        ('failed', 'Failed'),
        ('blocked', 'Blocked'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    username = models.CharField(max_length=150)
    device = models.ForeignKey(Device, on_delete=models.SET_NULL, null=True, blank=True)
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    ip_address = models.GenericIPAddressField()
    country_code = models.CharField(max_length=2, null=True, blank=True)
    city = models.CharField(max_length=100, null=True, blank=True)
    
    is_suspicious = models.BooleanField(default=False)
    risk_score = models.IntegerField(default=0)
    risk_reasons = models.JSONField(default=list)
    
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
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('flagged', 'Flagged'),
        ('blocked', 'Blocked'),
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
    
    external_txn_id = models.CharField(max_length=100, unique=True)
    amount = models.DecimalField(max_digits=15, decimal_places=2)
    currency = models.CharField(max_length=3, default='SAR')
    description = models.TextField(null=True, blank=True)
    beneficiary = models.CharField(max_length=255, null=True, blank=True)
    
    transaction_type = models.CharField(
        max_length=20, choices=TRANSACTION_TYPE_CHOICES, default='transfer'
    )
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    risk_score = models.IntegerField(default=0)
    risk_level = models.CharField(max_length=20, default='low')
    is_suspicious = models.BooleanField(default=False)
    risk_reasons = models.JSONField(default=list)
    triggered_patterns = models.JSONField(default=list)
    
    country_code = models.CharField(max_length=2, null=True, blank=True)
    city = models.CharField(max_length=100, null=True, blank=True)
    
    requires_manual_review = models.BooleanField(default=False)
    reviewed_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='reviewed_transactions'
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)
    review_notes = models.TextField(null=True, blank=True)
    
    raw_payload = models.JSONField(null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    
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
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    transaction = models.ForeignKey(Transaction, on_delete=models.CASCADE, null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    
    rule_id = models.CharField(max_length=50, null=True, blank=True)
    triggered_rules = models.JSONField(default=list)
    risk_score = models.IntegerField()
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    
    description = models.TextField()
    recommendations = models.TextField(null=True, blank=True)
    
    is_resolved = models.BooleanField(default=False)
    resolved_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True,
        related_name='resolved_frauds'
    )
    resolved_at = models.DateTimeField(null=True, blank=True)
    resolution_notes = models.TextField(null=True, blank=True)
    
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
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='risk_profile')
    
    overall_risk_score = models.IntegerField(default=0)
    risk_level = models.CharField(max_length=20, default='low')
    
    total_transactions = models.IntegerField(default=0)
    total_amount = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    suspicious_events_count = models.IntegerField(default=0)
    failed_login_count = models.IntegerField(default=0)
    
    avg_transaction_amount = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    usual_login_hours = models.JSONField(default=list)
    usual_countries = models.JSONField(default=list)
    trusted_devices_count = models.IntegerField(default=0)
    
    is_monitored = models.BooleanField(default=False)
    is_blocked = models.BooleanField(default=False)
    
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
    ip_address = models.GenericIPAddressField(unique=True)
    description = models.CharField(max_length=200, blank=True)
    
    added_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='whitelisted_ips')
    is_active = models.BooleanField(default=True)
    
    added_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'ip_whitelist'
        verbose_name = 'IP Whitelist'
        verbose_name_plural = 'IP Whitelist'
        ordering = ['-added_at']
    
    def __str__(self):
        status = "✅" if self.is_active else "❌"
        return f"{status} {self.ip_address} - {self.description or 'No description'}"
    
    def is_expired(self):
        if self.expires_at:
            return timezone.now() > self.expires_at
        return False
    
    @classmethod
    def is_whitelisted(cls, ip_address):
        try:
            entry = cls.objects.get(ip_address=ip_address, is_active=True)
            if entry.is_expired():
                entry.is_active = False
                entry.save()
                return False
            entry.last_used_at = timezone.now()
            entry.save(update_fields=['last_used_at'])
            return True
        except cls.DoesNotExist:
            return False


# ============================================
# 🚫 MODEL 7: IP BLOCKLIST (ব্লক করা IP)
# ============================================
class IPBlocklist(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    reason = models.TextField()
    blocked_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    is_active = models.BooleanField(default=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'ip_blocklist'
    
    def __str__(self):
        return f"Blocked IP: {self.ip_address}"
    
    @classmethod
    def is_superuser_ip(cls, ip_address):
        superuser_devices = Device.objects.filter(
            user__is_superuser=True,
            last_ip=ip_address
        )
        return superuser_devices.exists()
    
    def save(self, *args, **kwargs):
        if self.is_superuser_ip(self.ip_address):
            print(f"⚠️ WARNING: Attempted to block superuser IP {self.ip_address}. Preventing block.")
            return
        super().save(*args, **kwargs)


# ============================================
# 📝 MODEL 8: SYSTEM LOG (সিস্টেম লগ)
# ============================================
class SystemLog(models.Model):
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
# ⚙️ MODEL 9: FRAUD CONFIG (জালিয়াতি কনফিগারেশন)
# ============================================
class FraudConfig(models.Model):
    name = models.CharField(max_length=100, unique=True)
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=False)
    
    quick_whitelist_ips = models.JSONField(default=list, blank=True)
    
    geo_restriction_enabled = models.BooleanField(default=True)
    allowed_countries = models.JSONField(default=list)
    auto_block_non_allowed_ips = models.BooleanField(default=True)
    auto_trust_devices_from_allowed_countries = models.BooleanField(default=True)
    auto_block_devices_from_blocked_countries = models.BooleanField(default=True)
    
    max_login_attempts = models.IntegerField(default=5)
    login_attempt_window_minutes = models.IntegerField(default=5)
    require_trusted_device = models.BooleanField(default=True)
    
    high_amount_threshold = models.DecimalField(max_digits=15, decimal_places=2, default=100000)
    max_daily_transactions = models.IntegerField(default=50)
    max_transaction_amount_daily = models.DecimalField(max_digits=15, decimal_places=2, default=500000)
    max_transactions_per_hour = models.IntegerField(default=10)
    
    business_hours_start = models.IntegerField(default=8)
    business_hours_end = models.IntegerField(default=18)
    flag_outside_business_hours = models.BooleanField(default=True)
    
    risk_score_threshold_low = models.IntegerField(default=20)
    risk_score_threshold_medium = models.IntegerField(default=40)
    risk_score_threshold_high = models.IntegerField(default=70)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='created_configs')
    updated_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='updated_configs')
    
    class Meta:
        db_table = 'fraud_configs'
        ordering = ['-is_active', '-updated_at']
        verbose_name = 'Fraud Configuration'
        verbose_name_plural = 'Fraud Configurations'
    
    def __str__(self):
        status = "✅ ACTIVE" if self.is_active else "⚪ Inactive"
        return f"{status} - {self.name}"
    
    def save(self, *args, **kwargs):
        if self.is_active:
            FraudConfig.objects.filter(is_active=True).exclude(pk=self.pk).update(is_active=False)
        super().save(*args, **kwargs)
    
    @classmethod
    def get_active_config(cls):
        try:
            return cls.objects.get(is_active=True)
        except cls.DoesNotExist:
            return cls.create_default_config()
        except cls.MultipleObjectsReturned:
            return cls.objects.filter(is_active=True).first()
    
    @classmethod
    def create_default_config(cls):
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
