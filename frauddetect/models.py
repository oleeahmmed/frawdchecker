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
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='transactions')
    device = models.ForeignKey(Device, on_delete=models.SET_NULL, null=True, blank=True)
    
    # লেনদেনের ডিটেইলস
    external_txn_id = models.CharField(max_length=100, unique=True)  # বাহ্যিক ট্রানজেকশন ID
    amount = models.DecimalField(max_digits=15, decimal_places=2)    # পরিমাণ
    currency = models.CharField(max_length=3, default='SAR')         # মুদ্রা
    description = models.TextField(null=True, blank=True)            # বিবরণ
    beneficiary = models.CharField(max_length=255, null=True, blank=True)  # প্রাপক
    
    # স্ট্যাটাস
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    # ঝুঁকি মূল্যায়ন
    risk_score = models.IntegerField(default=0)           # ০-১০০
    risk_level = models.CharField(max_length=20, default='low')  # low/medium/high
    is_suspicious = models.BooleanField(default=False)
    
    # মেটাডেটা
    raw_payload = models.JSONField(null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    
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
# 🚫 MODEL 6: IP BLOCKLIST (ব্লক করা IP)
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