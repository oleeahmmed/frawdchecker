"""
🔔 Signals - Auto Create Default Config & Risk Profile
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Signals:
1. নতুন User হলে Risk Profile তৈরি
2. Migration এর পরে FraudConfig auto-create
3. Server start এ FraudConfig check
4. Transaction হলে Risk Profile আপডেট
"""

from django.db.models.signals import post_save, post_migrate
from django.dispatch import receiver
from django.contrib.auth.models import User
from django.db.models import Count

from frauddetect.models import RiskProfile, Transaction, FraudConfig


# ============================================
# Signal 1: নতুন User হলে Risk Profile তৈরি
# ============================================
@receiver(post_save, sender=User)
def create_risk_profile(sender, instance, created, **kwargs):
    """
    নতুন ব্যবহারকারীর জন্য স্বয়ংক্রিয়ভাবে Risk Profile তৈরি
    """
    if created:
        RiskProfile.objects.get_or_create(user=instance)
        print(f"✅ [Signal] Risk Profile created for user: {instance.username}")


# ============================================
# Signal 2: কোনো FraudConfig না থাকলে Default তৈরি
# ============================================
@receiver(post_migrate)
def create_default_fraud_config(sender, **kwargs):
    """
    Migration এর পরে যদি কোনো FraudConfig না থাকে, তাহলে Default তৈরি
    
    শুধু frauddetect app এর migration এর পরে চলবে
    """
    # Only run for frauddetect app
    if sender.name != 'frauddetect':
        return
    
    # Check if any FraudConfig exists
    if FraudConfig.objects.exists():
        active_config = FraudConfig.objects.filter(is_active=True).first()
        if active_config:
            print(f"✅ [Signal] Active Fraud Config found: {active_config.name}")
        else:
            print("⚠️  [Signal] No active Fraud Config! Please activate one in admin panel.")
        return
    
    # Create default config
    print("🔧 [Signal] No Fraud Config found. Creating default...")
    
    config = FraudConfig.objects.create(
        name='Saudi Arabia Bank Default',
        description='Default fraud detection configuration for Saudi Arabia banking compliance. Only allows login from Saudi Arabia.',
        is_active=True,
        
        # Geo-Restriction (Saudi Arabia Only)
        geo_restriction_enabled=True,
        allowed_countries=['SA'],  # Only Saudi Arabia
        auto_block_non_allowed_ips=True,
        auto_trust_devices_from_allowed_countries=True,
        auto_block_devices_from_blocked_countries=True,
        
        # Login Security
        max_login_attempts=5,
        login_attempt_window_minutes=5,
        require_trusted_device=True,
        
        # Transaction Fraud
        high_amount_threshold=100000,  # 100,000 SAR
        max_daily_transactions=50,
        max_transaction_amount_daily=500000,  # 500,000 SAR
        max_transactions_per_hour=10,
        
        # Business Hours
        business_hours_start=8,   # 8 AM
        business_hours_end=18,    # 6 PM
        flag_outside_business_hours=True,
        
        # Risk Scoring
        risk_score_threshold_low=20,
        risk_score_threshold_medium=40,
        risk_score_threshold_high=70,
    )
    
    print(f"✅ [Signal] Default Fraud Config created: {config.name}")
    print(f"   📍 Allowed Countries: {config.allowed_countries}")
    print(f"   🔒 Require Trusted Device: {config.require_trusted_device}")
    print(f"   🚫 Auto-block non-SA IPs: {config.auto_block_non_allowed_ips}")


# ============================================
# Signal 3: Transaction হলে Risk Profile আপডেট
# ============================================
# NOTE: Risk Profile is now updated via RiskProfileManager in serializers
# This signal is kept for backward compatibility and edge cases

@receiver(post_save, sender=Transaction)
def update_risk_profile_on_transaction(sender, instance, created, **kwargs):
    """
    প্রতিটি নতুন Transaction এ User এর Risk Profile আপডেট করা
    Note: Main updates happen in serializers via RiskProfileManager
    This is a fallback for direct model saves
    """
    if not created:
        return
    
    # Skip if already updated by RiskProfileManager (check last_updated)
    try:
        profile = instance.user.risk_profile
        # If profile was updated in last 5 seconds, skip (already handled by serializer)
        from django.utils import timezone
        from datetime import timedelta
        if profile.updated_at and (timezone.now() - profile.updated_at) < timedelta(seconds=5):
            return
    except RiskProfile.DoesNotExist:
        profile = RiskProfile.objects.create(user=instance.user)
    
    # Fallback update (only if not handled by RiskProfileManager)
    print(f"📊 [Signal Fallback] Risk Profile check for: {instance.user.username}")


# ============================================
# Signal 4: Startup Check - Ensure Active Config
# ============================================
def ensure_active_fraud_config():
    """
    নিশ্চিত করুন যে একটা active config আছে
    যদি না থাকে, তাহলে একটা তৈরি করুন
    
    This can be called from apps.py ready() method
    """
    try:
        config = FraudConfig.get_active_config()
        print(f"✅ Active Fraud Config: {config.name}")
        print(f"   📍 Allowed Countries: {config.allowed_countries}")
        return config
    except Exception as e:
        print(f"⚠️  Error getting active config: {e}")
        return None