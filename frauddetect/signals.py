from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.signals import user_logged_in, user_login_failed
from django.contrib.auth.models import User

from .models import RiskProfile, LoginEvent, Transaction, SystemLog
from .utils import get_client_ip, get_geo_location, get_country_risk_level


# ============================================
# Signal 1: নতুন User হলে Risk Profile তৈরি
# ============================================
@receiver(post_save, sender=User)
def create_risk_profile(sender, instance, created, **kwargs):
    """নতুন ব্যবহারকারীর জন্য স্বয়ংক্রিয়ভাবে Risk Profile তৈরি"""
    if created:
        RiskProfile.objects.create(user=instance)
        print(f"[Signal] Risk Profile created for user: {instance.username}")


# ============================================
# Signal 2: সফল Login হলে Log করা (DISABLED)
# ============================================
# NOTE: LoginEvent is now created in the custom login view (views.py)
# This signal is disabled to avoid duplicate records
# The custom view has complete fraud detection logic

# @receiver(user_logged_in)
# def log_successful_login(sender, request, user, **kwargs):
#     """সফল লগইন হলে LoginEvent তৈরি করা"""
#     # DISABLED - LoginEvent created in custom login view
#     pass


# ============================================
# Signal 3: ব্যর্থ Login হলে Log করা (DISABLED)
# ============================================
# NOTE: Failed login attempts are handled in the custom login view
# This signal is disabled to avoid duplicate records

# @receiver(user_login_failed)
# def log_failed_login(sender, credentials, request, **kwargs):
#     """ব্যর্থ লগইন চেষ্টা রেকর্ড করা"""
#     # DISABLED - LoginEvent created in custom login view
#     pass


# ============================================
# Signal 4: Transaction হলে Risk Profile আপডেট
# ============================================
@receiver(post_save, sender=Transaction)
def update_risk_profile_on_transaction(sender, instance, created, **kwargs):
    """প্রতিটি নতুন Transaction এ User এর Risk Profile আপডেট করা"""
    if created:
        try:
            profile = instance.user.risk_profile
        except RiskProfile.DoesNotExist:
            profile = RiskProfile.objects.create(user=instance.user)
        
        # পরিসংখ্যান আপডেট
        profile.total_transactions += 1
        profile.total_amount += instance.amount
        
        # গড় Transaction পরিমাণ
        if profile.total_transactions > 0:
            profile.avg_transaction_amount = profile.total_amount / profile.total_transactions
        
        # সন্দেহজনক ইভেন্ট গণনা
        if instance.is_suspicious:
            profile.suspicious_events_count += 1
        
        # Risk Level পুনর্নির্ধারণ
        if profile.suspicious_events_count >= 5 or profile.overall_risk_score >= 70:
            profile.risk_level = 'high'
        elif profile.suspicious_events_count >= 2 or profile.overall_risk_score >= 40:
            profile.risk_level = 'medium'
        else:
            profile.risk_level = 'low'
        
        profile.save()
        print(f"[Signal] Risk Profile updated for: {instance.user.username}")