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
# Signal 2: সফল Login হলে Log করা
# ============================================
@receiver(user_logged_in)
def log_successful_login(sender, request, user, **kwargs):
    """সফল লগইন হলে LoginEvent তৈরি করা"""
    ip = get_client_ip(request)
    geo = get_geo_location(ip)
    country_risk = get_country_risk_level(geo['country_code'])
    
    # সন্দেহজনক কিনা চেক
    is_suspicious = False
    risk_reasons = []
    risk_score = 0
    
    # অনুমোদিত নয় এমন দেশ থেকে লগইন
    if country_risk['level'] != 'low':
        is_suspicious = True
        risk_reasons.append(country_risk['reason'])
        risk_score += country_risk['score']
    
    # LoginEvent তৈরি
    LoginEvent.objects.create(
        user=user,
        username=user.username,
        status='success',
        ip_address=ip,
        country_code=geo['country_code'],
        city=geo['city'],
        is_suspicious=is_suspicious,
        risk_score=risk_score,
        risk_reasons=risk_reasons,
        user_agent=request.META.get('HTTP_USER_AGENT', '')
    )
    
    # System Log
    SystemLog.objects.create(
        log_type='login',
        level='warning' if is_suspicious else 'info',
        message=f"User {user.username} logged in from {ip} ({geo['city']}, {geo['country_code']})",
        user=user,
        ip_address=ip
    )
    
    print(f"[Signal] Login recorded for: {user.username}")


# ============================================
# Signal 3: ব্যর্থ Login হলে Log করা
# ============================================
@receiver(user_login_failed)
def log_failed_login(sender, credentials, request, **kwargs):
    """ব্যর্থ লগইন চেষ্টা রেকর্ড করা"""
    ip = get_client_ip(request)
    geo = get_geo_location(ip)
    username = credentials.get('username', 'Unknown')
    
    # LoginEvent তৈরি
    LoginEvent.objects.create(
        username=username,
        status='failed',
        ip_address=ip,
        country_code=geo['country_code'],
        city=geo['city'],
        is_suspicious=True,  # সব ব্যর্থ লগইন সন্দেহজনক
        risk_score=10,
        risk_reasons=['Failed login attempt'],
        user_agent=request.META.get('HTTP_USER_AGENT', '')
    )
    
    # System Log
    SystemLog.objects.create(
        log_type='security',
        level='warning',
        message=f"Failed login attempt for {username} from {ip}",
        ip_address=ip
    )
    
    print(f"[Signal] Failed login recorded for: {username}")


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