"""
📊 Risk Profile Manager - Professional Risk Assessment
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Real-time + Batch hybrid risk profile management.

Features:
✅ Real-time updates on login/transaction
✅ Behavioral pattern learning
✅ Risk decay over time
✅ Anomaly detection
"""

from django.utils import timezone
from django.db.models import Avg, Count, Sum
from datetime import timedelta
from collections import Counter


class RiskProfileManager:
    """
    📊 Professional Risk Profile Manager
    
    Handles all risk profile updates with:
    - Real-time event processing
    - Behavioral pattern analysis
    - Risk score calculation
    - Risk decay mechanism
    """
    
    # Risk weights
    WEIGHTS = {
        'failed_login': 5,
        'blocked_login': 15,
        'blocked_transaction': 20,
        'flagged_transaction': 10,
        'suspicious_event': 10,
        'new_device': 10,
        'new_country': 20,
        'unusual_hour': 10,
        'high_amount_txn': 15,
        'velocity_spike': 10,
        'trusted_device_bonus': -5,
        'good_transaction_bonus': -0.5,
        'time_decay_weekly': -5,
        'time_decay_monthly': -10,
    }
    
    # Risk level thresholds
    THRESHOLDS = {
        'low': 20,
        'medium': 40,
        'high': 70,
        'critical': 100,
    }
    
    def __init__(self, user):
        self.user = user
        self.profile = self._get_or_create_profile()
    
    def _get_or_create_profile(self):
        """Get or create risk profile for user"""
        from frauddetect.models import RiskProfile
        
        profile, created = RiskProfile.objects.get_or_create(
            user=self.user,
            defaults={
                'overall_risk_score': 0,
                'risk_level': 'low',
                'usual_login_hours': [],
                'usual_countries': [],
            }
        )
        if created:
            print(f"✅ Created RiskProfile for {self.user.username}")
        return profile
    
    # ═══════════════════════════════════════════════════════════════════════
    # LOGIN EVENT HANDLERS
    # ═══════════════════════════════════════════════════════════════════════
    
    def on_login_success(self, ip_address, country_code, city, device=None):
        """
        Handle successful login - update patterns and reduce risk
        """
        current_hour = timezone.now().hour
        
        # Update login hour pattern
        self._update_login_hours(current_hour)
        
        # Update country pattern
        is_new_country = self._update_countries(country_code)
        
        # Check if unusual hour
        is_unusual_hour = self._is_unusual_hour(current_hour)
        
        # Update trusted devices count
        if device and device.is_trusted:
            self._update_trusted_devices_count()
        
        # Calculate risk adjustments
        risk_change = 0
        reasons = []
        
        if is_new_country:
            risk_change += self.WEIGHTS['new_country']
            reasons.append(f"New country: {country_code}")
        
        if is_unusual_hour:
            risk_change += self.WEIGHTS['unusual_hour']
            reasons.append(f"Unusual login hour: {current_hour}:00")
        
        if device and device.is_trusted:
            risk_change += self.WEIGHTS['trusted_device_bonus']
            reasons.append("Trusted device bonus")
        
        # Good login reduces risk slightly
        if not is_new_country and not is_unusual_hour:
            risk_change -= 2
            reasons.append("Normal login pattern")
        
        # Apply changes
        self._adjust_risk_score(risk_change)
        self.profile.save()
        
        print(f"📊 Login Success - {self.user.username}: risk_change={risk_change}, reasons={reasons}")
        
        return {
            'risk_change': risk_change,
            'reasons': reasons,
            'new_risk_score': self.profile.overall_risk_score,
            'risk_level': self.profile.risk_level,
        }
    
    def on_login_failed(self, ip_address, country_code):
        """
        Handle failed login - increase risk
        """
        self.profile.failed_login_count += 1
        
        risk_change = self.WEIGHTS['failed_login']
        reasons = [f"Failed login attempt #{self.profile.failed_login_count}"]
        
        # Extra penalty for multiple failures
        if self.profile.failed_login_count >= 3:
            risk_change += 5
            reasons.append("Multiple failed attempts")
        
        self._adjust_risk_score(risk_change)
        self.profile.save()
        
        print(f"📊 Login Failed - {self.user.username}: risk_change=+{risk_change}")
        
        return {
            'risk_change': risk_change,
            'reasons': reasons,
            'new_risk_score': self.profile.overall_risk_score,
        }
    
    def on_login_blocked(self, reason, ip_address, country_code):
        """
        Handle blocked login - significant risk increase
        """
        self.profile.suspicious_events_count += 1
        
        risk_change = self.WEIGHTS['blocked_login']
        reasons = [f"Login blocked: {reason}"]
        
        self._adjust_risk_score(risk_change)
        self.profile.save()
        
        print(f"📊 Login Blocked - {self.user.username}: risk_change=+{risk_change}")
        
        return {
            'risk_change': risk_change,
            'reasons': reasons,
            'new_risk_score': self.profile.overall_risk_score,
        }
    
    # ═══════════════════════════════════════════════════════════════════════
    # TRANSACTION EVENT HANDLERS
    # ═══════════════════════════════════════════════════════════════════════
    
    def on_transaction_approved(self, amount, transaction_type):
        """
        Handle approved transaction - update stats and reduce risk
        """
        self.profile.total_transactions += 1
        self.profile.total_amount += amount
        
        # Update average
        self.profile.avg_transaction_amount = (
            self.profile.total_amount / self.profile.total_transactions
        )
        
        risk_change = 0
        reasons = []
        
        # Good transaction bonus
        risk_change += self.WEIGHTS['good_transaction_bonus']
        reasons.append("Approved transaction bonus")
        
        # Check if amount is unusually high
        if self.profile.total_transactions > 5:
            avg = float(self.profile.avg_transaction_amount)
            if avg > 0 and float(amount) > avg * 3:
                risk_change += self.WEIGHTS['high_amount_txn']
                reasons.append(f"Amount {amount} is 3x above average {avg:.2f}")
        
        self._adjust_risk_score(risk_change)
        self.profile.save()
        
        print(f"📊 Txn Approved - {self.user.username}: amount={amount}, risk_change={risk_change}")
        
        return {
            'risk_change': risk_change,
            'reasons': reasons,
            'new_risk_score': self.profile.overall_risk_score,
        }
    
    def on_transaction_flagged(self, amount, risk_reasons):
        """
        Handle flagged transaction - moderate risk increase
        """
        self.profile.total_transactions += 1
        self.profile.total_amount += amount
        self.profile.suspicious_events_count += 1
        
        # Update average
        if self.profile.total_transactions > 0:
            self.profile.avg_transaction_amount = (
                self.profile.total_amount / self.profile.total_transactions
            )
        
        risk_change = self.WEIGHTS['flagged_transaction']
        reasons = [f"Transaction flagged: {', '.join(risk_reasons[:3])}"]
        
        self._adjust_risk_score(risk_change)
        self.profile.save()
        
        print(f"📊 Txn Flagged - {self.user.username}: risk_change=+{risk_change}")
        
        return {
            'risk_change': risk_change,
            'reasons': reasons,
            'new_risk_score': self.profile.overall_risk_score,
        }
    
    def on_transaction_blocked(self, amount, block_reason):
        """
        Handle blocked transaction - significant risk increase
        """
        self.profile.suspicious_events_count += 1
        
        risk_change = self.WEIGHTS['blocked_transaction']
        reasons = [f"Transaction blocked: {block_reason}"]
        
        self._adjust_risk_score(risk_change)
        self.profile.save()
        
        print(f"📊 Txn Blocked - {self.user.username}: risk_change=+{risk_change}")
        
        return {
            'risk_change': risk_change,
            'reasons': reasons,
            'new_risk_score': self.profile.overall_risk_score,
        }
    
    # ═══════════════════════════════════════════════════════════════════════
    # BEHAVIORAL PATTERN ANALYSIS
    # ═══════════════════════════════════════════════════════════════════════
    
    def _update_login_hours(self, hour):
        """Update usual login hours pattern"""
        hours = self.profile.usual_login_hours or []
        hours.append(hour)
        
        # Keep last 100 login hours
        if len(hours) > 100:
            hours = hours[-100:]
        
        self.profile.usual_login_hours = hours
    
    def _update_countries(self, country_code):
        """Update usual countries and return if new"""
        countries = self.profile.usual_countries or []
        is_new = country_code not in countries
        
        if is_new and country_code not in ['LOCAL', 'Unknown']:
            countries.append(country_code)
        
        self.profile.usual_countries = countries
        return is_new and country_code not in ['LOCAL', 'Unknown']
    
    def _is_unusual_hour(self, hour):
        """Check if login hour is unusual based on pattern"""
        hours = self.profile.usual_login_hours or []
        
        if len(hours) < 10:
            # Not enough data, consider normal
            return False
        
        # Find most common hours
        hour_counts = Counter(hours)
        common_hours = [h for h, c in hour_counts.most_common(8)]
        
        # Check if current hour is in common hours (with 2-hour tolerance)
        for common_hour in common_hours:
            if abs(hour - common_hour) <= 2 or abs(hour - common_hour) >= 22:
                return False
        
        return True
    
    def _update_trusted_devices_count(self):
        """Update count of trusted devices"""
        from frauddetect.models import Device
        
        count = Device.objects.filter(
            user=self.user,
            is_trusted=True,
            is_blocked=False
        ).count()
        
        self.profile.trusted_devices_count = count
    
    # ═══════════════════════════════════════════════════════════════════════
    # RISK SCORE MANAGEMENT
    # ═══════════════════════════════════════════════════════════════════════
    
    def _adjust_risk_score(self, change):
        """Adjust risk score and update level"""
        new_score = self.profile.overall_risk_score + change
        
        # Clamp between 0 and 100
        new_score = max(0, min(100, new_score))
        
        self.profile.overall_risk_score = int(new_score)
        self.profile.risk_level = self._calculate_risk_level(new_score)
    
    def _calculate_risk_level(self, score):
        """Calculate risk level from score"""
        if score >= self.THRESHOLDS['high']:
            return 'high'
        elif score >= self.THRESHOLDS['medium']:
            return 'medium'
        else:
            return 'low'
    
    def apply_time_decay(self):
        """
        Apply time-based risk decay
        Call this periodically (daily cron job)
        """
        from frauddetect.models import LoginEvent, Transaction
        
        now = timezone.now()
        
        # Check last suspicious event
        last_suspicious_login = LoginEvent.objects.filter(
            user=self.user,
            is_suspicious=True
        ).order_by('-attempt_time').first()
        
        last_suspicious_txn = Transaction.objects.filter(
            user=self.user,
            is_suspicious=True
        ).order_by('-created_at').first()
        
        # Get most recent suspicious event
        last_suspicious = None
        if last_suspicious_login:
            last_suspicious = last_suspicious_login.attempt_time
        if last_suspicious_txn:
            if not last_suspicious or last_suspicious_txn.created_at > last_suspicious:
                last_suspicious = last_suspicious_txn.created_at
        
        if not last_suspicious:
            # No suspicious events ever - apply maximum decay
            days_clean = 30
        else:
            days_clean = (now - last_suspicious).days
        
        decay = 0
        reasons = []
        
        if days_clean >= 30:
            decay = self.WEIGHTS['time_decay_monthly']
            reasons.append(f"30+ days without issues")
        elif days_clean >= 7:
            decay = self.WEIGHTS['time_decay_weekly']
            reasons.append(f"{days_clean} days without issues")
        
        if decay < 0:
            self._adjust_risk_score(decay)
            self.profile.save()
            print(f"📊 Time Decay - {self.user.username}: decay={decay}, reasons={reasons}")
        
        return {
            'decay': decay,
            'reasons': reasons,
            'days_clean': days_clean,
            'new_risk_score': self.profile.overall_risk_score,
        }
    
    def recalculate_full_profile(self):
        """
        Full recalculation of risk profile
        Call this for batch updates or corrections
        """
        from frauddetect.models import LoginEvent, Transaction, Device
        
        # Reset counters
        self.profile.failed_login_count = LoginEvent.objects.filter(
            user=self.user,
            status='failed'
        ).count()
        
        self.profile.suspicious_events_count = (
            LoginEvent.objects.filter(user=self.user, is_suspicious=True).count() +
            Transaction.objects.filter(user=self.user, is_suspicious=True).count()
        )
        
        # Transaction stats
        txn_stats = Transaction.objects.filter(
            user=self.user,
            status='approved'
        ).aggregate(
            total=Count('id'),
            amount=Sum('amount'),
            avg=Avg('amount')
        )
        
        self.profile.total_transactions = txn_stats['total'] or 0
        self.profile.total_amount = txn_stats['amount'] or 0
        self.profile.avg_transaction_amount = txn_stats['avg'] or 0
        
        # Device count
        self.profile.trusted_devices_count = Device.objects.filter(
            user=self.user,
            is_trusted=True,
            is_blocked=False
        ).count()
        
        # Recalculate risk score
        risk_score = (
            (self.profile.failed_login_count * self.WEIGHTS['failed_login']) +
            (self.profile.suspicious_events_count * self.WEIGHTS['suspicious_event']) -
            (self.profile.trusted_devices_count * abs(self.WEIGHTS['trusted_device_bonus'])) -
            (self.profile.total_transactions * abs(self.WEIGHTS['good_transaction_bonus']))
        )
        
        risk_score = max(0, min(100, risk_score))
        self.profile.overall_risk_score = int(risk_score)
        self.profile.risk_level = self._calculate_risk_level(risk_score)
        
        self.profile.save()
        
        print(f"📊 Full Recalc - {self.user.username}: score={risk_score}, level={self.profile.risk_level}")
        
        return {
            'risk_score': self.profile.overall_risk_score,
            'risk_level': self.profile.risk_level,
            'failed_logins': self.profile.failed_login_count,
            'suspicious_events': self.profile.suspicious_events_count,
            'total_transactions': self.profile.total_transactions,
            'trusted_devices': self.profile.trusted_devices_count,
        }
    
    def get_profile_summary(self):
        """Get current profile summary"""
        return {
            'user': self.user.username,
            'risk_score': self.profile.overall_risk_score,
            'risk_level': self.profile.risk_level,
            'failed_login_count': self.profile.failed_login_count,
            'suspicious_events_count': self.profile.suspicious_events_count,
            'total_transactions': self.profile.total_transactions,
            'total_amount': float(self.profile.total_amount),
            'avg_transaction_amount': float(self.profile.avg_transaction_amount),
            'trusted_devices_count': self.profile.trusted_devices_count,
            'usual_countries': self.profile.usual_countries,
            'is_monitored': self.profile.is_monitored,
            'is_blocked': self.profile.is_blocked,
        }
