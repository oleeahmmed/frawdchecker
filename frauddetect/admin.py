from django.contrib import admin
from django.utils.html import format_html
from django.db.models import Count, Sum, Avg
from unfold.admin import ModelAdmin
from unfold.decorators import display
from frauddetect.models import (
    Device, 
    LoginEvent, 
    Transaction, 
    FraudEvent, 
    RiskProfile,
    IPWhitelist,
    IPBlocklist, 
    SystemLog,
    FraudConfig
)


# ============================================
# 📊 DASHBOARD CALLBACKS
# ============================================
def dashboard_callback(request, context):
    """Dashboard statistics"""
    context.update({
        "navigation": [
            {"title": "Dashboard", "link": "/admin/", "active": True},
        ]
    })
    return context


def environment_callback(request):
    """Environment badge"""
    return ["Development", "warning"]  # or "success", "info", "danger"


@admin.register(Device)
class DeviceAdmin(ModelAdmin):
    list_display = [
        'id', 'user', 'device_name', 'status_badge', 
        'trust_badge', 'whitelist_badge', 'block_badge', 'last_country_code', 'risk_score', 'last_seen_at'
    ]
    list_filter = ['status', 'is_trusted', 'is_blocked', 'is_whitelisted', 'last_country_code']
    search_fields = ['user__username', 'fingerprint_hash', 'last_ip']
    readonly_fields = ['fingerprint_hash', 'first_seen_at', 'last_seen_at', 'whitelisted_at']
    list_filter_submit = True
    list_fullwidth = True
    actions = ['trust_devices', 'untrust_devices', 'block_devices', 'unblock_devices', 'whitelist_devices', 'unwhitelist_devices']
    
    fieldsets = (
        ('Device Information', {
            'fields': ('user', 'fingerprint_hash', 'device_fingerprint')
        }),
        ('Device Details', {
            'fields': ('device_type', 'device_name', 'os_name', 'os_version', 'browser_name', 'browser_version')
        }),
        ('Location', {
            'fields': ('last_ip', 'last_country_code', 'last_city')
        }),
        ('Security Status', {
            'fields': ('status', 'is_trusted', 'is_blocked', 'risk_score')
        }),
        ('Whitelist Status', {
            'fields': ('is_whitelisted', 'whitelisted_at', 'whitelisted_by', 'whitelist_reason')
        }),
        ('Timestamps', {
            'fields': ('first_seen_at', 'last_seen_at')
        }),
    )
    
    @display(description='Status', label=True)
    def status_badge(self, obj):
        colors = {
            'normal': 'success',
            'suspicious': 'warning',
            'blocked': 'danger'
        }
        return colors.get(obj.status, 'info'), obj.status.upper()
    
    @display(description='Trusted', label=True)
    def trust_badge(self, obj):
        if obj.is_trusted:
            return 'success', '✅ TRUSTED'
        return 'warning', '⚠️ NOT TRUSTED'
    
    @display(description='Whitelisted', label=True)
    def whitelist_badge(self, obj):
        if obj.is_whitelisted:
            return 'success', '⭐ WHITELISTED'
        return 'secondary', '—'
    
    @display(description='Blocked', label=True)
    def block_badge(self, obj):
        if obj.is_blocked:
            return 'danger', '🚫 BLOCKED'
        return 'success', '✅ ACTIVE'
    
    @admin.action(description='✅ Trust selected devices')
    def trust_devices(self, request, queryset):
        """Trust selected devices"""
        count = queryset.update(is_trusted=True, status='normal')
        self.message_user(request, f'✅ {count} device(s) marked as TRUSTED')
    
    @admin.action(description='⚠️ Untrust selected devices')
    def untrust_devices(self, request, queryset):
        """Untrust selected devices"""
        count = queryset.update(is_trusted=False)
        self.message_user(request, f'⚠️ {count} device(s) marked as NOT TRUSTED')
    
    @admin.action(description='🚫 Block selected devices')
    def block_devices(self, request, queryset):
        """Block selected devices"""
        from frauddetect.utils import can_block_device
        
        blocked_count = 0
        protected_count = 0
        
        for device in queryset:
            can_block, reason = can_block_device(device)
            
            if can_block:
                device.is_blocked = True
                device.status = 'blocked'
                device.save()
                blocked_count += 1
                
                # Log the action
                SystemLog.objects.create(
                    log_type='security',
                    level='warning',
                    message=f'Device {device.id} blocked by admin {request.user.username}',
                    user=device.user,
                    ip_address=device.last_ip,
                    metadata={'device_id': device.id, 'admin': request.user.username}
                )
            else:
                protected_count += 1
                self.message_user(
                    request, 
                    f'⚠️ Cannot block device {device.id}: {reason}',
                    level='warning'
                )
        
        if blocked_count > 0:
            self.message_user(request, f'🚫 {blocked_count} device(s) BLOCKED')
        if protected_count > 0:
            self.message_user(
                request, 
                f'👑 {protected_count} superuser device(s) protected from blocking',
                level='warning'
            )
    
    @admin.action(description='✅ Unblock selected devices')
    def unblock_devices(self, request, queryset):
        """Unblock selected devices"""
        count = queryset.update(is_blocked=False, status='normal')
        
        # Log the action
        for device in queryset:
            SystemLog.objects.create(
                log_type='security',
                level='info',
                message=f'Device {device.id} unblocked by admin {request.user.username}',
                user=device.user,
                ip_address=device.last_ip,
                metadata={'device_id': device.id, 'admin': request.user.username}
            )
        
        self.message_user(request, f'✅ {count} device(s) UNBLOCKED')
    
    @admin.action(description='⭐ Whitelist selected devices')
    def whitelist_devices(self, request, queryset):
        """Whitelist selected devices (bypass all fraud checks)"""
        from django.utils import timezone
        
        count = 0
        for device in queryset:
            device.is_whitelisted = True
            device.whitelisted_at = timezone.now()
            device.whitelisted_by = request.user
            device.whitelist_reason = f'Whitelisted by admin {request.user.username}'
            device.save()
            count += 1
            
            # Log the action
            SystemLog.objects.create(
                log_type='security',
                level='info',
                message=f'Device {device.id} whitelisted by admin {request.user.username}',
                user=device.user,
                ip_address=device.last_ip,
                metadata={'device_id': device.id, 'admin': request.user.username}
            )
        
        self.message_user(request, f'⭐ {count} device(s) WHITELISTED')
    
    @admin.action(description='❌ Remove whitelist from selected devices')
    def unwhitelist_devices(self, request, queryset):
        """Remove whitelist from selected devices"""
        count = queryset.update(
            is_whitelisted=False,
            whitelisted_at=None,
            whitelisted_by=None,
            whitelist_reason=''
        )
        
        # Log the action
        for device in queryset:
            SystemLog.objects.create(
                log_type='security',
                level='info',
                message=f'Device {device.id} whitelist removed by admin {request.user.username}',
                user=device.user,
                ip_address=device.last_ip,
                metadata={'device_id': device.id, 'admin': request.user.username}
            )
        
        self.message_user(request, f'❌ {count} device(s) whitelist REMOVED')


@admin.register(LoginEvent)
class LoginEventAdmin(ModelAdmin):
    list_display = [
        'id', 'username', 'status_badge', 'is_suspicious', 
        'ip_address', 'country_code', 'risk_score', 'attempt_time'
    ]
    list_filter = ['status', 'is_suspicious', 'country_code', 'attempt_time']
    search_fields = ['username', 'ip_address']
    readonly_fields = ['attempt_time']
    list_filter_submit = True
    list_fullwidth = True
    
    fieldsets = (
        ('Login Details', {
            'fields': ('user', 'username', 'device', 'status')
        }),
        ('Location', {
            'fields': ('ip_address', 'country_code', 'city')
        }),
        ('Risk Assessment', {
            'fields': ('is_suspicious', 'risk_score', 'risk_reasons')
        }),
        ('Additional Info', {
            'fields': ('user_agent', 'attempt_time'),
            'classes': ('collapse',)
        }),
    )
    
    @display(description='Status', label=True)
    def status_badge(self, obj):
        colors = {
            'success': 'success',
            'failed': 'danger',
            'blocked': 'danger'
        }
        return colors.get(obj.status, 'info'), obj.status.upper()


@admin.register(Transaction)
class TransactionAdmin(ModelAdmin):
    list_display = [
        'id', 'external_txn_id', 'user', 'amount_display', 
        'status_badge', 'risk_badge', 'is_suspicious', 'created_at'
    ]
    list_filter = ['status', 'risk_level', 'is_suspicious', 'created_at', 'currency']
    search_fields = ['external_txn_id', 'user__username', 'beneficiary']
    readonly_fields = ['created_at', 'updated_at', 'risk_score', 'risk_level']
    list_filter_submit = True
    list_fullwidth = True
    
    fieldsets = (
        ('Transaction Details', {
            'fields': ('user', 'device', 'external_txn_id', 'amount', 'currency', 'beneficiary', 'description')
        }),
        ('Status', {
            'fields': ('status', 'approved_at')
        }),
        ('Risk Assessment', {
            'fields': ('risk_score', 'risk_level', 'is_suspicious')
        }),
        ('Metadata', {
            'fields': ('raw_payload', 'ip_address', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    @display(description='Amount')
    def amount_display(self, obj):
        return f"{obj.amount} {obj.currency}"
    
    @display(description='Status', label=True)
    def status_badge(self, obj):
        colors = {
            'pending': 'info',
            'approved': 'success',
            'rejected': 'danger',
            'flagged': 'warning'
        }
        return colors.get(obj.status, 'info'), obj.status.upper()
    
    @display(description='Risk', label=True)
    def risk_badge(self, obj):
        colors = {
            'low': 'success',
            'medium': 'warning',
            'high': 'danger'
        }
        return colors.get(obj.risk_level, 'info'), f"{obj.risk_level.upper()} ({obj.risk_score})"


@admin.register(FraudEvent)
class FraudEventAdmin(ModelAdmin):
    list_display = [
        'id', 'user', 'severity_badge', 'risk_score', 
        'is_resolved', 'detected_at'
    ]
    list_filter = ['severity', 'is_resolved', 'detected_at']
    search_fields = ['user__username', 'description']
    readonly_fields = ['detected_at', 'resolved_at']
    list_filter_submit = True
    list_fullwidth = True
    
    fieldsets = (
        ('Fraud Details', {
            'fields': ('transaction', 'user', 'rule_id', 'triggered_rules')
        }),
        ('Risk Assessment', {
            'fields': ('risk_score', 'severity', 'description', 'recommendations')
        }),
        ('Resolution', {
            'fields': ('is_resolved', 'resolved_by', 'resolution_notes')
        }),
        ('Timestamps', {
            'fields': ('detected_at', 'resolved_at')
        }),
    )
    
    @display(description='Severity', label=True)
    def severity_badge(self, obj):
        colors = {
            'low': 'info',
            'medium': 'warning',
            'high': 'danger',
            'critical': 'danger'
        }
        return colors.get(obj.severity, 'info'), obj.severity.upper()


@admin.register(RiskProfile)
class RiskProfileAdmin(ModelAdmin):
    list_display = [
        'id', 'user', 'risk_badge', 'overall_risk_score', 
        'total_transactions', 'suspicious_events_count', 
        'is_monitored', 'is_blocked'
    ]
    list_filter = ['risk_level', 'is_monitored', 'is_blocked']
    search_fields = ['user__username']
    readonly_fields = ['updated_at']
    list_filter_submit = True
    list_fullwidth = True
    
    fieldsets = (
        ('User', {
            'fields': ('user',)
        }),
        ('Risk Assessment', {
            'fields': ('overall_risk_score', 'risk_level')
        }),
        ('Statistics', {
            'fields': ('total_transactions', 'total_amount', 'suspicious_events_count', 'failed_login_count', 'avg_transaction_amount')
        }),
        ('Behavioral Patterns', {
            'fields': ('usual_login_hours', 'usual_countries', 'trusted_devices_count')
        }),
        ('Status', {
            'fields': ('is_monitored', 'is_blocked', 'last_reviewed_at')
        }),
        ('Timestamps', {
            'fields': ('updated_at',)
        }),
    )
    
    @display(description='Risk Level', label=True)
    def risk_badge(self, obj):
        colors = {
            'low': 'success',
            'medium': 'warning',
            'high': 'danger'
        }
        return colors.get(obj.risk_level, 'info'), obj.risk_level.upper()


@admin.register(IPWhitelist)
class IPWhitelistAdmin(ModelAdmin):
    """
    ✅ IP Whitelist Admin
    Whitelisted IPs bypass all fraud checks
    """
    list_display = ['id', 'ip_address', 'status_badge', 'description', 'added_by', 'added_at', 'expires_at', 'last_used_at']
    list_filter = ['is_active', 'added_at', 'expires_at']
    search_fields = ['ip_address', 'description']
    readonly_fields = ['added_at', 'last_used_at']
    list_filter_submit = True
    list_fullwidth = True
    actions = ['activate_whitelist', 'deactivate_whitelist']
    
    fieldsets = (
        ('IP Information', {
            'fields': ('ip_address', 'description')
        }),
        ('Whitelist Details', {
            'fields': ('added_by', 'is_active', 'expires_at')
        }),
        ('Timestamps', {
            'fields': ('added_at', 'last_used_at')
        }),
    )
    
    @display(description='Status', label=True)
    def status_badge(self, obj):
        if obj.is_expired():
            return 'warning', '⏰ EXPIRED'
        if obj.is_active:
            return 'success', '✅ ACTIVE'
        return 'secondary', '❌ INACTIVE'
    
    @admin.action(description='✅ Activate selected IP whitelist')
    def activate_whitelist(self, request, queryset):
        """Activate IP whitelist"""
        count = queryset.update(is_active=True)
        self.message_user(request, f'✅ {count} IP(s) WHITELISTED')
    
    @admin.action(description='❌ Deactivate selected IP whitelist')
    def deactivate_whitelist(self, request, queryset):
        """Deactivate IP whitelist"""
        count = queryset.update(is_active=False)
        self.message_user(request, f'❌ {count} IP whitelist(s) DEACTIVATED')
    
    def save_model(self, request, obj, form, change):
        """Save added_by"""
        if not change:
            obj.added_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(IPBlocklist)
class IPBlocklistAdmin(ModelAdmin):
    list_display = ['id', 'ip_address', 'status_badge', 'blocked_by', 'created_at', 'expires_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['ip_address', 'reason']
    readonly_fields = ['created_at']
    list_filter_submit = True
    list_fullwidth = True
    actions = ['activate_blocks', 'deactivate_blocks']
    
    fieldsets = (
        ('IP Information', {
            'fields': ('ip_address', 'reason')
        }),
        ('Block Details', {
            'fields': ('blocked_by', 'is_active', 'expires_at')
        }),
        ('Timestamps', {
            'fields': ('created_at',)
        }),
    )
    
    @display(description='Status', label=True)
    def status_badge(self, obj):
        if obj.is_active:
            return 'danger', '🚫 BLOCKED'
        return 'success', '✅ INACTIVE'
    
    @admin.action(description='🚫 Activate selected IP blocks')
    def activate_blocks(self, request, queryset):
        """Activate IP blocks"""
        from frauddetect.utils import can_block_ip
        
        blocked_count = 0
        protected_count = 0
        
        for ip_block in queryset:
            can_block, reason = can_block_ip(ip_block.ip_address)
            
            if can_block:
                ip_block.is_active = True
                ip_block.save()
                blocked_count += 1
            else:
                protected_count += 1
                self.message_user(
                    request,
                    f'⚠️ Cannot block IP {ip_block.ip_address}: {reason}',
                    level='warning'
                )
        
        if blocked_count > 0:
            self.message_user(request, f'🚫 {blocked_count} IP(s) BLOCKED')
        if protected_count > 0:
            self.message_user(
                request,
                f'👑 {protected_count} superuser IP(s) protected from blocking',
                level='warning'
            )
    
    @admin.action(description='✅ Deactivate selected IP blocks')
    def deactivate_blocks(self, request, queryset):
        """Deactivate IP blocks"""
        count = queryset.update(is_active=False)
        self.message_user(request, f'✅ {count} IP block(s) DEACTIVATED')


@admin.register(SystemLog)
class SystemLogAdmin(ModelAdmin):
    list_display = ['id', 'log_type', 'level_badge', 'short_message', 'user', 'created_at']
    list_filter = ['log_type', 'level', 'created_at']
    search_fields = ['message', 'user__username']
    readonly_fields = ['created_at']
    list_filter_submit = True
    list_fullwidth = True
    
    fieldsets = (
        ('Log Details', {
            'fields': ('log_type', 'level', 'message')
        }),
        ('Context', {
            'fields': ('user', 'ip_address', 'metadata')
        }),
        ('Timestamp', {
            'fields': ('created_at',)
        }),
    )
    
    @display(description='Level', label=True)
    def level_badge(self, obj):
        colors = {
            'info': 'info',
            'warning': 'warning',
            'error': 'danger',
            'critical': 'danger'
        }
        return colors.get(obj.level, 'info'), obj.level.upper()
    
    @display(description='Message')
    def short_message(self, obj):
        return obj.message[:50] + '...' if len(obj.message) > 50 else obj.message


@admin.register(FraudConfig)
class FraudConfigAdmin(ModelAdmin):
    """
    ⚙️ Fraud Configuration Admin
    Admin panel থেকে সহজে fraud detection settings পরিবর্তন করা যাবে
    """
    list_display = [
        'id', 'name', 'is_active_badge', 'geo_restriction_enabled', 
        'require_trusted_device', 'updated_at', 'updated_by'
    ]
    list_filter = ['is_active', 'geo_restriction_enabled', 'require_trusted_device', 'updated_at']
    search_fields = ['name', 'description']
    readonly_fields = ['created_at', 'updated_at', 'created_by', 'updated_by']
    list_filter_submit = True
    list_fullwidth = True
    
    fieldsets = (
        ('Configuration Info', {
            'fields': ('name', 'description', 'is_active')
        }),
        ('🌍 Geo-Restriction Settings', {
            'fields': (
                'geo_restriction_enabled',
                'allowed_countries',
                'auto_block_non_allowed_ips',
                'auto_trust_devices_from_allowed_countries',
                'auto_block_devices_from_blocked_countries'
            ),
            'description': 'Geographic access control settings'
        }),
        ('🔐 Login Security Settings', {
            'fields': (
                'max_login_attempts',
                'login_attempt_window_minutes',
                'require_trusted_device'
            ),
            'description': 'Login attempt limits and device trust requirements'
        }),
        ('💰 Transaction Fraud Settings', {
            'fields': (
                'high_amount_threshold',
                'max_daily_transactions',
                'max_transaction_amount_daily',
                'max_transactions_per_hour'
            ),
            'description': 'Transaction limits and thresholds'
        }),
        ('🕐 Business Hours', {
            'fields': (
                'business_hours_start',
                'business_hours_end',
                'flag_outside_business_hours'
            ),
            'description': 'Business hours configuration'
        }),
        ('📊 Risk Scoring', {
            'fields': (
                'risk_score_threshold_low',
                'risk_score_threshold_medium',
                'risk_score_threshold_high'
            ),
            'description': 'Risk score thresholds for classification'
        }),
        ('📝 Metadata', {
            'fields': ('created_at', 'updated_at', 'created_by', 'updated_by'),
            'classes': ('collapse',)
        }),
    )
    
    @display(description='Status', label=True)
    def is_active_badge(self, obj):
        if obj.is_active:
            return 'success', '✅ ACTIVE'
        return 'secondary', '⚪ Inactive'
    
    def save_model(self, request, obj, form, change):
        """Save created_by and updated_by"""
        if not change:
            obj.created_by = request.user
        obj.updated_by = request.user
        super().save_model(request, obj, form, change)
    
    def get_readonly_fields(self, request, obj=None):
        """Make created_by readonly after creation"""
        if obj:  # Editing existing object
            return self.readonly_fields
        return ['created_at', 'updated_at', 'updated_by']  # Creating new object