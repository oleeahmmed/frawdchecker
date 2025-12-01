from django.contrib import admin
from django.utils.html import format_html
from django.db.models import Count, Sum, Avg
from unfold.admin import ModelAdmin
from unfold.decorators import display
from .models import (
    Device, 
    LoginEvent, 
    Transaction, 
    FraudEvent, 
    RiskProfile, 
    IPBlocklist, 
    SystemLog
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
        'is_trusted', 'last_country_code', 'risk_score', 'last_seen_at'
    ]
    list_filter = ['status', 'is_trusted', 'is_blocked', 'last_country_code']
    search_fields = ['user__username', 'fingerprint_hash', 'last_ip']
    readonly_fields = ['fingerprint_hash', 'first_seen_at', 'last_seen_at']
    list_filter_submit = True
    list_fullwidth = True
    
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


@admin.register(IPBlocklist)
class IPBlocklistAdmin(ModelAdmin):
    list_display = ['id', 'ip_address', 'is_active', 'blocked_by', 'created_at', 'expires_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['ip_address', 'reason']
    readonly_fields = ['created_at']
    list_filter_submit = True
    list_fullwidth = True
    
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