from django.apps import AppConfig


class FrauddetectConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'frauddetect'
    
    def ready(self):
        # Signals import করা
        import frauddetect.signals
        print("[App] Fraud Detection signals loaded!")