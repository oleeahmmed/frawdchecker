from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views

# Router তৈরি
router = DefaultRouter()
router.register(r'devices', views.DeviceViewSet, basename='device')
router.register(r'login-events', views.LoginEventViewSet, basename='loginevent')
router.register(r'transactions', views.TransactionViewSet, basename='transaction')
router.register(r'fraud-events', views.FraudEventViewSet, basename='fraudevent')
router.register(r'risk-profiles', views.RiskProfileViewSet, basename='riskprofile')
router.register(r'system-logs', views.SystemLogViewSet, basename='systemlog')
router.register(r'ip-blocklist', views.IPBlocklistViewSet, basename='ipblocklist')

urlpatterns = [
    # Custom JWT Authentication with Device Tracking
    path('auth/login/', views.CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('auth/token/refresh/', views.CustomTokenRefreshView.as_view(), name='token_refresh'),
    
    # API Endpoints
    path('', include(router.urls)),
    path('dashboard/', views.DashboardView.as_view(), name='dashboard'),
]