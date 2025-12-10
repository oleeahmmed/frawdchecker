"""
🔗 URLs Configuration - Authentication & Transactions
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Authentication এবং Transaction endpoints।
"""

from django.urls import path
from frauddetect.views import (
    LoginView,
    CustomTokenRefreshView,
    CurrentUserView,
    TransactionCreateView,
    TransactionListView,
    TransactionDetailView,
    TransactionStatsView,
)

app_name = 'frauddetect'

urlpatterns = [
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 🔐 AUTHENTICATION ENDPOINTS
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    
    # Login - Get JWT tokens (username OR email)
    path('auth/login/', LoginView.as_view(), name='login'),
    
    # Refresh token - Get new access token
    path('auth/token/refresh/', CustomTokenRefreshView.as_view(), name='token_refresh'),
    
    # Current user info
    path('auth/me/', CurrentUserView.as_view(), name='current_user'),
    
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # 💰 TRANSACTION ENDPOINTS
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    
    # Create transaction with fraud detection
    path('transactions/create/', TransactionCreateView.as_view(), name='transaction_create'),
    
    # List user transactions
    path('transactions/', TransactionListView.as_view(), name='transaction_list'),
    
    # Transaction details
    path('transactions/<int:transaction_id>/', TransactionDetailView.as_view(), name='transaction_detail'),
    
    # Transaction statistics
    path('transactions/stats/', TransactionStatsView.as_view(), name='transaction_stats'),
]
