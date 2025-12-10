"""
📦 Views Package
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

All views are exported from here for easy import.

Usage:
    from frauddetect.views import LoginView, TransactionCreateView
"""

from .auth_views import (
    LoginView,
    CustomTokenRefreshView,
    CurrentUserView,
)

from .transaction_views import (
    TransactionCreateView,
    TransactionListView,
    TransactionDetailView,
    TransactionStatsView,
)

__all__ = [
    # Auth
    'LoginView',
    'CustomTokenRefreshView',
    'CurrentUserView',
    
    # Transaction
    'TransactionCreateView',
    'TransactionListView',
    'TransactionDetailView',
    'TransactionStatsView',
]
