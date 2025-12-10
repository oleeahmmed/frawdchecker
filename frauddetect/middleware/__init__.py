"""
📦 Middleware Package
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

All middleware are exported from here for easy import.

Usage:
    from frauddetect.middleware import LoginSecurityMiddleware
    from frauddetect.middleware import check_transaction_fraud
"""

from .login_middleware import (
    LoginSecurityMiddleware,
    get_client_ip,
    get_geo_location,
    is_ip_blocked,
    is_ip_whitelisted,
    get_allowed_countries,
    create_login_event,
    create_system_log,
    auto_block_ip,
)

from .transaction_middleware import (
    check_transaction_fraud,
    get_client_ip as get_txn_client_ip,
    get_geo_location as get_txn_geo_location,
    get_user_device,
)

__all__ = [
    # Login Middleware
    'LoginSecurityMiddleware',
    'get_client_ip',
    'get_geo_location',
    'is_ip_blocked',
    'is_ip_whitelisted',
    'get_allowed_countries',
    'create_login_event',
    'create_system_log',
    'auto_block_ip',
    
    # Transaction Middleware
    'check_transaction_fraud',
    'get_txn_client_ip',
    'get_txn_geo_location',
    'get_user_device',
]
