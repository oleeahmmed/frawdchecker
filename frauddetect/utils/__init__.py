"""
📦 Utils Package
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

All utility functions are exported from here for easy import.

Usage:
    from frauddetect.utils import is_superuser_device, RiskProfileManager
"""

from .superuser_protection import (
    is_superuser_username,
    is_superuser_ip,
    is_superuser_device,
    protect_superuser_device,
    can_block_ip,
    can_block_device,
    get_superuser_protection_status,
    superuser_bypass,
)

from .risk_profile_manager import RiskProfileManager

__all__ = [
    # Superuser protection
    'is_superuser_username',
    'is_superuser_ip',
    'is_superuser_device',
    'protect_superuser_device',
    'can_block_ip',
    'can_block_device',
    'get_superuser_protection_status',
    'superuser_bypass',
    # Risk Profile
    'RiskProfileManager',
]
