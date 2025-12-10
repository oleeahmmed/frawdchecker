"""
📦 Utils Package
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

All utility functions are exported from here for easy import.

Usage:
    from frauddetect.utils import is_superuser_device, superuser_bypass
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

__all__ = [
    'is_superuser_username',
    'is_superuser_ip',
    'is_superuser_device',
    'protect_superuser_device',
    'can_block_ip',
    'can_block_device',
    'get_superuser_protection_status',
    'superuser_bypass',
]
