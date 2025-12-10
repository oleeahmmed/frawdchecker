"""
📦 API Package
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

API URL configuration.

Usage in config/urls.py:
    from frauddetect.api import urlpatterns as frauddetect_urls
    
    urlpatterns = [
        path('api/', include(frauddetect_urls)),
    ]
"""

from .urls import urlpatterns

__all__ = ['urlpatterns']
