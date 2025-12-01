#!/usr/bin/env python
"""
Simple test to verify login blocking and record creation
"""

import os
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from django.contrib.auth.models import User
from frauddetect.models import LoginEvent, IPBlocklist, Device
from frauddetect.utils import get_client_ip, get_geo_location
from django.test import RequestFactory
from frauddetect.views import CustomTokenObtainPairSerializer

def test_login():
    print("\n" + "="*70)
    print("  TESTING LOGIN SYSTEM")
    print("="*70)
    
    # Check if test user exists
    try:
        user = User.objects.get(username='testuser')
        print(f"\n✅ Test user exists: {user.username}")
    except User.DoesNotExist:
        print("\n❌ Test user does not exist!")
        print("   Create one with: python manage.py createsuperuser")
        print("   Or: python manage.py shell")
        print("   >>> from django.contrib.auth.models import User")
        print("   >>> User.objects.create_user('testuser', 'test@example.com', 'testpass123')")
        return
    
    # Check current counts
    print(f"\n📊 Current Database State:")
    print(f"   LoginEvent count: {LoginEvent.objects.count()}")
    print(f"   IPBlocklist count: {IPBlocklist.objects.count()}")
    print(f"   Device count: {Device.objects.count()}")
    
    # Check settings
    from django.conf import settings
    print(f"\n⚙️  Settings:")
    print(f"   ALLOWED_COUNTRIES: {settings.ALLOWED_COUNTRIES}")
    print(f"   AUTO_BLOCK_NON_ALLOWED_COUNTRY_IPS: {settings.AUTO_BLOCK_NON_ALLOWED_COUNTRY_IPS}")
    print(f"   AUTO_BLOCK_DEVICES_FROM_BLOCKED_COUNTRIES: {settings.AUTO_BLOCK_DEVICES_FROM_BLOCKED_COUNTRIES}")
    
    # Test geolocation
    print(f"\n🌍 Testing Geolocation:")
    test_ips = {
        '185.84.108.1': 'Saudi Arabia (SA)',
        '8.8.8.8': 'USA (US)',
        '103.108.140.1': 'Bangladesh (BD)'
    }
    
    for ip, expected in test_ips.items():
        geo = get_geo_location(ip)
        print(f"   {ip} → {geo.get('country_name')} ({geo.get('country_code')})")
    
    print("\n" + "="*70)
    print("  MANUAL TEST INSTRUCTIONS")
    print("="*70)
    print("\n1. Start Django server:")
    print("   python manage.py runserver")
    print("\n2. Test login from USA (should be blocked):")
    print("   curl -X POST http://127.0.0.1:8000/api/auth/login/ \\")
    print("     -H 'Content-Type: application/json' \\")
    print("     -H 'X-Forwarded-For: 8.8.8.8' \\")
    print("     -d '{\"username\": \"testuser\", \"password\": \"testpass123\"}'")
    print("\n3. Check database after test:")
    print("   python manage.py shell")
    print("   >>> from frauddetect.models import LoginEvent, IPBlocklist, Device")
    print("   >>> LoginEvent.objects.all().values('username', 'status', 'ip_address', 'country_code')")
    print("   >>> IPBlocklist.objects.all().values('ip_address', 'reason', 'is_active')")
    print("   >>> Device.objects.all().values('user__username', 'is_trusted', 'is_blocked', 'last_country_code')")
    
    print("\n" + "="*70)

if __name__ == "__main__":
    test_login()
