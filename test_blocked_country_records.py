#!/usr/bin/env python
"""
Test Script: Verify that blocked country logins create all records
(Device, IPBlocklist, LoginEvent) before blocking

This ensures admins can review and unblock users later.
"""

import requests
import json

# Configuration
BASE_URL = "http://127.0.0.1:8000"
LOGIN_URL = f"{BASE_URL}/api/auth/login/"

# Test user credentials (create this user first)
TEST_USER = {
    "username": "testuser",
    "password": "testpass123"
}

def print_section(title):
    """Print a formatted section header"""
    print("\n" + "="*70)
    print(f"  {title}")
    print("="*70)

def test_blocked_country_login():
    """
    Test login from a blocked country
    Expected behavior:
    1. Device record created with is_blocked=True
    2. IP added to blocklist
    3. LoginEvent created with status='blocked'
    4. Login request blocked with 400 error
    """
    print_section("TEST: Login from Blocked Country (Bangladesh)")
    
    # Simulate login from Bangladesh (BD) - not in ALLOWED_COUNTRIES
    headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
        'X-Forwarded-For': '103.108.140.1',  # Bangladesh IP
    }
    
    payload = {
        "username": TEST_USER["username"],
        "password": TEST_USER["password"]
    }
    
    print(f"\n📤 Sending login request...")
    print(f"   Username: {TEST_USER['username']}")
    print(f"   Simulated IP: 103.108.140.1 (Bangladesh)")
    
    try:
        response = requests.post(LOGIN_URL, json=payload, headers=headers)
        
        print(f"\n📥 Response Status: {response.status_code}")
        print(f"   Response Body:")
        print(json.dumps(response.json(), indent=2))
        
        if response.status_code == 400:
            print("\n✅ EXPECTED: Login blocked (400 error)")
            response_data = response.json()
            
            # Check if all required info is in response
            if 'device_id' in response_data:
                print(f"✅ Device ID recorded: {response_data['device_id']}")
            else:
                print("❌ Device ID not in response")
            
            if 'login_event_id' in response_data:
                print(f"✅ Login Event ID recorded: {response_data['login_event_id']}")
            else:
                print("❌ Login Event ID not in response")
            
            if 'country_code' in response_data:
                print(f"✅ Country detected: {response_data['country_code']}")
            else:
                print("❌ Country code not in response")
            
            print("\n📋 What should be in the database:")
            print("   1. Device record with is_blocked=True")
            print("   2. IPBlocklist entry for 103.108.140.1")
            print("   3. LoginEvent with status='blocked'")
            print("   4. SystemLog entries")
            
        elif response.status_code == 200:
            print("\n❌ UNEXPECTED: Login succeeded (should be blocked)")
            print("   This means the blocking logic is not working correctly")
        else:
            print(f"\n⚠️  UNEXPECTED STATUS: {response.status_code}")
            
    except requests.exceptions.ConnectionError:
        print("\n❌ ERROR: Cannot connect to server")
        print("   Make sure Django server is running: python manage.py runserver")
    except Exception as e:
        print(f"\n❌ ERROR: {str(e)}")

def test_allowed_country_login():
    """
    Test login from an allowed country
    Expected behavior:
    1. Device record created with is_trusted=True
    2. IP NOT added to blocklist
    3. LoginEvent created with status='success'
    4. Login succeeds with JWT tokens
    """
    print_section("TEST: Login from Allowed Country (Saudi Arabia)")
    
    # Simulate login from Saudi Arabia (SA) - in ALLOWED_COUNTRIES
    headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0',
        'X-Forwarded-For': '185.84.108.1',  # Saudi Arabia IP
    }
    
    payload = {
        "username": TEST_USER["username"],
        "password": TEST_USER["password"]
    }
    
    print(f"\n📤 Sending login request...")
    print(f"   Username: {TEST_USER['username']}")
    print(f"   Simulated IP: 185.84.108.1 (Saudi Arabia)")
    
    try:
        response = requests.post(LOGIN_URL, json=payload, headers=headers)
        
        print(f"\n📥 Response Status: {response.status_code}")
        
        if response.status_code == 200:
            print("✅ EXPECTED: Login succeeded")
            response_data = response.json()
            
            if 'access' in response_data:
                print(f"✅ Access token received: {response_data['access'][:50]}...")
            
            if 'device_id' in response_data:
                print(f"✅ Device ID: {response_data['device_id']}")
            
            if 'device_trusted' in response_data:
                print(f"✅ Device trusted: {response_data['device_trusted']}")
            
            if 'security' in response_data:
                print(f"✅ Security info:")
                print(f"   Risk Score: {response_data['security'].get('risk_score')}")
                print(f"   Risk Level: {response_data['security'].get('risk_level')}")
            
            print("\n📋 What should be in the database:")
            print("   1. Device record with is_trusted=True")
            print("   2. NO IPBlocklist entry")
            print("   3. LoginEvent with status='success'")
            print("   4. SystemLog entries")
            
        else:
            print(f"\n❌ UNEXPECTED: Login failed with status {response.status_code}")
            print(json.dumps(response.json(), indent=2))
            
    except requests.exceptions.ConnectionError:
        print("\n❌ ERROR: Cannot connect to server")
        print("   Make sure Django server is running: python manage.py runserver")
    except Exception as e:
        print(f"\n❌ ERROR: {str(e)}")

def verify_database_records():
    """
    Instructions for verifying database records
    """
    print_section("DATABASE VERIFICATION")
    
    print("\n📋 To verify records were created, run these Django shell commands:")
    print("\n1. Check Device records:")
    print("   python manage.py shell")
    print("   >>> from frauddetect.models import Device")
    print("   >>> Device.objects.filter(user__username='testuser').values('id', 'is_trusted', 'is_blocked', 'status', 'last_country_code')")
    
    print("\n2. Check IPBlocklist:")
    print("   >>> from frauddetect.models import IPBlocklist")
    print("   >>> IPBlocklist.objects.all().values('ip_address', 'reason', 'is_active')")
    
    print("\n3. Check LoginEvent:")
    print("   >>> from frauddetect.models import LoginEvent")
    print("   >>> LoginEvent.objects.filter(username='testuser').values('id', 'status', 'ip_address', 'country_code', 'is_suspicious', 'risk_score')")
    
    print("\n4. Check SystemLog:")
    print("   >>> from frauddetect.models import SystemLog")
    print("   >>> SystemLog.objects.filter(log_type='security').order_by('-created_at')[:5].values('message', 'level', 'ip_address')")

def main():
    """Run all tests"""
    print("\n" + "🔒"*35)
    print("  BLOCKED COUNTRY LOGIN TEST SUITE")
    print("🔒"*35)
    
    print("\n📝 Prerequisites:")
    print("   1. Django server running: python manage.py runserver")
    print("   2. Test user created: username='testuser', password='testpass123'")
    print("   3. Settings configured:")
    print("      - GEO_RESTRICTION_ENABLED = True")
    print("      - ALLOWED_COUNTRIES = ['SA']")
    print("      - AUTO_BLOCK_NON_ALLOWED_COUNTRY_IPS = True")
    
    input("\n⏸️  Press Enter to start tests...")
    
    # Test 1: Blocked country
    test_blocked_country_login()
    
    input("\n⏸️  Press Enter to continue to next test...")
    
    # Test 2: Allowed country
    test_allowed_country_login()
    
    # Verification instructions
    verify_database_records()
    
    print("\n" + "="*70)
    print("  TESTS COMPLETED")
    print("="*70)
    print("\n✅ Key Points:")
    print("   1. Blocked logins should create Device, IPBlocklist, and LoginEvent")
    print("   2. Admins can review these records in Django admin")
    print("   3. Admins can unblock devices/IPs if needed")
    print("   4. All security events are logged for audit trail")

if __name__ == "__main__":
    main()
