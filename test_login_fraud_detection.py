#!/usr/bin/env python
"""
Test Login with Fraud Detection
Run: python test_login_fraud_detection.py
"""

import requests
import json
import time

BASE_URL = "http://localhost:8000"

def print_response(title, response):
    """Pretty print API response"""
    print(f"\n{'='*70}")
    print(f"📍 {title}")
    print(f"{'='*70}")
    print(f"Status Code: {response.status_code}")
    try:
        data = response.json()
        print(f"Response:\n{json.dumps(data, indent=2)}")
        return data
    except:
        print(f"Response: {response.text}")
        return None


def test_login_with_username(username, password):
    """Test login with username"""
    url = f"{BASE_URL}/api/auth/login/"
    data = {
        "username": username,
        "password": password
    }
    
    response = requests.post(url, json=data)
    return print_response(f"Login with Username: {username}", response)


def test_login_with_email(email, password):
    """Test login with email"""
    url = f"{BASE_URL}/api/auth/login/"
    data = {
        "email": email,
        "password": password
    }
    
    response = requests.post(url, json=data)
    return print_response(f"Login with Email: {email}", response)


def test_register_user():
    """Register a test user"""
    url = f"{BASE_URL}/api/auth/registration/"
    data = {
        "username": "testuser_fraud",
        "email": "testfraud@example.com",
        "password1": "TestPass123!@#",
        "password2": "TestPass123!@#",
        "first_name": "Test",
        "last_name": "User"
    }
    
    response = requests.post(url, json=data)
    return print_response("User Registration", response)


def test_multiple_logins(username, password, count=3):
    """Test multiple login attempts (velocity check)"""
    print(f"\n{'='*70}")
    print(f"🔄 Testing Velocity Check: {count} rapid login attempts")
    print(f"{'='*70}")
    
    for i in range(count):
        print(f"\n  Attempt {i+1}/{count}...")
        test_login_with_username(username, password)
        time.sleep(0.5)  # Small delay


def test_wrong_password(username):
    """Test login with wrong password"""
    url = f"{BASE_URL}/api/auth/login/"
    data = {
        "username": username,
        "password": "WrongPassword123"
    }
    
    response = requests.post(url, json=data)
    return print_response(f"Login with Wrong Password: {username}", response)


def test_missing_credentials():
    """Test login without credentials"""
    url = f"{BASE_URL}/api/auth/login/"
    
    # Test 1: No username or email
    print(f"\n{'='*70}")
    print(f"❌ Test: No username or email")
    print(f"{'='*70}")
    response = requests.post(url, json={"password": "test123"})
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
    
    # Test 2: No password
    print(f"\n{'='*70}")
    print(f"❌ Test: No password")
    print(f"{'='*70}")
    response = requests.post(url, json={"username": "testuser"})
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")


def analyze_login_response(data):
    """Analyze and display login response details"""
    if not data:
        return
    
    print(f"\n{'='*70}")
    print(f"📊 LOGIN ANALYSIS")
    print(f"{'='*70}")
    
    # User info
    if 'user' in data:
        user = data['user']
        print(f"\n👤 User Information:")
        print(f"  ID: {user.get('id')}")
        print(f"  Username: {user.get('username')}")
        print(f"  Email: {user.get('email')}")
        print(f"  Staff: {user.get('is_staff')}")
    
    # Device info
    if 'device_id' in data:
        print(f"\n📱 Device Information:")
        print(f"  Device ID: {data.get('device_id')}")
        print(f"  Trusted: {data.get('device_trusted')}")
        print(f"  New Device: {data.get('device_new')}")
    
    # Security info
    if 'security' in data:
        security = data['security']
        print(f"\n🛡️  Security Assessment:")
        print(f"  Risk Score: {security.get('risk_score')}")
        print(f"  Risk Level: {security.get('risk_level')}")
        print(f"  Suspicious: {security.get('is_suspicious')}")
        print(f"  Requires Verification: {security.get('requires_verification')}")
    
    # Location info
    if 'login_info' in data:
        location = data['login_info']
        print(f"\n📍 Location Information:")
        print(f"  IP Address: {location.get('ip_address')}")
        print(f"  Country: {location.get('country')} ({location.get('country_code')})")
        print(f"  City: {location.get('city')}")
        print(f"  Region: {location.get('region')}")
    
    # Warning
    if 'warning' in data:
        print(f"\n⚠️  WARNING: {data['warning']}")


def main():
    """Run all tests"""
    print("\n" + "="*70)
    print("🧪 LOGIN FRAUD DETECTION TEST SUITE")
    print("="*70)
    
    # Test 1: Register a test user
    print("\n\n🔹 Test 1: Register Test User")
    reg_data = test_register_user()
    
    if not reg_data or 'access' not in reg_data:
        print("\n⚠️  Registration failed or user already exists. Continuing with existing user...")
    
    # Test credentials
    username = "testuser_fraud"
    email = "testfraud@example.com"
    password = "TestPass123!@#"
    
    # Test 2: Login with username
    print("\n\n🔹 Test 2: Login with Username")
    data = test_login_with_username(username, password)
    if data:
        analyze_login_response(data)
    
    time.sleep(2)
    
    # Test 3: Login with email
    print("\n\n🔹 Test 3: Login with Email")
    data = test_login_with_email(email, password)
    if data:
        analyze_login_response(data)
    
    time.sleep(2)
    
    # Test 4: Login with wrong password
    print("\n\n🔹 Test 4: Login with Wrong Password")
    test_wrong_password(username)
    
    # Test 5: Missing credentials
    print("\n\n🔹 Test 5: Missing Credentials")
    test_missing_credentials()
    
    # Test 6: Velocity check (multiple rapid logins)
    print("\n\n🔹 Test 6: Velocity Check (Rapid Login Attempts)")
    test_multiple_logins(username, password, 5)
    
    print("\n\n" + "="*70)
    print("✅ ALL TESTS COMPLETED")
    print("="*70)
    print("\n📌 WHAT TO CHECK:")
    print("1. Console output from Django server (fraud detection logs)")
    print("2. Admin panel → Login Events (check risk scores)")
    print("3. Admin panel → System Logs (check security logs)")
    print("4. Admin panel → Devices (check device tracking)")
    print("\n📊 FRAUD DETECTION RULES TESTED:")
    print("  ✓ IP blocklist check")
    print("  ✓ Country risk assessment")
    print("  ✓ Velocity check (too many attempts)")
    print("  ✓ New device detection")
    print("  ✓ Device blocklist check")
    print("  ✓ Untrusted device detection")
    print("  ✓ IP change detection")
    print("\n")


if __name__ == "__main__":
    try:
        main()
    except requests.exceptions.ConnectionError:
        print("\n❌ Error: Cannot connect to the server.")
        print("Please make sure the Django server is running:")
        print("   python manage.py runserver")
    except KeyboardInterrupt:
        print("\n\n⚠️  Test interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
