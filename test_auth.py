#!/usr/bin/env python
"""
Test script for authentication API
Run: python test_auth.py
"""

import requests
import json

BASE_URL = "http://localhost:8000"

def print_response(title, response):
    """Pretty print API response"""
    print(f"\n{'='*60}")
    print(f"📍 {title}")
    print(f"{'='*60}")
    print(f"Status Code: {response.status_code}")
    try:
        print(f"Response:\n{json.dumps(response.json(), indent=2)}")
    except:
        print(f"Response: {response.text}")

def test_registration():
    """Test user registration"""
    url = f"{BASE_URL}/api/auth/registration/"
    data = {
        "username": "testuser",
        "email": "test@example.com",
        "password1": "TestPass123!",
        "password2": "TestPass123!",
        "first_name": "Test",
        "last_name": "User"
    }
    
    response = requests.post(url, json=data)
    print_response("Registration", response)
    
    if response.status_code == 201:
        return response.json()
    return None

def test_login(username="testuser", password="TestPass123!"):
    """Test custom JWT login"""
    url = f"{BASE_URL}/api/auth/login/"
    data = {
        "username": username,
        "password": password
    }
    
    response = requests.post(url, json=data)
    print_response("Login", response)
    
    if response.status_code == 200:
        return response.json()
    return None

def test_get_user(access_token):
    """Test getting current user"""
    url = f"{BASE_URL}/api/auth/user/"
    headers = {"Authorization": f"Bearer {access_token}"}
    
    response = requests.get(url, headers=headers)
    print_response("Get Current User", response)
    
    return response.json() if response.status_code == 200 else None

def test_get_devices(access_token):
    """Test getting user devices"""
    url = f"{BASE_URL}/api/devices/"
    headers = {"Authorization": f"Bearer {access_token}"}
    
    response = requests.get(url, headers=headers)
    print_response("Get Devices", response)
    
    return response.json() if response.status_code == 200 else None

def test_get_login_events(access_token):
    """Test getting login events"""
    url = f"{BASE_URL}/api/login-events/"
    headers = {"Authorization": f"Bearer {access_token}"}
    
    response = requests.get(url, headers=headers)
    print_response("Get Login Events", response)
    
    return response.json() if response.status_code == 200 else None

def test_token_refresh(refresh_token):
    """Test token refresh"""
    url = f"{BASE_URL}/api/auth/token/refresh/"
    data = {"refresh": refresh_token}
    
    response = requests.post(url, json=data)
    print_response("Token Refresh", response)
    
    return response.json() if response.status_code == 200 else None

def test_create_transaction(access_token):
    """Test creating a transaction"""
    url = f"{BASE_URL}/api/transactions/"
    headers = {"Authorization": f"Bearer {access_token}"}
    data = {
        "external_txn_id": "TXN-TEST-001",
        "amount": "5000.00",
        "currency": "BDT",
        "description": "Test transaction",
        "beneficiary": "Test Beneficiary"
    }
    
    response = requests.post(url, json=data, headers=headers)
    print_response("Create Transaction", response)
    
    return response.json() if response.status_code == 201 else None

def main():
    """Run all tests"""
    print("\n" + "="*60)
    print("🧪 FRAUD DETECTION API - AUTHENTICATION TEST")
    print("="*60)
    
    # Test 1: Registration
    print("\n\n🔹 Test 1: User Registration")
    reg_data = test_registration()
    
    if not reg_data:
        print("\n⚠️  Registration failed. Trying to login with existing user...")
    
    # Test 2: Login
    print("\n\n🔹 Test 2: Login")
    login_data = test_login()
    
    if not login_data:
        print("\n❌ Login failed. Cannot continue tests.")
        return
    
    access_token = login_data.get('access')
    refresh_token = login_data.get('refresh')
    
    # Test 3: Get Current User
    print("\n\n🔹 Test 3: Get Current User")
    test_get_user(access_token)
    
    # Test 4: Get Devices
    print("\n\n🔹 Test 4: Get User Devices")
    test_get_devices(access_token)
    
    # Test 5: Get Login Events
    print("\n\n🔹 Test 5: Get Login Events")
    test_get_login_events(access_token)
    
    # Test 6: Create Transaction
    print("\n\n🔹 Test 6: Create Transaction")
    test_create_transaction(access_token)
    
    # Test 7: Token Refresh
    print("\n\n🔹 Test 7: Token Refresh")
    test_token_refresh(refresh_token)
    
    print("\n\n" + "="*60)
    print("✅ All tests completed!")
    print("="*60)
    print("\n📖 For more details, visit:")
    print(f"   - Swagger UI: {BASE_URL}/api/docs/")
    print(f"   - ReDoc: {BASE_URL}/api/redoc/")
    print(f"   - Admin Panel: {BASE_URL}/admin/")
    print("\n")

if __name__ == "__main__":
    try:
        main()
    except requests.exceptions.ConnectionError:
        print("\n❌ Error: Cannot connect to the server.")
        print("Please make sure the Django server is running:")
        print("   python manage.py runserver")
    except Exception as e:
        print(f"\n❌ Error: {e}")
