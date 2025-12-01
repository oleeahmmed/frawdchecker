#!/usr/bin/env python
"""
Simple Login Test
"""

import requests
import json

BASE_URL = "http://localhost:8000"

def test_login(data, description):
    """Test login with given data"""
    print(f"\n{'='*60}")
    print(f"Testing: {description}")
    print(f"{'='*60}")
    print(f"Request: {json.dumps(data, indent=2)}")
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/auth/login/",
            json=data,
            headers={'Content-Type': 'application/json'}
        )
        
        print(f"\nStatus Code: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            print(f"✅ SUCCESS")
            print(f"User: {result.get('user', {}).get('username')}")
            print(f"Device ID: {result.get('device_id')}")
            print(f"Risk Score: {result.get('security', {}).get('risk_score')}")
            return True
        else:
            print(f"❌ FAILED")
            try:
                error = response.json()
                print(f"Error: {json.dumps(error, indent=2)}")
            except:
                print(f"Error: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ ERROR: {e}")
        return False


def main():
    print("\n" + "="*60)
    print("🧪 SIMPLE LOGIN TEST")
    print("="*60)
    
    # Test 1: Login with username
    test_login(
        {
            "username": "admin",
            "password": "admin"
        },
        "Login with username"
    )
    
    # Test 2: Login with email
    test_login(
        {
            "email": "admin@example.com",
            "password": "admin"
        },
        "Login with email"
    )
    
    # Test 3: Login with username_or_email (username)
    test_login(
        {
            "username_or_email": "admin",
            "password": "admin"
        },
        "Login with username_or_email (username)"
    )
    
    # Test 4: Login with username_or_email (email)
    test_login(
        {
            "username_or_email": "admin@example.com",
            "password": "admin"
        },
        "Login with username_or_email (email)"
    )
    
    # Test 5: Wrong password
    test_login(
        {
            "username": "admin",
            "password": "wrongpassword"
        },
        "Login with wrong password (should fail)"
    )
    
    # Test 6: No credentials
    test_login(
        {
            "password": "admin"
        },
        "Login without username/email (should fail)"
    )
    
    print("\n" + "="*60)
    print("✅ TESTS COMPLETED")
    print("="*60)
    print("\nNOTE: Make sure you have created a superuser:")
    print("  python manage.py createsuperuser")
    print("\n")


if __name__ == "__main__":
    try:
        main()
    except requests.exceptions.ConnectionError:
        print("\n❌ Error: Cannot connect to server")
        print("Make sure Django is running: python manage.py runserver")
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted")
