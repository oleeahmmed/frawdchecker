#!/usr/bin/env python
"""
Test IP Detection and Geolocation
Run: python test_ip_geolocation.py
"""

import os
import sys
import django

# Setup Django
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')
django.setup()

from frauddetect.utils import get_geo_location
import requests


def test_get_public_ip():
    """Get your actual public IP"""
    print("\n" + "="*60)
    print("🌐 DETECTING YOUR PUBLIC IP ADDRESS")
    print("="*60)
    
    services = [
        'https://api.ipify.org?format=json',
        'https://ipapi.co/json/',
        'http://ip-api.com/json/',
        'https://ifconfig.me/ip',
    ]
    
    for service in services:
        try:
            response = requests.get(service, timeout=5)
            if response.status_code == 200:
                if 'json' in service:
                    data = response.json()
                    ip = data.get('ip') or data.get('query')
                else:
                    ip = response.text.strip()
                
                if ip:
                    print(f"✓ Your public IP: {ip}")
                    return ip
        except Exception as e:
            print(f"✗ {service} failed: {e}")
            continue
    
    print("⚠ Could not detect public IP")
    return None


def test_geolocation(ip_address):
    """Test geolocation for an IP"""
    print("\n" + "="*60)
    print(f"📍 TESTING GEOLOCATION FOR: {ip_address}")
    print("="*60)
    
    result = get_geo_location(ip_address)
    
    print("\n📊 Geolocation Result:")
    print(f"  Country Code: {result.get('country_code')}")
    print(f"  Country Name: {result.get('country_name')}")
    print(f"  City: {result.get('city')}")
    print(f"  Region: {result.get('region')}")
    print(f"  Latitude: {result.get('latitude')}")
    print(f"  Longitude: {result.get('longitude')}")
    print(f"  Timezone: {result.get('timezone')}")
    
    return result


def test_local_ips():
    """Test local IP handling"""
    print("\n" + "="*60)
    print("🏠 TESTING LOCAL IP ADDRESSES")
    print("="*60)
    
    local_ips = ['127.0.0.1', '192.168.1.1', '10.0.0.1', 'localhost']
    
    for ip in local_ips:
        result = get_geo_location(ip)
        print(f"\n  IP: {ip}")
        print(f"  → Country: {result.get('country_code')}")
        print(f"  → City: {result.get('city')}")


def test_sample_ips():
    """Test with known public IPs"""
    print("\n" + "="*60)
    print("🌍 TESTING SAMPLE PUBLIC IPs")
    print("="*60)
    
    sample_ips = {
        '8.8.8.8': 'Google DNS (USA)',
        '1.1.1.1': 'Cloudflare DNS (USA)',
        '103.106.239.104': 'Bangladesh',
    }
    
    for ip, description in sample_ips.items():
        print(f"\n  Testing: {ip} ({description})")
        result = get_geo_location(ip)
        print(f"  → Country: {result.get('country_name')} ({result.get('country_code')})")
        print(f"  → City: {result.get('city')}")


def test_login_simulation():
    """Simulate a login to test the full flow"""
    print("\n" + "="*60)
    print("🔐 SIMULATING LOGIN REQUEST")
    print("="*60)
    
    import requests
    
    # First, get your public IP
    public_ip = test_get_public_ip()
    
    if not public_ip:
        print("\n⚠ Cannot test login without public IP")
        return
    
    # Test geolocation for your IP
    geo = test_geolocation(public_ip)
    
    print("\n" + "="*60)
    print("📝 EXPECTED LOGIN EVENT DATA:")
    print("="*60)
    print(f"  IP Address: {public_ip}")
    print(f"  Country: {geo.get('country_code')}")
    print(f"  City: {geo.get('city')}")
    print("\nThis is what should be saved in the LoginEvent table.")


def main():
    """Run all tests"""
    print("\n" + "="*60)
    print("🧪 IP DETECTION & GEOLOCATION TEST SUITE")
    print("="*60)
    
    # Test 1: Get your public IP
    public_ip = test_get_public_ip()
    
    # Test 2: Test geolocation for your IP
    if public_ip:
        test_geolocation(public_ip)
    
    # Test 3: Test local IPs
    test_local_ips()
    
    # Test 4: Test sample public IPs
    test_sample_ips()
    
    # Test 5: Simulate login
    test_login_simulation()
    
    print("\n" + "="*60)
    print("✅ ALL TESTS COMPLETED")
    print("="*60)
    print("\n📌 NEXT STEPS:")
    print("1. Start your Django server: python manage.py runserver")
    print("2. Try logging in via API: POST /api/auth/login/")
    print("3. Check the console output for IP and location detection")
    print("4. Check LoginEvent in admin panel to verify data is saved")
    print("\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠ Test interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
