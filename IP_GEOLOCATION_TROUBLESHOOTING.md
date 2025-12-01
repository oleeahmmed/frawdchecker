# 🌍 IP Detection & Geolocation Troubleshooting Guide

## ✅ What Was Fixed

### 1. **Improved IP Detection**
- Added multiple header checks (X-Forwarded-For, X-Real-IP, CF-Connecting-IP, etc.)
- Better handling of proxy chains
- Filters out private/local IPs when possible

### 2. **Enhanced Geolocation**
- Multiple API fallbacks (ipapi.co, ip-api.com, ipwhois.app)
- Better error handling
- Proper handling of local/private IPs
- Detailed logging for debugging

### 3. **Fixed LoginEvent Creation**
- Corrected field name: `country` → `country_code`
- Added all required fields (username, status, user_agent)
- Added detailed logging

### 4. **Added Response Data**
- Login response now includes detected IP and location
- Helps verify detection is working

---

## 🧪 Testing Steps

### Step 1: Test IP Detection & Geolocation

```bash
python test_ip_geolocation.py
```

This will:
- ✅ Detect your public IP address
- ✅ Test geolocation for your IP
- ✅ Test local IP handling
- ✅ Test sample public IPs
- ✅ Show what data will be saved

**Expected Output:**
```
🌐 DETECTING YOUR PUBLIC IP ADDRESS
✓ Your public IP: 103.106.239.104

📍 TESTING GEOLOCATION FOR: 103.106.239.104
✓ Geolocation from ip-api.com: BD - Dhaka

📊 Geolocation Result:
  Country Code: BD
  Country Name: Bangladesh
  City: Dhaka
  Region: Dhaka Division
  Latitude: 23.7104
  Longitude: 90.4074
  Timezone: Asia/Dhaka
```

---

### Step 2: Start Django Server

```bash
python manage.py runserver
```

---

### Step 3: Test Login API

```bash
curl -X POST http://localhost:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "username": "your_username",
    "password": "your_password"
  }'
```

**Check Console Output:**
```
🔍 Login attempt - User: john_doe, IP: 103.106.239.104
✓ Geolocation from ip-api.com: BD - Dhaka
📍 Location: Bangladesh (BD) - Dhaka
✓ Login event created: ID=1, Country=BD, City=Dhaka
```

**Check API Response:**
```json
{
  "access": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "refresh": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "user": {
    "id": 1,
    "username": "john_doe",
    "email": "john@example.com"
  },
  "device_id": 5,
  "device_trusted": true,
  "login_info": {
    "ip_address": "103.106.239.104",
    "country": "Bangladesh",
    "country_code": "BD",
    "city": "Dhaka",
    "region": "Dhaka Division"
  }
}
```

---

### Step 4: Verify in Admin Panel

1. Go to: `http://localhost:8000/admin/`
2. Navigate to: **Login Events**
3. Check the latest entry:
   - ✅ IP Address should show your actual IP
   - ✅ Country Code should show correct country (e.g., BD)
   - ✅ City should show correct city (e.g., Dhaka)

---

## 🔍 Common Issues & Solutions

### Issue 1: Shows "127.0.0.1" or "localhost"

**Cause:** You're testing from the same machine as the server

**Solution:**
- This is normal for local development
- The system correctly identifies it as LOCAL
- To test with real IP:
  - Deploy to a server
  - Use ngrok: `ngrok http 8000`
  - Test from a different device on your network

---

### Issue 2: Shows "Unknown" for Country/City

**Cause:** All geolocation APIs failed or rate limited

**Check Console Output:**
```
✗ ipapi.co timeout
✗ ip-api.com error: ...
✗ ipwhois.app error: ...
⚠ All geolocation APIs failed for IP: 103.106.239.104
```

**Solutions:**

1. **Check Internet Connection:**
   ```bash
   ping ipapi.co
   ping ip-api.com
   ```

2. **Check API Rate Limits:**
   - ipapi.co: 1,000 requests/day (free)
   - ip-api.com: 45 requests/minute (free)
   - ipwhois.app: 10,000 requests/month (free)

3. **Wait and Retry:**
   - APIs may be temporarily down
   - Rate limits reset after time

4. **Use Paid API (Production):**
   ```python
   # In utils.py, add your paid API
   {
       'name': 'ipgeolocation.io',
       'url': f'https://api.ipgeolocation.io/ipgeo?apiKey=YOUR_KEY&ip={ip_address}',
       'parser': lambda data: {...}
   }
   ```

---

### Issue 3: Wrong IP Detected

**Cause:** Behind proxy/load balancer without proper headers

**Check Headers:**
```python
# Add to views.py temporarily
print("All Headers:", request.META)
```

**Solution:** Configure your proxy to send correct headers:

**Nginx:**
```nginx
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
```

**Apache:**
```apache
RequestHeader set X-Forwarded-For %{REMOTE_ADDR}s
```

**Cloudflare:**
- Automatically sends `CF-Connecting-IP` (already handled)

---

### Issue 4: Private IP Detected (192.168.x.x, 10.x.x.x)

**Cause:** Request coming from local network

**This is Normal When:**
- Testing on localhost
- Behind NAT/router
- Using VPN

**To Get Public IP:**
```python
# The system tries to skip private IPs
# But if no public IP is found, it uses what's available
```

---

## 📊 Understanding IP Detection Flow

```
Request Arrives
    ↓
Check HTTP_X_FORWARDED_FOR
    ↓ (if not found)
Check HTTP_X_REAL_IP
    ↓ (if not found)
Check HTTP_CF_CONNECTING_IP (Cloudflare)
    ↓ (if not found)
Check HTTP_X_FORWARDED
    ↓ (if not found)
Check HTTP_FORWARDED_FOR
    ↓ (if not found)
Check HTTP_FORWARDED
    ↓ (if not found)
Check REMOTE_ADDR (fallback)
    ↓
Filter Private IPs (if possible)
    ↓
Return Best IP Found
```

---

## 🌐 Geolocation API Comparison

| API | Free Limit | Speed | Accuracy | Notes |
|-----|-----------|-------|----------|-------|
| ipapi.co | 1K/day | Fast | High | Primary choice |
| ip-api.com | 45/min | Fast | High | Good fallback |
| ipwhois.app | 10K/month | Medium | Medium | Third option |
| ipgeolocation.io | 1K/day | Fast | Very High | Paid plans available |
| ipstack.com | 100/month | Fast | Very High | Paid plans available |

---

## 🔧 Production Recommendations

### 1. Use Paid Geolocation API
```python
# For production, use a paid API with higher limits
# Example: ipgeolocation.io, ipstack.com, maxmind.com
```

### 2. Cache Geolocation Results
```python
from django.core.cache import cache

def get_geo_location_cached(ip_address):
    cache_key = f'geo_{ip_address}'
    result = cache.get(cache_key)
    
    if not result:
        result = get_geo_location(ip_address)
        cache.set(cache_key, result, 86400)  # Cache for 24 hours
    
    return result
```

### 3. Use MaxMind GeoIP2 Database (Offline)
```bash
pip install geoip2
```

```python
import geoip2.database

def get_geo_location_offline(ip_address):
    reader = geoip2.database.Reader('/path/to/GeoLite2-City.mmdb')
    response = reader.city(ip_address)
    
    return {
        'country_code': response.country.iso_code,
        'country_name': response.country.name,
        'city': response.city.name,
        'latitude': response.location.latitude,
        'longitude': response.location.longitude,
    }
```

### 4. Monitor API Usage
```python
# Add to settings.py
GEOLOCATION_API_CALLS = 0

# Track in utils.py
settings.GEOLOCATION_API_CALLS += 1
```

---

## 📝 Debugging Checklist

- [ ] Run `python test_ip_geolocation.py`
- [ ] Check console output during login
- [ ] Verify IP in login response
- [ ] Check LoginEvent in admin panel
- [ ] Test from different devices/networks
- [ ] Check API rate limits
- [ ] Verify internet connectivity
- [ ] Check proxy/load balancer configuration

---

## 🎯 Expected Behavior

### Local Development (localhost)
```
IP: 127.0.0.1
Country: LOCAL
City: Local
```

### Behind Router (Private Network)
```
IP: 192.168.1.100
Country: LOCAL
City: Local
```

### Public Internet
```
IP: 103.106.239.104
Country: BD (Bangladesh)
City: Dhaka
```

### Behind Proxy (with X-Forwarded-For)
```
IP: 203.0.113.50 (actual client IP)
Country: US (United States)
City: New York
```

---

## 📞 Still Having Issues?

1. **Check Console Logs:**
   - Look for 🔍, 📍, ✓, ✗ symbols
   - They show exactly what's happening

2. **Enable Debug Mode:**
   ```python
   # In utils.py, add more print statements
   print(f"DEBUG: Headers = {request.META}")
   print(f"DEBUG: IP = {ip_address}")
   print(f"DEBUG: Geo = {geo_data}")
   ```

3. **Test Individual Components:**
   ```python
   # In Django shell
   python manage.py shell
   
   >>> from frauddetect.utils import get_geo_location
   >>> get_geo_location('8.8.8.8')
   ```

4. **Check Database:**
   ```sql
   SELECT * FROM frauddetect_loginevent ORDER BY attempt_time DESC LIMIT 5;
   ```

---

Your IP detection and geolocation should now work perfectly! 🎉
