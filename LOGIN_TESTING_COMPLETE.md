# 🧪 Login Testing - সম্পূর্ণ গাইড (Test Commands সহ)

## 🎯 Overview

এই guide এ প্রতিটি login check test করার জন্য **ready-to-use commands** আছে।

---

## 🧪 Test Case 1: Normal Login (Success)

### কী Test করছি:
সাধারণ login - সব ঠিক থাকলে কী হয়

### Setup:
```bash
# User আছে কিনা check করো
python manage.py shell
```
```python
from django.contrib.auth.models import User
User.objects.filter(username='gsm').exists()
# True হলে আছে, False হলে নেই
exit()
```

### Test Command (Postman):
```
Method: POST
URL: http://127.0.0.1:8000/api/auth/login/
Body (JSON):
{
    "username": "gsm",
    "password": "your_password"
}
```

### Test Command (cURL):
```bash
curl -X POST http://127.0.0.1:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "username": "gsm",
    "password": "your_password"
  }'
```

### Expected Response:
```json
{
    "access": "eyJ0eXAiOiJKV1QiLCJhbGc...",
    "refresh": "eyJ0eXAiOiJKV1QiLCJhbGc...",
    "user": {
        "id": 1,
        "username": "gsm",
        "is_superuser": true
    },
    "device_id": 1,
    "device_trusted": true,
    "security": {
        "risk_score": 0,
        "risk_level": "safe"
    }
}
```

### ✅ Pass Criteria:
- Status code: 200
- `access` token পাবে
- `refresh` token পাবে
- `risk_score` = 0

---

## 🧪 Test Case 2: Wrong Password

### কী Test করছি:
ভুল password দিলে কী হয়

### Test Command (Postman):
```
Method: POST
URL: http://127.0.0.1:8000/api/auth/login/
Body (JSON):
{
    "username": "gsm",
    "password": "wrong_password_123"
}
```

### Test Command (cURL):
```bash
curl -X POST http://127.0.0.1:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "username": "gsm",
    "password": "wrong_password_123"
  }'
```

### Expected Response:
```json
{
    "error": "Invalid credentials"
}
```

### ✅ Pass Criteria:
- Status code: 400
- Error message পাবে
- Token পাবে না

### Verify Database:
```python
from frauddetect.models import LoginEvent

# Last failed login দেখো
failed = LoginEvent.objects.filter(
    username='gsm',
    status='failed'
).order_by('-attempt_time').first()

print(f"Username: {failed.username}")
print(f"Status: {failed.status}")
print(f"IP: {failed.ip_address}")
print(f"Time: {failed.attempt_time}")
```

---

## 🧪 Test Case 3: IP Blocked

### কী Test করছি:
Blocked IP থেকে login করলে কী হয়

### Setup - IP Block করো:
```bash
python manage.py shell
```
```python
from frauddetect.models import IPBlocklist
from django.contrib.auth.models import User

admin = User.objects.filter(is_superuser=True).first()

# IP block করো
IPBlocklist.objects.create(
    ip_address='192.168.1.100',
    reason='Testing blocked IP',
    is_active=True,
    blocked_by=admin
)

print("✅ IP 192.168.1.100 blocked!")
exit()
```

### Test Command (Postman):
```
Method: POST
URL: http://127.0.0.1:8000/api/auth/login/
Headers:
  X-Forwarded-For: 192.168.1.100
Body (JSON):
{
    "username": "gsm",
    "password": "your_password"
}
```

### Test Command (cURL):
```bash
curl -X POST http://127.0.0.1:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 192.168.1.100" \
  -d '{
    "username": "gsm",
    "password": "your_password"
  }'
```

### Expected Response:
```json
{
    "error": "Access Denied",
    "blocked": true,
    "reason": "ip_blocked",
    "message": "Your IP address (192.168.1.100) has been blocked",
    "details": {
        "ip_address": "192.168.1.100",
        "block_reason": "Testing blocked IP"
    }
}
```

### ✅ Pass Criteria:
- Status code: 400
- `blocked: true`
- `reason: "ip_blocked"`

### Cleanup - IP Unblock করো:
```python
from frauddetect.models import IPBlocklist

IPBlocklist.objects.filter(
    ip_address='192.168.1.100'
).update(is_active=False)

print("✅ IP unblocked!")
```

---

## 🧪 Test Case 4: Device Blocked

### কী Test করছি:
Blocked device থেকে login করলে কী হয়

### Setup - প্রথমে normal login করো:
```bash
curl -X POST http://127.0.0.1:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "Test123!"
  }'
```

Response থেকে `device_id` নোট করো (যেমন: 5)

### Setup - Device Block করো:
```bash
python manage.py shell
```
```python
from frauddetect.models import Device

# Device block করো (device_id = 5)
device = Device.objects.get(id=5)
device.is_blocked = True
device.is_trusted = False
device.save()

print(f"✅ Device {device.device_name} blocked!")
exit()
```

### Test Command:
Same browser/device থেকে আবার login করো:
```bash
curl -X POST http://127.0.0.1:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "Test123!"
  }'
```

### Expected Response:
```json
{
    "error": "Access Denied",
    "blocked": true,
    "reason": "device_blocked",
    "message": "This device has been blocked",
    "details": {
        "device_id": 5,
        "device_name": "Chrome Browser"
    }
}
```

### ✅ Pass Criteria:
- Status code: 400
- `reason: "device_blocked"`

### Cleanup - Device Unblock করো:
```python
from frauddetect.models import Device

device = Device.objects.get(id=5)
device.is_blocked = False
device.is_trusted = True
device.save()

print("✅ Device unblocked!")
```

---

## 🧪 Test Case 5: Country Restriction (Non-SA)

### কী Test করছি:
Saudi Arabia ছাড়া অন্য দেশ থেকে login করলে কী হয়

### Test Command (USA IP):
```bash
curl -X POST http://127.0.0.1:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 8.8.8.8" \
  -d '{
    "username": "gsm",
    "password": "your_password"
  }'
```

### Test Command (UK IP):
```bash
curl -X POST http://127.0.0.1:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 8.8.4.4" \
  -d '{
    "username": "gsm",
    "password": "your_password"
  }'
```

### Expected Response:
```json
{
    "error": "Access Denied",
    "blocked": true,
    "reason": "non_allowed_country",
    "message": "Access to this service is restricted to Saudi Arabia only",
    "details": {
        "your_country": "United States",
        "your_country_code": "US",
        "your_ip": "8.8.8.8",
        "allowed_countries": ["Saudi Arabia (SA)"]
    }
}
```

### ✅ Pass Criteria:
- Status code: 400
- `reason: "non_allowed_country"`
- IP automatically blocked

### Verify IP Blocked:
```python
from frauddetect.models import IPBlocklist

blocked = IPBlocklist.objects.filter(
    ip_address='8.8.8.8',
    is_active=True
).exists()

print(f"IP Blocked: {blocked}")  # Should be True
```

---

## 🧪 Test Case 6: Rate Limiting (Too Many Attempts)

### কী Test করছি:
5 মিনিটে 5 বারের বেশি failed login করলে কী হয়

### Test Script:
```bash
# 5 বার ভুল password দিয়ে login করো
for i in {1..5}; do
  echo "Attempt $i:"
  curl -X POST http://127.0.0.1:8000/api/auth/login/ \
    -H "Content-Type: application/json" \
    -d '{
      "username": "testuser",
      "password": "wrong_password"
    }'
  echo ""
  sleep 1
done

# 6th attempt
echo "Attempt 6 (should be blocked):"
curl -X POST http://127.0.0.1:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "wrong_password"
  }'
```

### Expected Response (6th attempt):
```json
{
    "error": "Access Denied",
    "blocked": true,
    "reason": "too_many_attempts",
    "message": "Too many failed login attempts. Your IP has been blocked.",
    "details": {
        "failed_attempts": 6,
        "time_window": "5 minutes",
        "max_allowed": 5,
        "ip_address": "127.0.0.1",
        "ip_blocked": true
    }
}
```

### ✅ Pass Criteria:
- First 5 attempts: "Invalid credentials"
- 6th attempt: "too_many_attempts"
- IP automatically blocked

### Cleanup:
```python
from frauddetect.models import IPBlocklist

# Unblock your IP
IPBlocklist.objects.filter(
    ip_address='127.0.0.1'
).update(is_active=False)

print("✅ IP unblocked!")
```

---

## 🧪 Test Case 7: IP Whitelist Bypass

### কী Test করছি:
Whitelisted IP সব check bypass করে কিনা

### Setup - IP Whitelist করো:
```bash
python manage.py shell
```
```python
from frauddetect.models import IPWhitelist

# IP whitelist করো
IPWhitelist.objects.create(
    ip_address='127.0.0.1',
    description='Testing whitelist',
    is_active=True
)

print("✅ IP 127.0.0.1 whitelisted!")
exit()
```

### Test 1: ভুল password দিয়ে 10 বার try করো
```bash
for i in {1..10}; do
  echo "Attempt $i:"
  curl -X POST http://127.0.0.1:8000/api/auth/login/ \
    -H "Content-Type: application/json" \
    -d '{
      "username": "testuser",
      "password": "wrong_password"
    }'
  sleep 1
done
```

### Expected:
- সব attempts "Invalid credentials" দেখাবে
- কোনো IP block হবে না
- Whitelist bypass করছে!

### ✅ Pass Criteria:
- 10 বার failed হলেও IP block হয় নি
- Whitelist কাজ করছে

### Cleanup:
```python
from frauddetect.models import IPWhitelist

IPWhitelist.objects.filter(
    ip_address='127.0.0.1'
).delete()

print("✅ IP removed from whitelist!")
```

---

## 🧪 Test Case 8: Superuser Bypass

### কী Test করছি:
Superuser সব checks bypass করে কিনা

### Test Command:
```bash
curl -X POST http://127.0.0.1:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "username": "gsm",
    "password": "your_password"
  }'
```

### Expected Response:
```json
{
    "access": "...",
    "user": {
        "is_superuser": true
    },
    "security": {
        "risk_score": 0,
        "risk_level": "superuser"
    },
    "superuser": true
}
```

### Server Logs দেখো:
```
👑 SUPERUSER: gsm - Bypassing all checks (Admin Protection)
```

### ✅ Pass Criteria:
- `is_superuser: true`
- `risk_level: "superuser"`
- Server logs এ "SUPERUSER" message

---

## 🧪 Test Case 9: Email Login

### কী Test করছি:
Email দিয়ে login করা যায় কিনা

### Test Command (Email):
```bash
curl -X POST http://127.0.0.1:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "gsm@example.com",
    "password": "your_password"
  }'
```

### Test Command (Auto-detect):
```bash
curl -X POST http://127.0.0.1:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "username_or_email": "gsm@example.com",
    "password": "your_password"
  }'
```

### Expected Response:
```json
{
    "access": "...",
    "user": {
        "username": "gsm",
        "email": "gsm@example.com"
    }
}
```

### ✅ Pass Criteria:
- Email দিয়ে login success
- Same response as username login

---

## 🧪 Test Case 10: Device Trust (New Device from SA)

### কী Test করছি:
Saudi Arabia থেকে নতুন device auto-trust হয় কিনা

### Test Command (Different User-Agent):
```bash
curl -X POST http://127.0.0.1:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -H "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)" \
  -d '{
    "username": "gsm",
    "password": "your_password"
  }'
```

### Expected Response:
```json
{
    "access": "...",
    "device_id": 6,
    "device_trusted": true,
    "device_new": true,
    "security": {
        "risk_score": 20,
        "risk_level": "low"
    }
}
```

### ✅ Pass Criteria:
- `device_new: true`
- `device_trusted: true` (auto-trusted from SA)
- New device_id

---

## 📊 Complete Test Checklist

```
Test Cases:
[ ] 1. Normal Login - Success
[ ] 2. Wrong Password - Failed
[ ] 3. Blocked IP - Blocked
[ ] 4. Blocked Device - Blocked
[ ] 5. Non-SA Country - Blocked + IP Blocked
[ ] 6. Rate Limiting - Blocked after 5 attempts
[ ] 7. IP Whitelist - Bypass all checks
[ ] 8. Superuser - Bypass all checks
[ ] 9. Email Login - Success
[ ] 10. New Device from SA - Auto-trusted
```

---

## 🔧 Useful Commands

### Check Login Events:
```python
from frauddetect.models import LoginEvent

# Last 10 logins
for login in LoginEvent.objects.all()[:10]:
    print(f"{login.username} - {login.status} - {login.ip_address}")
```

### Check Blocked IPs:
```python
from frauddetect.models import IPBlocklist

for ip in IPBlocklist.objects.filter(is_active=True):
    print(f"🚫 {ip.ip_address} - {ip.reason}")
```

### Check Devices:
```python
from frauddetect.models import Device

for device in Device.objects.filter(user__username='gsm'):
    print(f"{device.device_name} - Trusted: {device.is_trusted} - Blocked: {device.is_blocked}")
```

### Reset Everything:
```python
from frauddetect.models import IPBlocklist, Device

# Unblock all IPs
IPBlocklist.objects.all().update(is_active=False)

# Unblock all devices
Device.objects.all().update(is_blocked=False, is_trusted=True)

print("✅ All reset!")
```

---

## 🎯 Quick Test Script

Save this as `test_login.sh`:

```bash
#!/bin/bash

BASE_URL="http://127.0.0.1:8000/api/auth/login/"

echo "🧪 Testing Login System..."
echo ""

# Test 1: Normal Login
echo "Test 1: Normal Login"
curl -X POST $BASE_URL \
  -H "Content-Type: application/json" \
  -d '{"username": "gsm", "password": "your_password"}' \
  | python -m json.tool
echo ""

# Test 2: Wrong Password
echo "Test 2: Wrong Password"
curl -X POST $BASE_URL \
  -H "Content-Type: application/json" \
  -d '{"username": "gsm", "password": "wrong"}' \
  | python -m json.tool
echo ""

# Test 3: Email Login
echo "Test 3: Email Login"
curl -X POST $BASE_URL \
  -H "Content-Type: application/json" \
  -d '{"email": "gsm@example.com", "password": "your_password"}' \
  | python -m json.tool
echo ""

echo "✅ Tests complete!"
```

Run:
```bash
chmod +x test_login.sh
./test_login.sh
```

---

এই guide follow করে তুমি সব login checks test করতে পারবে! 🚀

প্রতিটি test case এ:
- ✅ Setup commands
- ✅ Test commands (Postman + cURL)
- ✅ Expected response
- ✅ Pass criteria
- ✅ Cleanup commands

সব ready! শুরু করো! 😊
