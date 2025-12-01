# Blocked Country Login Records

## Overview

When a user attempts to login from a **non-allowed country** (e.g., not Saudi Arabia), the system now:

1. ✅ **Creates all records** (Device, IPBlocklist, LoginEvent)
2. ✅ **Marks them as blocked**
3. ✅ **Blocks the login attempt**
4. ✅ **Allows admins to review and unblock later**

This ensures complete audit trail and flexibility for administrators.

---

## Flow Diagram

```
User Login from Non-Allowed Country (e.g., Bangladesh)
    ↓
1. GeoRestrictionMiddleware (BYPASSED for login endpoint)
    ↓
2. Authentication (username/password verified)
    ↓
3. Device Created/Updated
   - is_blocked = True
   - is_trusted = False
   - status = 'blocked'
   - last_country_code = 'BD'
    ↓
4. IP Added to Blocklist (if AUTO_BLOCK_NON_ALLOWED_COUNTRY_IPS = True)
   - ip_address = user's IP
   - reason = "Automatic block: Login attempt from non-allowed country BD"
   - is_active = True
   - blocked_by = First superuser
    ↓
5. LoginEvent Created
   - status = 'blocked'
   - is_suspicious = True
   - risk_score = 100+
   - risk_reasons = ['Device is blocked', ...]
    ↓
6. SystemLog Created
   - log_type = 'security'
   - level = 'critical'
   - message = "Blocked login attempt for {username} from {ip}"
    ↓
7. Login Request Blocked (400 Error)
   - Returns error with device_id, login_event_id, country info
```

---

## Database Records Created

### 1. Device Record

```python
Device.objects.filter(user__username='testuser')
```

**Fields:**
- `is_blocked` = `True` ✅
- `is_trusted` = `False`
- `status` = `'blocked'`
- `last_country_code` = `'BD'` (or other non-allowed country)
- `risk_score` = `70+`
- `fingerprint_hash` = Unique device fingerprint

**Admin Action:** Can change `is_blocked` to `False` to unblock device

---

### 2. IPBlocklist Record

```python
IPBlocklist.objects.filter(ip_address='103.108.140.1')
```

**Fields:**
- `ip_address` = User's IP
- `reason` = `"Automatic block: Login attempt from non-allowed country BD (Bangladesh)"`
- `is_active` = `True` ✅
- `blocked_by` = First superuser (system admin)
- `created_at` = Timestamp

**Admin Action:** Can change `is_active` to `False` to unblock IP

---

### 3. LoginEvent Record

```python
LoginEvent.objects.filter(username='testuser', status='blocked')
```

**Fields:**
- `status` = `'blocked'` ✅
- `is_suspicious` = `True`
- `risk_score` = `100+`
- `risk_reasons` = `['Device is blocked', 'IP address is blocked', ...]`
- `country_code` = `'BD'`
- `city` = User's city
- `ip_address` = User's IP
- `device` = Link to Device record

**Admin Action:** Review for audit trail (read-only)

---

### 4. SystemLog Records

```python
SystemLog.objects.filter(log_type='security', level='critical')
```

**Multiple logs created:**

1. **Device creation log:**
   - Message: "New device blocked for {username} from {country_code}"
   - Level: `warning`

2. **IP blocklist log:**
   - Message: "IP {ip} automatically added to blocklist during login"
   - Level: `critical`

3. **Login blocked log:**
   - Message: "Blocked login attempt for {username} from {ip}"
   - Level: `critical`

**Admin Action:** Review for audit trail (read-only)

---

## API Response (Blocked Login)

When login is blocked, the API returns:

```json
{
  "error": "Login blocked due to security concerns",
  "message": "Your login attempt has been blocked. All details have been recorded.",
  "risk_score": 115,
  "reasons": [
    "Device is blocked (not from allowed country)",
    "IP address is blocked",
    "Login from new device"
  ],
  "device_id": 5,
  "login_event_id": 12,
  "country_detected": "Bangladesh",
  "country_code": "BD",
  "contact": "Please contact support if you believe this is an error."
}
```

**Status Code:** `400 Bad Request`

---

## Admin Unblocking Process

### Option 1: Unblock Device

1. Go to Django Admin → Devices
2. Find the device by user or device ID
3. Change `is_blocked` to `False`
4. Change `status` to `'normal'`
5. Optionally change `is_trusted` to `True`
6. Save

**Result:** User can login from this device (if IP is also unblocked)

---

### Option 2: Unblock IP Address

1. Go to Django Admin → IP Blocklist
2. Find the IP address
3. Change `is_active` to `False`
4. Save

**Result:** This IP is no longer blocked

---

### Option 3: Unblock Both

For complete access, unblock both:
1. Device (set `is_blocked = False`)
2. IP Address (set `is_active = False`)

**Result:** User can login normally

---

## Settings Configuration

### Required Settings (config/settings.py)

```python
# Enable geo-restriction
GEO_RESTRICTION_ENABLED = True

# Allowed countries (ISO 3166-1 alpha-2 codes)
ALLOWED_COUNTRIES = ['SA']  # Saudi Arabia only

# Auto-block devices from non-allowed countries
AUTO_BLOCK_DEVICES_FROM_BLOCKED_COUNTRIES = True

# Auto-add IPs to blocklist
AUTO_BLOCK_NON_ALLOWED_COUNTRY_IPS = True

# Auto-trust devices from allowed countries
AUTO_TRUST_DEVICES_FROM_ALLOWED_COUNTRIES = True
```

---

## Testing

### Test Script

Run the test script to verify behavior:

```bash
python test_blocked_country_records.py
```

**Prerequisites:**
1. Django server running: `python manage.py runserver`
2. Test user created: username='testuser', password='testpass123'

### Manual Testing

#### Test 1: Login from Blocked Country

```bash
curl -X POST http://127.0.0.1:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 103.108.140.1" \
  -d '{
    "username": "testuser",
    "password": "testpass123"
  }'
```

**Expected:** 400 error with device_id and login_event_id

#### Test 2: Login from Allowed Country

```bash
curl -X POST http://127.0.0.1:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 185.84.108.1" \
  -d '{
    "username": "testuser",
    "password": "testpass123"
  }'
```

**Expected:** 200 success with JWT tokens

---

## Verification Commands

### Django Shell

```python
python manage.py shell

# Check Device records
from frauddetect.models import Device
Device.objects.filter(user__username='testuser').values(
    'id', 'is_trusted', 'is_blocked', 'status', 'last_country_code', 'risk_score'
)

# Check IPBlocklist
from frauddetect.models import IPBlocklist
IPBlocklist.objects.all().values(
    'ip_address', 'reason', 'is_active', 'blocked_by__username'
)

# Check LoginEvent
from frauddetect.models import LoginEvent
LoginEvent.objects.filter(username='testuser').order_by('-attempt_time').values(
    'id', 'status', 'ip_address', 'country_code', 'is_suspicious', 'risk_score'
)

# Check SystemLog
from frauddetect.models import SystemLog
SystemLog.objects.filter(log_type='security').order_by('-created_at')[:10].values(
    'message', 'level', 'ip_address', 'created_at'
)
```

---

## Benefits

### 1. Complete Audit Trail
- Every login attempt is recorded
- Admins can see who tried to login from where
- Full history for compliance and security review

### 2. Flexible Management
- Admins can unblock legitimate users
- Can whitelist specific devices or IPs
- Can review and adjust security policies

### 3. Security First
- Blocks suspicious logins immediately
- Prevents unauthorized access
- Complies with KSA data residency requirements

### 4. User Experience
- Clear error messages
- Contact information provided
- Users know their attempt was recorded

---

## Superuser Bypass

**Important:** Superusers (is_superuser=True) bypass ALL fraud detection:
- No device blocking
- No IP blocking
- No geo-restriction
- Always trusted

**Regular staff (is_staff=True but is_superuser=False):**
- Subject to all fraud detection rules
- Can be blocked if from non-allowed country

---

## Troubleshooting

### Issue: Records not created

**Check:**
1. Is `AUTO_BLOCK_NON_ALLOWED_COUNTRY_IPS = True`?
2. Is `AUTO_BLOCK_DEVICES_FROM_BLOCKED_COUNTRIES = True`?
3. Is the country code detected correctly?
4. Check Django logs for errors

### Issue: Login not blocked

**Check:**
1. Is `GEO_RESTRICTION_ENABLED = True`?
2. Is the country in `ALLOWED_COUNTRIES`?
3. Is the user a superuser? (superusers bypass blocking)
4. Check middleware order in settings.py

### Issue: IP not added to blocklist

**Check:**
1. Is `AUTO_BLOCK_NON_ALLOWED_COUNTRY_IPS = True`?
2. Is there a superuser in the database? (needed for blocked_by field)
3. Check SystemLog for error messages

---

## Related Documentation

- [GEO_RESTRICTION_KSA_COMPLIANCE.md](GEO_RESTRICTION_KSA_COMPLIANCE.md) - Geo-restriction setup
- [AUTO_IP_BLOCKING_GUIDE.md](AUTO_IP_BLOCKING_GUIDE.md) - IP blocking details
- [DEVICE_MANAGEMENT_SUMMARY.md](DEVICE_MANAGEMENT_SUMMARY.md) - Device management
- [SUPERUSER_VS_STAFF.md](SUPERUSER_VS_STAFF.md) - Access control levels

---

## Summary

✅ **All records are created** before blocking
✅ **Admins can review and unblock** anytime
✅ **Complete audit trail** for compliance
✅ **Security maintained** with immediate blocking
✅ **Flexible management** for legitimate users
