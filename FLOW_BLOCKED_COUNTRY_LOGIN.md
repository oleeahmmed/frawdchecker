# Complete Flow: Blocked Country Login

## Scenario: User from Bangladesh tries to login

**User:** testuser  
**Country:** Bangladesh (BD) - NOT in ALLOWED_COUNTRIES  
**IP:** 103.108.140.1  
**Expected:** Login blocked, but all records created

---

## Step-by-Step Flow

### Step 1: User Sends Login Request

```bash
POST /api/auth/login/
{
  "username": "testuser",
  "password": "testpass123"
}
```

**Headers:**
- `X-Forwarded-For: 103.108.140.1` (Bangladesh IP)
- `User-Agent: Mozilla/5.0 ...`

---

### Step 2: GeoRestrictionMiddleware (BYPASSED)

```python
# frauddetect/middleware.py - GeoRestrictionMiddleware

# Skip for login endpoint (authentication not done yet)
if request.path.startswith('/api/auth/'):
    return None  # Continue to next middleware
```

**Result:** ✅ Passes through (login endpoint is exempt)

---

### Step 3: Authentication

```python
# frauddetect/views.py - CustomTokenObtainPairSerializer

# Verify username and password
user = authenticate(username='testuser', password='testpass123')
```

**Result:** ✅ User authenticated (credentials valid)

---

### Step 4: Get Geolocation

```python
# frauddetect/utils.py - get_geo_location()

ip_address = '103.108.140.1'
geo_data = get_geo_location(ip_address)

# Returns:
{
    'country_code': 'BD',
    'country_name': 'Bangladesh',
    'city': 'Dhaka',
    'region': 'Dhaka Division'
}
```

**Result:** ✅ Country detected: Bangladesh (BD)

---

### Step 5: Check Allowed Countries

```python
# config/settings.py

ALLOWED_COUNTRIES = ['SA']  # Only Saudi Arabia

# Check
country_code = 'BD'
is_from_allowed_country = 'BD' in ['SA']  # False
```

**Result:** ❌ Bangladesh is NOT in allowed countries

---

### Step 6: Create/Update Device (ALWAYS)

```python
# frauddetect/views.py - CustomTokenObtainPairSerializer

device, created = Device.objects.get_or_create(
    user=user,
    fingerprint_hash=fingerprint_hash,
    defaults={
        'last_ip': '103.108.140.1',
        'is_trusted': False,  # Not from allowed country
        'is_blocked': True,   # Auto-block
        'status': 'blocked',
        'last_country_code': 'BD',
        'risk_score': 70
    }
)
```

**Result:** ✅ Device created with `is_blocked=True`

**Database Record:**
```python
Device(
    id=5,
    user=testuser,
    is_blocked=True,
    is_trusted=False,
    status='blocked',
    last_country_code='BD',
    risk_score=70
)
```

---

### Step 7: Add IP to Blocklist (ALWAYS)

```python
# frauddetect/views.py - CustomTokenObtainPairSerializer

# Check if IP already blocked
ip_already_blocked = IPBlocklist.objects.filter(
    ip_address='103.108.140.1'
).exists()

if not ip_already_blocked:
    # Get first superuser
    system_admin = User.objects.filter(is_superuser=True).first()
    
    # Create blocklist entry
    IPBlocklist.objects.create(
        ip_address='103.108.140.1',
        reason='Automatic block: Login attempt from non-allowed country BD (Bangladesh)',
        is_active=True,
        blocked_by=system_admin
    )
```

**Result:** ✅ IP added to blocklist

**Database Record:**
```python
IPBlocklist(
    id=3,
    ip_address='103.108.140.1',
    reason='Automatic block: Login attempt from non-allowed country BD (Bangladesh)',
    is_active=True,
    blocked_by=admin_user
)
```

---

### Step 8: Calculate Risk Score

```python
# frauddetect/views.py - CustomTokenObtainPairSerializer

risk_score = 0
risk_reasons = []

# Rule 1: IP is blocked
risk_score += 100
risk_reasons.append('IP address is blocked')

# Rule 2: Device is blocked
risk_score += 100
risk_reasons.append('Device is blocked (not from allowed country)')

# Rule 3: New device
risk_score += 15
risk_reasons.append('Login from new device')

# Total risk_score = 215
should_block = True  # Because device.is_blocked = True
```

**Result:** ⚠️ Risk Score = 215 (Critical)

---

### Step 9: Create LoginEvent (ALWAYS)

```python
# frauddetect/views.py - CustomTokenObtainPairSerializer

login_event = LoginEvent.objects.create(
    user=user,
    username='testuser',
    device=device,
    status='blocked',  # Because should_block = True
    ip_address='103.108.140.1',
    country_code='BD',
    city='Dhaka',
    is_suspicious=True,
    risk_score=215,
    risk_reasons=[
        'IP address is blocked',
        'Device is blocked (not from allowed country)',
        'Login from new device'
    ],
    user_agent='Mozilla/5.0 ...'
)
```

**Result:** ✅ LoginEvent created with `status='blocked'`

**Database Record:**
```python
LoginEvent(
    id=12,
    user=testuser,
    status='blocked',
    ip_address='103.108.140.1',
    country_code='BD',
    is_suspicious=True,
    risk_score=215,
    risk_reasons=['IP address is blocked', 'Device is blocked', ...]
)
```

---

### Step 10: Create SystemLog Entries (ALWAYS)

```python
# frauddetect/views.py - CustomTokenObtainPairSerializer

# Log 1: Device creation
SystemLog.objects.create(
    log_type='security',
    level='warning',
    message='New device blocked for testuser from BD',
    user=user,
    ip_address='103.108.140.1'
)

# Log 2: IP blocklist
SystemLog.objects.create(
    log_type='security',
    level='critical',
    message='IP 103.108.140.1 automatically added to blocklist during login',
    user=user,
    ip_address='103.108.140.1'
)

# Log 3: Login blocked
SystemLog.objects.create(
    log_type='security',
    level='critical',
    message='Blocked login attempt for testuser from 103.108.140.1',
    user=user,
    ip_address='103.108.140.1'
)
```

**Result:** ✅ Three SystemLog entries created

---

### Step 11: Block Login (AFTER all records created)

```python
# frauddetect/views.py - CustomTokenObtainPairSerializer

if should_block:
    raise serializers.ValidationError({
        'error': 'Login blocked due to security concerns',
        'message': 'Your login attempt has been blocked. All details have been recorded.',
        'risk_score': 215,
        'reasons': risk_reasons,
        'device_id': 5,
        'login_event_id': 12,
        'country_detected': 'Bangladesh',
        'country_code': 'BD',
        'contact': 'Please contact support if you believe this is an error.'
    })
```

**Result:** 🚫 Login blocked with 400 error

---

### Step 12: API Response

```json
HTTP/1.1 400 Bad Request
Content-Type: application/json

{
  "error": "Login blocked due to security concerns",
  "message": "Your login attempt has been blocked. All details have been recorded.",
  "risk_score": 215,
  "reasons": [
    "IP address is blocked",
    "Device is blocked (not from allowed country)",
    "Login from new device"
  ],
  "device_id": 5,
  "login_event_id": 12,
  "country_detected": "Bangladesh",
  "country_code": "BD",
  "contact": "Please contact support if you believe this is an error."
}
```

---

## Database State After Blocked Login

### Device Table

| id | user | is_blocked | is_trusted | status | last_country_code | risk_score |
|----|------|------------|------------|--------|-------------------|------------|
| 5 | testuser | **True** | False | blocked | BD | 70 |

### IPBlocklist Table

| id | ip_address | reason | is_active | blocked_by |
|----|------------|--------|-----------|------------|
| 3 | 103.108.140.1 | Automatic block: Login attempt from non-allowed country BD | **True** | admin |

### LoginEvent Table

| id | user | status | ip_address | country_code | is_suspicious | risk_score |
|----|------|--------|------------|--------------|---------------|------------|
| 12 | testuser | **blocked** | 103.108.140.1 | BD | True | 215 |

### SystemLog Table

| id | log_type | level | message |
|----|----------|-------|---------|
| 45 | security | warning | New device blocked for testuser from BD |
| 46 | security | critical | IP 103.108.140.1 automatically added to blocklist |
| 47 | security | critical | Blocked login attempt for testuser from 103.108.140.1 |

---

## Admin Unblocking Process

### Option 1: Unblock Device Only

```python
device = Device.objects.get(id=5)
device.is_blocked = False
device.status = 'normal'
device.save()
```

**Result:** Device unblocked, but IP still blocked → Login still fails

---

### Option 2: Unblock IP Only

```python
ip_block = IPBlocklist.objects.get(ip_address='103.108.140.1')
ip_block.is_active = False
ip_block.save()
```

**Result:** IP unblocked, but device still blocked → Login still fails

---

### Option 3: Unblock Both (RECOMMENDED)

```python
# Unblock device
device = Device.objects.get(id=5)
device.is_blocked = False
device.is_trusted = True  # Optional: trust the device
device.status = 'normal'
device.save()

# Unblock IP
ip_block = IPBlocklist.objects.get(ip_address='103.108.140.1')
ip_block.is_active = False
ip_block.save()
```

**Result:** ✅ User can now login successfully

---

## Comparison: Before vs After

### BEFORE (Old Behavior)

```
Login from BD → GeoRestrictionMiddleware blocks → 403 error
❌ No Device record
❌ No IPBlocklist record
❌ No LoginEvent record
❌ No audit trail
```

### AFTER (New Behavior)

```
Login from BD → Authentication → Device created → IP blocked → LoginEvent created → 400 error
✅ Device record (is_blocked=True)
✅ IPBlocklist record (is_active=True)
✅ LoginEvent record (status='blocked')
✅ Complete audit trail
✅ Admin can unblock later
```

---

## Key Benefits

1. **Complete Audit Trail:** Every login attempt is recorded
2. **Flexible Management:** Admins can unblock legitimate users
3. **Security Maintained:** Suspicious logins still blocked immediately
4. **Compliance:** Full history for regulatory requirements
5. **User Experience:** Clear error messages with contact info

---

## Related Files

- **Middleware:** `frauddetect/middleware.py`
- **Views:** `frauddetect/views.py`
- **Models:** `frauddetect/models.py`
- **Settings:** `config/settings.py`
- **Test:** `test_blocked_country_records.py`
- **Docs:** `BLOCKED_COUNTRY_RECORDS.md`, `BLOCKED_COUNTRY_BANGLA.md`
