# 🔐 Device Management Flow - Complete Guide

## 📊 How Device Management Works

### Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         USER LOGIN REQUEST                               │
│                    POST /api/auth/login/                                 │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  STEP 1: GeoRestrictionMiddleware (BEFORE Authentication)               │
│  ───────────────────────────────────────────────────────────────────    │
│  • Get IP address                                                        │
│  • Get country from IP                                                   │
│  • Check: Is country in ALLOWED_COUNTRIES?                              │
│                                                                           │
│  IF NOT in ALLOWED_COUNTRIES:                                            │
│    → BLOCK REQUEST (403 Forbidden)                                       │
│    → Return error message                                                │
│    → STOP HERE                                                           │
│                                                                           │
│  IF in ALLOWED_COUNTRIES:                                                │
│    → Continue to next step                                               │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  STEP 2: IPBlocklistMiddleware (BEFORE Authentication)                  │
│  ───────────────────────────────────────────────────────────────────    │
│  • Check if IP is in blocklist                                           │
│                                                                           │
│  IF IP is blocked:                                                       │
│    → BLOCK REQUEST (403 Forbidden)                                       │
│    → STOP HERE                                                           │
│                                                                           │
│  IF IP is not blocked:                                                   │
│    → Continue to authentication                                          │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  STEP 3: Authentication (Login View)                                     │
│  ───────────────────────────────────────────────────────────────────    │
│  • Validate username/email and password                                  │
│  • Authenticate user                                                     │
│  • Generate JWT tokens                                                   │
│                                                                           │
│  IF authentication fails:                                                │
│    → Return 401 Unauthorized                                             │
│    → STOP HERE                                                           │
│                                                                           │
│  IF authentication succeeds:                                             │
│    → User is now authenticated                                           │
│    → Continue to device tracking                                         │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  STEP 4: DeviceFingerprintMiddleware (AFTER Authentication)             │
│  ═══════════════════════════════════════════════════════════════════    │
│  THIS IS WHERE DEVICE MANAGEMENT HAPPENS                                 │
│  ═══════════════════════════════════════════════════════════════════    │
│                                                                           │
│  A. Calculate device fingerprint                                         │
│     • User-Agent + Language + Encoding → Hash                            │
│                                                                           │
│  B. Get geolocation                                                      │
│     • IP → Country Code (e.g., SA, BD, US)                              │
│                                                                           │
│  C. Check if device exists in database                                   │
│     • Query: Device.objects.get(user=user, fingerprint=hash)            │
│                                                                           │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  CASE 1: Device NOT Found (New Device)                          │   │
│  │  ─────────────────────────────────────────────────────────────  │   │
│  │                                                                   │   │
│  │  IF country in ALLOWED_COUNTRIES (e.g., SA):                     │   │
│  │    → Create device with:                                         │   │
│  │       • is_trusted = TRUE  ✓                                     │   │
│  │       • is_blocked = FALSE                                       │   │
│  │       • status = 'normal'                                        │   │
│  │    → Log: "NEW DEVICE TRUSTED"                                   │   │
│  │    → Allow login to continue                                     │   │
│  │                                                                   │   │
│  │  IF country NOT in ALLOWED_COUNTRIES (e.g., BD):                 │   │
│  │    → Create device with:                                         │   │
│  │       • is_trusted = FALSE                                       │   │
│  │       • is_blocked = TRUE  🚫                                    │   │
│  │       • status = 'blocked'                                       │   │
│  │    → Log: "NEW DEVICE BLOCKED"                                   │   │
│  │    → BLOCK LOGIN (403 Forbidden)                                 │   │
│  │    → Return error message                                        │   │
│  │    → STOP HERE                                                   │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                           │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  CASE 2: Device Found (Existing Device)                         │   │
│  │  ─────────────────────────────────────────────────────────────  │   │
│  │                                                                   │   │
│  │  Check device.is_blocked:                                        │   │
│  │                                                                   │   │
│  │  IF device.is_blocked = TRUE:                                    │   │
│  │    → Log: "LOGIN BLOCKED - Device is blocked"                    │   │
│  │    → BLOCK LOGIN (403 Forbidden)                                 │   │
│  │    → Return error message                                        │   │
│  │    → STOP HERE                                                   │   │
│  │                                                                   │   │
│  │  IF device.is_blocked = FALSE:                                   │   │
│  │    → Update device:                                              │   │
│  │       • last_seen_at = now()                                     │   │
│  │       • last_ip = current_ip                                     │   │
│  │    → Log: "DEVICE ALLOWED"                                       │   │
│  │    → Allow login to continue                                     │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                           │
│  D. Attach device to request                                             │
│     • request.device = device                                            │
│     • Available in views                                                 │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  STEP 5: Login View Continues (Fraud Detection)                         │
│  ───────────────────────────────────────────────────────────────────    │
│  • Run fraud detection rules                                             │
│  • Calculate risk score                                                  │
│  • Create login event                                                    │
│  • Return JWT tokens + user info                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 🎯 Key Rules

### Rule 1: Country-Based Device Trust
```python
IF device from ALLOWED_COUNTRIES (e.g., SA):
    → is_trusted = True
    → is_blocked = False
    → Allow login ✓

IF device NOT from ALLOWED_COUNTRIES:
    → is_trusted = False
    → is_blocked = True
    → Block login 🚫
```

### Rule 2: Blocked Device Check
```python
IF device.is_blocked = True:
    → Block login immediately
    → Return 403 Forbidden
    → No further processing

IF device.is_blocked = False:
    → Allow login to continue
```

---

## 📝 Examples

### Example 1: First Login from Saudi Arabia

```
User: john_doe
IP: 185.45.6.100
Country: SA (Saudi Arabia)
Device: New (not in database)

Flow:
1. Geo-restriction: SA in ALLOWED_COUNTRIES? YES ✓
2. IP blocklist: IP blocked? NO ✓
3. Authentication: Credentials valid? YES ✓
4. Device check: Device exists? NO
   → Create new device:
      • is_trusted = TRUE
      • is_blocked = FALSE
      • status = 'normal'
   → Log: "NEW DEVICE TRUSTED"
5. Continue with fraud detection
6. Return: Login successful ✓

Result: ✅ LOGIN ALLOWED
Device Status: TRUSTED
```

---

### Example 2: First Login from Bangladesh

```
User: john_doe
IP: 103.106.239.104
Country: BD (Bangladesh)
Device: New (not in database)

Flow:
1. Geo-restriction: BD in ALLOWED_COUNTRIES? NO
   → BLOCK REQUEST (403)
   → STOP HERE

Result: 🚫 ACCESS DENIED (Geo-restriction)
Message: "Access restricted to Saudi Arabia only"
```

---

### Example 3: Second Login from Saudi Arabia (Same Device)

```
User: john_doe
IP: 185.45.6.100
Country: SA (Saudi Arabia)
Device: Exists (device_id = 5, is_trusted = True, is_blocked = False)

Flow:
1. Geo-restriction: SA in ALLOWED_COUNTRIES? YES ✓
2. IP blocklist: IP blocked? NO ✓
3. Authentication: Credentials valid? YES ✓
4. Device check: Device exists? YES
   → Check: is_blocked? NO
   → Update device:
      • last_seen_at = now()
      • last_ip = 185.45.6.100
   → Log: "DEVICE ALLOWED"
5. Continue with fraud detection
6. Return: Login successful ✓

Result: ✅ LOGIN ALLOWED
Device Status: TRUSTED (existing)
```

---

### Example 4: Login from Blocked Device

```
User: john_doe
IP: 198.51.100.25
Country: US (United States)
Device: Exists (device_id = 12, is_trusted = False, is_blocked = True)

Flow:
1. Geo-restriction: US in ALLOWED_COUNTRIES? NO
   → BLOCK REQUEST (403)
   → STOP HERE

Alternative (if geo-restriction was bypassed somehow):
1. Authentication: Credentials valid? YES ✓
2. Device check: Device exists? YES
   → Check: is_blocked? YES
   → BLOCK LOGIN (403)
   → Log: "LOGIN BLOCKED - Device is blocked"
   → STOP HERE

Result: 🚫 LOGIN BLOCKED
Message: "Device blocked - not from allowed country"
```

---

## 🗄️ Database Structure

### Device Table

```sql
CREATE TABLE frauddetect_device (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    fingerprint_hash VARCHAR(64),
    device_fingerprint TEXT,
    last_ip VARCHAR(45),
    last_seen_at DATETIME,
    is_trusted BOOLEAN,      -- TRUE if from ALLOWED_COUNTRIES
    is_blocked BOOLEAN,      -- TRUE if NOT from ALLOWED_COUNTRIES
    status VARCHAR(20),      -- 'normal' or 'blocked'
    created_at DATETIME,
    updated_at DATETIME
);
```

### Example Records

```
┌────┬─────────┬──────────────┬─────────────┬──────────────┬──────────────┬────────┐
│ id │ user_id │ fingerprint  │ last_ip     │ is_trusted   │ is_blocked   │ status │
├────┼─────────┼──────────────┼─────────────┼──────────────┼──────────────┼────────┤
│ 1  │ 1       │ abc123...    │ 185.45.6.1  │ TRUE         │ FALSE        │ normal │  ← SA device
│ 2  │ 1       │ def456...    │ 103.106.2.1 │ FALSE        │ TRUE         │ blocked│  ← BD device
│ 3  │ 2       │ ghi789...    │ 185.45.7.1  │ TRUE         │ FALSE        │ normal │  ← SA device
└────┴─────────┴──────────────┴─────────────┴──────────────┴──────────────┴────────┘
```

---

## 🔧 Configuration

### settings.py

```python
# Enable geo-restriction
GEO_RESTRICTION_ENABLED = True

# Allowed countries
ALLOWED_COUNTRIES = ['SA']  # Only Saudi Arabia

# Auto-trust devices from allowed countries
AUTO_TRUST_DEVICES_FROM_ALLOWED_COUNTRIES = True

# Auto-block devices from non-allowed countries
AUTO_BLOCK_DEVICES_FROM_BLOCKED_COUNTRIES = True
```

---

## 📊 Response Examples

### Successful Login (Trusted Device)

```json
{
  "access": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "refresh": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "user": {...},
  "device_id": 5,
  "device_trusted": true,
  "device_new": false,
  "security": {
    "risk_score": 5,
    "risk_level": "low"
  }
}
```

### Blocked Login (Blocked Device)

```json
{
  "error": "Device Blocked",
  "message": "This device has been blocked because it is not from an allowed country.",
  "details": "Access is restricted to Saudi Arabia only.",
  "device_id": 12,
  "country_detected": "Bangladesh",
  "country_code": "BD",
  "contact": "Please contact support if you believe this is an error."
}
```

---

## 🧪 Testing

### Test 1: Login from SA (Should Work)

```bash
# Assuming your server is in SA or you've whitelisted your IP
curl -X POST http://localhost:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "pass123"}'

# Expected: Success, device trusted
```

### Test 2: Check Device in Admin

1. Go to: `http://localhost:8000/admin/frauddetect/device/`
2. Find your device
3. Check:
   - ✅ is_trusted = True (if from SA)
   - ✅ is_blocked = False (if from SA)
   - ✅ status = 'normal' (if from SA)

---

## 📝 Console Logs

When you login, you'll see:

```
🔍 Login attempt - User: john_doe, IP: 185.45.6.100
📍 Location: Saudi Arabia (SA) - Riyadh
✓ Geo-check passed: SA (Saudi Arabia) - IP: 185.45.6.100
✓ NEW DEVICE TRUSTED: User=john_doe, Country=SA, Device=5
✓ DEVICE ALLOWED: Device 5 (trusted=True) for user john_doe
✓ Login event created: ID=1, Risk=5, Suspicious=False
```

Or if blocked:

```
🔍 Login attempt - User: john_doe, IP: 103.106.239.104
📍 Location: Bangladesh (BD) - Dhaka
🚫 GEO-BLOCKED: Access from BD (Bangladesh) - IP: 103.106.239.104
```

---

Your device management is now fully automated based on country! 🇸🇦🔒
