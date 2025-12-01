# 🇸🇦 Geo-Restriction & KSA Compliance Guide

## 📋 Overview

This system implements **strict geographic access control** to comply with **Saudi Arabia data residency requirements**. Only users from Saudi Arabia (and optionally other specified countries) can access the application.

---

## 🎯 Key Features

### 1. **Geographic Access Control**
- ✅ Only allows access from Saudi Arabia by default
- ✅ Blocks all access from other countries
- ✅ Configurable to add more countries
- ✅ Runs BEFORE authentication (maximum security)

### 2. **Automatic Device Trust**
- ✅ Devices from Saudi Arabia are automatically trusted
- ✅ Devices from other countries are automatically blocked
- ✅ No manual device approval needed for KSA users

### 3. **Data Residency Compliance**
- ✅ Ensures all user data stays in Saudi Arabia
- ✅ Prevents access from unauthorized regions
- ✅ Comprehensive audit logging
- ✅ Meets regulatory requirements

---

## ⚙️ Configuration

### settings.py

```python
# ============================================
# GEO-RESTRICTION SETTINGS (KSA Compliance)
# ============================================

# Enable/disable geo-restriction
GEO_RESTRICTION_ENABLED = True  # Set to False to disable

# Allowed countries (ISO 3166-1 alpha-2 codes)
ALLOWED_COUNTRIES = [
    'SA',  # Saudi Arabia (Primary)
    # Add more countries as needed:
    # 'AE',  # United Arab Emirates
    # 'KW',  # Kuwait
    # 'QA',  # Qatar
    # 'BH',  # Bahrain
    # 'OM',  # Oman
]

# Action for non-allowed countries
# 'block' = Deny access (strict)
# 'flag' = Allow but mark suspicious (monitoring)
GEO_RESTRICTION_ACTION = 'block'

# Whitelist specific IPs (bypass geo-restriction)
GEO_RESTRICTION_WHITELIST_IPS = [
    # '203.0.113.50',  # Example: Office IP
    # '198.51.100.0/24',  # Example: Office network
]

# Auto-trust devices from allowed countries
AUTO_TRUST_DEVICES_FROM_ALLOWED_COUNTRIES = True

# Auto-block devices from non-allowed countries
AUTO_BLOCK_DEVICES_FROM_BLOCKED_COUNTRIES = True
```

---

## 🔒 Security Layers

### Layer 1: Geo-Restriction Middleware (FIRST)
```
Request → Check Country → Block if not SA → Continue if SA
```

**Purpose:** Block access from non-Saudi Arabia countries BEFORE any processing

**When it runs:** Before authentication, before IP blocklist, before everything

**What it does:**
1. Gets client IP address
2. Determines country from IP
3. Checks if country is in ALLOWED_COUNTRIES
4. Blocks request if not allowed
5. Logs the attempt

### Layer 2: IP Blocklist Middleware
```
Request → Check if IP blocked → Block if yes → Continue if no
```

### Layer 3: Device Fingerprint Middleware
```
Request → Track device → Auto-trust if from SA → Auto-block if not from SA
```

---

## 📊 How It Works

### Scenario 1: User from Saudi Arabia

```
┌─────────────────────────────────────────────────────────────┐
│  User Login from Saudi Arabia                               │
│  IP: 185.45.6.100                                           │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  GeoRestrictionMiddleware                                    │
│  • Detects country: SA (Saudi Arabia)                       │
│  • Checks: Is SA in ALLOWED_COUNTRIES? YES ✓                │
│  • Action: Allow request to continue                        │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  Authentication & Login                                      │
│  • User authenticates successfully                           │
│  • Device created/updated                                    │
│  • Device auto-trusted: is_trusted = True ✓                 │
│  • Risk score: Low                                           │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  Response: Login Successful                                  │
│  • Access token provided                                     │
│  • Device trusted                                            │
│  • Full access granted                                       │
└─────────────────────────────────────────────────────────────┘
```

---

### Scenario 2: User from Outside Saudi Arabia

```
┌─────────────────────────────────────────────────────────────┐
│  User Login from Bangladesh                                  │
│  IP: 103.106.239.104                                        │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  GeoRestrictionMiddleware                                    │
│  • Detects country: BD (Bangladesh)                         │
│  • Checks: Is BD in ALLOWED_COUNTRIES? NO ✗                 │
│  • Action: BLOCK REQUEST                                     │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  Response: 403 Forbidden                                     │
│  {                                                           │
│    "error": "Access Denied",                                │
│    "message": "Access restricted to Saudi Arabia only",     │
│    "country_detected": "Bangladesh",                        │
│    "country_code": "BD"                                     │
│  }                                                           │
│                                                              │
│  • Request STOPPED                                           │
│  • No authentication attempted                               │
│  • No database access                                        │
│  • Logged for audit                                          │
└─────────────────────────────────────────────────────────────┘
```

---

## 🌍 Adding More Countries

To allow access from additional countries, update `settings.py`:

```python
ALLOWED_COUNTRIES = [
    'SA',  # Saudi Arabia
    'AE',  # United Arab Emirates
    'KW',  # Kuwait
    'QA',  # Qatar
    'BH',  # Bahrain
    'OM',  # Oman
]
```

**Country Codes (ISO 3166-1 alpha-2):**
- SA = Saudi Arabia
- AE = United Arab Emirates
- KW = Kuwait
- QA = Qatar
- BH = Bahrain
- OM = Oman
- EG = Egypt
- JO = Jordan
- LB = Lebanon
- MA = Morocco
- TN = Tunisia
- TR = Turkey

[Full list: https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2]

---

## 🔓 IP Whitelisting

For admin access or testing from outside Saudi Arabia:

```python
GEO_RESTRICTION_WHITELIST_IPS = [
    '203.0.113.50',        # Single IP
    '198.51.100.0/24',     # IP range (CIDR)
    '192.0.2.0/24',        # Another range
]
```

**Use cases:**
- Admin access from office outside SA
- Testing from development environment
- Trusted partner access
- Emergency access

---

## 📝 Response Examples

### Blocked Access (Non-SA Country)

```json
{
  "error": "Access Denied",
  "message": "Access to this service is restricted to Saudi Arabia only.",
  "details": "This application complies with Saudi Arabia data residency requirements.",
  "country_detected": "Bangladesh",
  "country_code": "BD",
  "contact": "Please contact support if you believe this is an error."
}
```

### Successful Login (SA Country)

```json
{
  "access": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "refresh": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "user": {...},
  "device_id": 5,
  "device_trusted": true,  // ← Auto-trusted (from SA)
  "device_new": true,
  "security": {
    "risk_score": 5,       // ← Low risk (from SA)
    "risk_level": "low",
    "is_suspicious": false
  },
  "login_info": {
    "ip_address": "185.45.6.100",
    "country": "Saudi Arabia",
    "country_code": "SA",
    "city": "Riyadh"
  }
}
```

---

## 🧪 Testing

### Test 1: Access from Saudi Arabia

```bash
# This should work
curl -X POST http://localhost:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "pass123"}'
```

**Expected:** Login successful, device auto-trusted

---

### Test 2: Access from Outside SA (Simulated)

Since you're testing locally, the system will detect your actual location. To test geo-restriction:

1. **Temporarily disable for testing:**
   ```python
   # In settings.py
   GEO_RESTRICTION_ENABLED = False
   ```

2. **Or add your IP to whitelist:**
   ```python
   GEO_RESTRICTION_WHITELIST_IPS = [
       'YOUR_PUBLIC_IP',
   ]
   ```

3. **Or test in production** with actual Saudi Arabia server

---

### Test 3: Check Logs

```bash
# Start server and watch logs
python manage.py runserver

# Look for these messages:
# ✓ Geo-check passed: SA (Saudi Arabia) - IP: 185.45.6.100
# 🚫 GEO-BLOCKED: Access from BD (Bangladesh) - IP: 103.106.239.104
```

---

## 📊 Monitoring

### Check Blocked Attempts

```python
from frauddetect.models import SystemLog

# Get geo-blocked attempts
blocked = SystemLog.objects.filter(
    log_type='security',
    level='critical',
    message__contains='Geo-restriction'
).order_by('-created_at')

for log in blocked[:10]:
    print(f"{log.created_at}: {log.message}")
    print(f"  IP: {log.ip_address}")
    print(f"  Country: {log.metadata.get('country_name')}")
```

### Dashboard Metrics

Add to admin dashboard:
- Total geo-blocked attempts
- Countries attempting access
- Most blocked IPs
- Whitelist usage

---

## 🔧 Troubleshooting

### Issue 1: Can't access from Saudi Arabia

**Check:**
1. Is `GEO_RESTRICTION_ENABLED = True`?
2. Is 'SA' in `ALLOWED_COUNTRIES`?
3. Is geolocation API working?
4. Check console logs for country detection

**Solution:**
```python
# Temporarily disable to test
GEO_RESTRICTION_ENABLED = False
```

---

### Issue 2: Need access for testing

**Solution 1: Whitelist your IP**
```python
GEO_RESTRICTION_WHITELIST_IPS = [
    'YOUR_PUBLIC_IP',
]
```

**Solution 2: Disable temporarily**
```python
GEO_RESTRICTION_ENABLED = False
```

---

### Issue 3: Wrong country detected

**Check:**
- Geolocation API response
- IP address detection
- VPN/proxy usage

**Debug:**
```python
# In views.py, add:
print(f"Detected IP: {ip_address}")
print(f"Geo data: {geo_data}")
```

---

## 📋 Compliance Checklist

- [x] Geo-restriction enabled
- [x] Only Saudi Arabia allowed by default
- [x] Blocks access from other countries
- [x] Auto-trusts devices from SA
- [x] Auto-blocks devices from non-SA
- [x] Comprehensive logging
- [x] Audit trail maintained
- [x] Configurable for future expansion
- [x] IP whitelisting for exceptions
- [x] Runs before authentication

---

## 🎯 Production Deployment

### 1. Verify Settings

```python
# settings.py - Production
GEO_RESTRICTION_ENABLED = True
ALLOWED_COUNTRIES = ['SA']
GEO_RESTRICTION_ACTION = 'block'
AUTO_TRUST_DEVICES_FROM_ALLOWED_COUNTRIES = True
AUTO_BLOCK_DEVICES_FROM_BLOCKED_COUNTRIES = True
```

### 2. Test Thoroughly

- Test from Saudi Arabia IP
- Test from non-SA IP (should block)
- Test whitelist IPs
- Check logs

### 3. Monitor

- Set up alerts for geo-blocked attempts
- Review logs regularly
- Monitor for unusual patterns

---

## 📞 Support

For questions about:
- **KSA compliance:** Check with legal team
- **Adding countries:** Update `ALLOWED_COUNTRIES`
- **Whitelisting IPs:** Update `GEO_RESTRICTION_WHITELIST_IPS`
- **Technical issues:** Check logs and documentation

---

Your application now enforces strict geographic access control for Saudi Arabia compliance! 🇸🇦🔒
