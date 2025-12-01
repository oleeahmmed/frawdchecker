# 🔐 Login Fraud Detection System

## 🎯 Features

### 1. **Flexible Login**
- ✅ Login with username
- ✅ Login with email
- ✅ Both methods supported

### 2. **Comprehensive Fraud Detection**
- ✅ IP blocklist check
- ✅ Country risk assessment
- ✅ Velocity check (rate limiting)
- ✅ New device detection
- ✅ Device blocklist check
- ✅ Untrusted device detection
- ✅ IP change detection

### 3. **Real-time Risk Scoring**
- Risk score: 0-100
- Risk levels: low, medium, high
- Automatic blocking for high-risk logins

---

## 📊 Fraud Detection Rules

### Rule 1: IP Blocklist Check
**Risk Score:** +100 (BLOCKS LOGIN)

**Triggers when:**
- IP address is in the blocklist
- IP has been manually blocked by admin

**Action:**
- Login is blocked immediately
- Returns 403 error

```json
{
  "error": "Login blocked due to security concerns",
  "risk_score": 100,
  "reasons": ["IP address is blocked"]
}
```

---

### Rule 2: Country Risk Assessment
**Risk Score:** +5 to +30

**Triggers when:**
- Login from high-risk country: +30
- Login from medium-risk country: +15
- Login from low-risk country: +5

**Countries:**
```python
HIGH_RISK: ['YE', 'SY', 'IQ', 'SD', 'SO', 'LY', 'AF', 'IR', 'NG', 'PK', 'BD']
MEDIUM_RISK: ['EG', 'JO', 'MA', 'TN', 'TR', 'IN', 'CN', 'BR', 'MX']
LOW_RISK: ['SA', 'AE', 'KW', 'QA', 'BH', 'OM', 'US', 'CA', 'UK', 'GB', 'DE', 'FR']
```

---

### Rule 3: Velocity Check
**Risk Score:** +25

**Triggers when:**
- More than 10 login attempts in 1 hour
- Indicates potential brute force attack

**Action:**
- Marks login as suspicious
- Logs security event

---

### Rule 4: New Device Detection
**Risk Score:** +15

**Triggers when:**
- First time login from this device
- Device fingerprint not recognized

**Action:**
- Creates new device record
- Marks as untrusted by default
- May require additional verification

---

### Rule 5: Device Blocklist Check
**Risk Score:** +100 (BLOCKS LOGIN)

**Triggers when:**
- Device has been blocked by admin
- Device marked as compromised

**Action:**
- Login is blocked immediately
- Returns 403 error

---

### Rule 6: Untrusted Device
**Risk Score:** +10

**Triggers when:**
- Device exists but not marked as trusted
- User hasn't verified this device

**Action:**
- Increases risk score
- May require 2FA or email verification

---

### Rule 7: IP Change Detection
**Risk Score:** +20

**Triggers when:**
- Same device, different IP address
- Indicates VPN usage or location change

**Action:**
- Marks as suspicious
- Logs the IP change

---

## 🔄 Login Flow with Fraud Detection

```
┌─────────────────────────────────────────────────────────────┐
│                    LOGIN REQUEST                             │
│  POST /api/auth/login/                                       │
│  { "username": "john" OR "email": "john@example.com" }       │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  STEP 1: Validate Credentials                                │
│  • Check username or email provided                          │
│  • Authenticate user                                         │
│  • Check if account is active                                │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  STEP 2: Extract Request Data                                │
│  • Get IP address                                            │
│  • Calculate device fingerprint                              │
│  • Get geolocation                                           │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  STEP 3: Run Fraud Detection Rules                           │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Rule 1: IP Blocklist Check                           │  │
│  │  → If blocked: STOP (403 Error)                       │  │
│  └───────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Rule 2: Country Risk Assessment                      │  │
│  │  → Add risk score based on country                    │  │
│  └───────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Rule 3: Velocity Check                               │  │
│  │  → Check login attempts in last hour                  │  │
│  └───────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Rule 4: New Device Detection                         │  │
│  │  → Check if device is known                           │  │
│  └───────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Rule 5: Device Blocklist Check                       │  │
│  │  → If blocked: STOP (403 Error)                       │  │
│  └───────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Rule 6: Untrusted Device                             │  │
│  │  → Add risk score if not trusted                      │  │
│  └───────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Rule 7: IP Change Detection                          │  │
│  │  → Check if IP changed for known device               │  │
│  └───────────────────────────────────────────────────────┘  │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  STEP 4: Calculate Total Risk                                │
│  • Sum all risk scores                                       │
│  • Determine risk level (low/medium/high)                    │
│  • Decide if suspicious                                      │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  STEP 5: Create Login Event                                  │
│  • Save to database with risk assessment                     │
│  • Create system log                                         │
│  • Update device last seen                                   │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  STEP 6: Generate Response                                   │
│  • JWT tokens (access + refresh)                             │
│  • User information                                          │
│  • Device information                                        │
│  • Security assessment                                       │
│  • Location information                                      │
│  • Warning (if suspicious)                                   │
└─────────────────────────────────────────────────────────────┘
```

---

## 📝 API Examples

### Login with Username

```bash
curl -X POST http://localhost:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "password": "SecurePass123!"
  }'
```

### Login with Email

```bash
curl -X POST http://localhost:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "SecurePass123!"
  }'
```

### Response (Normal Login)

```json
{
  "access": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "refresh": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "user": {
    "id": 1,
    "username": "john_doe",
    "email": "john@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "is_staff": false
  },
  "device_id": 5,
  "device_trusted": true,
  "device_new": false,
  "security": {
    "risk_score": 15,
    "risk_level": "low",
    "is_suspicious": false,
    "requires_verification": false
  },
  "login_info": {
    "ip_address": "103.106.239.104",
    "country": "Bangladesh",
    "country_code": "BD",
    "city": "Dhaka",
    "region": "Dhaka Division"
  }
}
```

### Response (Suspicious Login)

```json
{
  "access": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "refresh": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "user": {...},
  "device_id": 12,
  "device_trusted": false,
  "device_new": true,
  "security": {
    "risk_score": 65,
    "risk_level": "medium",
    "is_suspicious": true,
    "requires_verification": true
  },
  "login_info": {...},
  "warning": "This login appears suspicious. Additional verification may be required."
}
```

### Response (Blocked Login)

```json
{
  "error": "Login blocked due to security concerns",
  "risk_score": 100,
  "reasons": [
    "IP address is blocked",
    "Device is blocked"
  ]
}
```

---

## 🧪 Testing

### Run Test Suite

```bash
python test_login_fraud_detection.py
```

### Manual Testing

1. **Normal Login:**
   ```bash
   # Should succeed with low risk score
   curl -X POST http://localhost:8000/api/auth/login/ \
     -H "Content-Type: application/json" \
     -d '{"username": "testuser", "password": "pass123"}'
   ```

2. **Login from New Device:**
   ```bash
   # Use different User-Agent
   curl -X POST http://localhost:8000/api/auth/login/ \
     -H "Content-Type: application/json" \
     -H "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)" \
     -d '{"username": "testuser", "password": "pass123"}'
   ```

3. **Rapid Login Attempts (Velocity Check):**
   ```bash
   # Run this 5 times quickly
   for i in {1..5}; do
     curl -X POST http://localhost:8000/api/auth/login/ \
       -H "Content-Type: application/json" \
       -d '{"username": "testuser", "password": "pass123"}'
     sleep 1
   done
   ```

---

## 📊 Monitoring

### Check Login Events

```python
# In Django shell
from frauddetect.models import LoginEvent

# Recent logins
LoginEvent.objects.order_by('-attempt_time')[:10]

# Suspicious logins
LoginEvent.objects.filter(is_suspicious=True)

# High-risk logins
LoginEvent.objects.filter(risk_score__gte=70)
```

### Check System Logs

```python
from frauddetect.models import SystemLog

# Security logs
SystemLog.objects.filter(log_type='security').order_by('-created_at')[:10]

# Blocked attempts
SystemLog.objects.filter(level='critical')
```

---

## 🛠️ Admin Actions

### Block an IP

```python
from frauddetect.models import IPBlocklist

IPBlocklist.objects.create(
    ip_address='203.0.113.50',
    reason='Multiple failed login attempts',
    blocked_by=admin_user,
    is_active=True
)
```

### Block a Device

```python
from frauddetect.models import Device

device = Device.objects.get(id=5)
device.is_blocked = True
device.status = 'blocked'
device.save()
```

### Trust a Device

```python
device = Device.objects.get(id=5)
device.is_trusted = True
device.status = 'normal'
device.save()
```

---

## 🎯 Risk Score Breakdown

| Risk Score | Risk Level | Action |
|-----------|-----------|--------|
| 0-39 | Low | Allow login |
| 40-69 | Medium | Allow but flag as suspicious |
| 70-99 | High | Allow but require verification |
| 100+ | Critical | Block login |

---

## ✅ Security Checklist

- [x] IP blocklist check before authentication
- [x] Device blocklist check after authentication
- [x] Country risk assessment
- [x] Velocity/rate limiting
- [x] New device detection
- [x] IP change detection
- [x] Comprehensive logging
- [x] Real-time risk scoring
- [x] Automatic blocking for critical risks
- [x] Flexible login (username or email)

---

Your login system now has enterprise-grade fraud detection! 🛡️
