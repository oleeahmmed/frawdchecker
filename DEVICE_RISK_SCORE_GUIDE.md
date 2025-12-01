# 📊 Device Risk Score System

## Overview

Every device now has a **risk score** (0-100) that indicates how risky the device is. This score is automatically calculated based on multiple factors.

---

## 🎯 Risk Score Levels

| Score | Level | Status | Action |
|-------|-------|--------|--------|
| 0-20 | **Low** | ✅ Trusted | Allow login |
| 21-50 | **Medium** | ⚠️ Suspicious | Allow but monitor |
| 51-100 | **High** | 🚫 Blocked | Block login |

---

## 📊 Risk Score Calculation

### Factor 1: Device Blocked Status (Critical)
```
IF device.is_blocked = True:
    risk_score = 100 (Maximum)
    → LOGIN BLOCKED
```

### Factor 2: Device Not Trusted
```
IF device.is_trusted = False:
    risk_score += 30
```

### Factor 3: Country Risk
```
IF country NOT in ALLOWED_COUNTRIES:
    risk_score += 40
```

### Factor 4: Device Status
```
IF device.status = 'blocked':
    risk_score += 50
ELIF device.status = 'suspicious':
    risk_score += 20
```

### Factor 5: New Device
```
IF device age < 24 hours:
    risk_score += 10
ELIF device age < 7 days:
    risk_score += 5
```

---

## 📝 Examples

### Example 1: Trusted Device from Saudi Arabia

```python
Device:
  - is_trusted: True
  - is_blocked: False
  - status: 'normal'
  - country: 'SA'
  - age: 30 days

Calculation:
  Base: 0
  + Not trusted: 0 (is trusted)
  + Country risk: 0 (SA is allowed)
  + Status: 0 (normal)
  + New device: 0 (old device)
  = Total: 0

Risk Level: LOW ✅
Action: Allow login
```

---

### Example 2: New Device from Saudi Arabia

```python
Device:
  - is_trusted: True
  - is_blocked: False
  - status: 'normal'
  - country: 'SA'
  - age: 2 hours

Calculation:
  Base: 0
  + Not trusted: 0 (is trusted)
  + Country risk: 0 (SA is allowed)
  + Status: 0 (normal)
  + New device: 10 (< 24 hours)
  = Total: 10

Risk Level: LOW ✅
Action: Allow login (but monitor)
```

---

### Example 3: Untrusted Device from Saudi Arabia

```python
Device:
  - is_trusted: False
  - is_blocked: False
  - status: 'suspicious'
  - country: 'SA'
  - age: 5 days

Calculation:
  Base: 0
  + Not trusted: 30
  + Country risk: 0 (SA is allowed)
  + Status: 20 (suspicious)
  + New device: 5 (< 7 days)
  = Total: 55

Risk Level: HIGH 🚫
Action: Block login
```

---

### Example 4: Device from Non-Allowed Country

```python
Device:
  - is_trusted: False
  - is_blocked: True
  - status: 'blocked'
  - country: 'BD'
  - age: 1 hour

Calculation:
  Base: 0
  + Blocked: 100 (CRITICAL)
  = Total: 100

Risk Level: HIGH 🚫
Action: Block login immediately
```

---

## 🔄 When Risk Score is Calculated

1. **Device Creation** - Initial risk score assigned
2. **Every Login** - Risk score recalculated
3. **Middleware Processing** - Updated in real-time

---

## 📊 Database Structure

```sql
CREATE TABLE devices (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    fingerprint_hash VARCHAR(64),
    is_trusted BOOLEAN,
    is_blocked BOOLEAN,
    status VARCHAR(20),
    risk_score INTEGER DEFAULT 0,  -- ← Risk Score (0-100)
    last_country_code VARCHAR(2),
    first_seen_at DATETIME,
    last_seen_at DATETIME
);
```

---

## 🔍 Viewing Device Risk Scores

### In Admin Panel

1. Go to: `http://localhost:8000/admin/frauddetect/device/`
2. You'll see `risk_score` column for each device
3. Sort by risk_score to see highest risk devices

### Via API

```bash
curl -X GET http://localhost:8000/api/devices/ \
  -H "Authorization: Bearer <token>"
```

Response:
```json
{
  "results": [
    {
      "id": 5,
      "user": {...},
      "is_trusted": true,
      "is_blocked": false,
      "status": "normal",
      "risk_score": 10,  // ← Risk Score
      "last_country_code": "SA"
    }
  ]
}
```

### In Python

```python
from frauddetect.models import Device

# Get high-risk devices
high_risk = Device.objects.filter(risk_score__gte=51)

for device in high_risk:
    print(f"Device {device.id}: Risk={device.risk_score}")
```

---

## 📝 Response Examples

### Blocked Device Login (with Risk Score)

```json
{
  "error": "Device Blocked",
  "message": "This device has been blocked because it is not from an allowed country.",
  "device_id": 12,
  "device_risk_score": 100,
  "device_risk_level": "high",
  "country_detected": "Bangladesh",
  "country_code": "BD"
}
```

### Successful Login (with Risk Score)

```json
{
  "access": "token...",
  "device_id": 5,
  "device_trusted": true,
  "device_risk_score": 10,
  "device_risk_level": "low",
  "security": {
    "risk_score": 5,
    "risk_level": "low"
  }
}
```

---

## 🧪 Testing

### Check Device Risk Scores

```python
from frauddetect.models import Device
from frauddetect.utils import calculate_device_risk_score, get_device_risk_level

# Get a device
device = Device.objects.get(id=5)

# Calculate risk score
risk_score = calculate_device_risk_score(device, 'SA')
risk_level = get_device_risk_level(risk_score)

print(f"Device {device.id}:")
print(f"  Risk Score: {risk_score}")
print(f"  Risk Level: {risk_level}")
print(f"  Is Trusted: {device.is_trusted}")
print(f"  Is Blocked: {device.is_blocked}")
```

---

## 📊 Console Logs

When a user logs in, you'll see:

```
✓ NEW DEVICE TRUSTED: User=john_doe, Country=SA, Device=5, Risk=10
✓ EXISTING DEVICE: User=john_doe, Device=5, Risk=10, Trusted=True
```

Or if blocked:

```
🚫 NEW DEVICE BLOCKED: User=john_doe, Country=BD, Device=12, Risk=100
🚫 LOGIN BLOCKED: Device 12 is blocked for user john_doe, Risk Score=100
```

---

## 🎯 Key Benefits

1. **Quantifiable Risk** - Exact number instead of just "suspicious"
2. **Transparent** - Users can see why device is risky
3. **Actionable** - Clear thresholds for blocking
4. **Auditable** - Risk score stored in database
5. **Flexible** - Easy to adjust thresholds

---

## ⚙️ Customization

### Adjust Risk Thresholds

Edit `frauddetect/utils.py`:

```python
def calculate_device_risk_score(device, country_code='Unknown'):
    risk_score = 0
    
    # Adjust these values:
    if not device.is_trusted:
        risk_score += 30  # Change this
    
    if country_code not in allowed_countries:
        risk_score += 40  # Change this
    
    # ... etc
```

### Adjust Risk Levels

```python
def get_device_risk_level(risk_score):
    if risk_score >= 51:  # Change threshold
        return 'high'
    elif risk_score >= 21:  # Change threshold
        return 'medium'
    else:
        return 'low'
```

---

Your devices now have quantifiable risk scores! 📊🔒
