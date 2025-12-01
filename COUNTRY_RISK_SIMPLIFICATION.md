# Country Risk Simplification

## Date: December 2, 2025

## Overview

Simplified the country risk assessment system from a 3-tier approach (HIGH/MEDIUM/LOW) to a simple binary approach (ALLOWED/NOT ALLOWED).

---

## Changes Made

### Before (Complex 3-Tier System)

```python
# settings.py
HIGH_RISK_COUNTRIES = ['YE', 'SY', 'IQ', 'SD', 'SO', 'LY', 'AF', 'IR', 'NG', 'PK', 'BD']
MEDIUM_RISK_COUNTRIES = ['EG', 'JO', 'MA', 'TN', 'TR', 'IN', 'CN', 'BR', 'MX']
LOW_RISK_COUNTRIES = ['SA', 'AE', 'KW', 'QA', 'BH', 'OM', 'US', 'CA', 'UK', 'GB', 'DE', 'FR']

# utils.py
def get_country_risk_level(country_code):
    if country in HIGH_RISK_COUNTRIES:
        return {'level': 'high', 'score': 30, ...}
    elif country in MEDIUM_RISK_COUNTRIES:
        return {'level': 'medium', 'score': 15, ...}
    elif country in LOW_RISK_COUNTRIES:
        return {'level': 'low', 'score': 5, ...}
    else:
        return {'level': 'medium', 'score': 20, ...}
```

### After (Simple Binary System)

```python
# settings.py
ALLOWED_COUNTRIES = ['SA', 'BD']  # Only these countries are allowed
# No need for HIGH_RISK_COUNTRIES, MEDIUM_RISK_COUNTRIES, LOW_RISK_COUNTRIES

# utils.py
def get_country_risk_level(country_code):
    allowed_countries = getattr(settings, 'ALLOWED_COUNTRIES', ['SA'])
    
    if country in allowed_countries:
        return {'level': 'low', 'score': 0, 'reason': 'Allowed Country'}
    else:
        return {'level': 'high', 'score': 50, 'reason': 'Non-Allowed Country'}
```

---

## Benefits

### 1. Simplicity
- Only one setting to manage: `ALLOWED_COUNTRIES`
- Clear binary decision: allowed or not allowed
- No confusion about risk levels

### 2. Consistency
- All non-allowed countries treated equally
- No need to categorize countries into risk tiers
- Easier to understand and maintain

### 3. Security
- Stricter approach: non-allowed = high risk
- Clear compliance with KSA requirements
- No gray areas

### 4. Maintainability
- Less configuration to manage
- Easier to add/remove allowed countries
- No need to update multiple lists

---

## Risk Score Changes

### Before

| Country Type | Risk Score | Example |
|-------------|------------|---------|
| High Risk | +30 | Bangladesh, Pakistan |
| Medium Risk | +15 | Egypt, India |
| Low Risk | +5 | Saudi Arabia, UAE |
| Unknown | +20 | Any other country |

### After

| Country Type | Risk Score | Example |
|-------------|------------|---------|
| Allowed | 0 | Saudi Arabia, Bangladesh |
| Not Allowed | +50 | All other countries |
| Unknown | +50 | Unknown country |

---

## Files Modified

### 1. `config/settings.py`
- Removed `HIGH_RISK_COUNTRIES`
- Removed `MEDIUM_RISK_COUNTRIES`
- Removed `LOW_RISK_COUNTRIES`
- Added comment explaining simplified approach

### 2. `frauddetect/utils.py`
- Updated `get_country_risk_level()` function
- Now only checks `ALLOWED_COUNTRIES`
- Returns score 0 for allowed, 50 for not allowed

### 3. `frauddetect/views.py`
- Updated comment in login view
- Changed "High-risk country" to "Non-allowed country"
- Logic remains the same (checks `level != 'low'`)

### 4. `frauddetect/signals.py`
- Updated comment in login signal
- Changed "উচ্চ ঝুঁকির দেশ" to "অনুমোদিত নয় এমন দেশ"
- Logic remains the same (checks `level != 'low'`)

---

## Configuration

### Current Settings

```python
# config/settings.py

# Allowed countries (ISO 3166-1 alpha-2 codes)
ALLOWED_COUNTRIES = [
    'SA',  # Saudi Arabia (Primary)
    'BD',  # Bangladesh (for testing)
]

# All other countries are automatically considered high-risk
# and will be blocked if AUTO_BLOCK_DEVICES_FROM_BLOCKED_COUNTRIES = True
```

### To Add More Countries

Simply add to the `ALLOWED_COUNTRIES` list:

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

---

## Behavior

### Allowed Country (e.g., Saudi Arabia)

```
User from SA → Country Risk: 0 → Device: Trusted → Login: Success
```

### Not Allowed Country (e.g., India)

```
User from IN → Country Risk: 50 → Device: Blocked → Login: Blocked
```

---

## Testing

### Test Allowed Country

```bash
curl -X POST http://127.0.0.1:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 185.84.108.1" \
  -d '{"username": "testuser", "password": "testpass123"}'
```

**Expected:** Login success with risk_score = 0

### Test Not Allowed Country

```bash
curl -X POST http://127.0.0.1:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 103.108.140.1" \
  -d '{"username": "testuser", "password": "testpass123"}'
```

**Expected:** Login blocked with risk_score = 50+

---

## Backward Compatibility

✅ **Fully backward compatible:**
- Existing code that checks `country_risk['level'] != 'low'` still works
- No database changes required
- No API changes
- Existing devices and login events remain valid

---

## Migration Notes

### No Database Migration Needed

The changes are only in:
- Settings configuration
- Risk calculation logic
- No model changes

### No Code Changes Needed

If you have custom code that uses:
- `country_risk['level']` - Still works (returns 'low' or 'high')
- `country_risk['score']` - Still works (returns 0 or 50)
- `country_risk['reason']` - Still works (returns descriptive text)

---

## Summary

✅ **Simplified from 3-tier to binary**
✅ **Only ALLOWED_COUNTRIES setting needed**
✅ **Clearer security model**
✅ **Easier to maintain**
✅ **Fully backward compatible**
✅ **No database changes**

---

## Related Settings

```python
# config/settings.py

# Enable geo-restriction
GEO_RESTRICTION_ENABLED = True

# Allowed countries (binary approach)
ALLOWED_COUNTRIES = ['SA', 'BD']

# Auto-block devices from non-allowed countries
AUTO_BLOCK_DEVICES_FROM_BLOCKED_COUNTRIES = True

# Auto-add IPs to blocklist
AUTO_BLOCK_NON_ALLOWED_COUNTRY_IPS = True

# Auto-trust devices from allowed countries
AUTO_TRUST_DEVICES_FROM_ALLOWED_COUNTRIES = True
```

All these settings work together to provide a simple, secure, and maintainable system.
