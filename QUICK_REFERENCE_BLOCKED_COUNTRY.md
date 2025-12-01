# Quick Reference: Blocked Country Login

## What Changed?

**BEFORE:** Login from non-allowed country → Blocked immediately → No records created

**NOW:** Login from non-allowed country → Records created → Then blocked → Admin can review/unblock

---

## Records Created (Even When Blocked)

| Record Type | Status | Can Unblock? |
|------------|--------|--------------|
| **Device** | `is_blocked=True` | ✅ Yes (Admin) |
| **IPBlocklist** | `is_active=True` | ✅ Yes (Admin) |
| **LoginEvent** | `status='blocked'` | ❌ No (Read-only) |
| **SystemLog** | Multiple entries | ❌ No (Read-only) |

---

## Quick Test

### 1. Test Blocked Country (Bangladesh)

```bash
curl -X POST http://127.0.0.1:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 103.108.140.1" \
  -d '{"username": "testuser", "password": "testpass123"}'
```

**Expected:** 400 error with `device_id` and `login_event_id`

### 2. Check Database

```python
python manage.py shell

from frauddetect.models import Device, IPBlocklist, LoginEvent

# Device created and blocked
Device.objects.filter(user__username='testuser', is_blocked=True)

# IP added to blocklist
IPBlocklist.objects.filter(ip_address='103.108.140.1', is_active=True)

# Login event with status='blocked'
LoginEvent.objects.filter(username='testuser', status='blocked')
```

---

## Quick Unblock

### Unblock Device

```python
device = Device.objects.get(id=5)
device.is_blocked = False
device.status = 'normal'
device.save()
```

### Unblock IP

```python
ip_block = IPBlocklist.objects.get(ip_address='103.108.140.1')
ip_block.is_active = False
ip_block.save()
```

### Via Django Admin

1. **Devices:** Admin → Devices → Find device → Set `is_blocked=False` → Save
2. **IPs:** Admin → IP Blocklist → Find IP → Set `is_active=False` → Save

---

## Settings

```python
# config/settings.py

GEO_RESTRICTION_ENABLED = True
ALLOWED_COUNTRIES = ['SA']
AUTO_BLOCK_DEVICES_FROM_BLOCKED_COUNTRIES = True
AUTO_BLOCK_NON_ALLOWED_COUNTRY_IPS = True
```

---

## API Response (Blocked)

```json
{
  "error": "Login blocked due to security concerns",
  "device_id": 5,
  "login_event_id": 12,
  "country_code": "BD",
  "country_detected": "Bangladesh",
  "risk_score": 115,
  "reasons": ["Device is blocked", "IP address is blocked"]
}
```

---

## Superuser Bypass

✅ **Superusers (is_superuser=True):**
- Never blocked
- No device/IP restrictions
- Always trusted

❌ **Regular Staff (is_staff=True, is_superuser=False):**
- Subject to all rules
- Can be blocked

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Records not created | Check `AUTO_BLOCK_*` settings |
| Login not blocked | Check `GEO_RESTRICTION_ENABLED` |
| IP not in blocklist | Check if superuser exists (needed for `blocked_by`) |
| Can't unblock | Use Django Admin or shell |

---

## Files

- **Documentation:** `BLOCKED_COUNTRY_RECORDS.md`
- **Bangla Guide:** `BLOCKED_COUNTRY_BANGLA.md`
- **Test Script:** `test_blocked_country_records.py`
- **Code:** `frauddetect/middleware.py`, `frauddetect/views.py`

---

## Summary

✅ All records created before blocking
✅ Admin can review and unblock
✅ Complete audit trail
✅ Security maintained
