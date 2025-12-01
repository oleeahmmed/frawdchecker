# 🚫 Automatic IP Blocking System

## 📋 Overview

The system now **automatically adds IPs to the blocklist** when they attempt to access from non-allowed countries. This provides an additional layer of security by permanently blocking malicious or unauthorized access attempts.

---

## 🎯 How It Works

```
┌─────────────────────────────────────────────────────────────┐
│  Request from Non-Allowed Country                           │
│  IP: 103.106.239.104                                        │
│  Country: BD (Bangladesh)                                   │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  GeoRestrictionMiddleware                                    │
│  • Detects country: BD                                       │
│  • Checks: Is BD in ALLOWED_COUNTRIES? NO                   │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  AUTO-BLOCK PROCESS                                          │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  1. Check if IP already in blocklist                  │  │
│  │     → Query: IPBlocklist.objects.filter(ip=...)      │  │
│  │                                                        │  │
│  │  2. If NOT in blocklist:                             │  │
│  │     → Create new IPBlocklist entry                    │  │
│  │     → Set is_active = True                           │  │
│  │     → Set reason = "Auto-block from BD"              │  │
│  │     → Log to SystemLog                               │  │
│  │                                                        │  │
│  │  3. If already in blocklist:                         │  │
│  │     → Skip (already blocked)                          │  │
│  └───────────────────────────────────────────────────────┘  │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│  BLOCK REQUEST                                               │
│  • Return 403 Forbidden                                      │
│  • IP now permanently blocked                                │
│  • Future requests from this IP blocked immediately          │
└─────────────────────────────────────────────────────────────┘
```

---

## ⚙️ Configuration

### settings.py

```python
# Enable/disable automatic IP blocking
AUTO_BLOCK_NON_ALLOWED_COUNTRY_IPS = True  # Set to False to disable

# Allowed countries
ALLOWED_COUNTRIES = ['SA']  # Only Saudi Arabia

# Geo-restriction action
GEO_RESTRICTION_ACTION = 'block'
```

---

## 📊 What Gets Blocked

### Automatically Blocked:
- ✅ IPs from non-allowed countries
- ✅ First-time access attempts
- ✅ Repeated access attempts
- ✅ Any country not in ALLOWED_COUNTRIES

### NOT Blocked:
- ✅ IPs from allowed countries (SA)
- ✅ Whitelisted IPs
- ✅ Private/local IPs (development)
- ✅ Superuser access

---

## 📝 Example Scenarios

### Scenario 1: First Access from Bangladesh

```
Request:
  IP: 103.106.239.104
  Country: BD (Bangladesh)
  User: Attempting to access

Flow:
1. Geo-check: BD not in ALLOWED_COUNTRIES
2. Check blocklist: IP not found
3. AUTO-BLOCK: Add IP to blocklist
   → IPBlocklist.objects.create(
       ip_address='103.106.239.104',
       reason='Automatic block: Access from BD',
       is_active=True
     )
4. Block request: Return 403

Result: 
  🚫 Access blocked
  🚫 IP added to blocklist
  
Console:
  🚫 GEO-BLOCKED: Access from BD (Bangladesh) - IP: 103.106.239.104
  🚫 IP AUTO-BLOCKED: 103.106.239.104 added to blocklist (Country: BD)
```

---

### Scenario 2: Second Access from Same IP

```
Request:
  IP: 103.106.239.104 (already blocked)
  Country: BD (Bangladesh)

Flow:
1. IP Blocklist Check (runs BEFORE geo-check)
   → IP found in blocklist
   → Block immediately
2. Never reaches geo-restriction middleware

Result:
  🚫 Access blocked (by IP blocklist)
  ⚠️  IP already in blocklist
  
Console:
  🚫 IP BLOCKED: 103.106.239.104 is in blocklist
```

---

### Scenario 3: Access from Saudi Arabia

```
Request:
  IP: 185.45.6.100
  Country: SA (Saudi Arabia)

Flow:
1. Geo-check: SA in ALLOWED_COUNTRIES ✓
2. No auto-block (allowed country)
3. Continue processing

Result:
  ✅ Access allowed
  ✅ IP NOT added to blocklist
  
Console:
  ✓ Geo-check passed: SA (Saudi Arabia) - IP: 185.45.6.100
```

---

## 🗄️ Database Structure

### IPBlocklist Table

```sql
CREATE TABLE frauddetect_ipblocklist (
    id INTEGER PRIMARY KEY,
    ip_address VARCHAR(45) UNIQUE,
    reason TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    blocked_by_id INTEGER NULL,  -- NULL for automatic blocks
    created_at DATETIME,
    expires_at DATETIME NULL
);
```

### Example Records

```
┌────┬──────────────────┬────────────────────────────────┬───────────┬──────────────┐
│ id │ ip_address       │ reason                         │ is_active │ blocked_by   │
├────┼──────────────────┼────────────────────────────────┼───────────┼──────────────┤
│ 1  │ 103.106.239.104  │ Auto-block: Access from BD     │ TRUE      │ NULL         │
│ 2  │ 198.51.100.25    │ Auto-block: Access from US     │ TRUE      │ NULL         │
│ 3  │ 203.0.113.50     │ Manual block by admin          │ TRUE      │ 1 (admin)    │
└────┴──────────────────┴────────────────────────────────┴───────────┴──────────────┘
```

---

## 📊 Monitoring

### View Auto-Blocked IPs

```python
from frauddetect.models import IPBlocklist

# Get all auto-blocked IPs
auto_blocked = IPBlocklist.objects.filter(
    blocked_by__isnull=True  # NULL = automatic
)

for ip in auto_blocked:
    print(f"IP: {ip.ip_address}")
    print(f"Reason: {ip.reason}")
    print(f"Blocked at: {ip.created_at}")
```

### Check System Logs

```python
from frauddetect.models import SystemLog

# Get auto-block logs
logs = SystemLog.objects.filter(
    message__contains='automatically added to blocklist'
).order_by('-created_at')

for log in logs[:10]:
    print(f"{log.created_at}: {log.message}")
    print(f"  Country: {log.metadata.get('country_code')}")
```

### Admin Panel

1. Go to: `http://localhost:8000/admin/frauddetect/ipblocklist/`
2. Filter by: `blocked_by = None` (automatic blocks)
3. See all auto-blocked IPs

---

## 🔧 Management

### Unblock an IP

```python
from frauddetect.models import IPBlocklist

# Deactivate block
ip_block = IPBlocklist.objects.get(ip_address='103.106.239.104')
ip_block.is_active = False
ip_block.save()

# Or delete completely
ip_block.delete()
```

### Whitelist an IP (Prevent Auto-Block)

```python
# In settings.py
GEO_RESTRICTION_WHITELIST_IPS = [
    '103.106.239.104',  # This IP won't be auto-blocked
]
```

### Disable Auto-Blocking

```python
# In settings.py
AUTO_BLOCK_NON_ALLOWED_COUNTRY_IPS = False
```

---

## 📝 Console Logs

### When IP is Auto-Blocked:

```
🚫 GEO-BLOCKED: Access from BD (Bangladesh) - IP: 103.106.239.104
🚫 IP AUTO-BLOCKED: 103.106.239.104 added to blocklist (Country: BD)
```

### When IP Already Blocked:

```
⚠️  IP already in blocklist: 103.106.239.104
```

### When IP is Allowed:

```
✓ Geo-check passed: SA (Saudi Arabia) - IP: 185.45.6.100
```

---

## 🎯 Benefits

1. **Automatic Protection** - No manual intervention needed
2. **Permanent Blocking** - Once blocked, always blocked
3. **Performance** - Blocked IPs rejected immediately
4. **Audit Trail** - All blocks logged
5. **Scalable** - Handles unlimited IPs

---

## ⚠️ Important Notes

### 1. Permanent Blocks
- Auto-blocked IPs are **permanently blocked** by default
- They won't be able to access even if they change country
- Unblock manually if needed

### 2. Whitelisting
- Use whitelist for legitimate IPs from non-SA countries
- Whitelisted IPs bypass all geo-restrictions

### 3. Superusers
- Superusers bypass all restrictions
- Their IPs are never auto-blocked

### 4. Development
- Local IPs (127.0.0.1, 192.168.x.x) are never blocked
- Disable auto-blocking during development if needed

---

## 🧪 Testing

### Test Auto-Blocking

1. **Disable for testing:**
   ```python
   AUTO_BLOCK_NON_ALLOWED_COUNTRY_IPS = False
   ```

2. **Or use whitelist:**
   ```python
   GEO_RESTRICTION_WHITELIST_IPS = ['YOUR_IP']
   ```

3. **Check blocked IPs:**
   ```bash
   python manage.py shell
   >>> from frauddetect.models import IPBlocklist
   >>> IPBlocklist.objects.filter(blocked_by__isnull=True)
   ```

---

## 📊 Statistics

### View Blocking Stats

```python
from frauddetect.models import IPBlocklist, SystemLog

# Total auto-blocked IPs
total_auto_blocked = IPBlocklist.objects.filter(
    blocked_by__isnull=True
).count()

# Auto-blocks today
from django.utils import timezone
today = timezone.now().date()

auto_blocks_today = SystemLog.objects.filter(
    created_at__date=today,
    message__contains='automatically added to blocklist'
).count()

print(f"Total auto-blocked IPs: {total_auto_blocked}")
print(f"Auto-blocks today: {auto_blocks_today}")
```

---

Your system now automatically blocks IPs from non-allowed countries! 🚫🔒
