# Quick Fix: Blocked IP Access

## Problem: My IP is Blocked, How Do I Login?

### Solution: Login Page is Always Accessible! ✅

Even if your IP is blocked, you can still:
1. Access the login page
2. Login as superuser
3. Unblock your IP

---

## Step-by-Step Fix

### Option 1: Login as Superuser (Recommended)

```
1. Go to login page: http://your-domain.com/api/auth/login/
   ✅ Page loads (middleware exemption)

2. Login with superuser credentials:
   {
     "username": "admin",
     "password": "your_password"
   }
   ✅ Login success (superuser bypass)

3. Go to Django Admin: http://your-domain.com/admin/

4. Navigate to IP Blocklist:
   Admin → Fraud Detect → IP Blocklist

5. Find your IP and unblock:
   - Search for your IP address
   - Click on it
   - Set "Is active" to False
   - Save

6. Done! Your IP is unblocked ✅
```

### Option 2: Django Shell (Server Access)

If you have SSH access to the server:

```bash
# SSH into server
ssh user@your-server

# Navigate to project
cd /path/to/project

# Activate virtual environment
source venv/bin/activate

# Run Django shell
python manage.py shell

# Unblock IP
from frauddetect.models import IPBlocklist
IPBlocklist.objects.filter(ip_address='YOUR_IP_HERE').update(is_active=False)

# Exit
exit()
```

### Option 3: Database Direct Access

If you have database access:

```sql
-- SQLite
UPDATE ip_blocklist SET is_active = 0 WHERE ip_address = 'YOUR_IP_HERE';

-- PostgreSQL/MySQL
UPDATE ip_blocklist SET is_active = false WHERE ip_address = 'YOUR_IP_HERE';
```

---

## How It Works Now

### Before (Problematic)
```
Blocked IP → Middleware blocks → 403 Error → Can't access login page ❌
```

### After (Fixed)
```
Blocked IP → Middleware skips auth endpoints → Login page loads ✅
          → Login as superuser → Success ✅
          → Unblock IP in admin → Done ✅
```

---

## Exempted Endpoints

These endpoints are **always accessible**, even from blocked IPs:

- `/api/auth/login/` - Login
- `/api/auth/register/` - Register
- `/api/auth/token/refresh/` - Refresh token
- `/admin/*` - Django Admin
- `/static/*` - Static files
- `/media/*` - Media files

---

## Important Notes

### Superuser vs Regular User

**Superuser (is_superuser=True):**
- ✅ Can login from any country
- ✅ Can login from blocked IP
- ✅ Bypasses all restrictions
- ✅ Can unblock IPs

**Regular User:**
- ❌ Blocked if from non-allowed country
- ❌ Blocked if IP is blacklisted
- ❌ Cannot bypass restrictions
- ❌ Cannot unblock IPs

### Create Superuser

If you don't have a superuser:

```bash
python manage.py createsuperuser
```

---

## Testing

### Test Login Page Access (Blocked IP)

```bash
curl -X GET http://127.0.0.1:8000/api/auth/login/ \
  -H "X-Forwarded-For: 8.8.8.8"
```

**Expected:** ✅ Page accessible

### Test Superuser Login (Blocked IP)

```bash
curl -X POST http://127.0.0.1:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 8.8.8.8" \
  -d '{
    "username": "admin",
    "password": "admin123"
  }'
```

**Expected:** ✅ Login success

---

## Troubleshooting

### Issue: Still can't access login page

**Check:**
1. Is the server running?
2. Is the URL correct?
3. Are you using the right port?

### Issue: Superuser login blocked

**Check:**
1. Is the user actually a superuser? (is_superuser=True)
2. Are credentials correct?
3. Check Django logs for errors

### Issue: Can't find IP in blocklist

**Check:**
1. What's your actual IP? Visit: https://whatismyipaddress.com/
2. Search in Django Admin → IP Blocklist
3. Check SystemLog for blocking events

---

## Prevention

### Whitelist Your IP

Add your IP to whitelist in settings:

```python
# config/settings.py

GEO_RESTRICTION_WHITELIST_IPS = [
    '203.0.113.50',      # Your office IP
    '198.51.100.0/24',   # Your office network
]
```

### Add More Allowed Countries

```python
# config/settings.py

ALLOWED_COUNTRIES = [
    'SA',  # Saudi Arabia
    'AE',  # UAE
    'US',  # USA
]
```

---

## Summary

✅ **Login page always accessible**
✅ **Superusers can always login**
✅ **Easy to unblock IPs**
✅ **Multiple recovery options**
✅ **No deadlock situations**

You're never locked out! 🎉
