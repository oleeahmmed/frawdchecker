# Login Page Access Fix

## Problem

**Before:** If an admin's IP was blocked, they couldn't even access the login page to fix the issue. This created a deadlock situation where:
1. Admin from USA tries to login
2. IP gets blocked automatically
3. Admin can't access login page anymore
4. Admin can't unblock themselves or other users

## Solution

**After:** Authentication endpoints (`/api/auth/*`) are now **exempted** from IP blocking and geo-restriction middleware. This allows:
1. Anyone can access the login page
2. Login attempt is evaluated during authentication
3. Records are created (Device, IPBlocklist, LoginEvent)
4. Superusers can still login regardless of IP/country
5. Regular users from blocked countries are blocked AFTER login attempt

---

## Flow Comparison

### Before (Problematic)

```
User from USA → Middleware checks IP → IP blocked → 403 Error
❌ Can't access login page
❌ Can't login
❌ Can't unblock
```

### After (Fixed)

```
User from USA → Middleware skips auth endpoints → Login page loads ✅
    ↓
User submits credentials → Authentication checks IP/country
    ↓
If Superuser → Login success ✅ (bypass all checks)
If Regular User → Records created → Login blocked ❌ (but records exist for admin review)
```

---

## Middleware Changes

### 1. GeoRestrictionMiddleware

**Before:**
```python
# Skip for admin panel and static files
if request.path.startswith('/admin/') or request.path.startswith('/static/'):
    return None
```

**After:**
```python
# Skip for admin panel, static files, and authentication endpoints
if (request.path.startswith('/admin/') or 
    request.path.startswith('/static/') or
    request.path.startswith('/media/') or
    request.path.startswith('/api/auth/')):  # Allow all auth endpoints
    return None
```

### 2. IPBlocklistMiddleware

**Before:**
```python
def process_request(self, request):
    # Check if user is superuser
    if hasattr(request, 'user') and request.user.is_authenticated and request.user.is_superuser:
        return None
    
    # Check if IP is blocked
    if is_blocked:
        return JsonResponse({'error': 'Access Denied'}, status=403)
```

**After:**
```python
def process_request(self, request):
    # Skip for authentication endpoints (FIRST)
    if (request.path.startswith('/admin/') or 
        request.path.startswith('/static/') or
        request.path.startswith('/media/') or
        request.path.startswith('/api/auth/')):
        return None
    
    # Check if user is superuser
    if hasattr(request, 'user') and request.user.is_authenticated and request.user.is_superuser:
        return None
    
    # Check if IP is blocked
    if is_blocked:
        return JsonResponse({'error': 'Access Denied'}, status=403)
```

---

## Exempted Endpoints

The following endpoints are now **exempted** from IP blocking and geo-restriction:

| Endpoint | Purpose | Accessible |
|----------|---------|------------|
| `/admin/*` | Django Admin Panel | ✅ Yes |
| `/static/*` | Static files (CSS, JS) | ✅ Yes |
| `/media/*` | Media files (uploads) | ✅ Yes |
| `/api/auth/*` | All authentication endpoints | ✅ Yes |

### Authentication Endpoints Included

- `/api/auth/login/` - Login endpoint
- `/api/auth/register/` - Registration endpoint
- `/api/auth/token/refresh/` - Token refresh
- `/api/auth/logout/` - Logout endpoint
- Any other `/api/auth/*` endpoints

---

## Security Model

### Layer 1: Middleware (Exempted for Auth)

```
Request → GeoRestrictionMiddleware → Skip if /api/auth/*
       → IPBlocklistMiddleware → Skip if /api/auth/*
       → Continue to authentication
```

### Layer 2: Authentication (Enforced)

```
Login Attempt → Check credentials
             → Check IP/country
             → Create records (Device, IPBlocklist, LoginEvent)
             → If superuser → Allow ✅
             → If regular user from blocked country → Block ❌
```

---

## User Scenarios

### Scenario 1: Superuser from USA

```
1. Access login page: ✅ Allowed (middleware skips)
2. Submit credentials: ✅ Valid
3. Check IP/country: USA (not allowed)
4. Check user type: Superuser
5. Result: ✅ LOGIN SUCCESS (superuser bypass)
```

**Records Created:**
- LoginEvent: status='success', risk_score=0
- No Device record (superuser bypass)
- No IPBlocklist entry

### Scenario 2: Regular User from USA

```
1. Access login page: ✅ Allowed (middleware skips)
2. Submit credentials: ✅ Valid
3. Check IP/country: USA (not allowed)
4. Create Device: is_blocked=True
5. Add IP to blocklist: is_active=True
6. Create LoginEvent: status='blocked'
7. Result: ❌ LOGIN BLOCKED (400 error)
```

**Records Created:**
- Device: is_blocked=True, is_trusted=False
- IPBlocklist: is_active=True, reason="Non-allowed country"
- LoginEvent: status='blocked', risk_score=50+

### Scenario 3: Regular User from Saudi Arabia

```
1. Access login page: ✅ Allowed (middleware skips)
2. Submit credentials: ✅ Valid
3. Check IP/country: SA (allowed)
4. Create Device: is_trusted=True
5. Create LoginEvent: status='success'
6. Result: ✅ LOGIN SUCCESS
```

**Records Created:**
- Device: is_blocked=False, is_trusted=True
- No IPBlocklist entry
- LoginEvent: status='success', risk_score=0

### Scenario 4: Admin from USA (Already Blocked IP)

```
1. Access login page: ✅ Allowed (middleware skips)
2. Submit credentials: ✅ Valid
3. Check IP: Already in blocklist
4. Check user type: Superuser
5. Result: ✅ LOGIN SUCCESS (superuser bypass)
```

**Admin can now:**
- Access Django Admin
- Unblock their own IP
- Unblock other users' IPs
- Review all blocked login attempts

---

## Admin Workflow

### If Admin's IP Gets Blocked

1. **Access Login Page:** ✅ Still accessible (middleware exemption)
2. **Login as Superuser:** ✅ Success (superuser bypass)
3. **Go to Django Admin:** `/admin/`
4. **Navigate to IP Blocklist:** `/admin/frauddetect/ipblocklist/`
5. **Find Your IP:** Search for your IP address
6. **Unblock:** Set `is_active = False`
7. **Save:** IP is now unblocked

### To Unblock Other Users

1. **Login as Superuser:** ✅ Always works
2. **Review Blocked Logins:** `/admin/frauddetect/loginevent/` → Filter by status='blocked'
3. **Unblock Device:** `/admin/frauddetect/device/` → Set `is_blocked = False`
4. **Unblock IP:** `/admin/frauddetect/ipblocklist/` → Set `is_active = False`
5. **Notify User:** User can now login

---

## Testing

### Test 1: Access Login Page from Blocked IP

```bash
# Simulate blocked IP (USA)
curl -X GET http://127.0.0.1:8000/api/auth/login/ \
  -H "X-Forwarded-For: 8.8.8.8"
```

**Expected:** ✅ Login page accessible (not blocked by middleware)

### Test 2: Login as Superuser from Blocked Country

```bash
curl -X POST http://127.0.0.1:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 8.8.8.8" \
  -d '{
    "username": "admin",
    "password": "admin123"
  }'
```

**Expected:** ✅ Login success (superuser bypass)

### Test 3: Login as Regular User from Blocked Country

```bash
curl -X POST http://127.0.0.1:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 8.8.8.8" \
  -d '{
    "username": "testuser",
    "password": "testpass123"
  }'
```

**Expected:** ❌ Login blocked (400 error) but records created

### Test 4: Access Other Endpoints from Blocked IP

```bash
curl -X GET http://127.0.0.1:8000/api/devices/ \
  -H "X-Forwarded-For: 8.8.8.8"
```

**Expected:** ❌ 403 Forbidden (middleware blocks non-auth endpoints)

---

## Configuration

### Settings

```python
# config/settings.py

# Enable geo-restriction
GEO_RESTRICTION_ENABLED = True

# Allowed countries
ALLOWED_COUNTRIES = ['SA', 'BD']

# Auto-block settings
AUTO_BLOCK_DEVICES_FROM_BLOCKED_COUNTRIES = True
AUTO_BLOCK_NON_ALLOWED_COUNTRY_IPS = True
```

### Middleware Order (Important!)

```python
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'frauddetect.middleware.GeoRestrictionMiddleware',  # FIRST (with exemptions)
    'frauddetect.middleware.IPBlocklistMiddleware',     # SECOND (with exemptions)
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',  # Authentication
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'allauth.account.middleware.AccountMiddleware',
    'frauddetect.middleware.DeviceFingerprintMiddleware',  # LAST (after auth)
]
```

---

## Benefits

### 1. No Deadlock
✅ Admins can always access login page
✅ Superusers can always login
✅ Admins can unblock themselves and others

### 2. Security Maintained
✅ Non-auth endpoints still blocked
✅ Regular users from blocked countries still blocked
✅ All attempts recorded for audit

### 3. Flexibility
✅ Records created before blocking
✅ Admins can review and unblock
✅ Complete audit trail

### 4. User Experience
✅ Clear error messages
✅ Contact information provided
✅ Users know their attempt was recorded

---

## Important Notes

### Superuser vs Staff

- **Superuser (is_superuser=True):**
  - ✅ Can login from any country
  - ✅ Can login from blocked IP
  - ✅ Bypasses all fraud detection
  - ✅ Can unblock IPs and devices

- **Regular Staff (is_staff=True, is_superuser=False):**
  - ❌ Subject to all fraud detection rules
  - ❌ Can be blocked if from non-allowed country
  - ❌ Cannot bypass IP blocking
  - ✅ Can access Django Admin (if logged in)

### Emergency Access

If all superusers are locked out:
1. Access server directly (SSH)
2. Run Django shell: `python manage.py shell`
3. Unblock IP manually:
   ```python
   from frauddetect.models import IPBlocklist
   IPBlocklist.objects.filter(ip_address='YOUR_IP').update(is_active=False)
   ```
4. Login as superuser

---

## Summary

✅ **Login page always accessible**
✅ **Superusers can always login**
✅ **Admins can unblock IPs**
✅ **Security maintained for regular users**
✅ **Complete audit trail**
✅ **No deadlock situations**

The system now provides a perfect balance between security and administrative access.
