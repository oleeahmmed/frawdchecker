# 🔐 Login API - Simple Usage Guide

## 3 Ways to Login

### Method 1: Login with Username

```bash
curl -X POST http://localhost:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "password": "SecurePass123!"
  }'
```

### Method 2: Login with Email

```bash
curl -X POST http://localhost:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "SecurePass123!"
  }'
```

### Method 3: Login with Username OR Email (Auto-detect)

```bash
# With username
curl -X POST http://localhost:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "username_or_email": "john_doe",
    "password": "SecurePass123!"
  }'

# With email (auto-detected)
curl -X POST http://localhost:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "username_or_email": "john@example.com",
    "password": "SecurePass123!"
  }'
```

---

## Success Response

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

---

## Error Responses

### Invalid Credentials

```json
{
  "detail": "Invalid credentials"
}
```

### Missing Credentials

```json
{
  "detail": "Must provide username or email"
}
```

### Blocked Login

```json
{
  "error": "Login blocked due to security concerns",
  "risk_score": 100,
  "reasons": [
    "IP address is blocked"
  ]
}
```

---

## Using the Access Token

After successful login, use the access token in subsequent requests:

```bash
curl -X GET http://localhost:8000/api/transactions/ \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc..."
```

---

## Refresh Token

When access token expires, use refresh token to get a new one:

```bash
curl -X POST http://localhost:8000/api/auth/token/refresh/ \
  -H "Content-Type: application/json" \
  -d '{
    "refresh": "eyJ0eXAiOiJKV1QiLCJhbGc..."
  }'
```

---

## JavaScript Example

```javascript
// Login function
async function login(usernameOrEmail, password) {
  const response = await fetch('http://localhost:8000/api/auth/login/', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      username_or_email: usernameOrEmail,
      password: password
    })
  });
  
  if (response.ok) {
    const data = await response.json();
    
    // Save tokens
    localStorage.setItem('access_token', data.access);
    localStorage.setItem('refresh_token', data.refresh);
    
    console.log('Login successful!');
    console.log('User:', data.user);
    console.log('Risk Score:', data.security.risk_score);
    
    return data;
  } else {
    const error = await response.json();
    console.error('Login failed:', error);
    throw new Error(error.detail || 'Login failed');
  }
}

// Usage
login('john_doe', 'SecurePass123!')
  .then(data => console.log('Logged in:', data.user.username))
  .catch(error => console.error('Error:', error));
```

---

## Python Example

```python
import requests

def login(username_or_email, password):
    response = requests.post(
        'http://localhost:8000/api/auth/login/',
        json={
            'username_or_email': username_or_email,
            'password': password
        }
    )
    
    if response.status_code == 200:
        data = response.json()
        print(f"Login successful!")
        print(f"User: {data['user']['username']}")
        print(f"Risk Score: {data['security']['risk_score']}")
        return data
    else:
        error = response.json()
        print(f"Login failed: {error}")
        return None

# Usage
data = login('john_doe', 'SecurePass123!')
if data:
    access_token = data['access']
    # Use access_token for subsequent requests
```

---

## Testing

Run the simple test:

```bash
python test_simple_login.py
```

This will test all 3 login methods and show you the results.

---

## Quick Start

1. **Create a superuser:**
   ```bash
   python manage.py createsuperuser
   ```

2. **Start the server:**
   ```bash
   python manage.py runserver
   ```

3. **Test login:**
   ```bash
   python test_simple_login.py
   ```

4. **Or use curl:**
   ```bash
   curl -X POST http://localhost:8000/api/auth/login/ \
     -H "Content-Type: application/json" \
     -d '{"username": "admin", "password": "your_password"}'
   ```

---

## Key Points

✅ **3 ways to login:** username, email, or username_or_email
✅ **Auto-detection:** System detects if input is email (contains @)
✅ **Fraud detection:** Every login is checked for security risks
✅ **Device tracking:** Automatically tracks and manages devices
✅ **Comprehensive response:** Includes user, device, security, and location info

---

That's it! Your login API is ready to use! 🎉
