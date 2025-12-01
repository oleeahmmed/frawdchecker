# 🔐 Authentication API Guide

Complete guide for using JWT authentication with the Fraud Detection System.

## 📋 Table of Contents

1. [Overview](#overview)
2. [Authentication Endpoints](#authentication-endpoints)
3. [Usage Examples](#usage-examples)
4. [Device Tracking](#device-tracking)
5. [Error Handling](#error-handling)

---

## Overview

This system uses **JWT (JSON Web Token)** authentication with device fingerprinting for enhanced security. We provide two authentication approaches:

1. **Custom JWT Login** - With device tracking (Recommended)
2. **dj-rest-auth** - Full-featured authentication with registration

---

## Authentication Endpoints

### 🔑 Custom JWT Login (with Device Tracking)

**Endpoint:** `POST /api/auth/login/`

**Request:**
```json
{
    "username": "your_username",
    "password": "your_password"
}
```

**Response:**
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
    "device_trusted": true
}
```

**Features:**
- ✅ Automatic device fingerprinting
- ✅ Login event tracking
- ✅ Geo-location detection
- ✅ Suspicious activity detection

---

### 🔄 Token Refresh

**Endpoint:** `POST /api/auth/token/refresh/`

**Request:**
```json
{
    "refresh": "eyJ0eXAiOiJKV1QiLCJhbGc..."
}
```

**Response:**
```json
{
    "access": "eyJ0eXAiOiJKV1QiLCJhbGc...",
    "refresh": "eyJ0eXAiOiJKV1QiLCJhbGc..."
}
```

---

### 📝 Registration (dj-rest-auth)

**Endpoint:** `POST /api/auth/registration/`

**Request:**
```json
{
    "username": "new_user",
    "email": "user@example.com",
    "password1": "SecurePassword123!",
    "password2": "SecurePassword123!",
    "first_name": "John",
    "last_name": "Doe"
}
```

**Response:**
```json
{
    "access": "eyJ0eXAiOiJKV1QiLCJhbGc...",
    "refresh": "eyJ0eXAiOiJKV1QiLCJhbGc...",
    "user": {
        "id": 2,
        "username": "new_user",
        "email": "user@example.com",
        "first_name": "John",
        "last_name": "Doe"
    }
}
```

---

### 🚪 Logout

**Endpoint:** `POST /api/auth/logout/`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request:**
```json
{
    "refresh": "eyJ0eXAiOiJKV1QiLCJhbGc..."
}
```

**Response:**
```json
{
    "detail": "Successfully logged out."
}
```

---

### 👤 Get Current User

**Endpoint:** `GET /api/auth/user/`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response:**
```json
{
    "id": 1,
    "username": "john_doe",
    "email": "john@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "is_staff": false,
    "date_joined": "2024-01-15T10:30:00Z"
}
```

---

### 🔐 Change Password

**Endpoint:** `POST /api/auth/password/change/`

**Headers:**
```
Authorization: Bearer <access_token>
```

**Request:**
```json
{
    "old_password": "OldPassword123!",
    "new_password1": "NewPassword456!",
    "new_password2": "NewPassword456!"
}
```

---

### 📧 Password Reset

**Step 1: Request Reset**

**Endpoint:** `POST /api/auth/password/reset/`

**Request:**
```json
{
    "email": "user@example.com"
}
```

**Step 2: Confirm Reset**

**Endpoint:** `POST /api/auth/password/reset/confirm/`

**Request:**
```json
{
    "uid": "MQ",
    "token": "abc123-def456",
    "new_password1": "NewPassword789!",
    "new_password2": "NewPassword789!"
}
```

---

## Usage Examples

### Python (requests)

```python
import requests

# Login
response = requests.post('http://localhost:8000/api/auth/login/', json={
    'username': 'john_doe',
    'password': 'password123'
})

data = response.json()
access_token = data['access']
refresh_token = data['refresh']

# Make authenticated request
headers = {'Authorization': f'Bearer {access_token}'}
transactions = requests.get(
    'http://localhost:8000/api/transactions/',
    headers=headers
)

print(transactions.json())
```

---

### JavaScript (fetch)

```javascript
// Login
const login = async () => {
    const response = await fetch('http://localhost:8000/api/auth/login/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            username: 'john_doe',
            password: 'password123'
        })
    });
    
    const data = await response.json();
    localStorage.setItem('access_token', data.access);
    localStorage.setItem('refresh_token', data.refresh);
    
    return data;
};

// Make authenticated request
const getTransactions = async () => {
    const token = localStorage.getItem('access_token');
    
    const response = await fetch('http://localhost:8000/api/transactions/', {
        headers: {
            'Authorization': `Bearer ${token}`
        }
    });
    
    return await response.json();
};

// Refresh token
const refreshToken = async () => {
    const refresh = localStorage.getItem('refresh_token');
    
    const response = await fetch('http://localhost:8000/api/auth/token/refresh/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ refresh })
    });
    
    const data = await response.json();
    localStorage.setItem('access_token', data.access);
    
    return data;
};
```

---

### cURL

```bash
# Login
curl -X POST http://localhost:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "password": "password123"
  }'

# Make authenticated request
curl -X GET http://localhost:8000/api/transactions/ \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc..."

# Refresh token
curl -X POST http://localhost:8000/api/auth/token/refresh/ \
  -H "Content-Type: application/json" \
  -d '{
    "refresh": "eyJ0eXAiOiJKV1QiLCJhbGc..."
  }'
```

---

## Device Tracking

When you login using `/api/auth/login/`, the system automatically:

1. **Calculates device fingerprint** from:
   - User Agent
   - Accept Language
   - Accept Encoding
   - Screen Resolution (if provided)

2. **Tracks device information**:
   - IP Address
   - Geo-location (Country, City)
   - Last seen timestamp
   - Trust status

3. **Creates login event** with:
   - Success/Failure status
   - Suspicious activity detection
   - Location tracking

4. **Returns device info** in response:
   - `device_id`: Unique device identifier
   - `device_trusted`: Whether device is trusted

---

## Error Handling

### Common Error Responses

**401 Unauthorized**
```json
{
    "detail": "Authentication credentials were not provided."
}
```

**401 Invalid Credentials**
```json
{
    "detail": "Unable to log in with provided credentials."
}
```

**401 Token Expired**
```json
{
    "detail": "Given token not valid for any token type",
    "code": "token_not_valid",
    "messages": [
        {
            "token_class": "AccessToken",
            "token_type": "access",
            "message": "Token is invalid or expired"
        }
    ]
}
```

**403 Forbidden**
```json
{
    "detail": "You do not have permission to perform this action."
}
```

**400 Bad Request**
```json
{
    "username": ["This field is required."],
    "password": ["This field is required."]
}
```

---

## Token Lifetime

- **Access Token**: 1 hour
- **Refresh Token**: 7 days
- **Auto-rotation**: Enabled (new refresh token on each refresh)

---

## Security Features

✅ **JWT Authentication** - Stateless, secure token-based auth  
✅ **Device Fingerprinting** - Track and identify user devices  
✅ **Login Event Tracking** - Monitor all login attempts  
✅ **Geo-location Detection** - Track login locations  
✅ **Suspicious Activity Detection** - Flag unusual login patterns  
✅ **IP Blocklist** - Block malicious IP addresses  
✅ **Token Rotation** - Automatic refresh token rotation  
✅ **CORS Protection** - Configured for specific origins  

---

## Testing the API

### Using Swagger UI

Visit: `http://localhost:8000/api/docs/`

1. Click on "Authorize" button
2. Enter: `Bearer <your_access_token>`
3. Test all endpoints interactively

### Using ReDoc

Visit: `http://localhost:8000/api/redoc/`

---

## Complete API Endpoints Summary

### Authentication
- `POST /api/auth/login/` - Login with device tracking
- `POST /api/auth/token/refresh/` - Refresh access token
- `POST /api/auth/logout/` - Logout
- `POST /api/auth/registration/` - Register new user
- `GET /api/auth/user/` - Get current user
- `PUT /api/auth/user/` - Update user profile
- `POST /api/auth/password/change/` - Change password
- `POST /api/auth/password/reset/` - Request password reset
- `POST /api/auth/password/reset/confirm/` - Confirm password reset

### Fraud Detection
- `GET /api/devices/` - List user devices
- `GET /api/login-events/` - List login events
- `GET /api/transactions/` - List transactions
- `POST /api/transactions/` - Create transaction (with fraud check)
- `GET /api/fraud-events/` - List fraud events
- `GET /api/risk-profiles/` - List risk profiles
- `GET /api/dashboard/` - Dashboard statistics (Admin only)

---

## Need Help?

- 📖 Full API Documentation: `http://localhost:8000/api/docs/`
- 📝 ReDoc: `http://localhost:8000/api/redoc/`
- 🔧 Admin Panel: `http://localhost:8000/admin/`
