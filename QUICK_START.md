# 🚀 Quick Start Guide

Get your Fraud Detection API up and running in minutes!

## 📦 Installation

### 1. Install Dependencies

```bash
# Activate virtual environment
source venv/bin/activate

# Install packages
pip install -r requirements.txt
```

### 2. Run Migrations

```bash
python manage.py migrate
```

### 3. Create Superuser (Admin)

```bash
python manage.py createsuperuser
```

Follow the prompts:
- Username: `admin`
- Email: `admin@example.com`
- Password: (your secure password)

### 4. Start Development Server

```bash
python manage.py runserver
```

Server will start at: `http://localhost:8000`

---

## 🧪 Test the API

### Option 1: Using Test Script

```bash
# In a new terminal
python test_auth.py
```

This will test:
- ✅ User registration
- ✅ Login with JWT
- ✅ Get current user
- ✅ Device tracking
- ✅ Login events
- ✅ Transaction creation
- ✅ Token refresh

### Option 2: Using Swagger UI

1. Open browser: `http://localhost:8000/api/docs/`
2. Click "Authorize" button
3. Login to get token
4. Test all endpoints interactively

### Option 3: Using cURL

```bash
# Register a new user
curl -X POST http://localhost:8000/api/auth/registration/ \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "email": "john@example.com",
    "password1": "SecurePass123!",
    "password2": "SecurePass123!",
    "first_name": "John",
    "last_name": "Doe"
  }'

# Login
curl -X POST http://localhost:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "password": "SecurePass123!"
  }'

# Use the access token from login response
export TOKEN="your_access_token_here"

# Get current user
curl -X GET http://localhost:8000/api/auth/user/ \
  -H "Authorization: Bearer $TOKEN"

# Create a transaction
curl -X POST http://localhost:8000/api/transactions/ \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "external_txn_id": "TXN-001",
    "amount": "10000.00",
    "currency": "BDT",
    "description": "Test payment",
    "beneficiary": "John Smith"
  }'
```

---

## 📚 Available Endpoints

### 🔐 Authentication
- `POST /api/auth/login/` - Login (Custom JWT with device tracking)
- `POST /api/auth/registration/` - Register new user
- `POST /api/auth/token/refresh/` - Refresh access token
- `POST /api/auth/logout/` - Logout
- `GET /api/auth/user/` - Get current user
- `POST /api/auth/password/change/` - Change password

### 📱 Device Management
- `GET /api/devices/` - List user devices
- `POST /api/devices/{id}/trust/` - Mark device as trusted
- `POST /api/devices/{id}/block/` - Block device (Admin)

### 🔍 Login Events
- `GET /api/login-events/` - List login history
- `GET /api/login-events/suspicious/` - List suspicious logins

### 💰 Transactions
- `GET /api/transactions/` - List transactions
- `POST /api/transactions/` - Create transaction (with fraud detection)
- `GET /api/transactions/flagged/` - List flagged transactions
- `POST /api/transactions/{id}/approve/` - Approve transaction (Admin)
- `POST /api/transactions/{id}/reject/` - Reject transaction (Admin)

### 🚨 Fraud Events
- `GET /api/fraud-events/` - List fraud events
- `GET /api/fraud-events/unresolved/` - List unresolved events
- `POST /api/fraud-events/{id}/resolve/` - Resolve fraud event (Admin)

### 📊 Risk Profiles
- `GET /api/risk-profiles/` - List user risk profiles
- `GET /api/risk-profiles/high_risk/` - List high-risk users (Admin)

### 🛡️ Admin Only
- `GET /api/system-logs/` - System activity logs
- `GET /api/ip-blocklist/` - IP blocklist management
- `GET /api/dashboard/` - Dashboard statistics

---

## 🎯 Key Features

### 1. JWT Authentication
- Secure token-based authentication
- Access token (1 hour lifetime)
- Refresh token (7 days lifetime)
- Automatic token rotation

### 2. Device Fingerprinting
- Automatic device identification
- Track device usage patterns
- Trust/block devices
- Multi-device support

### 3. Fraud Detection
- Real-time transaction analysis
- Risk scoring (0-100)
- Multiple fraud rules:
  - High amount detection
  - Velocity checking
  - Geo-location analysis
  - Time-based patterns
  - Device trust verification

### 4. Login Tracking
- Complete login history
- Suspicious login detection
- Geo-location tracking
- Failed attempt monitoring

### 5. Admin Dashboard
- Transaction statistics
- Fraud event monitoring
- Risk profile management
- System logs

---

## 🔧 Configuration

### JWT Settings (config/settings.py)

```python
SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(hours=1),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ROTATE_REFRESH_TOKENS': True,
}
```

### Fraud Detection Settings

```python
FRAUD_SETTINGS = {
    'MAX_LOGIN_ATTEMPTS': 5,
    'HIGH_AMOUNT_THRESHOLD': 100000,  # BDT
    'MAX_DAILY_TRANSACTIONS': 50,
    'MAX_TRANSACTIONS_PER_HOUR': 10,
}
```

---

## 📖 Documentation

- **API Documentation**: `http://localhost:8000/api/docs/`
- **ReDoc**: `http://localhost:8000/api/redoc/`
- **Admin Panel**: `http://localhost:8000/admin/`
- **Authentication Guide**: See `AUTHENTICATION_API_GUIDE.md`
- **Full Documentation**: See `API_DOCUMENTATION.md`

---

## 🐛 Troubleshooting

### Issue: "Authentication credentials were not provided"
**Solution**: Make sure you're including the Authorization header:
```
Authorization: Bearer <your_access_token>
```

### Issue: "Token is invalid or expired"
**Solution**: Use the refresh token to get a new access token:
```bash
curl -X POST http://localhost:8000/api/auth/token/refresh/ \
  -H "Content-Type: application/json" \
  -d '{"refresh": "your_refresh_token"}'
```

### Issue: "CSRF Failed"
**Solution**: For API requests, use JWT authentication instead of session authentication.

---

## 📞 Support

For detailed information, check:
- `AUTHENTICATION_API_GUIDE.md` - Complete authentication guide
- `API_DOCUMENTATION.md` - Full API reference
- `FRAUD_DETECTION_DOCUMENTATION.md` - Fraud detection details

---

## ✅ Next Steps

1. ✅ Create a superuser account
2. ✅ Test the authentication endpoints
3. ✅ Create some test transactions
4. ✅ Check the admin panel
5. ✅ Review fraud detection rules
6. ✅ Customize settings for your needs

Happy coding! 🎉
