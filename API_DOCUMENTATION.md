# 📚 API Documentation

Swagger and ReDoc have been successfully added to your Fraud Detection API!

## 🔗 Access Points

After starting your development server with `python manage.py runserver`, you can access:

### 1. **Swagger UI** (Interactive API Documentation)
```
http://127.0.0.1:8000/api/docs/
```
- Interactive interface to test API endpoints
- Try out requests directly from the browser
- See request/response examples
- Authentication support

### 2. **ReDoc** (Beautiful API Documentation)
```
http://127.0.0.1:8000/api/redoc/
```
- Clean, three-panel design
- Easy to read and navigate
- Perfect for sharing with team members
- Mobile-friendly

### 3. **OpenAPI Schema** (Raw JSON/YAML)
```
http://127.0.0.1:8000/api/schema/
```
- Download the OpenAPI 3.0 schema
- Use with API clients like Postman, Insomnia
- Generate client SDKs

## 📋 API Endpoints Overview

### Devices
- `GET /api/devices/` - List all devices
- `GET /api/devices/{id}/` - Get device details
- `POST /api/devices/{id}/trust/` - Mark device as trusted
- `POST /api/devices/{id}/block/` - Block device (Admin)

### Login Events
- `GET /api/login-events/` - List login events
- `GET /api/login-events/{id}/` - Get login event details
- `GET /api/login-events/suspicious/` - List suspicious logins

### Transactions (🔥 Core Feature)
- `GET /api/transactions/` - List all transactions
- `POST /api/transactions/` - Create transaction (with fraud detection)
- `GET /api/transactions/{id}/` - Get transaction details
- `POST /api/transactions/{id}/approve/` - Approve transaction (Admin)
- `POST /api/transactions/{id}/reject/` - Reject transaction (Admin)
- `GET /api/transactions/flagged/` - List flagged transactions

### Fraud Events
- `GET /api/fraud-events/` - List fraud events
- `GET /api/fraud-events/{id}/` - Get fraud event details
- `POST /api/fraud-events/{id}/resolve/` - Resolve fraud event (Admin)
- `GET /api/fraud-events/unresolved/` - List unresolved events

### Risk Profiles
- `GET /api/risk-profiles/` - List risk profiles
- `GET /api/risk-profiles/{id}/` - Get risk profile details
- `GET /api/risk-profiles/high_risk/` - List high-risk users (Admin)

### System Logs
- `GET /api/system-logs/` - List system logs (Admin)
- `GET /api/system-logs/?type=security` - Filter by type
- `GET /api/system-logs/?level=error` - Filter by level

### IP Blocklist
- `GET /api/ip-blocklist/` - List blocked IPs (Admin)
- `POST /api/ip-blocklist/` - Add IP to blocklist (Admin)
- `DELETE /api/ip-blocklist/{id}/` - Remove from blocklist (Admin)

### Dashboard
- `GET /api/dashboard/` - Get dashboard statistics (Admin)

## 🔐 Authentication

The API uses Session Authentication. You need to:
1. Login through Django admin or API
2. Include session cookie in requests
3. Or use the "Authorize" button in Swagger UI

## 🚀 Quick Start

1. Start the development server:
```bash
python manage.py runserver
```

2. Open Swagger UI in your browser:
```
http://127.0.0.1:8000/api/docs/
```

3. Click "Authorize" and login with your credentials

4. Try out the API endpoints!

## 📦 What Was Added

### Packages
- `drf-spectacular` - OpenAPI 3.0 schema generation

### Configuration Files Modified
1. **config/settings.py**
   - Added `drf_spectacular` to `INSTALLED_APPS`
   - Added `DEFAULT_SCHEMA_CLASS` to `REST_FRAMEWORK`
   - Added `SPECTACULAR_SETTINGS` configuration

2. **config/urls.py**
   - Added `/api/schema/` - OpenAPI schema endpoint
   - Added `/api/docs/` - Swagger UI endpoint
   - Added `/api/redoc/` - ReDoc endpoint

3. **frauddetect/views.py**
   - Added `@extend_schema_view` decorators for better documentation
   - Added tags and descriptions for all endpoints
   - Added parameter documentation

## 🎨 Customization

You can customize the API documentation in `config/settings.py` under `SPECTACULAR_SETTINGS`:

```python
SPECTACULAR_SETTINGS = {
    'TITLE': 'Your API Title',
    'DESCRIPTION': 'Your API Description',
    'VERSION': '1.0.0',
    # ... more settings
}
```

## 📝 Notes

- Swagger UI is best for testing and development
- ReDoc is best for documentation and sharing
- Both are automatically generated from your code
- No manual documentation maintenance needed!

Enjoy your new API documentation! 🎉
