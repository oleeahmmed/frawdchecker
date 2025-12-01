# Django Unfold Admin Setup - Fraud Detection System

## ✅ Fixed Issues

### 1. Middleware Error Fixed
**Problem:** `FieldError: Invalid field name(s) for model Device: 'user_agent'`

**Solution:** Removed the `user_agent` field from the Device creation in `frauddetect/middleware.py` (line 37). The `user_agent` field belongs to `LoginEvent` model, not `Device` model.

### 2. Django Unfold Integration
Successfully integrated Django Unfold admin theme with:
- Modern, clean UI
- Color-coded status badges
- Organized fieldsets
- Enhanced list displays
- Custom navigation sidebar

## 🎨 Features Added

### Admin Enhancements
- **Status Badges**: Color-coded labels for statuses (success, warning, danger, info)
- **Fieldsets**: Organized form fields into logical sections
- **List Filters**: Enhanced filtering with submit buttons
- **Full Width Lists**: Better use of screen space
- **Custom Navigation**: Organized sidebar with icons

### Models Configured
1. **Device** - Track user devices with security status
2. **LoginEvent** - Monitor login attempts and suspicious activity
3. **Transaction** - Financial transactions with risk assessment
4. **FraudEvent** - Detected fraud events with severity levels
5. **RiskProfile** - User risk profiles and behavioral patterns
6. **IPBlocklist** - Blocked IP addresses management
7. **SystemLog** - System activity logs

## 🚀 How to Run

```bash
# Activate virtual environment
source venv/bin/activate

# Collect static files (if not done)
python manage.py collectstatic --noinput

# Run migrations (if needed)
python manage.py migrate

# Create superuser (if not exists)
python manage.py createsuperuser

# Run development server
python manage.py runserver
```

## 📱 Access Admin Panel

1. Start the server: `python manage.py runserver`
2. Open browser: http://127.0.0.1:8000/admin/
3. Login with your superuser credentials

## 🎯 Admin Features

### Dashboard
- Custom navigation with organized sections
- Environment badge showing "Development"
- Quick access to all models

### Device Management
- View all registered devices
- Filter by status, trust level, country
- See risk scores and last activity

### Login Events
- Monitor all login attempts
- Identify suspicious activities
- Track by IP and location

### Transactions
- View all financial transactions
- Risk assessment with color coding
- Filter by status and risk level

### Fraud Detection
- Review detected fraud events
- Severity levels (low, medium, high, critical)
- Resolution tracking

### Risk Profiles
- User risk assessment
- Behavioral patterns
- Transaction statistics

## 🎨 Color Scheme

- **Success** (Green): Normal, approved, low risk
- **Warning** (Orange): Suspicious, medium risk, flagged
- **Danger** (Red): Blocked, failed, high risk, critical
- **Info** (Blue): Pending, informational

## 📝 Configuration

All Unfold settings are in `config/settings.py` under the `UNFOLD` dictionary:
- Site title and header
- Custom navigation
- Color scheme
- Dashboard callbacks

## 🔧 Customization

To customize the admin further, edit:
- `frauddetect/admin.py` - Admin classes and displays
- `config/settings.py` - Unfold configuration
- Add custom dashboard widgets in `dashboard_callback()`
