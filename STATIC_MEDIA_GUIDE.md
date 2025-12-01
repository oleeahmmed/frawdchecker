# 📁 Static & Media Files Configuration Guide

Complete guide for managing static and media files in your Django Fraud Detection project.

---

## 📂 Directory Structure

```
fraud_detection_project/
├── static/                    # Your custom static files
│   ├── css/                  # Custom CSS files
│   ├── js/                   # Custom JavaScript files
│   ├── images/               # Static images (logos, icons)
│   └── .gitkeep
│
├── staticfiles/              # Collected static files (auto-generated)
│   ├── admin/               # Django admin static files
│   ├── rest_framework/      # DRF static files
│   └── unfold/              # Unfold admin theme
│
└── media/                    # User uploaded files
    ├── uploads/             # General uploads
    ├── documents/           # Document uploads
    ├── images/              # Image uploads
    └── .gitkeep
```

---

## ⚙️ Configuration

### Settings (config/settings.py)

```python
# Static Files Configuration
STATIC_URL = '/static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [
    BASE_DIR / 'static',
]

# Media Files Configuration
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'
```

### URLs (config/urls.py)

```python
from django.conf import settings
from django.conf.urls.static import static

# In development, serve media files
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
```

---

## 🎨 Static Files

### What are Static Files?

Static files are CSS, JavaScript, images, fonts that are part of your application code.

### Adding Custom Static Files

**1. Create a CSS file:**

```bash
# Create file: static/css/custom.css
```

```css
/* static/css/custom.css */
.fraud-alert {
    background-color: #ff4444;
    color: white;
    padding: 10px;
    border-radius: 5px;
}

.safe-transaction {
    background-color: #44ff44;
    color: black;
    padding: 10px;
    border-radius: 5px;
}
```

**2. Create a JavaScript file:**

```bash
# Create file: static/js/fraud-detector.js
```

```javascript
// static/js/fraud-detector.js
function checkTransactionRisk(amount) {
    if (amount > 100000) {
        return 'high';
    } else if (amount > 50000) {
        return 'medium';
    }
    return 'low';
}
```

**3. Add images:**

```bash
# Copy your logo
cp /path/to/logo.png static/images/logo.png
```

### Using Static Files in Templates

```html
{% load static %}

<!DOCTYPE html>
<html>
<head>
    <link rel="stylesheet" href="{% static 'css/custom.css' %}">
    <script src="{% static 'js/fraud-detector.js' %}"></script>
</head>
<body>
    <img src="{% static 'images/logo.png' %}" alt="Logo">
</body>
</html>
```

### Collecting Static Files

Before deploying to production, collect all static files:

```bash
python manage.py collectstatic
```

This copies all static files to `staticfiles/` directory.

---

## 📤 Media Files

### What are Media Files?

Media files are user-uploaded content like profile pictures, documents, etc.

### Example: Adding Profile Picture to User

**1. Update Model (if needed):**

```python
# frauddetect/models.py
from django.db import models
from django.contrib.auth.models import User

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    profile_picture = models.ImageField(
        upload_to='uploads/profiles/',
        null=True,
        blank=True
    )
    document = models.FileField(
        upload_to='documents/',
        null=True,
        blank=True
    )
```

**2. Create Serializer:**

```python
# frauddetect/serializers.py
class UserProfileSerializer(serializers.ModelSerializer):
    profile_picture = serializers.ImageField(required=False)
    
    class Meta:
        model = UserProfile
        fields = ['user', 'profile_picture', 'document']
```

**3. Create View:**

```python
# frauddetect/views.py
from rest_framework.parsers import MultiPartParser, FormParser

class UserProfileViewSet(viewsets.ModelViewSet):
    serializer_class = UserProfileSerializer
    parser_classes = [MultiPartParser, FormParser]
    
    def perform_create(self, serializer):
        serializer.save(user=self.request.user)
```

**4. Upload File via API:**

```bash
# Using cURL
curl -X POST http://localhost:8000/api/profile/ \
  -H "Authorization: Bearer <token>" \
  -F "profile_picture=@/path/to/image.jpg"
```

```python
# Using Python requests
import requests

url = "http://localhost:8000/api/profile/"
headers = {"Authorization": "Bearer <token>"}
files = {"profile_picture": open("image.jpg", "rb")}

response = requests.post(url, headers=headers, files=files)
```

```javascript
// Using JavaScript fetch
const formData = new FormData();
formData.append('profile_picture', fileInput.files[0]);

fetch('http://localhost:8000/api/profile/', {
    method: 'POST',
    headers: {
        'Authorization': 'Bearer ' + token
    },
    body: formData
});
```

### Accessing Media Files

**In Templates:**
```html
{% if user.profile.profile_picture %}
    <img src="{{ user.profile.profile_picture.url }}" alt="Profile">
{% endif %}
```

**In API Response:**
```json
{
    "id": 1,
    "user": 1,
    "profile_picture": "http://localhost:8000/media/uploads/profiles/image.jpg"
}
```

---

## 🔒 Security Best Practices

### 1. Validate File Types

```python
from django.core.exceptions import ValidationError

def validate_image(image):
    file_size = image.size
    limit_mb = 5
    if file_size > limit_mb * 1024 * 1024:
        raise ValidationError(f"Max file size is {limit_mb}MB")
    
    valid_extensions = ['.jpg', '.jpeg', '.png', '.gif']
    ext = os.path.splitext(image.name)[1].lower()
    if ext not in valid_extensions:
        raise ValidationError(f"Unsupported file extension. Use: {valid_extensions}")

class UserProfile(models.Model):
    profile_picture = models.ImageField(
        upload_to='uploads/profiles/',
        validators=[validate_image]
    )
```

### 2. Secure File Names

```python
import uuid
from django.utils.text import slugify

def upload_to_path(instance, filename):
    ext = filename.split('.')[-1]
    filename = f"{uuid.uuid4()}.{ext}"
    return f"uploads/{instance.user.id}/{filename}"

class UserProfile(models.Model):
    profile_picture = models.ImageField(upload_to=upload_to_path)
```

### 3. Restrict Access

```python
from django.http import FileResponse
from django.shortcuts import get_object_or_404

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def download_document(request, document_id):
    document = get_object_or_404(Document, id=document_id, user=request.user)
    return FileResponse(document.file.open(), as_attachment=True)
```

---

## 🚀 Production Configuration

### Using WhiteNoise (Recommended)

**1. Install WhiteNoise:**

```bash
pip install whitenoise
```

**2. Update settings.py:**

```python
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',  # Add this
    # ... other middleware
]

# WhiteNoise configuration
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'
```

**3. Collect static files:**

```bash
python manage.py collectstatic --noinput
```

### Using AWS S3 for Media Files

**1. Install boto3:**

```bash
pip install boto3 django-storages
```

**2. Update settings.py:**

```python
INSTALLED_APPS += ['storages']

# AWS S3 Configuration
AWS_ACCESS_KEY_ID = 'your-access-key'
AWS_SECRET_ACCESS_KEY = 'your-secret-key'
AWS_STORAGE_BUCKET_NAME = 'your-bucket-name'
AWS_S3_REGION_NAME = 'us-east-1'
AWS_S3_CUSTOM_DOMAIN = f'{AWS_STORAGE_BUCKET_NAME}.s3.amazonaws.com'

# Media files on S3
DEFAULT_FILE_STORAGE = 'storages.backends.s3boto3.S3Boto3Storage'
MEDIA_URL = f'https://{AWS_S3_CUSTOM_DOMAIN}/media/'
```

---

## 🧪 Testing File Uploads

### Test Script

```python
# test_file_upload.py
import requests

def test_file_upload():
    # Login first
    login_response = requests.post('http://localhost:8000/api/auth/login/', json={
        'username': 'testuser',
        'password': 'password123'
    })
    
    token = login_response.json()['access']
    
    # Upload file
    headers = {'Authorization': f'Bearer {token}'}
    files = {'profile_picture': open('test_image.jpg', 'rb')}
    
    response = requests.post(
        'http://localhost:8000/api/profile/',
        headers=headers,
        files=files
    )
    
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")

if __name__ == '__main__':
    test_file_upload()
```

---

## 📋 Common Commands

```bash
# Collect all static files
python manage.py collectstatic

# Collect static files without prompts
python manage.py collectstatic --noinput

# Clear collected static files
python manage.py collectstatic --clear --noinput

# Find static files
python manage.py findstatic css/custom.css

# Check static files configuration
python manage.py check --deploy
```

---

## 🐛 Troubleshooting

### Issue: Static files not loading

**Solution:**
```bash
# Make sure you've collected static files
python manage.py collectstatic

# Check STATIC_URL and STATIC_ROOT in settings
# Verify URLs are configured correctly
```

### Issue: Media files not accessible

**Solution:**
```python
# In development, make sure DEBUG = True
# Check MEDIA_URL and MEDIA_ROOT settings
# Verify urls.py includes media URL patterns
```

### Issue: File upload fails

**Solution:**
```python
# Check file size limits
# Verify file type validators
# Ensure directory permissions are correct
chmod 755 media/
```

---

## 📦 Required Packages

```txt
# For image processing
Pillow==12.0.0

# For production static files
whitenoise==6.8.2

# For AWS S3 (optional)
boto3==1.35.0
django-storages==1.14.4
```

---

## ✅ Checklist

- [x] Static files directory created
- [x] Media files directory created
- [x] Settings configured
- [x] URLs configured
- [x] .gitignore updated
- [x] File validators added
- [x] Security measures implemented
- [ ] Production storage configured (S3/CDN)
- [ ] File upload tested
- [ ] Static files collected

---

## 📚 Additional Resources

- Django Static Files: https://docs.djangoproject.com/en/5.0/howto/static-files/
- Django File Uploads: https://docs.djangoproject.com/en/5.0/topics/http/file-uploads/
- WhiteNoise: http://whitenoise.evans.io/
- Django Storages: https://django-storages.readthedocs.io/

---

Your static and media files are now properly configured! 🎉
