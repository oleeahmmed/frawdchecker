"""
🔐 Login Views - Saudi Arabia Bank Compliance
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Authentication endpoints with complete fraud detection.
"""

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.views import TokenRefreshView
from drf_spectacular.utils import (
    extend_schema, 
    OpenApiExample, 
    OpenApiResponse,
    OpenApiParameter
)
from drf_spectacular.types import OpenApiTypes
from django.conf import settings
from frauddetect.serializers import LoginSerializer, UserInfoSerializer
from frauddetect.models import IPWhitelist
from django.utils import timezone


@extend_schema(
    tags=['🔐 Authentication'],
    summary='Login - Get JWT Tokens',
    description="""
## 🔐 User Authentication with Fraud Detection

Login to the system and receive JWT tokens. This endpoint includes **complete fraud detection** 
with 6 security checks for Saudi Arabia banking compliance.

### 🛡️ Security Features
| Feature | Description |
|---------|-------------|
| 🌍 Geo-Restriction | Only Saudi Arabia (SA) allowed |
| 📱 Device Fingerprinting | Track and trust devices |
| 🚫 IP Blocklist | Block malicious IPs |
| ⚡ Rate Limiting | Max 5 attempts per 5 minutes |
| 📊 Risk Assessment | Real-time risk scoring |
| 📝 Audit Logging | Complete login history |

### 📝 Login Options
You can login using any of these methods:

**Option 1:** Username + Password
```json
{"username": "john_doe", "password": "your_password"}
```

**Option 2:** Email + Password
```json
{"email": "john@example.com", "password": "your_password"}
```

**Option 3:** Auto-detect (username or email)
```json
{"username_or_email": "john@example.com", "password": "your_password"}
```

### ⚠️ Possible Errors
| Code | Reason | Description |
|------|--------|-------------|
| 400 | Invalid credentials | Wrong username/password |
| 403 | IP blocked | Your IP is in blocklist |
| 403 | Country blocked | Access from non-SA country |
| 403 | Device not trusted | Device needs admin approval |
| 403 | Too many attempts | Rate limit exceeded |

### 🔑 Token Lifetime
- **Access Token:** 1 hour
- **Refresh Token:** 7 days
    """,
    request=LoginSerializer,
    responses={
        200: OpenApiResponse(
            response=LoginSerializer,
            description='✅ Login successful',
            examples=[
                OpenApiExample(
                    'Successful Login',
                    summary='Login Success Response',
                    description='User successfully authenticated',
                    value={
                        "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
                        "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
                        "user": {
                            "id": 1,
                            "username": "john_doe",
                            "email": "john@example.com",
                            "first_name": "John",
                            "last_name": "Doe",
                            "is_staff": False,
                            "is_superuser": False
                        },
                        "device_id": 1,
                        "device_trusted": True,
                        "device_new": False,
                        "security": {
                            "risk_score": 10,
                            "risk_level": "safe",
                            "is_suspicious": False,
                            "requires_verification": False
                        },
                        "login_info": {
                            "ip_address": "203.0.113.50",
                            "country": "Saudi Arabia",
                            "country_code": "SA",
                            "city": "Riyadh"
                        }
                    }
                )
            ]
        ),
        400: OpenApiResponse(
            description='❌ Invalid credentials',
            examples=[
                OpenApiExample(
                    'Invalid Credentials',
                    value={"error": "Invalid credentials"}
                )
            ]
        ),
        403: OpenApiResponse(
            description='🚫 Access denied',
            examples=[
                OpenApiExample(
                    'IP Blocked',
                    summary='IP Address Blocked',
                    value={
                        "error": "Access Denied",
                        "blocked": True,
                        "reason": "ip_blocked",
                        "message": "Your IP address has been blocked",
                        "contact": "Please contact support"
                    }
                ),
                OpenApiExample(
                    'Country Blocked',
                    summary='Non-SA Country',
                    value={
                        "error": "Access Denied",
                        "blocked": True,
                        "reason": "non_allowed_country",
                        "message": "Access restricted to Saudi Arabia only",
                        "details": {
                            "your_country": "United States",
                            "your_country_code": "US",
                            "allowed_countries": ["Saudi Arabia (SA)"]
                        }
                    }
                ),
                OpenApiExample(
                    'Device Not Trusted',
                    summary='Untrusted Device',
                    value={
                        "error": "Access Denied",
                        "blocked": True,
                        "reason": "device_not_trusted",
                        "message": "This device is not trusted",
                        "contact": "Contact administrator to trust this device"
                    }
                )
            ]
        )
    },
    examples=[
        OpenApiExample(
            'Login with Username',
            summary='Username Login',
            description='Login using username and password',
            value={
                "username": "john_doe",
                "password": "SecurePass123!"
            },
            request_only=True
        ),
        OpenApiExample(
            'Login with Email',
            summary='Email Login',
            description='Login using email and password',
            value={
                "email": "john@example.com",
                "password": "SecurePass123!"
            },
            request_only=True
        ),
        OpenApiExample(
            'Auto-detect Login',
            summary='Auto-detect (Username or Email)',
            description='System auto-detects if input is username or email',
            value={
                "username_or_email": "john@example.com",
                "password": "SecurePass123!"
            },
            request_only=True
        )
    ]
)
class LoginView(APIView):
    """
    🔐 Login API with Complete Fraud Detection
    
    POST /api/auth/login/
    """
    
    permission_classes = [AllowAny]
    serializer_class = LoginSerializer
    
    def post(self, request):
        """Handle login request"""
        serializer = LoginSerializer(
            data=request.data,
            context={'request': request}
        )
        
        if serializer.is_valid():
            return Response(
                serializer.validated_data,
                status=status.HTTP_200_OK
            )
        
        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST
        )


@extend_schema(
    tags=['🔐 Authentication'],
    summary='Refresh Access Token',
    description="""
## 🔄 Refresh JWT Access Token

Use your refresh token to get a new access token without re-authenticating.

### 📝 How to Use
1. When your access token expires (after 1 hour), use this endpoint
2. Send your refresh token in the request body
3. Receive a new access token

### ⏰ Token Lifetime
| Token Type | Lifetime |
|------------|----------|
| Access Token | 1 hour |
| Refresh Token | 7 days |

### 🔄 Token Rotation
- When you refresh, a new refresh token is also issued
- The old refresh token is blacklisted
- This prevents token reuse attacks

### ⚠️ Important
- Store refresh tokens securely (httpOnly cookies recommended)
- Never expose refresh tokens in URLs or logs
- Refresh tokens are single-use
    """,
    request={
        'application/json': {
            'type': 'object',
            'properties': {
                'refresh': {
                    'type': 'string',
                    'description': 'Your refresh token'
                }
            },
            'required': ['refresh']
        }
    },
    responses={
        200: OpenApiResponse(
            description='✅ Token refreshed successfully',
            examples=[
                OpenApiExample(
                    'Token Refreshed',
                    value={
                        "access": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIi..."
                    }
                )
            ]
        ),
        401: OpenApiResponse(
            description='❌ Invalid or expired refresh token',
            examples=[
                OpenApiExample(
                    'Invalid Token',
                    value={
                        "detail": "Token is invalid or expired",
                        "code": "token_not_valid"
                    }
                )
            ]
        )
    },
    examples=[
        OpenApiExample(
            'Refresh Token Request',
            value={
                "refresh": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ0b2tlbl90eXBlIjoicmVmcmVzaCIs..."
            },
            request_only=True
        )
    ]
)
class CustomTokenRefreshView(TokenRefreshView):
    """
    🔄 Refresh JWT Token
    
    POST /api/auth/token/refresh/
    """
    permission_classes = [AllowAny]


@extend_schema(
    tags=['🔐 Authentication'],
    summary='Get Current User Info',
    description="""
## 👤 Get Current User Information

Retrieve information about the currently authenticated user.

### 🔑 Authentication Required
This endpoint requires a valid JWT access token in the Authorization header:
```
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc...
```

### 📊 Response Fields
| Field | Type | Description |
|-------|------|-------------|
| id | integer | User ID |
| username | string | Username |
| email | string | Email address |
| first_name | string | First name |
| last_name | string | Last name |
| is_staff | boolean | Staff status |
| is_superuser | boolean | Superuser status |
| date_joined | datetime | Account creation date |
    """,
    responses={
        200: OpenApiResponse(
            response=UserInfoSerializer,
            description='✅ User information retrieved',
            examples=[
                OpenApiExample(
                    'User Info',
                    value={
                        "id": 1,
                        "username": "john_doe",
                        "email": "john@example.com",
                        "first_name": "John",
                        "last_name": "Doe",
                        "is_staff": False,
                        "is_superuser": False,
                        "date_joined": "2024-01-15T10:30:00Z"
                    }
                )
            ]
        ),
        401: OpenApiResponse(
            description='❌ Not authenticated',
            examples=[
                OpenApiExample(
                    'Not Authenticated',
                    value={"error": "Not authenticated"}
                )
            ]
        )
    }
)
class CurrentUserView(APIView):
    """
    👤 Get Current User Info
    
    GET /api/auth/me/
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Get current user information"""
        if not request.user or not request.user.is_authenticated:
            return Response(
                {'error': 'Not authenticated'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        serializer = UserInfoSerializer(request.user)
        return Response(serializer.data)
