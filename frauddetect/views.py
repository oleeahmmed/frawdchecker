"""
🔐 Login Views - Saudi Arabia Bank Compliance
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

শুধু login এবং token refresh।
সব fraud detection serializer এ হচ্ছে।
"""

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.views import TokenRefreshView
from drf_spectacular.utils import extend_schema
from django.conf import settings
from .serializers import LoginSerializer, UserInfoSerializer
from .models import IPWhitelist
from django.utils import timezone


@extend_schema(
    tags=['Authentication'],
    summary='Login to get JWT tokens',
    description='Login with username or email. Includes complete fraud detection with 6 security checks.',
    request=LoginSerializer,
    responses={200: LoginSerializer}
)
class LoginView(APIView):
    """
    🔐 Login API with Complete Fraud Detection
    
    POST /api/auth/login/
    
    Features:
    - Username OR Email login
    - Saudi Arabia compliance (SA only)
    - Complete fraud detection
    - Device fingerprinting
    - Risk assessment
    - Audit logging
    """
    
    permission_classes = [AllowAny]
    serializer_class = LoginSerializer
    
    def post(self, request):
        """
        Handle login request
        """
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
    tags=['Authentication'],
    summary='Refresh JWT access token',
    description="""
🔄 Refresh Access Token

Use your refresh token to get a new access token.

**Request:**
```json
{
    "refresh": "eyJ0eXAiOiJKV1QiLCJhbGc..."
}
```

**Response:**
```json
{
    "access": "eyJ0eXAiOiJKV1QiLCJhbGc..."
}
```

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⏰ **Token Lifetime:**
- Access Token: 1 hour
- Refresh Token: 7 days
    """
)
class CustomTokenRefreshView(TokenRefreshView):
    """
    🔄 Refresh JWT Token
    
    POST /api/auth/token/refresh/
    """
    permission_classes = [AllowAny]


@extend_schema(
    tags=['Authentication'],
    summary='Get current user info',
    description='Get information about the currently authenticated user',
    responses={200: UserInfoSerializer}
)
class CurrentUserView(APIView):
    """
    👤 Get Current User Info
    
    GET /api/auth/me/
    
    Returns information about the currently authenticated user.
    Requires valid JWT token in Authorization header.
    """
    
    def get(self, request):
        """
        Get current user information
        """
        if not request.user or not request.user.is_authenticated:
            return Response(
                {'error': 'Not authenticated'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        serializer = UserInfoSerializer(request.user)
        return Response(serializer.data)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 🔐 IP WHITELIST MANAGEMENT API (Commented out - not in URLs)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Note: IP Whitelist can be managed through Django Admin Panel
# To enable this API, uncomment and add to urls.py
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# @extend_schema(
#     tags=['IP Whitelist Management'],
#     summary='Add IP to Whitelist',
#     description="""
# 🔐 Add IP Address to Whitelist
# 
# **REQUIRES SECRET KEY** - Must provide `X-Whitelist-Secret` header
# """,
# )
# class IPWhitelistAddView(APIView):
#     """
#     🔐 Add IP to Whitelist
#     
#     POST /api/whitelist/add/
#     
#     Requires secret key in header: X-Whitelist-Secret
#     """
#     permission_classes = [AllowAny]
#     
#     def post(self, request):
#         """Add IP to whitelist"""
#         # Implementation here
#         pass