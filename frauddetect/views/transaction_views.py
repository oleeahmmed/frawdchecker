"""
💰 Transaction API Views
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Transaction endpoints with complete fraud detection.
"""

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from drf_spectacular.utils import (
    extend_schema, 
    OpenApiExample, 
    OpenApiResponse,
    OpenApiParameter
)
from drf_spectacular.types import OpenApiTypes
from frauddetect.models import Transaction
from frauddetect.serializers import (
    TransactionCreateSerializer,
    TransactionListSerializer,
    TransactionDetailSerializer
)


@extend_schema(
    tags=['💰 Transactions'],
    summary='Create Transaction with Fraud Detection',
    description="""
## 💰 Create New Transaction

Create a new financial transaction with **real-time fraud detection**. 
This endpoint performs 12 comprehensive fraud checks before approving.

### 🛡️ Fraud Detection Checks
| # | Check | Risk Points |
|---|-------|-------------|
| 1 | IP Blacklist | 🚫 Block |
| 2 | Country Restriction | 🚫 Block |
| 3 | Device Trust | 🚫 Block |
| 4 | Amount Threshold | +30 |
| 5 | Velocity (per hour) | +50 |
| 6 | Daily Limits | +40 |
| 7 | Business Hours | +10-20 |
| 8 | User Average | +40 |
| 9 | Dormant Account | +45 |
| 10 | New Account | +50 |
| 11 | Transaction Type | +30-40 |
| 12 | New Device | +40 |

### 📊 Risk Levels
| Risk Score | Level | Action |
|------------|-------|--------|
| 0-19 | ✅ Safe | Approve |
| 20-39 | 🟢 Low | Approve |
| 40-59 | 🟡 Medium | Flag |
| 60-79 | 🟠 High | Hold for review |
| 80-100 | 🔴 Critical | Block |

### 💳 Transaction Types
| Type | Description | Risk |
|------|-------------|------|
| `transfer` | Bank Transfer | Normal |
| `p2p` | Peer-to-Peer | +30 if >100K |
| `international` | International Transfer | +35 |
| `crypto` | Cryptocurrency | +40 |
| `bill_payment` | Bill Payment | Normal |
| `purchase` | Purchase | Normal |
| `cash_withdrawal` | Cash Withdrawal | Normal |
| `deposit` | Deposit | Normal |

### 🔑 Authentication Required
Include JWT token in header:
```
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc...
```
    """,
    request=TransactionCreateSerializer,
    responses={
        200: OpenApiResponse(
            response=TransactionCreateSerializer,
            description='✅ Transaction created successfully',
            examples=[
                OpenApiExample(
                    'Approved Transaction',
                    summary='Transaction Approved',
                    value={
                        "success": True,
                        "transaction": {
                            "id": 1,
                            "external_txn_id": "TXN-A1B2C3D4E5F6",
                            "amount": "50000.00",
                            "currency": "SAR",
                            "beneficiary": "Ahmed Mohammed",
                            "transaction_type": "transfer",
                            "status": "approved",
                            "risk_score": 15,
                            "risk_level": "safe",
                            "requires_manual_review": False,
                            "created_at": "2024-12-10T10:30:00Z"
                        },
                        "fraud_check": {
                            "risk_score": 15,
                            "risk_level": "safe",
                            "risk_reasons": [],
                            "triggered_patterns": [],
                            "requires_manual_review": False
                        },
                        "location_info": {
                            "ip_address": "203.0.113.50",
                            "country": "Saudi Arabia",
                            "country_code": "SA",
                            "city": "Riyadh"
                        }
                    }
                ),
                OpenApiExample(
                    'Flagged Transaction',
                    summary='Transaction Flagged for Review',
                    value={
                        "success": True,
                        "transaction": {
                            "id": 2,
                            "external_txn_id": "TXN-X1Y2Z3W4V5U6",
                            "amount": "150000.00",
                            "currency": "SAR",
                            "status": "flagged",
                            "risk_score": 55,
                            "risk_level": "medium",
                            "requires_manual_review": False
                        },
                        "fraud_check": {
                            "risk_score": 55,
                            "risk_level": "medium",
                            "risk_reasons": [
                                "Amount 150000 exceeds threshold 100000",
                                "Transaction outside business hours: 22:00"
                            ],
                            "triggered_patterns": [
                                "amount_exceeds_threshold",
                                "outside_business_hours"
                            ]
                        }
                    }
                )
            ]
        ),
        400: OpenApiResponse(
            description='❌ Validation error or transaction blocked',
            examples=[
                OpenApiExample(
                    'High Risk Blocked',
                    summary='Transaction Blocked - High Risk',
                    value={
                        "error": "Transaction Blocked",
                        "reason": "high_risk",
                        "message": "Transaction blocked due to high fraud risk",
                        "risk_score": 85,
                        "risk_reasons": [
                            "New account (5 days) with high-value transaction",
                            "Amount 300% above user average",
                            "High amount from new device"
                        ]
                    }
                ),
                OpenApiExample(
                    'Daily Limit Exceeded',
                    summary='Daily Limit Exceeded',
                    value={
                        "error": "Transaction Blocked",
                        "reason": "daily_limit_exceeded",
                        "message": "Daily transaction limit exceeded",
                        "today_amount": 520000,
                        "max_amount": 500000
                    }
                ),
                OpenApiExample(
                    'Velocity Limit',
                    summary='Too Many Transactions',
                    value={
                        "error": "Transaction Blocked",
                        "reason": "high_velocity",
                        "message": "Too many transactions. Maximum 10 per hour allowed.",
                        "transaction_count": 12,
                        "max_allowed": 10
                    }
                )
            ]
        ),
        401: OpenApiResponse(
            description='❌ Authentication required'
        )
    },
    examples=[
        OpenApiExample(
            'Bank Transfer',
            summary='Standard Bank Transfer',
            value={
                "amount": 50000,
                "currency": "SAR",
                "beneficiary": "Ahmed Mohammed",
                "transaction_type": "transfer",
                "description": "Monthly salary transfer"
            },
            request_only=True
        ),
        OpenApiExample(
            'International Transfer',
            summary='International Wire Transfer',
            value={
                "amount": 25000,
                "currency": "SAR",
                "beneficiary": "John Smith - US Bank",
                "transaction_type": "international",
                "description": "Business payment"
            },
            request_only=True
        ),
        OpenApiExample(
            'P2P Transfer',
            summary='Peer-to-Peer Transfer',
            value={
                "amount": 5000,
                "currency": "SAR",
                "beneficiary": "Mohammed Ali",
                "transaction_type": "p2p",
                "description": "Personal transfer"
            },
            request_only=True
        )
    ]
)
class TransactionCreateView(APIView):
    """
    💰 Create Transaction with Fraud Detection
    
    POST /api/transactions/create/
    """
    
    permission_classes = [IsAuthenticated]
    serializer_class = TransactionCreateSerializer
    
    def post(self, request):
        """Create new transaction with fraud detection"""
        serializer = TransactionCreateSerializer(
            data=request.data,
            context={'request': request}
        )
        
        if serializer.is_valid():
            result = serializer.save()
            return Response(result, status=status.HTTP_200_OK)
        
        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST
        )


@extend_schema(
    tags=['💰 Transactions'],
    summary='List User Transactions',
    description="""
## 📋 List All User Transactions

Retrieve a list of all transactions for the authenticated user, 
ordered by creation date (newest first).

### 📊 Response Fields
| Field | Type | Description |
|-------|------|-------------|
| id | integer | Transaction ID |
| external_txn_id | string | External reference ID |
| amount | decimal | Transaction amount |
| currency | string | Currency code (SAR) |
| beneficiary | string | Recipient name |
| transaction_type | string | Type of transaction |
| status | string | pending/approved/rejected/flagged |
| risk_score | integer | Fraud risk score (0-100) |
| risk_level | string | safe/low/medium/high/critical |
| is_suspicious | boolean | Flagged as suspicious |
| requires_manual_review | boolean | Needs admin review |
| created_at | datetime | Creation timestamp |

### 🔑 Authentication Required
Include JWT token in header:
```
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc...
```
    """,
    responses={
        200: OpenApiResponse(
            response=TransactionListSerializer(many=True),
            description='✅ List of transactions',
            examples=[
                OpenApiExample(
                    'Transaction List',
                    value=[
                        {
                            "id": 3,
                            "external_txn_id": "TXN-A1B2C3D4E5F6",
                            "user_username": "john_doe",
                            "device_name": "Windows PC",
                            "amount": "50000.00",
                            "currency": "SAR",
                            "beneficiary": "Ahmed Mohammed",
                            "transaction_type": "transfer",
                            "status": "approved",
                            "risk_score": 10,
                            "risk_level": "safe",
                            "is_suspicious": False,
                            "requires_manual_review": False,
                            "created_at": "2024-12-10T10:30:00Z"
                        },
                        {
                            "id": 2,
                            "external_txn_id": "TXN-X1Y2Z3W4V5U6",
                            "user_username": "john_doe",
                            "device_name": "Windows PC",
                            "amount": "150000.00",
                            "currency": "SAR",
                            "beneficiary": "Company XYZ",
                            "transaction_type": "transfer",
                            "status": "flagged",
                            "risk_score": 55,
                            "risk_level": "medium",
                            "is_suspicious": True,
                            "requires_manual_review": False,
                            "created_at": "2024-12-09T15:45:00Z"
                        }
                    ]
                )
            ]
        ),
        401: OpenApiResponse(description='❌ Authentication required')
    }
)
class TransactionListView(APIView):
    """
    📋 List User Transactions
    
    GET /api/transactions/
    """
    
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Get user's transactions"""
        transactions = Transaction.objects.filter(
            user=request.user
        ).order_by('-created_at')
        
        serializer = TransactionListSerializer(transactions, many=True)
        return Response(serializer.data)


@extend_schema(
    tags=['💰 Transactions'],
    summary='Get Transaction Details',
    description="""
## 🔍 Get Transaction Details

Retrieve detailed information about a specific transaction including 
full fraud detection results and review status.

### 📊 Additional Detail Fields
| Field | Type | Description |
|-------|------|-------------|
| description | string | Transaction description |
| risk_reasons | array | List of risk factors |
| triggered_patterns | array | Fraud patterns detected |
| ip_address | string | IP used for transaction |
| country_code | string | Country of origin |
| city | string | City of origin |
| reviewed_by_username | string | Admin who reviewed |
| reviewed_at | datetime | Review timestamp |
| review_notes | string | Admin notes |

### 🔑 Authentication Required
You can only view your own transactions.
    """,
    parameters=[
        OpenApiParameter(
            name='transaction_id',
            type=OpenApiTypes.INT,
            location=OpenApiParameter.PATH,
            description='Transaction ID',
            required=True
        )
    ],
    responses={
        200: OpenApiResponse(
            response=TransactionDetailSerializer,
            description='✅ Transaction details',
            examples=[
                OpenApiExample(
                    'Transaction Detail',
                    value={
                        "id": 1,
                        "external_txn_id": "TXN-A1B2C3D4E5F6",
                        "user_username": "john_doe",
                        "device_name": "Windows PC",
                        "amount": "50000.00",
                        "currency": "SAR",
                        "beneficiary": "Ahmed Mohammed",
                        "transaction_type": "transfer",
                        "description": "Monthly salary transfer",
                        "status": "approved",
                        "risk_score": 10,
                        "risk_level": "safe",
                        "risk_reasons": [],
                        "triggered_patterns": [],
                        "is_suspicious": False,
                        "requires_manual_review": False,
                        "ip_address": "203.0.113.50",
                        "country_code": "SA",
                        "city": "Riyadh",
                        "reviewed_by_username": None,
                        "reviewed_at": None,
                        "review_notes": None,
                        "created_at": "2024-12-10T10:30:00Z",
                        "updated_at": "2024-12-10T10:30:00Z",
                        "approved_at": "2024-12-10T10:30:00Z"
                    }
                )
            ]
        ),
        404: OpenApiResponse(
            description='❌ Transaction not found',
            examples=[
                OpenApiExample(
                    'Not Found',
                    value={"error": "Transaction not found"}
                )
            ]
        ),
        401: OpenApiResponse(description='❌ Authentication required')
    }
)
class TransactionDetailView(APIView):
    """
    🔍 Transaction Details
    
    GET /api/transactions/{id}/
    """
    
    permission_classes = [IsAuthenticated]
    
    def get(self, request, transaction_id):
        """Get transaction details"""
        try:
            transaction = Transaction.objects.get(
                id=transaction_id,
                user=request.user
            )
        except Transaction.DoesNotExist:
            return Response(
                {'error': 'Transaction not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        serializer = TransactionDetailSerializer(transaction)
        return Response(serializer.data)


@extend_schema(
    tags=['💰 Transactions'],
    summary='Get Transaction Statistics',
    description="""
## 📊 Transaction Statistics Dashboard

Get comprehensive statistics about your transactions including 
totals, averages, and risk distribution.

### 📈 Statistics Included

#### All Time Stats
| Metric | Description |
|--------|-------------|
| total_transactions | Total number of transactions |
| total_amount | Sum of all transaction amounts |
| avg_amount | Average transaction amount |
| approved | Count of approved transactions |
| pending | Count of pending transactions |
| rejected | Count of rejected transactions |
| flagged | Count of flagged transactions |

#### Today's Stats
| Metric | Description |
|--------|-------------|
| total_transactions | Transactions today |
| total_amount | Amount transacted today |

#### This Month Stats
| Metric | Description |
|--------|-------------|
| total_transactions | Transactions this month |
| total_amount | Amount transacted this month |

#### Risk Summary
| Level | Description |
|-------|-------------|
| safe | Risk score 0-19 |
| low | Risk score 20-39 |
| medium | Risk score 40-59 |
| high | Risk score 60-79 |
| critical | Risk score 80-100 |

### 🔑 Authentication Required
Include JWT token in header.
    """,
    responses={
        200: OpenApiResponse(
            description='✅ Transaction statistics',
            examples=[
                OpenApiExample(
                    'Statistics',
                    value={
                        "all_time": {
                            "total_transactions": 150,
                            "total_amount": 2500000,
                            "avg_amount": 16666.67,
                            "approved": 140,
                            "pending": 5,
                            "rejected": 2,
                            "flagged": 3
                        },
                        "today": {
                            "total_transactions": 5,
                            "total_amount": 75000
                        },
                        "this_month": {
                            "total_transactions": 45,
                            "total_amount": 850000
                        },
                        "risk_summary": {
                            "safe": 100,
                            "low": 35,
                            "medium": 10,
                            "high": 4,
                            "critical": 1
                        }
                    }
                )
            ]
        ),
        401: OpenApiResponse(description='❌ Authentication required')
    }
)
class TransactionStatsView(APIView):
    """
    📊 Transaction Statistics
    
    GET /api/transactions/stats/
    """
    
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """Get transaction statistics"""
        from django.db.models import Sum, Count, Avg
        from datetime import timedelta
        from django.utils import timezone
        
        user = request.user
        
        # All time stats
        all_txns = Transaction.objects.filter(user=user)
        
        # Today's stats
        today_start = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
        today_txns = all_txns.filter(created_at__gte=today_start)
        
        # This month stats
        month_start = timezone.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        month_txns = all_txns.filter(created_at__gte=month_start)
        
        stats = {
            'all_time': {
                'total_transactions': all_txns.count(),
                'total_amount': all_txns.aggregate(Sum('amount'))['amount__sum'] or 0,
                'avg_amount': all_txns.aggregate(Avg('amount'))['amount__avg'] or 0,
                'approved': all_txns.filter(status='approved').count(),
                'pending': all_txns.filter(status='pending').count(),
                'rejected': all_txns.filter(status='rejected').count(),
                'flagged': all_txns.filter(status='flagged').count(),
            },
            'today': {
                'total_transactions': today_txns.count(),
                'total_amount': today_txns.aggregate(Sum('amount'))['amount__sum'] or 0,
            },
            'this_month': {
                'total_transactions': month_txns.count(),
                'total_amount': month_txns.aggregate(Sum('amount'))['amount__sum'] or 0,
            },
            'risk_summary': {
                'safe': all_txns.filter(risk_level='safe').count(),
                'low': all_txns.filter(risk_level='low').count(),
                'medium': all_txns.filter(risk_level='medium').count(),
                'high': all_txns.filter(risk_level='high').count(),
                'critical': all_txns.filter(risk_level='critical').count(),
            }
        }
        
        return Response(stats)
