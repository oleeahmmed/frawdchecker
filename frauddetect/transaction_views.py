"""
💰 Transaction API Views
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Simple transaction API with fraud detection.
"""

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from drf_spectacular.utils import extend_schema, OpenApiExample
from .models import Transaction
from .transaction_serializers import (
    TransactionCreateSerializer,
    TransactionListSerializer,
    TransactionDetailSerializer
)


@extend_schema(
    tags=['Transactions'],
    summary='Create Transaction with Fraud Detection',
    description='Create a new transaction with complete fraud detection. Includes 12 fraud checks.',
    request=TransactionCreateSerializer,
    responses={200: TransactionCreateSerializer}
)
class TransactionCreateView(APIView):
    """
    💰 Create Transaction with Fraud Detection
    
    POST /api/transactions/create/
    
    Requires JWT authentication.
    """
    
    permission_classes = [IsAuthenticated]
    serializer_class = TransactionCreateSerializer
    
    def post(self, request):
        """
        Create new transaction with fraud detection
        """
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
    tags=['Transactions'],
    summary='List User Transactions',
    description='Get list of all transactions for current user',
    responses={200: TransactionListSerializer}
)
class TransactionListView(APIView):
    """
    📋 List User Transactions
    
    GET /api/transactions/
    
    Returns all transactions for the authenticated user.
    """
    
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """
        Get user's transactions
        """
        transactions = Transaction.objects.filter(
            user=request.user
        ).order_by('-created_at')
        
        serializer = TransactionListSerializer(transactions, many=True)
        return Response(serializer.data)


@extend_schema(
    tags=['Transactions'],
    summary='Get Transaction Details',
    description='Get detailed information about a specific transaction',
    responses={200: TransactionDetailSerializer}
)
class TransactionDetailView(APIView):
    """
    🔍 Transaction Details
    
    GET /api/transactions/{id}/
    
    Returns detailed information about a specific transaction.
    """
    
    permission_classes = [IsAuthenticated]
    
    def get(self, request, transaction_id):
        """
        Get transaction details
        """
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
    tags=['Transactions'],
    summary='Get Transaction Statistics',
    description='Get statistics about user transactions'
)
class TransactionStatsView(APIView):
    """
    📊 Transaction Statistics
    
    GET /api/transactions/stats/
    
    Returns statistics about user's transactions.
    """
    
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """
        Get transaction statistics
        """
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
