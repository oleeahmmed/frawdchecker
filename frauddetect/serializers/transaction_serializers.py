"""
💰 Transaction Serializers with Fraud Detection
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Simple transaction serializer with built-in fraud detection.
"""

from rest_framework import serializers
from django.utils import timezone
from frauddetect.models import Transaction
from frauddetect.middleware import check_transaction_fraud, get_client_ip, get_geo_location, get_user_device
import uuid


class TransactionCreateSerializer(serializers.Serializer):
    """
    💰 Create Transaction with Fraud Detection
    """
    
    # Input fields
    amount = serializers.DecimalField(
        max_digits=15,
        decimal_places=2,
        required=True,
        help_text="Transaction amount"
    )
    currency = serializers.CharField(
        max_length=3,
        default='SAR',
        help_text="Currency code (e.g., SAR, USD)"
    )
    beneficiary = serializers.CharField(
        max_length=255,
        required=False,
        allow_blank=True,
        help_text="Beneficiary name"
    )
    transaction_type = serializers.ChoiceField(
        choices=[
            ('transfer', 'Bank Transfer'),
            ('p2p', 'Peer-to-Peer'),
            ('international', 'International Transfer'),
            ('cash_withdrawal', 'Cash Withdrawal'),
            ('bill_payment', 'Bill Payment'),
            ('purchase', 'Purchase'),
            ('crypto', 'Cryptocurrency'),
            ('deposit', 'Deposit'),
            ('other', 'Other'),
        ],
        default='transfer',
        help_text="Type of transaction"
    )
    description = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text="Transaction description"
    )
    
    # Output fields (read-only)
    success = serializers.BooleanField(read_only=True)
    transaction = serializers.DictField(read_only=True)
    fraud_check = serializers.DictField(read_only=True)
    
    def validate_amount(self, value):
        """Validate amount is positive"""
        if value <= 0:
            raise serializers.ValidationError("Amount must be greater than 0")
        return value
    
    def create(self, validated_data):
        """Create transaction with fraud detection"""
        request = self.context.get('request')
        user = request.user
        
        # Prepare transaction data
        transaction_data = {
            'amount': validated_data['amount'],
            'currency': validated_data.get('currency', 'SAR'),
            'beneficiary': validated_data.get('beneficiary', ''),
            'transaction_type': validated_data.get('transaction_type', 'transfer'),
            'description': validated_data.get('description', ''),
        }
        
        # RUN FRAUD DETECTION
        fraud_result = check_transaction_fraud(request, user, transaction_data)
        
        # If blocked, raise validation error and update risk profile
        if not fraud_result['allowed']:
            # UPDATE RISK PROFILE - Blocked transaction
            from frauddetect.utils import RiskProfileManager
            risk_manager = RiskProfileManager(user)
            risk_manager.on_transaction_blocked(
                amount=transaction_data['amount'],
                block_reason=fraud_result.get('error', {}).get('reason', 'high_risk')
            )
            raise serializers.ValidationError(fraud_result['error'])
        
        # CREATE TRANSACTION
        ip_address = get_client_ip(request)
        geo_data = get_geo_location(ip_address)
        device = get_user_device(request, user)
        
        # Generate external transaction ID
        external_txn_id = f"TXN-{uuid.uuid4().hex[:12].upper()}"
        
        # Determine status based on risk
        if fraud_result['action'] == 'hold':
            status = 'pending'
        elif fraud_result['action'] == 'flag':
            status = 'flagged'
        else:
            status = 'approved'
        
        # Create transaction
        transaction = Transaction.objects.create(
            user=user,
            device=device,
            external_txn_id=external_txn_id,
            amount=transaction_data['amount'],
            currency=transaction_data['currency'],
            beneficiary=transaction_data['beneficiary'],
            transaction_type=transaction_data['transaction_type'],
            description=transaction_data['description'],
            
            # Fraud detection results
            risk_score=fraud_result['risk_score'],
            risk_level=fraud_result['risk_level'],
            risk_reasons=fraud_result['risk_reasons'],
            triggered_patterns=fraud_result['triggered_patterns'],
            is_suspicious=fraud_result['risk_score'] >= 40,
            requires_manual_review=fraud_result['requires_manual_review'],
            
            # Location
            ip_address=ip_address,
            country_code=geo_data['country_code'],
            city=geo_data['city'],
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            
            # Status
            status=status,
            approved_at=timezone.now() if status == 'approved' else None,
        )
        
        # UPDATE RISK PROFILE based on transaction status
        from frauddetect.utils import RiskProfileManager
        risk_manager = RiskProfileManager(user)
        
        if status == 'approved':
            risk_manager.on_transaction_approved(
                amount=transaction_data['amount'],
                transaction_type=transaction_data['transaction_type']
            )
        elif status == 'flagged':
            risk_manager.on_transaction_flagged(
                amount=transaction_data['amount'],
                risk_reasons=fraud_result['risk_reasons']
            )
        
        # RETURN RESPONSE
        return {
            'success': True,
            'transaction': {
                'id': transaction.id,
                'external_txn_id': transaction.external_txn_id,
                'amount': str(transaction.amount),
                'currency': transaction.currency,
                'beneficiary': transaction.beneficiary,
                'transaction_type': transaction.transaction_type,
                'status': transaction.status,
                'risk_score': transaction.risk_score,
                'risk_level': transaction.risk_level,
                'requires_manual_review': transaction.requires_manual_review,
                'created_at': transaction.created_at.isoformat(),
            },
            'fraud_check': {
                'risk_score': fraud_result['risk_score'],
                'risk_level': fraud_result['risk_level'],
                'risk_reasons': fraud_result['risk_reasons'],
                'triggered_patterns': fraud_result['triggered_patterns'],
                'requires_manual_review': fraud_result['requires_manual_review'],
            },
            'location_info': fraud_result.get('location_info', {}),
        }


class TransactionListSerializer(serializers.ModelSerializer):
    """Transaction list serializer"""
    user_username = serializers.CharField(source='user.username', read_only=True)
    device_name = serializers.CharField(source='device.device_name', read_only=True)
    
    class Meta:
        model = Transaction
        fields = [
            'id',
            'external_txn_id',
            'user_username',
            'device_name',
            'amount',
            'currency',
            'beneficiary',
            'transaction_type',
            'status',
            'risk_score',
            'risk_level',
            'is_suspicious',
            'requires_manual_review',
            'created_at',
        ]
        read_only_fields = fields


class TransactionDetailSerializer(serializers.ModelSerializer):
    """Transaction detail serializer"""
    user_username = serializers.CharField(source='user.username', read_only=True)
    device_name = serializers.CharField(source='device.device_name', read_only=True)
    reviewed_by_username = serializers.CharField(source='reviewed_by.username', read_only=True)
    
    class Meta:
        model = Transaction
        fields = [
            'id',
            'external_txn_id',
            'user_username',
            'device_name',
            'amount',
            'currency',
            'beneficiary',
            'transaction_type',
            'description',
            'status',
            'risk_score',
            'risk_level',
            'risk_reasons',
            'triggered_patterns',
            'is_suspicious',
            'requires_manual_review',
            'ip_address',
            'country_code',
            'city',
            'reviewed_by_username',
            'reviewed_at',
            'review_notes',
            'created_at',
            'updated_at',
            'approved_at',
        ]
        read_only_fields = fields
