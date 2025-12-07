# 💰 Transaction Fraud Testing - সম্পূর্ণ গাইড

## 🎯 Overview

Transaction এ **12টি fraud checks** আছে। প্রতিটি check test করার commands এখানে।

---

## 📝 Transaction এ কী কী Check হয় (12টি)

```
1. 👑 Superuser কিনা?
2. 🚫 IP Blocked কিনা?
3. 🌍 Saudi Arabia থেকে কিনা?
4. 🔒 Device Trusted কিনা?
5. 💰 Amount Threshold exceed করেছে কিনা?
6. ⚡ High Velocity (10 txn/hour)?
7. 📊 Daily Limit exceed করেছে কিনা?
8. 🕐 Business Hours এর বাইরে কিনা?
9. 📈 User Average থেকে বেশি কিনা?
10. 😴 Dormant Account কিনা?
11. 🆕 New Account কিনা?
12. 🌐 Transaction Type Risk
```

---

## 🔑 Prerequisites

### Step 1: Login করো (Token নাও)
```bash
curl -X POST http://127.0.0.1:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{
    "username": "gsm",
    "password": "your_password"
  }'
```

Response থেকে `access` token copy করো।

### Step 2: Token Variable Set করো
```bash
# Bash এ
export TOKEN="your_access_token_here"

# Or Postman এ environment variable use করো
```

---

## 🧪 Test Case 1: Normal Transaction (Success)

### কী Test করছি:
সাধারণ transaction - সব ঠিক থাকলে কী হয়

### Test Command:
```bash
curl -X POST http://127.0.0.1:8000/api/transactions/create/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "amount": 5000,
    "currency": "SAR",
    "beneficiary": "Test User",
    "transaction_type": "transfer",
    "description": "Normal transaction"
  }'
```

### Expected Response:
```json
{
    "success": true,
    "transaction": {
        "id": 1,
        "external_txn_id": "TXN-ABC123",
        "amount": "5000.00",
        "status": "approved",
        "risk_score": 0,
        "risk_level": "safe"
    },
    "fraud_check": {
        "risk_score": 0,
        "risk_level": "safe",
        "requires_manual_review": false
    }
}
```

### ✅ Pass Criteria:
- Status: 200
- `status: "approved"`
- `risk_score: 0`

---

## 🧪 Test Case 2: High Amount (Threshold Exceeded)

### কী Test করছি:
100,000 SAR এর বেশি amount হলে কী হয়

### Test Command:
```bash
curl -X POST http://127.0.0.1:8000/api/transactions/create/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "amount": 150000,
    "currency": "SAR",
    "beneficiary": "High Value Test",
    "transaction_type": "transfer",
    "description": "Testing high amount"
  }'
```

### Expected Response:
```json
{
    "success": true,
    "transaction": {
        "amount": "150000.00",
        "status": "flagged",
        "risk_score": 30,
        "risk_level": "low"
    },
    "fraud_check": {
        "risk_score": 30,
        "risk_reasons": ["Amount 150000 exceeds threshold 100000"],
        "triggered_patterns": ["amount_exceeds_threshold"]
    }
}
```

### ✅ Pass Criteria:
- `status: "flagged"`
- `risk_score: 30`
- `triggered_patterns` এ "amount_exceeds_threshold"

---

## 🧪 Test Case 3: High Velocity (Too Many Transactions)

### কী Test করছি:
1 hour এ 10+ transactions করলে কী হয়

### Test Script:
```bash
# 10 বার transaction করো
for i in {1..10}; do
  echo "Transaction $i:"
  curl -X POST http://127.0.0.1:8000/api/transactions/create/ \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d "{
      \"amount\": 1000,
      \"currency\": \"SAR\",
      \"beneficiary\": \"Test $i\",
      \"transaction_type\": \"transfer\"
    }"
  sleep 1
done

# 11th transaction (should be blocked)
echo "Transaction 11 (should be blocked):"
curl -X POST http://127.0.0.1:8000/api/transactions/create/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "amount": 1000,
    "currency": "SAR",
    "beneficiary": "Test 11",
    "transaction_type": "transfer"
  }'
```

### Expected Response (11th):
```json
{
    "error": "Transaction Blocked",
    "reason": "high_velocity",
    "message": "Too many transactions. Maximum 10 per hour allowed.",
    "transaction_count": 11,
    "max_allowed": 10
}
```

### ✅ Pass Criteria:
- First 10: Success
- 11th: Blocked
- `reason: "high_velocity"`

---

## 🧪 Test Case 4: Daily Limit Exceeded

### কী Test করছি:
Daily amount limit (500,000 SAR) exceed করলে কী হয়

### Test Command:
```bash
# First transaction: 400,000 SAR
curl -X POST http://127.0.0.1:8000/api/transactions/create/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "amount": 400000,
    "currency": "SAR",
    "beneficiary": "Test",
    "transaction_type": "transfer"
  }'

# Second transaction: 200,000 SAR (total = 600,000)
curl -X POST http://127.0.0.1:8000/api/transactions/create/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "amount": 200000,
    "currency": "SAR",
    "beneficiary": "Test",
    "transaction_type": "transfer"
  }'
```

### Expected Response (2nd):
```json
{
    "error": "Transaction Blocked",
    "reason": "daily_limit_exceeded",
    "message": "Daily transaction limit exceeded",
    "today_amount": 600000,
    "max_amount": 500000
}
```

### ✅ Pass Criteria:
- First: Success
- Second: Blocked
- `reason: "daily_limit_exceeded"`

---

## 🧪 Test Case 5: Outside Business Hours

### কী Test করছি:
Business hours (8 AM - 6 PM) এর বাইরে transaction করলে কী হয়

### Test Command:
```bash
# Normal transaction
curl -X POST http://127.0.0.1:8000/api/transactions/create/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "amount": 10000,
    "currency": "SAR",
    "beneficiary": "Test",
    "transaction_type": "transfer"
  }'
```

### Expected Response (if outside business hours):
```json
{
    "success": true,
    "transaction": {
        "risk_score": 20,
        "risk_level": "low"
    },
    "fraud_check": {
        "risk_reasons": ["Transaction at high-risk hour: 2:00"],
        "triggered_patterns": ["high_risk_hours"]
    }
}
```

### ✅ Pass Criteria:
- রাত 12-6 AM: `risk_score: 20`
- `triggered_patterns: ["high_risk_hours"]`

---

## 🧪 Test Case 6: International Transfer

### কী Test করছি:
International transaction এ risk বেশি কিনা

### Test Command:
```bash
curl -X POST http://127.0.0.1:8000/api/transactions/create/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "amount": 50000,
    "currency": "SAR",
    "beneficiary": "International User",
    "transaction_type": "international",
    "description": "International transfer"
  }'
```

### Expected Response:
```json
{
    "success": true,
    "transaction": {
        "transaction_type": "international",
        "risk_score": 35,
        "risk_level": "low"
    },
    "fraud_check": {
        "risk_reasons": ["International transfer"],
        "triggered_patterns": ["international_transfer"]
    }
}
```

### ✅ Pass Criteria:
- `risk_score: 35`
- `triggered_patterns: ["international_transfer"]`

---

## 🧪 Test Case 7: Crypto Transaction

### Test Command:
```bash
curl -X POST http://127.0.0.1:8000/api/transactions/create/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "amount": 30000,
    "currency": "SAR",
    "beneficiary": "Crypto Exchange",
    "transaction_type": "crypto",
    "description": "Crypto purchase"
  }'
```

### Expected Response:
```json
{
    "success": true,
    "transaction": {
        "transaction_type": "crypto",
        "risk_score": 40,
        "risk_level": "medium"
    },
    "fraud_check": {
        "risk_reasons": ["Cryptocurrency transaction"],
        "triggered_patterns": ["crypto_transaction"]
    }
}
```

### ✅ Pass Criteria:
- `risk_score: 40`
- `risk_level: "medium"`

---

## 🧪 Test Case 8: P2P High Value

### Test Command:
```bash
curl -X POST http://127.0.0.1:8000/api/transactions/create/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "amount": 120000,
    "currency": "SAR",
    "beneficiary": "Friend",
    "transaction_type": "p2p",
    "description": "P2P transfer"
  }'
```

### Expected Response:
```json
{
    "success": true,
    "transaction": {
        "risk_score": 60,
        "risk_level": "high",
        "requires_manual_review": true
    },
    "fraud_check": {
        "risk_reasons": [
            "Amount 120000 exceeds threshold 100000",
            "High-value P2P transfer"
        ]
    }
}
```

### ✅ Pass Criteria:
- `risk_score: 60+`
- `requires_manual_review: true`

---

## 🧪 Test Case 9: Blocked IP

### Setup - IP Block করো:
```python
from frauddetect.models import IPBlocklist
from django.contrib.auth.models import User

admin = User.objects.filter(is_superuser=True).first()
IPBlocklist.objects.create(
    ip_address='192.168.1.100',
    reason='Test',
    is_active=True,
    blocked_by=admin
)
```

### Test Command:
```bash
curl -X POST http://127.0.0.1:8000/api/transactions/create/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Forwarded-For: 192.168.1.100" \
  -d '{
    "amount": 5000,
    "currency": "SAR",
    "beneficiary": "Test",
    "transaction_type": "transfer"
  }'
```

### Expected Response:
```json
{
    "error": "Transaction Blocked",
    "reason": "blacklisted_ip",
    "message": "Your IP address has been blocked",
    "ip_address": "192.168.1.100"
}
```

### ✅ Pass Criteria:
- Status: 400
- `reason: "blacklisted_ip"`

---

## 🧪 Test Case 10: Untrusted Device

### Setup - Device Untrust করো:
```python
from frauddetect.models import Device

# User এর device নাও
device = Device.objects.filter(user__username='gsm').first()
device.is_trusted = False
device.save()

print(f"✅ Device {device.id} untrusted!")
```

### Test Command:
```bash
curl -X POST http://127.0.0.1:8000/api/transactions/create/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "amount": 5000,
    "currency": "SAR",
    "beneficiary": "Test",
    "transaction_type": "transfer"
  }'
```

### Expected Response:
```json
{
    "error": "Transaction Blocked",
    "reason": "untrusted_device",
    "message": "This device is not trusted for transactions"
}
```

### Cleanup:
```python
device.is_trusted = True
device.save()
```

---

## 📊 Complete Test Checklist

```
[ ] 1. Normal Transaction - Success (5,000 SAR)
[ ] 2. High Amount - Flagged (150,000 SAR)
[ ] 3. High Velocity - Blocked (11 txns/hour)
[ ] 4. Daily Limit - Blocked (600,000 SAR)
[ ] 5. Outside Business Hours - Flagged
[ ] 6. International Transfer - Higher risk
[ ] 7. Crypto Transaction - Higher risk
[ ] 8. P2P High Value - Manual review
[ ] 9. Blocked IP - Blocked
[ ] 10. Untrusted Device - Blocked
[ ] 11. Non-SA Country - Blocked
[ ] 12. Superuser - Bypass all
```

---

## 🎯 Quick Test Script

Save as `test_transactions.sh`:
```bash
#!/bin/bash

# Get token first
echo "Getting token..."
TOKEN=$(curl -s -X POST http://127.0.0.1:8000/api/auth/login/ \
  -H "Content-Type: application/json" \
  -d '{"username": "gsm", "password": "your_password"}' \
  | python -m json.tool | grep '"access"' | cut -d'"' -f4)

echo "Token: ${TOKEN:0:20}..."
echo ""

# Test 1: Normal
echo "Test 1: Normal Transaction (5,000 SAR)"
curl -X POST http://127.0.0.1:8000/api/transactions/create/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"amount": 5000, "currency": "SAR", "beneficiary": "Test", "transaction_type": "transfer"}' \
  | python -m json.tool
echo ""

# Test 2: High Amount
echo "Test 2: High Amount (150,000 SAR)"
curl -X POST http://127.0.0.1:8000/api/transactions/create/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"amount": 150000, "currency": "SAR", "beneficiary": "Test", "transaction_type": "transfer"}' \
  | python -m json.tool
echo ""

# Test 3: International
echo "Test 3: International Transfer"
curl -X POST http://127.0.0.1:8000/api/transactions/create/ \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"amount": 50000, "currency": "SAR", "beneficiary": "Test", "transaction_type": "international"}' \
  | python -m json.tool
echo ""

echo "✅ Tests complete!"
```

Run:
```bash
chmod +x test_transactions.sh
./test_transactions.sh
```

---

## 🔧 Useful Commands

### View Transactions:
```python
from frauddetect.models import Transaction

for txn in Transaction.objects.all()[:10]:
    print(f"{txn.external_txn_id} - {txn.amount} - {txn.risk_score} - {txn.status}")
```

### View by Risk Level:
```python
high_risk = Transaction.objects.filter(risk_level='high')
print(f"High risk transactions: {high_risk.count()}")
```

### Reset for Testing:
```python
Transaction.objects.all().delete()
print("✅ All transactions deleted!")
```

---

এই guide follow করে সব transaction fraud checks test করতে পারবে! 🚀
