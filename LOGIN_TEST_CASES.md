# 🔐 Login Test Cases - সহজ বাংলায়

## 📝 Login এ কী কী Check হয় (8টি)

### ✅ **Check 1: Superuser কিনা?**

**কী দেখে:**
- User এর `is_superuser` field

**কী করে:**
- ✅ যদি superuser হয় → সব check বাদ দিয়ে সরাসরি login
- ❌ যদি না হয় → পরের check এ যায়

**উদাহরণ:**
```
User: gsm (superuser)
→ ✅ সরাসরি login, কোনো check নেই
```

---

### ✅ **Check 2: IP Whitelist এ আছে কিনা?**

**কী দেখে:**
- `ip_whitelist` table এ IP আছে কিনা

**কী করে:**
- ✅ যদি whitelist এ থাকে → সব check বাদ দিয়ে সরাসরি login
- ❌ যদি না থাকে → পরের check এ যায়

**উদাহরণ:**
```
IP: 127.0.0.1 (whitelist এ আছে)
→ ✅ সরাসরি login, কোনো check নেই
```

**কেন দরকার:**
- Office IP, Admin IP এর জন্য
- Trusted locations

---

### 🚫 **Check 3: IP Block করা আছে কিনা?**

**কী দেখে:**
- `ip_blocklist` table এ IP আছে কিনা
- `is_active = True` কিনা

**কী করে:**
- ✅ যদি blocked থাকে → 🚫 Login বন্ধ
- ❌ যদি না থাকে → পরের check এ যায়

**উদাহরণ:**
```
IP: 192.168.1.100 (blocked)
→ 🚫 "Your IP has been blocked"
```

**কখন block হয়:**
- Manual block (admin করে)
- Auto-block (5 বার ভুল password)
- Auto-block (অন্য দেশ থেকে login)

---

### 🔑 **Check 4: Password সঠিক কিনা?**

**কী দেখে:**
- `auth_user` table এ username আছে কিনা
- Password match করে কিনা

**কী করে:**
- ✅ যদি সঠিক হয় → পরের check এ যায়
- ❌ যদি ভুল হয় → 🚫 Login failed

**উদাহরণ:**
```
Username: gsm
Password: wrong123
→ 🚫 "Invalid credentials"
→ Failed login save হয়
```

**কী save হয়:**
- `login_events` table এ:
  - username
  - status = 'failed'
  - ip_address
  - attempt_time

---

### 📱 **Check 5: Device Block করা আছে কিনা?**

**কী দেখে:**
- `devices` table এ device খুঁজে
- `is_blocked` field check করে

**কী করে:**
- ✅ যদি blocked থাকে → 🚫 Login বন্ধ
- ❌ যদি না থাকে → পরের check এ যায়

**উদাহরণ:**
```
Device: Chrome Browser (ID: 5)
is_blocked = True
→ 🚫 "This device has been blocked"
```

**Device কিভাবে identify করে:**
- Browser fingerprint
- User agent
- IP address
- সব মিলিয়ে একটা unique hash তৈরি করে

---

### 🔒 **Check 6: Device Trusted কিনা?**

**কী দেখে:**
- `devices` table এ `is_trusted` field

**কী করে:**
- ✅ যদি trusted হয় → পরের check এ যায়
- ❌ যদি না হয় → 🚫 Login বন্ধ

**উদাহরণ:**
```
Device: New Phone
is_trusted = False
→ 🚫 "Device not trusted"
```

**কখন auto-trust হয়:**
- ✅ Saudi Arabia থেকে নতুন device → Auto-trust
- ❌ অন্য দেশ থেকে → Untrusted থাকে

---

### 🌍 **Check 7: Saudi Arabia থেকে কিনা?**

**কী দেখে:**
- IP address থেকে country detect করে
- `fraud_configs` table এ `allowed_countries` check করে

**কী করে:**
- ✅ যদি SA থেকে হয় → পরের check এ যায়
- ❌ যদি অন্য দেশ থেকে হয় → 🚫 Login বন্ধ + IP block

**উদাহরণ:**
```
IP: 8.8.8.8 (USA)
Country: US
→ 🚫 "Only Saudi Arabia users allowed"
→ IP automatically blocked
```

**Allowed countries:**
- Default: শুধু `SA` (Saudi Arabia)
- Admin panel থেকে change করা যায়

---

### ⏰ **Check 8: বেশি চেষ্টা করেছে কিনা?**

**কী দেখে:**
- `login_events` table এ last 5 minutes এর failed attempts
- Count করে কতবার failed হয়েছে

**কী করে:**
- ✅ যদি < 5 attempts → Login allow
- ❌ যদি >= 5 attempts → 🚫 Login বন্ধ + IP block

**উদাহরণ:**
```
Last 5 minutes এ:
- 10:00 AM - Failed
- 10:01 AM - Failed
- 10:02 AM - Failed
- 10:03 AM - Failed
- 10:04 AM - Failed
- 10:05 AM - Try again
→ 🚫 "Too many attempts. IP blocked"
```

**Settings:**
- Max attempts: 5
- Time window: 5 minutes
- Admin panel থেকে change করা যায়

---

## 🎯 সব Check Pass হলে কী হয়:

```
✅ JWT tokens তৈরি হয়:
   - access_token (1 hour)
   - refresh_token (7 days)

✅ Database এ save হয়:
   - login_events table এ (status: success)
   - devices table update হয় (last_seen_at)

✅ Response পাবে:
   {
     "access": "token...",
     "refresh": "token...",
     "user": {...},
     "device_id": 5,
     "security": {
       "risk_score": 0,
       "risk_level": "safe"
     }
   }
```

---

## 📊 প্রতিটি Check এর Priority:

```
Priority 1 (সবচেয়ে বেশি):
👑 Superuser → সব bypass
✅ IP Whitelist → সব bypass

Priority 2 (Critical):
🚫 IP Blocked → Block
🔑 Password Wrong → Failed

Priority 3 (Security):
📱 Device Blocked → Block
🔒 Device Untrusted → Block

Priority 4 (Compliance):
🌍 Wrong Country → Block + IP Block
⏰ Too Many Attempts → Block + IP Block
```

---

## 💡 Test Scenarios:

### **Scenario 1: Normal User (Success)**
```
User: john
Password: ✅ Correct
IP: 127.0.0.1 (SA)
Device: Chrome (Trusted)
Attempts: 0

Result: ✅ Login Success
```

### **Scenario 2: Wrong Password**
```
User: john
Password: ❌ Wrong
IP: 127.0.0.1

Result: 🚫 Login Failed
Save: login_events (failed)
```

### **Scenario 3: Blocked IP**
```
User: john
Password: ✅ Correct
IP: 192.168.1.100 (Blocked)

Result: 🚫 Login Blocked
Message: "IP blocked"
```

### **Scenario 4: USA থেকে Login**
```
User: john
Password: ✅ Correct
IP: 8.8.8.8 (USA)

Result: 🚫 Login Blocked
Message: "Only SA allowed"
Action: IP auto-blocked
```

### **Scenario 5: Too Many Attempts**
```
User: john
Failed attempts: 5 times in 5 minutes

Result: 🚫 Login Blocked
Message: "Too many attempts"
Action: IP auto-blocked
```

### **Scenario 6: Superuser**
```
User: gsm (Superuser)
Password: ✅ Correct

Result: ✅ Login Success
Note: সব checks bypass!
```

### **Scenario 7: Blocked Device**
```
User: john
Password: ✅ Correct
Device: Chrome (Blocked)

Result: 🚫 Login Blocked
Message: "Device blocked"
```

### **Scenario 8: Untrusted Device**
```
User: john
Password: ✅ Correct
Device: New Phone (Untrusted)
Country: USA

Result: 🚫 Login Blocked
Message: "Device not trusted"
```

### **Scenario 9: Whitelisted IP**
```
User: john
Password: ❌ Wrong (10 times)
IP: 127.0.0.1 (Whitelisted)

Result: ✅ Still allowed
Note: Whitelist সব bypass করে!
```

### **Scenario 10: Email Login**
```
User: john@example.com (email)
Password: ✅ Correct

Result: ✅ Login Success
Note: Email দিয়েও login করা যায়
```

---

## 🎯 Summary Table:

| Test Case | Condition | Expected Result |
|-----------|-----------|-----------------|
| 1. Normal Login | Valid credentials, SA IP, Trusted device | ✅ Success |
| 2. Wrong Password | Invalid password | 🚫 Failed |
| 3. Blocked IP | IP in blocklist | 🚫 Blocked |
| 4. Blocked Device | Device blocked | 🚫 Blocked |
| 5. Untrusted Device | Device not trusted, non-SA | 🚫 Blocked |
| 6. Non-SA Country | IP from USA/UK/etc | 🚫 Blocked + IP blocked |
| 7. Rate Limiting | 5+ failed attempts in 5 min | 🚫 Blocked + IP blocked |
| 8. Whitelisted IP | IP in whitelist | ✅ Bypass all checks |
| 9. Superuser | is_superuser=True | ✅ Bypass all checks |
| 10. Email Login | Email instead of username | ✅ Success |

---

## 🔄 Login Flow Diagram:

```
User Login Request
    ↓
👑 Superuser? → YES → ✅ Login Success
    ↓ NO
✅ IP Whitelisted? → YES → ✅ Login Success
    ↓ NO
🚫 IP Blocked? → YES → 🚫 Login Blocked
    ↓ NO
🔑 Password Correct? → NO → 🚫 Login Failed
    ↓ YES
📱 Device Blocked? → YES → 🚫 Login Blocked
    ↓ NO
🔒 Device Trusted? → NO → 🚫 Login Blocked
    ↓ YES
🌍 Country SA? → NO → 🚫 Login Blocked + IP Blocked
    ↓ YES
⏰ Too Many Attempts? → YES → 🚫 Login Blocked + IP Blocked
    ↓ NO
✅ Login Success
    ↓
Save: login_events, devices
Return: JWT tokens
```

---

## 📋 Quick Reference:

**8টি Security Checks:**
1. ✅ Superuser bypass
2. ✅ IP Whitelist bypass
3. 🚫 IP Blocklist check
4. 🔑 Password verification
5. 📱 Device block check
6. 🔒 Device trust check
7. 🌍 Country restriction (SA only)
8. ⏰ Rate limiting (5 attempts/5min)

**Auto-block হয় যখন:**
- 5 বার ভুল password
- অন্য দেশ থেকে login
- Manual block (admin)

**Auto-trust হয় যখন:**
- Saudi Arabia থেকে নতুন device
- Superuser এর device

**Bypass করে:**
- Superuser (সব checks)
- Whitelisted IP (সব checks)

---

এই হলো তোমার complete login test cases! 🚀
