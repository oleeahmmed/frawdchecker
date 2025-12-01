# ব্লক করা দেশ থেকে লগইন রেকর্ড (Blocked Country Login Records)

## সংক্ষিপ্ত বিবরণ

যখন কোনো ব্যবহারকারী **অনুমোদিত নয় এমন দেশ** থেকে (যেমন: সৌদি আরব ছাড়া অন্য দেশ) লগইন করার চেষ্টা করে, তখন সিস্টেম:

1. ✅ **সব রেকর্ড তৈরি করে** (Device, IPBlocklist, LoginEvent)
2. ✅ **সেগুলোকে ব্লক হিসেবে চিহ্নিত করে**
3. ✅ **লগইন ব্লক করে**
4. ✅ **অ্যাডমিনকে পরে রিভিউ ও আনব্লক করার সুযোগ দেয়**

এটি সম্পূর্ণ অডিট ট্রেইল এবং অ্যাডমিনদের জন্য নমনীয়তা নিশ্চিত করে।

---

## কী কী রেকর্ড তৈরি হয়?

### ১. ডিভাইস রেকর্ড (Device)

```python
Device.objects.filter(user__username='testuser')
```

**ফিল্ড:**
- `is_blocked` = `True` ✅ (ব্লক করা)
- `is_trusted` = `False` (বিশ্বস্ত নয়)
- `status` = `'blocked'` (স্ট্যাটাস: ব্লক)
- `last_country_code` = `'BD'` (শেষ দেশ: বাংলাদেশ)
- `risk_score` = `70+` (ঝুঁকি স্কোর)

**অ্যাডমিন কী করতে পারে:**
- `is_blocked` কে `False` করে ডিভাইস আনব্লক করতে পারে

---

### ২. আইপি ব্লকলিস্ট (IPBlocklist)

```python
IPBlocklist.objects.filter(ip_address='103.108.140.1')
```

**ফিল্ড:**
- `ip_address` = ব্যবহারকারীর আইপি
- `reason` = `"Automatic block: Login attempt from non-allowed country BD (Bangladesh)"`
- `is_active` = `True` ✅ (সক্রিয়)
- `blocked_by` = প্রথম সুপারইউজার (সিস্টেম অ্যাডমিন)

**অ্যাডমিন কী করতে পারে:**
- `is_active` কে `False` করে আইপি আনব্লক করতে পারে

---

### ৩. লগইন ইভেন্ট (LoginEvent)

```python
LoginEvent.objects.filter(username='testuser', status='blocked')
```

**ফিল্ড:**
- `status` = `'blocked'` ✅ (স্ট্যাটাস: ব্লক)
- `is_suspicious` = `True` (সন্দেহজনক)
- `risk_score` = `100+` (ঝুঁকি স্কোর)
- `risk_reasons` = `['Device is blocked', 'IP address is blocked', ...]`
- `country_code` = `'BD'` (দেশ কোড)
- `ip_address` = ব্যবহারকারীর আইপি

**অ্যাডমিন কী করতে পারে:**
- অডিট ট্রেইলের জন্য রিভিউ করতে পারে (শুধু পড়া যায়)

---

### ৪. সিস্টেম লগ (SystemLog)

```python
SystemLog.objects.filter(log_type='security', level='critical')
```

**তিনটি লগ তৈরি হয়:**

1. **ডিভাইস তৈরির লগ:**
   - বার্তা: "New device blocked for {username} from {country_code}"

2. **আইপি ব্লকলিস্ট লগ:**
   - বার্তা: "IP {ip} automatically added to blocklist during login"

3. **লগইন ব্লক লগ:**
   - বার্তা: "Blocked login attempt for {username} from {ip}"

---

## API রেসপন্স (ব্লক করা লগইন)

যখন লগইন ব্লক করা হয়, API রিটার্ন করে:

```json
{
  "error": "Login blocked due to security concerns",
  "message": "Your login attempt has been blocked. All details have been recorded.",
  "risk_score": 115,
  "reasons": [
    "Device is blocked (not from allowed country)",
    "IP address is blocked",
    "Login from new device"
  ],
  "device_id": 5,
  "login_event_id": 12,
  "country_detected": "Bangladesh",
  "country_code": "BD",
  "contact": "Please contact support if you believe this is an error."
}
```

**স্ট্যাটাস কোড:** `400 Bad Request`

---

## অ্যাডমিন কীভাবে আনব্লক করবে?

### অপশন ১: ডিভাইস আনব্লক

1. Django Admin → Devices এ যান
2. ইউজার বা ডিভাইস আইডি দিয়ে খুঁজুন
3. `is_blocked` কে `False` করুন
4. `status` কে `'normal'` করুন
5. সেভ করুন

**ফলাফল:** ব্যবহারকারী এই ডিভাইস থেকে লগইন করতে পারবে

---

### অপশন ২: আইপি আনব্লক

1. Django Admin → IP Blocklist এ যান
2. আইপি অ্যাড্রেস খুঁজুন
3. `is_active` কে `False` করুন
4. সেভ করুন

**ফলাফল:** এই আইপি আর ব্লক থাকবে না

---

### অপশন ৩: উভয়ই আনব্লক

সম্পূর্ণ অ্যাক্সেসের জন্য দুটোই আনব্লক করুন:
1. ডিভাইস (`is_blocked = False`)
2. আইপি অ্যাড্রেস (`is_active = False`)

**ফলাফল:** ব্যবহারকারী স্বাভাবিকভাবে লগইন করতে পারবে

---

## সেটিংস কনফিগারেশন

### প্রয়োজনীয় সেটিংস (config/settings.py)

```python
# জিও-রেস্ট্রিকশন চালু করুন
GEO_RESTRICTION_ENABLED = True

# অনুমোদিত দেশ (ISO 3166-1 alpha-2 কোড)
ALLOWED_COUNTRIES = ['SA']  # শুধু সৌদি আরব

# অনুমোদিত নয় এমন দেশ থেকে ডিভাইস অটো-ব্লক
AUTO_BLOCK_DEVICES_FROM_BLOCKED_COUNTRIES = True

# আইপি অটো-ব্লকলিস্টে যোগ করুন
AUTO_BLOCK_NON_ALLOWED_COUNTRY_IPS = True

# অনুমোদিত দেশ থেকে ডিভাইস অটো-ট্রাস্ট
AUTO_TRUST_DEVICES_FROM_ALLOWED_COUNTRIES = True
```

---

## টেস্টিং

### টেস্ট স্ক্রিপ্ট চালান

```bash
python test_blocked_country_records.py
```

**পূর্বশর্ত:**
1. Django সার্ভার চালু: `python manage.py runserver`
2. টেস্ট ইউজার তৈরি: username='testuser', password='testpass123'

---

## ভেরিফিকেশন কমান্ড

### Django Shell

```python
python manage.py shell

# ডিভাইস রেকর্ড চেক করুন
from frauddetect.models import Device
Device.objects.filter(user__username='testuser').values(
    'id', 'is_trusted', 'is_blocked', 'status', 'last_country_code'
)

# আইপি ব্লকলিস্ট চেক করুন
from frauddetect.models import IPBlocklist
IPBlocklist.objects.all().values('ip_address', 'reason', 'is_active')

# লগইন ইভেন্ট চেক করুন
from frauddetect.models import LoginEvent
LoginEvent.objects.filter(username='testuser').values(
    'id', 'status', 'ip_address', 'country_code', 'risk_score'
)

# সিস্টেম লগ চেক করুন
from frauddetect.models import SystemLog
SystemLog.objects.filter(log_type='security').order_by('-created_at')[:5].values(
    'message', 'level', 'ip_address'
)
```

---

## সুবিধা

### ১. সম্পূর্ণ অডিট ট্রেইল
- প্রতিটি লগইন চেষ্টা রেকর্ড করা হয়
- অ্যাডমিন দেখতে পারে কে কোথা থেকে লগইন করার চেষ্টা করেছে
- কমপ্লায়েন্স এবং সিকিউরিটি রিভিউয়ের জন্য সম্পূর্ণ ইতিহাস

### ২. নমনীয় ম্যানেজমেন্ট
- অ্যাডমিন বৈধ ব্যবহারকারীদের আনব্লক করতে পারে
- নির্দিষ্ট ডিভাইস বা আইপি হোয়াইটলিস্ট করতে পারে
- সিকিউরিটি পলিসি রিভিউ ও সমন্বয় করতে পারে

### ৩. সিকিউরিটি প্রথম
- সন্দেহজনক লগইন তাৎক্ষণিকভাবে ব্লক করে
- অননুমোদিত অ্যাক্সেস প্রতিরোধ করে
- KSA ডেটা রেসিডেন্সি প্রয়োজনীয়তা মেনে চলে

### ৪. ইউজার এক্সপেরিয়েন্স
- স্পষ্ট এরর মেসেজ
- যোগাযোগের তথ্য প্রদান করা হয়
- ব্যবহারকারী জানে তার চেষ্টা রেকর্ড করা হয়েছে

---

## সুপারইউজার বাইপাস

**গুরুত্বপূর্ণ:** সুপারইউজার (is_superuser=True) সব ফ্রড ডিটেকশন বাইপাস করে:
- কোনো ডিভাইস ব্লকিং নেই
- কোনো আইপি ব্লকিং নেই
- কোনো জিও-রেস্ট্রিকশন নেই
- সবসময় বিশ্বস্ত

**সাধারণ স্টাফ (is_staff=True কিন্তু is_superuser=False):**
- সব ফ্রড ডিটেকশন নিয়মের অধীন
- অনুমোদিত নয় এমন দেশ থেকে হলে ব্লক হতে পারে

---

## সারসংক্ষেপ

✅ **সব রেকর্ড তৈরি হয়** ব্লক করার আগে
✅ **অ্যাডমিন রিভিউ ও আনব্লক করতে পারে** যেকোনো সময়
✅ **সম্পূর্ণ অডিট ট্রেইল** কমপ্লায়েন্সের জন্য
✅ **সিকিউরিটি বজায় থাকে** তাৎক্ষণিক ব্লকিং দিয়ে
✅ **নমনীয় ম্যানেজমেন্ট** বৈধ ব্যবহারকারীদের জন্য
