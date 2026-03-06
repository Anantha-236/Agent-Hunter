# Meesho Bug Bounty Program — Manual Hunting Guide

> **Policy Restriction:** Meesho prohibits automated scanners/tools against production systems.  
> All testing must be done **manually** using Burp Suite, browser DevTools, and similar intercept-based tools.

---

## Table of Contents

1. [Scope & Rules](#scope--rules)
2. [Setup & Tools](#setup--tools)
3. [Phase 1: Reconnaissance](#phase-1-reconnaissance)
4. [Phase 2: Authentication & Authorization](#phase-2-authentication--authorization)
5. [Phase 3: Injection Attacks](#phase-3-injection-attacks)
6. [Phase 4: Business Logic Bugs](#phase-4-business-logic-bugs)
7. [Phase 5: Misconfiguration](#phase-5-misconfiguration)
8. [Phase 6: Mobile App Testing](#phase-6-mobile-app-testing)
9. [Phase 7: API Security](#phase-7-api-security)
10. [Reporting Template](#reporting-template)
11. [Payout Priority](#payout-priority)
12. [Do's and Don'ts](#dos-and-donts)

---

## Scope & Rules

### In Scope
- `meesho.com` and its subdomains (confirm exact scope on HackerOne program page)
- Meesho Android/iOS mobile applications
- APIs used by web and mobile apps

### Out of Scope (Typical)
- Third-party services (payment gateways, CDNs)
- Social engineering / phishing attacks
- Physical attacks
- Denial of Service (DoS/DDoS)
- Automated scanning against production

### Rules
- **No automated scanners** — Manual testing only
- **No testing on other users' accounts** without permission
- **No data exfiltration** — Stop once you prove access
- **No destructive testing** — Don't delete data, crash services
- **Report promptly** — Don't sit on vulnerabilities
- **One report per bug** — Don't chain multiple issues into one

---

## Setup & Tools

### Required Tools

| Tool | Purpose | Download |
|------|---------|----------|
| **Burp Suite Community** | HTTP proxy, intercept & modify requests | https://portswigger.net/burp/communitydownload |
| **Browser DevTools** | Network inspection, JS debugging | Built into Chrome/Firefox |
| **Wappalyzer** | Technology fingerprinting | Browser extension |
| **FoxyProxy** | Quick proxy switching | Browser extension |
| **jadx** | Android APK decompilation | https://github.com/skylot/jadx |
| **Frida** | Mobile runtime hooking | https://frida.re |
| **curl / httpie** | Manual HTTP request crafting | CLI tools |

### Setup Steps

1. **Install Burp Suite Community Edition**
2. **Configure browser proxy** → `127.0.0.1:8080`
3. **Install Burp CA certificate** in browser (for HTTPS interception)
4. **Create 2 Meesho test accounts** (Account A and Account B)
   - Use different emails, phone numbers
   - You'll use these to test authorization bugs
5. **Enable Burp's Site Map** → Browse Meesho normally to capture all endpoints

---

## Phase 1: Reconnaissance

### 1.1 Passive Recon (No Requests Sent)

```
# Check for public information
- Google dorks:
    site:meesho.com
    site:meesho.com filetype:json
    site:meesho.com inurl:api
    site:meesho.com intitle:"index of"
    site:*.meesho.com

- Check Wayback Machine: https://web.archive.org/web/*/meesho.com
- Check crt.sh for subdomains: https://crt.sh/?q=%25.meesho.com
- GitHub dork: "meesho.com" password OR secret OR api_key OR token
```

### 1.2 Active Recon (Through Browser + Burp)

```
Browse these paths manually:
  /robots.txt
  /sitemap.xml
  /.well-known/security.txt
  /api/
  /graphql
  /swagger/
  /api-docs/
  /admin/
  /debug/
  /health
  /status
  /config
  /env
```

### 1.3 Technology Fingerprinting

- Check `Server`, `X-Powered-By`, `X-Frame-Options` response headers
- Note cookie names (reveals framework: `JSESSIONID` = Java, `csrftoken` = Django, etc.)
- Check JavaScript source files for:
  - API base URLs
  - Hardcoded tokens/keys
  - Internal endpoints
  - Developer comments

### 1.4 Endpoint Mapping

1. Open Burp Suite → Proxy → Intercept OFF
2. Browse Meesho: login, search products, add to cart, checkout flow, profile, settings
3. Go to Burp's **Target → Site Map** — you now have every endpoint
4. Export or note down all unique API paths
5. Categorize them:
   - **Auth endpoints** (login, register, password reset, OTP)
   - **User data endpoints** (profile, address, orders)
   - **Product endpoints** (search, details, reviews)
   - **Cart/Checkout endpoints** (add to cart, apply coupon, payment)
   - **Seller endpoints** (if accessible)

---

## Phase 2: Authentication & Authorization

> **This is where the highest-paying bugs live on e-commerce platforms.**

### 2.1 IDOR (Insecure Direct Object Reference)

**What:** Accessing another user's data by changing an ID in the request.

**How to test:**

1. Login as Account A
2. Perform an action (view order, view address, view profile)
3. In Burp, find the request — note the ID parameter (e.g., `order_id=12345`)
4. Login as Account B
5. Perform the same action — note Account B's ID (e.g., `order_id=67890`)
6. **Replay Account A's request but with Account B's session token** — if you see Account A's data, it's IDOR

**Endpoints to test for IDOR:**

```
GET /api/v1/orders/{order_id}           → Change order_id
GET /api/v1/users/{user_id}/profile     → Change user_id
GET /api/v1/addresses/{address_id}      → Change address_id
GET /api/v1/payments/{payment_id}       → Change payment_id
PUT /api/v1/users/{user_id}/email       → Change user_id
DELETE /api/v1/addresses/{address_id}   → Delete other's address?
```

**Tips:**
- Try numeric IDs: increment/decrement by 1
- Try UUIDs: swap between accounts
- Try encoded IDs: base64-decode, modify, re-encode
- Try both GET and POST/PUT/DELETE on same endpoint

### 2.2 Broken Authentication

**Password Reset Flow:**
1. Request password reset for Account A
2. Intercept the reset link/OTP
3. Check if:
   - Reset token is predictable (sequential, timestamp-based)
   - Token can be reused
   - Token works for a different account
   - OTP is brute-forceable (no rate limiting)
   - Response leaks the OTP/token

**Session Management:**
- Does logout actually invalidate the session token?
- Can you use the old token after logout?
- Are tokens rotated after password change?
- Is there session fixation (can you set someone else's session)?

**OTP Bypass:**
```
1. Enter phone number → receive OTP
2. Intercept the OTP verification request
3. Try:
   - Brute force (0000-9999 if 4-digit), check for rate limiting
   - Modify response from "invalid" to "valid" (response manipulation)
   - Check if OTP is in the response headers/body
   - Try null OTP, empty OTP, or "000000"
   - Check if OTP is reusable
```

### 2.3 Privilege Escalation

- Use a **buyer** account's session token on **seller**-only API endpoints
- Try accessing admin endpoints with a regular user token
- Check if role parameter can be modified in profile update requests
- Look for hidden parameters: `role`, `is_admin`, `user_type`, `permissions`

### 2.4 CSRF (Cross-Site Request Forgery)

Test on state-changing actions:
```
- Email change
- Password change
- Address add/update/delete
- Phone number change
- Account deletion
- Payment method changes
```

**How:**
1. Capture the request in Burp
2. Right-click → Engagement tools → Generate CSRF PoC
3. Open the PoC HTML in a browser while logged into Meesho
4. If the action succeeds without user interaction → CSRF vulnerability

**Check for:**
- Missing CSRF token
- CSRF token not validated server-side
- CSRF token reusable across sessions
- CSRF token in GET parameter (leaked via Referer header)

### 2.5 Race Condition

**How:**
1. Capture a request (e.g., apply coupon, claim reward)
2. Send to Burp Intruder or use Turbo Intruder
3. Send 20-50 identical requests simultaneously
4. Check if the action was applied multiple times

**Test on:**
- Coupon/discount code application
- Referral reward claiming
- Limited stock purchase
- Wallet credit/cashback
- Follow/unfollow (can you get double rewards?)

---

## Phase 3: Injection Attacks

### 3.1 Cross-Site Scripting (XSS)

**Input fields to test:**

| Location | Type |
|----------|------|
| Search bar | Reflected XSS |
| Profile name | Stored XSS |
| Address fields | Stored XSS |
| Product reviews | Stored XSS |
| Support chat messages | Stored XSS |
| File upload (filename) | Stored XSS |

**Payloads to try (one at a time):**

```html
<!-- Basic -->
<script>alert(1)</script>
"><script>alert(1)</script>
'><script>alert(1)</script>

<!-- Event handlers -->
"><img src=x onerror=alert(1)>
"><svg onload=alert(1)>
" onfocus=alert(1) autofocus="
" onmouseover=alert(1) "

<!-- Filter bypass -->
<ScRiPt>alert(1)</ScRiPt>
<img src=x onerror=alert&#40;1&#41;>
<svg/onload=alert(1)>
javascript:alert(1)

<!-- Polyglot -->
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//
```

**Steps:**
1. Enter payload in input field
2. Submit the form
3. Check if the payload is reflected in the page source
4. If reflected, check if it executes (pop-up alert box)
5. For stored XSS, check if it triggers when another user views it

### 3.2 SQL Injection

**Where to test:**
- Search parameters
- Filter/sort parameters
- Login forms
- API query parameters
- Any parameter that likely queries a database

**Payloads:**

```sql
-- Error-based detection
'
''
' OR '1'='1
' OR '1'='1' --
' UNION SELECT NULL--
1' ORDER BY 1--
1' ORDER BY 100--

-- Time-based blind
' OR SLEEP(5)--
' OR pg_sleep(5)--
1' AND (SELECT SLEEP(5))--

-- Boolean-based blind
' AND '1'='1  (true — normal response)
' AND '1'='2  (false — different response)
```

**Look for:**
- Database error messages in response
- Different response length/content for true vs false conditions
- Time delays in response

### 3.3 Server-Side Template Injection (SSTI)

**Test in any field that reflects your input:**

```
{{7*7}}         → If you see 49, it's vulnerable
${7*7}          → Alternative syntax
<%= 7*7 %>      → ERB (Ruby)
#{7*7}          → Pug/Jade
{{constructor.constructor('return this')()}}  → Angular/JS
```

### 3.4 Server-Side Request Forgery (SSRF)

**Where to test:**
- Image/file URL inputs (profile picture upload via URL)
- Webhook URLs
- Any parameter accepting a URL

**Payloads:**
```
http://127.0.0.1
http://localhost
http://169.254.169.254/latest/meta-data/  (AWS metadata)
http://[::1]
http://0x7f000001
http://2130706433
```

**Use Burp Collaborator or webhook.site to detect blind SSRF.**

### 3.5 Open Redirect

**Where to test:**
- Login redirect: `?next=`, `?redirect=`, `?url=`, `?return_to=`
- Logout redirect
- OAuth callback URLs

**Payloads:**
```
https://evil.com
//evil.com
/\evil.com
////evil.com
https://meesho.com@evil.com
https://meesho.com.evil.com
javascript:alert(1)
```

---

## Phase 4: Business Logic Bugs

> **E-commerce platforms are goldmines for business logic bugs.**

### 4.1 Price Manipulation

1. Add item to cart
2. Proceed to checkout
3. Intercept the checkout/payment request in Burp
4. Look for price, amount, quantity, discount fields
5. Try:
   - Set price to `0` or `1`
   - Set quantity to `-1` (negative)
   - Set discount to `100` (100%)
   - Modify total amount

### 4.2 Coupon/Discount Abuse

- Apply expired coupon codes
- Apply same coupon multiple times
- Apply seller-specific coupons as a buyer
- Use coupon on items excluded from the offer
- Stack multiple coupons (if only one should apply)
- Race condition: apply coupon simultaneously from multiple sessions

### 4.3 Payment Flow Bypass

1. Start checkout → reach payment step
2. Intercept the payment callback/confirmation request
3. Try:
   - Modify payment status from `pending` to `success`
   - Replay a successful payment callback for a new order
   - Skip payment step entirely (jump to order confirmation)
   - Use a `0` amount payment

### 4.4 Cart Manipulation

- Add item → remove item → check if price updates correctly
- Change quantity after price calculation
- Add item that's out of stock (modify stock check param)
- Negative quantity in cart

### 4.5 Referral System Abuse

- Self-referral (refer your own account)
- Claim referral bonus multiple times
- Referral with non-existent accounts
- Modify referral reward amount in request

### 4.6 Order Manipulation

- Cancel order after refund is initiated → double refund?
- Modify shipping address after order is shipped
- Access/modify other users' orders via API
- Change order status via API manipulation

### 4.7 Seller-Side Logic (if accessible)

- List product with negative price
- Modify another seller's product listing
- Access another seller's sales data
- Withdraw more money than available balance

---

## Phase 5: Misconfiguration

### 5.1 CORS Misconfiguration

```bash
# Send request with arbitrary Origin header
curl -H "Origin: https://evil.com" -I https://meesho.com/api/endpoint

# Check response for:
Access-Control-Allow-Origin: https://evil.com     ← VULNERABLE
Access-Control-Allow-Credentials: true             ← CRITICAL if combined
```

**Also test:**
```
Origin: null
Origin: https://meesho.com.evil.com
Origin: https://evilmeesho.com
```

### 5.2 Security Headers

Check for missing headers:
```
X-Frame-Options                   → Missing = Clickjacking possible
Content-Security-Policy           → Missing = XSS easier
Strict-Transport-Security         → Missing = Downgrade attacks
X-Content-Type-Options            → Missing = MIME sniffing
Referrer-Policy                   → Missing = Data leakage
Permissions-Policy                → Missing = Feature abuse
```

### 5.3 Information Disclosure

- Verbose error messages (stack traces, DB info)
- API responses with excessive data (PII in list endpoints)
- Source code comments with sensitive info
- Exposed `.git/`, `.env`, `/debug/`, `/phpinfo.php`
- Version numbers in headers

### 5.4 Subdomain Takeover

1. Find Meesho subdomains via `crt.sh`
2. Check if any subdomain points to an unclaimed service (S3, Heroku, GitHub Pages, etc.)
3. If CNAME exists but service is unclaimed → takeover possible

### 5.5 S3 Bucket Misconfiguration

If you find S3 bucket URLs in responses:
```bash
aws s3 ls s3://bucket-name --no-sign-request
# If it lists files → public read
# Try uploading:
aws s3 cp test.txt s3://bucket-name/test.txt --no-sign-request
# If it works → public write (CRITICAL)
```

---

## Phase 6: Mobile App Testing

### 6.1 Setup

1. Download Meesho APK from APKMirror
2. Install on emulator or rooted device
3. Configure device proxy → Burp Suite (`127.0.0.1:8080`)
4. Install Burp CA certificate on device

### 6.2 Static Analysis

```bash
# Decompile APK
jadx -d output_dir meesho.apk

# Search for secrets
grep -r "api_key\|secret\|password\|token\|key" output_dir/
grep -r "http://\|https://" output_dir/ | grep -v "meesho.com"

# Look for:
- Hardcoded API keys
- Hardcoded credentials
- Internal/staging API URLs
- Firebase URLs (check if database is public)
- AWS keys
```

### 6.3 Dynamic Analysis

- Intercept all mobile API traffic through Burp
- Mobile APIs often have **weaker authorization** than web
- Check if certificate pinning is enforced (use Frida to bypass if needed)
- Test same bugs as web (IDOR, auth bypass, injection) on mobile endpoints
- Mobile-specific: check deep links, intent handlers, exported activities

### 6.4 Firebase Check

If you find Firebase URLs (`*.firebaseio.com`):
```
https://PROJECT-NAME.firebaseio.com/.json
```
If it returns data → open Firebase database (CRITICAL)

---

## Phase 7: API Security

### 7.1 API Enumeration

- Capture all API calls from Burp Site Map
- Look for API versioning: `/api/v1/` → try `/api/v2/`, `/api/internal/`
- Check for GraphQL: `/graphql` → use introspection query:

```json
{"query": "{__schema{types{name,fields{name}}}}"}
```

### 7.2 Rate Limiting

Test if rate limiting exists on:
- Login (brute force protection)
- OTP verification
- Password reset
- API endpoints (data scraping)

**How:** Send 100+ requests rapidly. If no blocking/throttling → missing rate limit.

### 7.3 HTTP Method Tampering

```
# If GET /api/users/123 returns data, try:
DELETE /api/users/123
PUT /api/users/123   (with modified body)
PATCH /api/users/123
OPTIONS /api/users/123  (check allowed methods)
```

### 7.4 Mass Assignment

```json
// Normal profile update request:
PUT /api/users/me
{"name": "John", "email": "john@example.com"}

// Try adding extra fields:
PUT /api/users/me
{"name": "John", "email": "john@example.com", "role": "admin", "is_verified": true, "balance": 99999}
```

### 7.5 JWT Issues (if JWT is used)

- Decode JWT at https://jwt.io
- Try changing algorithm to `none`
- Try changing `alg` from RS256 to HS256
- Modify claims (user_id, role) and re-sign with empty key
- Check if expired tokens still work

---

## Reporting Template

When you find a bug, submit a report on HackerOne with this structure:

```markdown
## Title
[Bug Type] — Brief description (e.g., "IDOR — Access any user's order details via /api/v1/orders/{id}")

## Summary
One paragraph explaining the vulnerability and its impact.

## Severity
Critical / High / Medium / Low (with justification)

## Steps to Reproduce
1. Login to Meesho with Account A (email: test1@example.com)
2. Navigate to Orders page
3. Intercept the request in Burp Suite:
   GET /api/v1/orders/12345
   Authorization: Bearer <account_a_token>
4. Note the order_id: 12345
5. Login to Account B
6. Replay the same request with Account B's token but Account A's order_id
7. Observe: Account A's order details are returned

## Impact
- An attacker can access any user's order details including:
  - Full name, phone number, delivery address
  - Order items and payment information
- Affects all Meesho users (~150M+)

## Proof of Concept
[Attach screenshots, HTTP request/response pairs]

## Suggested Fix
- Implement server-side authorization check: verify that the authenticated user
  owns the requested resource before returning data.
```

---

## Payout Priority

Focus on these bug types first (highest payout → lowest):

| Priority | Bug Type | Typical Impact | Expected Payout |
|----------|----------|---------------|-----------------|
| 1 | Account Takeover | Full account control | $$$$ |
| 2 | IDOR exposing PII | Mass data leakage | $$$ |
| 3 | Payment/Logic bypass | Financial loss | $$$ |
| 4 | Stored XSS | Session hijacking | $$ |
| 5 | SSRF to internal | Internal network access | $$ |
| 6 | SQL Injection | Data breach | $$ |
| 7 | CSRF on critical actions | Unauthorized actions | $ |
| 8 | Open Redirect | Phishing | $ |
| 9 | Info Disclosure | Minor data leak | $ |
| 10 | Missing headers | Low impact | $ |

---

## Do's and Don'ts

### Do's
- Create your own test accounts for testing
- Stop testing as soon as you confirm the vulnerability
- Report immediately after discovery
- Include clear steps to reproduce
- Be professional and respectful in communication
- Test during off-peak hours when possible
- Keep detailed notes of all testing

### Don'ts
- **DO NOT use automated scanners** (Meesho explicitly prohibits this)
- DO NOT access other real users' data
- DO NOT perform DoS/DDoS attacks
- DO NOT exfiltrate data — prove access, then stop
- DO NOT test on production with destructive payloads
- DO NOT publicly disclose before Meesho fixes the issue
- DO NOT chain social engineering with technical bugs
- DO NOT modify or delete any data that isn't yours

---

## Quick-Start Checklist

```
[ ] Burp Suite installed and configured
[ ] Two Meesho test accounts created
[ ] Browser proxy configured (127.0.0.1:8080)
[ ] Burp CA cert installed in browser
[ ] Browsed all Meesho pages to build Site Map
[ ] Identified all API endpoints
[ ] Tested IDOR on every endpoint with IDs
[ ] Tested auth bypass on sensitive endpoints
[ ] Tested XSS on all input fields
[ ] Tested business logic on checkout/cart/coupon
[ ] Tested CORS misconfiguration
[ ] Checked for information disclosure
[ ] Documented all findings with screenshots
[ ] Submitted reports on HackerOne
```

---

*Last updated: March 1, 2026*
