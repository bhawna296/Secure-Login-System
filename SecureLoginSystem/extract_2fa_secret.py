import urllib.request
import re
import pyotp
import http.cookiejar
from urllib.error import HTTPError

# Create a cookie jar to store session cookies
cookie_jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(cookie_jar),
    urllib.request.HTTPRedirectHandler()  # Handle redirects
)

# Step 0: Register a new account (allow redirects)
print("Step 0: Registering new account...")
register_data = "username=2fatester&email=2fatester@example.com&password=SecurePass123!&confirm_password=SecurePass123!"
register_req = urllib.request.Request(
    "http://127.0.0.1:5000/register",
    data=register_data.encode('utf-8'),
    headers={"Content-Type": "application/x-www-form-urlencoded"}
)
try:
    response = opener.open(register_req)
    print("✅ Account registered")
except HTTPError as e:
    if e.code == 302:  # Redirect on success
        print("✅ Account registered (redirect)")
    else:
        print(f"Response code: {e.code}")
except Exception as e:
    print(f"⚠️  Registration response: {e}")

# Step 1: Login to get a valid session
print("\nStep 1: Logging in...")
login_data = "username=2fatester&password=SecurePass123!"
login_req = urllib.request.Request(
    "http://127.0.0.1:5000/login",
    data=login_data.encode('utf-8'),
    headers={"Content-Type": "application/x-www-form-urlencoded"}
)
try:
    response = opener.open(login_req)
    html = response.read().decode('utf-8')
    if 'dashboard' in html.lower() or 'welcome' in html.lower():
        print("✅ Login successful - got dashboard")
    else:
        print("⚠️  Login response received")
except Exception as e:
    print(f"❌ Login failed: {e}")
    exit()

# Step 2: Access 2FA setup page
print("\nStep 2: Accessing 2FA setup page...")
try:
    response = opener.open("http://127.0.0.1:5000/2fa/setup")
    html_content = response.read().decode('utf-8')
    print("✅ 2FA setup page accessed")
except Exception as e:
    print(f"❌ Failed to access 2FA setup: {e}")
    exit()

# Step 2: Access 2FA setup page
print("\nStep 2: Accessing 2FA setup page...")
try:
    response = opener.open("http://127.0.0.1:5000/2fa/setup")
    html_content = response.read().decode('utf-8')
    print("✅ 2FA setup page accessed")
except Exception as e:
    print(f"❌ Failed to access 2FA setup: {e}")
    exit()

# Step 3: Extract the secret code
print("\nStep 3: Extracting TOTP secret...")
# Save HTML for inspection
with open('2fa_response.html', 'w') as f:
    f.write(html_content)
print("HTML saved to 2fa_response.html")

# Try different regex patterns
patterns = [
    r'<code class="secret-code">([A-Z0-9]+)</code>',
    r'<code[^>]*>([A-Z0-9]{20,})</code>',
    r'secret-code["\'>]+([A-Z0-9]{20,})'
]

secret = None
for pattern in patterns:
    match = re.search(pattern, html_content)
    if match:
        secret = match.group(1)
        print(f"✅ Secret found with pattern: {pattern}")
        break

if not secret:
    print("❌ Secret not found - checking HTML content...")
    lines_with_code = [line for line in html_content.split('\n') if 'code' in line.lower() or 'secret' in line.lower()]
    for line in lines_with_code[:5]:
        print(line)
    exit()

# Step 4: Generate a valid TOTP code
print("\nStep 4: Generating TOTP code...")
totp = pyotp.TOTP(secret)
current_code = totp.now()
print(f"✅ Current 2FA Code: {current_code}")
print(f"   (This code is valid for ~30 seconds)")

# Step 5: Show provisioning URI for manual setup
print("\nStep 5: QR Code Info:")
uri = totp.provisioning_uri(name="2fatest@example.com", issuer_name="SecureLoginDemo")
print(f"Provisioning URI: {uri[:80]}...")
print("\n✅ You can now use this code to verify 2FA setup!")
print(f"\nSecret: {secret}")
print(f"Code: {current_code}")
