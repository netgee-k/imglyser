# quick_test.py
import requests

BASE_URL = "http://localhost:8000"

print("Testing imglyser...")

# 1. Test health
print("\n1. Testing health endpoint...")
response = requests.get(f"{BASE_URL}/api/health")
print(f"   Status: {response.status_code}")
print(f"   Response: {response.json()}")

# 2. Test login
print("\n2. Testing login...")
response = requests.post(
    f"{BASE_URL}/api/login",
    data={"username": "admin", "password": "admin123"}
)
print(f"   Status: {response.status_code}")
print(f"   Response: {response.text[:100]}...")

if response.status_code == 200:
    session_cookie = response.cookies.get('session_id')
    print(f"   Got session cookie: {session_cookie[:20]}...")
    
    # 3. Create a test image and upload
    print("\n3. Creating test image...")
    from PIL import Image
    import io
    
    img = Image.new('RGB', (100, 100), color='red')
    img_bytes = io.BytesIO()
    img.save(img_bytes, format='JPEG')
    img_bytes.seek(0)
    
    files = {'file': ('test.jpg', img_bytes, 'image/jpeg')}
    cookies = {'session_id': session_cookie}
    
    print("   Uploading test image...")
    response = requests.post(
        f"{BASE_URL}/api/analyze",
        files=files,
        cookies=cookies,
        timeout=30
    )
    
    print(f"   Upload Status: {response.status_code}")
    if response.status_code == 200:
        result = response.json()
        print(f"   Success! Session ID: {result.get('session_id')}")
        print(f"   Risk Score: {result.get('risk_score')}")
        print(f"   Summary: {result.get('summary')}")
    else:
        print(f"   Error: {response.text}")
else:
    print("   Login failed!")