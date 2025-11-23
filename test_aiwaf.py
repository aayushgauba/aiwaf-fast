"""
Test script to demonstrate AIWAF functionality
"""
import requests
import time

# Test different scenarios against the AIWAF protected API

BASE_URL = "http://localhost:8000"

def test_normal_browser_request():
    """Test with normal browser headers - should pass"""
    print("\n=== Testing Normal Browser Request ===")
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    }
    
    try:
        response = requests.get(f"{BASE_URL}/api/data", headers=headers)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.json()}")
    except Exception as e:
        print(f"Error: {e}")

def test_bot_request():
    """Test with bot-like headers - should be blocked"""
    print("\n=== Testing Bot Request (curl) ===")
    
    headers = {
        'User-Agent': 'curl/7.68.0',
        'Accept': '*/*'
    }
    
    try:
        response = requests.get(f"{BASE_URL}/test/bot-like", headers=headers)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.json()}")
    except Exception as e:
        print(f"Error: {e}")

def test_suspicious_user_agent():
    """Test with suspicious user agent - should be blocked"""
    print("\n=== Testing Suspicious User Agent ===")
    
    headers = {
        'User-Agent': 'python-requests/2.25.1',
        'Accept': 'application/json'
    }
    
    try:
        response = requests.get(f"{BASE_URL}/api/data", headers=headers)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.json()}")
    except Exception as e:
        print(f"Error: {e}")

def test_missing_headers():
    """Test with missing required headers - should be blocked"""
    print("\n=== Testing Missing Headers ===")
    
    # Only provide minimal headers
    headers = {
        'User-Agent': 'SomeBot/1.0'
        # Missing Accept header
    }
    
    try:
        response = requests.get(f"{BASE_URL}/api/data", headers=headers)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.json()}")
    except Exception as e:
        print(f"Error: {e}")

def test_rate_limiting():
    """Test rate limiting - should be blocked after many requests"""
    print("\n=== Testing Rate Limiting ===")
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (compatible; TestBot/1.0)',
        'Accept': 'text/html,application/xhtml+xml'
    }
    
    print("Making rapid requests to trigger rate limiting...")
    
    for i in range(10):
        try:
            response = requests.get(f"{BASE_URL}/test/rate-limit", headers=headers)
            print(f"Request {i+1}: Status {response.status_code}")
            
            if response.status_code == 429:
                print("Rate limiting triggered!")
                print(f"Response: {response.json()}")
                break
        except Exception as e:
            print(f"Request {i+1} Error: {e}")
        
        time.sleep(0.1)  # Small delay

def test_exempted_path():
    """Test exempted path - should always pass"""
    print("\n=== Testing Exempted Path (/health) ===")
    
    headers = {
        'User-Agent': 'BadBot/1.0'  # Would normally be blocked
    }
    
    try:
        response = requests.get(f"{BASE_URL}/health", headers=headers)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.json()}")
    except Exception as e:
        print(f"Error: {e}")

def test_statistics():
    """Get AIWAF statistics"""
    print("\n=== Getting AIWAF Statistics ===")
    
    try:
        response = requests.get(f"{BASE_URL}/admin/aiwaf/stats")
        print(f"Status: {response.status_code}")
        stats = response.json()
        
        print(f"Total blocked IPs: {stats['blacklist']['total_blocked']}")
        print(f"Header validation enabled: {stats['configuration']['header_validation_enabled']}")
        print(f"Rate limiting enabled: {stats['configuration']['rate_limiting_enabled']}")
        
    except Exception as e:
        print(f"Error: {e}")

def main():
    """Run all tests"""
    print("AIWAF Testing Suite")
    print("Make sure the example app is running: python examples/example_app.py")
    print("=" * 50)
    
    # Test various scenarios
    test_normal_browser_request()
    test_bot_request() 
    test_suspicious_user_agent()
    test_missing_headers()
    test_exempted_path()
    test_rate_limiting()
    test_statistics()
    
    print("\n" + "=" * 50)
    print("Testing completed!")
    print("\nTo test manually:")
    print("# Good request:")
    print('curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \\')
    print('     -H "Accept: text/html,application/xhtml+xml" \\')
    print(f'     {BASE_URL}/api/data')
    print("\n# Bot request (should be blocked):")
    print(f'curl {BASE_URL}/test/bot-like')

if __name__ == "__main__":
    main()