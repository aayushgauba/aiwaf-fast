"""
Quick test script to verify AIWAF functionality using requests library
"""
import requests

def test_bot_detection():
    """Test bot detection with various user agents"""
    
    test_cases = [
        {
            "name": "Normal Browser",
            "headers": {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive'
            },
            "should_pass": True
        },
        {
            "name": "Python Requests (should be blocked)",
            "headers": {
                'User-Agent': 'python-requests/2.25.1',
                'Accept': 'application/json'
            },
            "should_pass": False
        },
        {
            "name": "Curl (should be blocked)",
            "headers": {
                'User-Agent': 'curl/7.68.0',
                'Accept': '*/*'
            },
            "should_pass": False
        },
        {
            "name": "Empty User Agent (should be blocked)",
            "headers": {
                'User-Agent': '',
                'Accept': 'text/html'
            },
            "should_pass": False
        },
        {
            "name": "Missing Accept Header (should be blocked)",
            "headers": {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                # Missing Accept header
            },
            "should_pass": False
        }
    ]
    
    base_url = "http://localhost:8000"
    
    print("AIWAF Bot Detection Test")
    print("=" * 50)
    
    for test_case in test_cases:
        print(f"\nTesting: {test_case['name']}")
        print(f"Expected to {'PASS' if test_case['should_pass'] else 'BLOCK'}")
        
        try:
            response = requests.get(f"{base_url}/api/data", headers=test_case['headers'], timeout=10)
            
            status = response.status_code
            if status == 200:
                result = "PASSED"
            elif status == 403:
                result = "BLOCKED"
            else:
                result = f"UNEXPECTED STATUS: {status}"
            
            print(f"Result: {result}")
            
            if test_case['should_pass'] and status == 200:
                print("✓ Test passed as expected")
            elif not test_case['should_pass'] and status == 403:
                print("✓ Test blocked as expected")
            else:
                print("✗ Test result unexpected!")
                print(f"Response: {response.text[:200]}...")
            
        except requests.exceptions.RequestException as e:
            print(f"Error: {e}")
        
        print("-" * 30)

if __name__ == "__main__":
    test_bot_detection()