"""
Test server without auto-exemptions to properly test bot detection
"""
from fastapi import FastAPI, Request
import sys
import os
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Add the parent directory to the path to import aiwaf
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aiwaf import AIWAF

# Create FastAPI app
app = FastAPI(title="Test AIWAF - No Auto Exemptions")

# Initialize AIWAF with auto-exemptions disabled
aiwaf_config = {
    "header_validation": {
        "enabled": True,
        "block_suspicious": True,
        "quality_threshold": 2,
        "exempt_paths": ["/health", "/debug"]
    },
    "exemptions": {
        "private_ips_exempted": False,  # Disable auto-exemption
        "localhost_exempted": False,
        "auto_exempt_patterns": []
    },
    "rate_limiting": {
        "enabled": False
    },
    "logging": {
        "level": "DEBUG"
    }
}

print("Initializing AIWAF with no auto-exemptions...")
aiwaf = AIWAF(app, **aiwaf_config)
print("AIWAF initialized!")

@app.get("/")
async def root():
    return {"message": "Test API - Bot detection active"}

@app.get("/debug") 
async def debug_endpoint(request: Request):
    """Debug endpoint to show request details"""
    return {
        "headers": dict(request.headers),
        "ip": request.client.host if request.client else "unknown",
        "path": request.url.path,
        "method": request.method,
        "message": "This endpoint is exempt from bot detection"
    }

@app.get("/api/test")
async def api_test_endpoint():
    """Test endpoint that should trigger bot detection"""
    return {"message": "If you see this, you passed bot detection", "status": "success"}

if __name__ == "__main__":
    import uvicorn
    print("Starting test server on port 8002...")
    uvicorn.run(app, host="127.0.0.1", port=8002, log_level="info")
