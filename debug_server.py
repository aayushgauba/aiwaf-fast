"""
Simple debug version of the example app with verbose logging
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
app = FastAPI(title="Debug AIWAF Example")

# Initialize AIWAF with debug configuration
aiwaf_config = {
    "header_validation": {
        "enabled": True,
        "block_suspicious": True,
        "quality_threshold": 2,  # Lower threshold for easier testing
        "exempt_paths": ["/health", "/debug"]
    },
    "rate_limiting": {
        "enabled": False  # Disable for debugging
    },
    "logging": {
        "level": "DEBUG"
    }
}

print("Initializing AIWAF...")
aiwaf = AIWAF(app, **aiwaf_config)
print("AIWAF initialized!")

@app.get("/")
async def root():
    return {"message": "Debug AIWAF API"}

@app.get("/debug")
async def debug_endpoint(request: Request):
    """Debug endpoint to show request details"""
    return {
        "headers": dict(request.headers),
        "ip": request.client.host if request.client else "unknown",
        "path": request.url.path,
        "method": request.method
    }

@app.get("/api/test")
async def test_endpoint():
    """Simple test endpoint"""
    return {"message": "Test endpoint", "status": "protected"}

if __name__ == "__main__":
    import uvicorn
    print("Starting debug server on port 8001...")
    uvicorn.run(app, host="0.0.0.0", port=8001, log_level="debug")