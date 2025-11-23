"""
Configuration-based AIWAF example
"""
from fastapi import FastAPI
import sys
import os

# Add the parent directory to the path to import aiwaf
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aiwaf import AIWAF, AIWAFConfig

# Create FastAPI app
app = FastAPI(title="Config-based AIWAF Example")

# Load configuration from file (create config.json first)
config_file = "aiwaf_config.json"

# Create a sample config file if it doesn't exist
if not os.path.exists(config_file):
    sample_config = {
        "header_validation": {
            "enabled": True,
            "block_suspicious": False,  # Warning mode only
            "quality_threshold": 2,
            "exempt_paths": ["/health", "/metrics", "/docs", "/openapi.json"]
        },
        "rate_limiting": {
            "enabled": True,
            "max_requests": 30,
            "window_seconds": 60
        },
        "security": {
            "log_blocked_requests": True,
            "log_suspicious_requests": True
        },
        "logging": {
            "level": "INFO"
        }
    }
    
    import json
    with open(config_file, 'w') as f:
        json.dump(sample_config, f, indent=2)
    
    print(f"Created sample configuration file: {config_file}")

# Initialize AIWAF with configuration file
aiwaf = AIWAF(app, config_file=config_file)

@app.get("/")
async def root():
    return {"message": "API with file-based AIWAF configuration"}

@app.get("/health")
async def health():
    """Health endpoint (exempted in config)"""
    return {"status": "healthy", "aiwaf": aiwaf.health_check()}

@app.get("/api/data")
async def get_data():
    return {"data": "Protected endpoint", "config_based": True}

@app.get("/admin/config")
async def show_config():
    """Show current configuration"""
    return aiwaf.config.get_all()

if __name__ == "__main__":
    import uvicorn
    print(f"Starting app with configuration from: {config_file}")
    uvicorn.run(app, host="0.0.0.0", port=8002)