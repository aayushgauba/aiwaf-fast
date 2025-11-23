"""
Example FastAPI application demonstrating AIWAF usage
"""
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import sys
import os

# Add the parent directory to the path to import aiwaf
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aiwaf import AIWAF, AIWAFConfig

# Create FastAPI app
app = FastAPI(
    title="AIWAF Example API",
    description="Example API protected by AI Web Application Firewall",
    version="1.0.0"
)

# Initialize AIWAF with custom configuration
aiwaf_config = {
    "header_validation": {
        "enabled": True,
        "block_suspicious": True,
        "quality_threshold": 3,
        "exempt_paths": ["/health", "/docs", "/openapi.json", "/admin"]
    },
    "rate_limiting": {
        "enabled": True,
        "max_requests": 50,
        "window_seconds": 300
    },
    "security": {
        "log_blocked_requests": True,
        "log_suspicious_requests": True
    }
}

# Initialize AIWAF
aiwaf = AIWAF(app, **aiwaf_config)


# API Endpoints

@app.get("/")
async def root():
    """Root endpoint."""
    return {"message": "Welcome to AIWAF protected API"}


@app.get("/health")
async def health_check():
    """Health check endpoint (exempt from AIWAF)."""
    aiwaf_health = aiwaf.health_check()
    return {
        "status": "healthy",
        "aiwaf": aiwaf_health
    }


@app.get("/api/data")
async def get_data():
    """Protected data endpoint."""
    return {
        "data": "This is protected data",
        "timestamp": __import__('time').time()
    }


@app.post("/api/upload")
async def upload_data(request: Request):
    """Protected upload endpoint."""
    body = await request.body()
    return {
        "message": "Data uploaded successfully",
        "size": len(body)
    }


@app.get("/api/user/{user_id}")
async def get_user(user_id: int):
    """Get user information."""
    return {
        "user_id": user_id,
        "name": f"User {user_id}",
        "status": "active"
    }


# Admin Endpoints

@app.get("/admin/aiwaf/stats")
async def aiwaf_statistics():
    """Get AIWAF statistics (admin endpoint)."""
    return aiwaf.get_statistics()


@app.get("/admin/aiwaf/activity")
async def aiwaf_activity(hours: int = 24):
    """Get recent AIWAF activity."""
    return aiwaf.get_recent_activity(hours)


@app.post("/admin/aiwaf/block")
async def block_ip(ip: str, reason: str = "Manual block", duration: int = None):
    """Block an IP address."""
    success = aiwaf.block_ip(ip, reason, duration)
    return {
        "success": success,
        "message": f"IP {ip} {'blocked' if success else 'not blocked (possibly exempted)'}"
    }


@app.post("/admin/aiwaf/unblock")
async def unblock_ip(ip: str):
    """Unblock an IP address."""
    success = aiwaf.unblock_ip(ip)
    return {
        "success": success,
        "message": f"IP {ip} {'unblocked' if success else 'was not blocked'}"
    }


@app.post("/admin/aiwaf/exempt")
async def exempt_ip(ip: str, reason: str = "Manual exemption"):
    """Add IP to exemption list."""
    aiwaf.add_exemption(ip, reason)
    return {
        "success": True,
        "message": f"IP {ip} added to exemption list"
    }


@app.delete("/admin/aiwaf/exempt")
async def remove_exemption(ip: str):
    """Remove IP from exemption list."""
    success = aiwaf.remove_exemption(ip)
    return {
        "success": success,
        "message": f"IP {ip} {'removed from exemption list' if success else 'was not exempted'}"
    }


@app.get("/admin/aiwaf/config")
async def get_aiwaf_config():
    """Get current AIWAF configuration."""
    return aiwaf.config.get_all()


@app.put("/admin/aiwaf/config")
async def update_aiwaf_config(updates: dict):
    """Update AIWAF configuration."""
    try:
        aiwaf.update_config(updates)
        return {"success": True, "message": "Configuration updated"}
    except ValueError as e:
        return JSONResponse(
            content={"error": "Invalid configuration", "details": str(e)},
            status_code=400
        )


@app.post("/admin/aiwaf/cleanup")
async def cleanup_aiwaf():
    """Perform AIWAF cleanup."""
    result = aiwaf.cleanup()
    return result


# Test endpoints for demonstrating AIWAF features

@app.get("/test/bot-like")
async def test_bot_like_request(request: Request):
    """
    Endpoint for testing bot detection.
    Try accessing this with curl or without proper browser headers.
    """
    return {
        "message": "If you see this, you passed the bot detection",
        "user_agent": request.headers.get("user-agent", "None"),
        "headers": dict(request.headers)
    }


@app.get("/test/rate-limit")
async def test_rate_limit():
    """
    Endpoint for testing rate limiting.
    Make many rapid requests to trigger rate limiting.
    """
    import time
    return {
        "message": "Rate limit test endpoint",
        "timestamp": time.time(),
        "tip": "Make many rapid requests to test rate limiting"
    }


@app.get("/test/headers")
async def test_headers(request: Request):
    """Show request headers for debugging."""
    return {
        "headers": dict(request.headers),
        "ip": request.client.host if request.client else "unknown",
        "method": request.method,
        "url": str(request.url)
    }


# Error handlers

@app.exception_handler(403)
async def forbidden_handler(request: Request, exc):
    """Handle 403 Forbidden responses."""
    return JSONResponse(
        content={
            "error": "Forbidden",
            "message": "Access denied by AIWAF security policies",
            "path": request.url.path
        },
        status_code=403
    )


@app.exception_handler(429)
async def rate_limit_handler(request: Request, exc):
    """Handle 429 Too Many Requests responses."""
    return JSONResponse(
        content={
            "error": "Too Many Requests", 
            "message": "Rate limit exceeded. Please slow down.",
            "path": request.url.path
        },
        status_code=429
    )


if __name__ == "__main__":
    import uvicorn
    
    print("Starting AIWAF Example API...")
    print("Available endpoints:")
    print("  - http://localhost:8000/ (root)")
    print("  - http://localhost:8000/health (health check)")
    print("  - http://localhost:8000/docs (API documentation)")
    print("  - http://localhost:8000/api/data (protected data)")
    print("  - http://localhost:8000/admin/aiwaf/stats (AIWAF statistics)")
    print("  - http://localhost:8000/test/bot-like (test bot detection)")
    print("  - http://localhost:8000/test/rate-limit (test rate limiting)")
    print("")
    print("Try testing with curl:")
    print("  curl http://localhost:8000/test/bot-like")
    print("  curl -H 'User-Agent: MyBot/1.0' http://localhost:8000/test/bot-like")
    print("")
    
    uvicorn.run(
        "example_app:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )