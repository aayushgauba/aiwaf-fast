"""
Simple example showing basic AIWAF usage
"""
from fastapi import FastAPI
import sys
import os

# Add the parent directory to the path to import aiwaf
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aiwaf import AIWAF

# Create FastAPI app
app = FastAPI(title="Simple AIWAF Example")

# Initialize AIWAF with default settings
aiwaf = AIWAF(app)

@app.get("/")
async def root():
    return {"message": "Hello, this API is protected by AIWAF!"}

@app.get("/api/protected")
async def protected_endpoint():
    return {"data": "This is protected data"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)