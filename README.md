# AIWAF - AI Web Application Firewall for FastAPI

[![Python Version](https://img.shields.io/pypi/pyversions/aiwaf-fastapi)](https://pypi.org/project/aiwaf-fastapi/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.68%2B-009688.svg?style=flat&logo=FastAPI&logoColor=white)](https://fastapi.tiangolo.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

AIWAF is a comprehensive security middleware suite for FastAPI applications that provides intelligent protection against bots, malicious requests, and various web attacks.

## Features

### 🤖 Intelligent Bot Detection
- **Header Analysis**: Validates HTTP headers to identify suspicious patterns
- **User-Agent Detection**: Recognizes bot patterns while allowing legitimate crawlers  
- **Header Quality Scoring**: Assigns quality scores based on header completeness
- **Suspicious Combinations**: Detects unusual header combinations

### 🛡️ Advanced Security
- **IP Blacklisting**: Automatic and manual IP blocking with temporary/permanent options
- **IP Whitelisting**: Exemption system for trusted IPs and networks
- **Rate Limiting**: Configurable rate limiting with automatic blocking
- **Request Monitoring**: Comprehensive logging and statistics

### ⚙️ Flexible Configuration
- **Multiple Storage Backends**: Memory and file-based storage
- **Environment Variable Support**: Easy deployment configuration
- **JSON Configuration Files**: Centralized configuration management
- **Runtime Configuration**: Update settings without restart

### 📊 Monitoring & Analytics
- **Real-time Statistics**: Detailed blocking and security metrics
- **Activity Monitoring**: Track recent security events
- **Health Checks**: Built-in system health monitoring
- **Export Capabilities**: Data export for analysis

## Quick Start

### Installation

```bash
pip install fastapi uvicorn
```

### Basic Usage

```python
from fastapi import FastAPI
from aiwaf import AIWAF

# Create FastAPI app
app = FastAPI()

# Initialize AIWAF with default settings
aiwaf = AIWAF(app)

@app.get("/")
async def root():
    return {"message": "Protected by AIWAF!"}

@app.get("/api/data")
async def get_data():
    return {"data": "This endpoint is protected"}
```

### Run the Application

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

## Configuration

### Basic Configuration

```python
from aiwaf import AIWAF, AIWAFConfig

# Custom configuration
config = {
    "header_validation": {
        "enabled": True,
        "block_suspicious": True,
        "quality_threshold": 3,
        "exempt_paths": ["/health", "/docs"]
    },
    "rate_limiting": {
        "enabled": True,
        "max_requests": 100,
        "window_seconds": 300
    }
}

aiwaf = AIWAF(app, **config)
```

### Configuration File

Create `aiwaf_config.json`:

```json
{
  "header_validation": {
    "enabled": true,
    "block_suspicious": true,
    "quality_threshold": 3,
    "exempt_paths": ["/health", "/metrics", "/docs"],
    "custom_suspicious_patterns": ["badbot", "scanner"],
    "custom_legitimate_patterns": ["googlebot", "bingbot"]
  },
  "rate_limiting": {
    "enabled": true,
    "max_requests": 50,
    "window_seconds": 300
  },
  "storage": {
    "backend": "file",
    "file_path": "aiwaf_data.json"
  },
  "security": {
    "log_blocked_requests": true,
    "log_suspicious_requests": true
  }
}
```

Load from file:

```python
aiwaf = AIWAF(app, config_file="aiwaf_config.json")
```

### Environment Variables

```bash
export AIWAF_HEADER_VALIDATION_ENABLED=true
export AIWAF_HEADER_BLOCK_SUSPICIOUS=true
export AIWAF_HEADER_QUALITY_THRESHOLD=3
export AIWAF_RATE_LIMITING_ENABLED=true
export AIWAF_RATE_MAX_REQUESTS=100
export AIWAF_STORAGE_BACKEND=file
```

## Advanced Usage

### Manual IP Management

```python
# Block an IP
aiwaf.block_ip("192.168.1.100", "Suspicious activity", duration=3600)

# Permanently block an IP
aiwaf.block_ip("10.0.0.50", "Malicious requests")

# Whitelist an IP
aiwaf.add_exemption("203.0.113.10", "Trusted partner")

# Check if IP is blocked
if aiwaf.is_blocked("192.168.1.100"):
    print("IP is blocked")

# Unblock an IP
aiwaf.unblock_ip("192.168.1.100")
```

### Statistics and Monitoring

```python
# Get comprehensive statistics
stats = aiwaf.get_statistics()
print(f"Total blocked IPs: {stats['blacklist']['total_blocked']}")

# Get recent activity
activity = aiwaf.get_recent_activity(hours=24)
print(f"Blocks in last 24h: {activity['summary']['blocks_in_period']}")

# Health check
health = aiwaf.health_check()
print(f"System status: {health['status']}")
```

### Runtime Configuration Updates

```python
# Update configuration at runtime
aiwaf.update_config({
    "header_validation": {
        "quality_threshold": 2
    },
    "rate_limiting": {
        "max_requests": 200
    }
})

# Enable/disable features
aiwaf.enable_feature("rate_limiting")
aiwaf.disable_feature("header_validation")
```

## API Endpoints for Management

Add these endpoints to your FastAPI app for web-based management:

```python
@app.get("/admin/aiwaf/stats")
async def get_aiwaf_stats():
    return aiwaf.get_statistics()

@app.post("/admin/aiwaf/block")
async def block_ip(ip: str, reason: str):
    success = aiwaf.block_ip(ip, reason)
    return {"success": success}

@app.post("/admin/aiwaf/exempt")  
async def exempt_ip(ip: str):
    aiwaf.add_exemption(ip)
    return {"success": True}
```

## Testing Bot Detection

Test the bot detection with curl:

```bash
# This should be blocked (curl user agent)
curl http://localhost:8000/api/data

# This should be allowed (browser-like headers)
curl -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
     -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
     -H "Accept-Language: en-US,en;q=0.5" \
     -H "Accept-Encoding: gzip, deflate" \
     -H "Connection: keep-alive" \
     http://localhost:8000/api/data
```

## Architecture

AIWAF consists of several key components:

### Core Components

1. **HeaderValidationMiddleware**: Analyzes HTTP headers for bot detection
2. **BlacklistManager**: Manages IP blocking and whitelisting
3. **Storage System**: Pluggable storage backends (memory/file)
4. **Configuration System**: Flexible configuration management
5. **Rate Limiter**: Request rate limiting and throttling

### Request Flow

```
Request → AIWAF Middleware → Header Analysis → Rate Limiting → Blacklist Check → FastAPI App
```

### Storage Backends

- **Memory Storage**: Fast, in-memory storage (default)
- **File Storage**: Persistent JSON file storage
- **Extensible**: Easy to add Redis, database backends

## Configuration Reference

### Header Validation

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `enabled` | bool | `true` | Enable header validation |
| `block_suspicious` | bool | `true` | Block suspicious requests |
| `quality_threshold` | int | `3` | Minimum header quality score |
| `exempt_paths` | list | `[]` | Paths exempt from validation |
| `custom_suspicious_patterns` | list | `[]` | Custom bot patterns |
| `custom_legitimate_patterns` | list | `[]` | Custom legitimate bot patterns |

### Rate Limiting

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `enabled` | bool | `true` | Enable rate limiting |
| `max_requests` | int | `100` | Max requests per window |
| `window_seconds` | int | `300` | Time window in seconds |

### Storage

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `backend` | str | `"memory"` | Storage backend type |
| `file_path` | str | `"aiwaf_data.json"` | File storage path |

## Examples

Check the `examples/` directory for complete working examples:

- `simple_example.py`: Basic AIWAF usage
- `example_app.py`: Full-featured example with admin endpoints
- `config_example.py`: Configuration file example

## Development

### Setup Development Environment

```bash
git clone https://github.com/aiwaf/aiwaf-fastapi.git
cd aiwaf-fastapi
pip install -e ".[dev]"
```

### Run Tests

```bash
pytest
```

### Code Formatting

```bash
black aiwaf/
flake8 aiwaf/
```

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests to our GitHub repository.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- GitHub Issues: [Report bugs and request features](https://github.com/aiwaf/aiwaf-fastapi/issues)
- Documentation: [Full documentation](https://aiwaf-fastapi.readthedocs.io/)
- Discussions: [Community discussions](https://github.com/aiwaf/aiwaf-fastapi/discussions)

## Changelog

### Version 1.0.0
- Initial release
- Header validation middleware
- IP blacklisting and whitelisting
- Rate limiting
- Multiple storage backends
- Configuration management
- Statistics and monitoring
- FastAPI integration