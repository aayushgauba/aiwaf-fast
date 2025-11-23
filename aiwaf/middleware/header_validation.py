"""
Header validation middleware for FastAPI - detects bots and malicious requests
"""
import re
import logging
from typing import Callable, List, Dict, Any, Set, Optional
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from ..utils import get_ip, is_exempt, is_static_file
from ..blacklist import BlacklistManager

logger = logging.getLogger(__name__)


class HeaderValidationMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware that validates HTTP headers to detect bots and malicious requests.
    
    This middleware analyzes request headers to identify:
    - Missing required browser headers
    - Suspicious user agent patterns
    - Unusual header combinations
    - Low-quality header profiles
    """
    
    # Standard browser headers that legitimate requests should have
    REQUIRED_HEADERS = [
        'user-agent',
        'accept',
    ]
    
    # Headers that browsers typically send
    BROWSER_HEADERS = [
        'accept-language',
        'accept-encoding',
        'connection',
        'cache-control',
    ]
    
    # Suspicious User-Agent patterns
    SUSPICIOUS_USER_AGENTS = [
        r'bot',
        r'crawler',
        r'spider',
        r'scraper',
        r'curl',
        r'wget',
        r'python',
        r'java',
        r'node',
        r'go-http',
        r'axios',
        r'okhttp',
        r'libwww',
        r'lwp-trivial',
        r'mechanize',
        r'requests',
        r'urllib',
        r'httpie',
        r'postman',
        r'insomnia',
        r'^$',  # Empty user agent
        r'mozilla/4\.0$',  # Fake old browser
        r'mozilla/5\.0$',  # Incomplete mozilla string
    ]
    
    # Known legitimate bot user agents to whitelist
    LEGITIMATE_BOTS = [
        r'googlebot',
        r'bingbot',
        r'slurp',  # Yahoo
        r'duckduckbot',
        r'baiduspider',
        r'yandexbot',
        r'facebookexternalhit',
        r'twitterbot',
        r'linkedinbot',
        r'whatsapp',
        r'telegrambot',
        r'applebot',
        r'pingdom',
        r'uptimerobot',
        r'statuscake',
        r'site24x7',
    ]
    
    def __init__(
        self,
        app,
        enabled: bool = True,
        block_suspicious: bool = True,
        quality_threshold: int = 3,
        exempt_paths: Optional[Set[str]] = None,
        custom_suspicious_patterns: Optional[List[str]] = None,
        custom_legitimate_patterns: Optional[List[str]] = None,
        trust_legitimate_bots: bool = False
    ):
        """
        Initialize the header validation middleware.
        
        Args:
            app: FastAPI application
            enabled: Whether the middleware is enabled
            block_suspicious: Whether to block suspicious requests
            quality_threshold: Minimum header quality score required
            exempt_paths: Additional paths to exempt from validation
            custom_suspicious_patterns: Additional suspicious UA patterns
            custom_legitimate_patterns: Additional legitimate bot patterns
            trust_legitimate_bots: Allow listed bot user agents to bypass suspicion checks
        """
        super().__init__(app)
        self.enabled = enabled
        self.block_suspicious = block_suspicious
        self.quality_threshold = quality_threshold
        self.exempt_paths = exempt_paths or set()
        self.trust_legitimate_bots = trust_legitimate_bots
        
        # Extend patterns with custom ones
        if custom_suspicious_patterns:
            self.suspicious_patterns = self.SUSPICIOUS_USER_AGENTS + custom_suspicious_patterns
        else:
            self.suspicious_patterns = self.SUSPICIOUS_USER_AGENTS
            
        if custom_legitimate_patterns:
            self.legitimate_patterns = self.LEGITIMATE_BOTS + custom_legitimate_patterns
        else:
            self.legitimate_patterns = self.LEGITIMATE_BOTS
        
        # Suspicious header combinations
        self.suspicious_combinations = [
            # High version HTTP with old user agent
            {
                'condition': lambda headers, scope: (
                    scope.get('scheme') == 'https' and
                    'mozilla/4.0' in headers.get('user-agent', '').lower()
                ),
                'reason': 'HTTPS with old browser user agent'
            },
            # No Accept header but has User-Agent
            {
                'condition': lambda headers, scope: (
                    headers.get('user-agent') and
                    not headers.get('accept')
                ),
                'reason': 'User-Agent present but no Accept header'
            },
            # Accept */* only (very generic)
            {
                'condition': lambda headers, scope: (
                    headers.get('accept') == '*/*' and
                    not any(h in headers for h in ['accept-language', 'accept-encoding'])
                ),
                'reason': 'Generic Accept header without language/encoding'
            },
            # No browser-standard headers at all
            {
                'condition': lambda headers, scope: (
                    headers.get('user-agent') and
                    not any(headers.get(h) for h in ['accept-language', 'accept-encoding', 'connection'])
                ),
                'reason': 'Missing all browser-standard headers'
            },
            # Suspicious HTTP version patterns
            {
                'condition': lambda headers, scope: (
                    'user-agent' in headers and
                    scope.get('http_version') == '1.0' and
                    'chrome' in headers.get('user-agent', '').lower()
                ),
                'reason': 'Modern browser with HTTP/1.0'
            }
        ]
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process the request through header validation."""
        logger.debug(f"HeaderValidationMiddleware: Processing request to {request.url.path}")
        
        if not self.enabled:
            logger.debug("HeaderValidationMiddleware: Disabled, skipping")
            return await call_next(request)
        
        # Skip if request is exempted
        if is_exempt(request, self.exempt_paths):
            logger.debug(f"HeaderValidationMiddleware: Path {request.url.path} is exempted")
            return await call_next(request)
        
        ip = get_ip(request)
        logger.debug(f"HeaderValidationMiddleware: Processing IP {ip}")
        
        # Check IP-level exemption
        from ..storage import get_exemption_store
        exemption_store = get_exemption_store()
        if exemption_store.is_exempted(ip):
            return await call_next(request)
        
        # Skip for static files and common paths
        if self._is_static_request(request):
            return await call_next(request)
        
        # Get headers from request
        headers = dict(request.headers)
        
        try:
            quality_score = self._calculate_header_quality(headers)
            violation_reason = None
            
            # Check for missing required headers
            missing_headers = self._check_missing_headers(headers)
            if missing_headers:
                violation_reason = f"Missing required headers: {', '.join(missing_headers)}"
            
            # Check for suspicious user agent
            if violation_reason is None:
                suspicious_ua = self._check_user_agent(headers.get('user-agent', ''))
                if suspicious_ua:
                    violation_reason = f"Suspicious user agent: {suspicious_ua}"
            
            # Check for suspicious header combinations
            if violation_reason is None:
                suspicious_combo = self._check_header_combinations(headers, request.scope)
                if suspicious_combo:
                    violation_reason = f"Suspicious headers: {suspicious_combo}"
            
            # Check header quality score
            if violation_reason is None and quality_score < self.quality_threshold:
                violation_reason = f"Low header quality score: {quality_score}"
            
            if violation_reason:
                if not self.block_suspicious:
                    logger.warning(
                        f"Header validation would block {ip}: {violation_reason} "
                        f"(Path: {request.url.path})"
                    )
                    return await call_next(request)
                
                return self._block_request(ip, violation_reason, request.url.path)
            
            # Log legitimate request (debug level)
            logger.debug(
                f"Header validation passed for {ip} - "
                f"Path: {request.url.path}, Quality: {quality_score}"
            )
            
        except Exception as e:
            logger.error(f"Error in header validation for {ip}: {e}")
            # Don't block on validation errors, just log and continue
        
        return await call_next(request)
    
    def _is_static_request(self, request: Request) -> bool:
        """Check if this is a request for static files"""
        path = request.url.path.lower()
        
        # Use the utility function
        if is_static_file(path):
            return True
        
        # Check additional static paths
        static_paths = ['/static/', '/media/', '/assets/', '/favicon.ico']
        if any(path.startswith(static_path) for static_path in static_paths):
            return True
        
        return False
    
    def _check_missing_headers(self, headers: Dict[str, str]) -> List[str]:
        """Check for missing required headers"""
        missing = []
        
        for header in self.REQUIRED_HEADERS:
            if not headers.get(header):
                missing.append(header)
        
        return missing
    
    def _check_user_agent(self, user_agent: str) -> Optional[str]:
        """Check if user agent is suspicious"""
        if not user_agent:
            return "Empty user agent"
        
        user_agent_lower = user_agent.lower()
        
        is_legitimate_bot = any(
            re.search(legitimate_pattern, user_agent_lower)
            for legitimate_pattern in self.legitimate_patterns
        )
        
        # Check for suspicious patterns
        suspicious_match = None
        for suspicious_pattern in self.suspicious_patterns:
            if re.search(suspicious_pattern, user_agent_lower, re.IGNORECASE):
                suspicious_match = suspicious_pattern
                break
        
        if suspicious_match:
            if self.trust_legitimate_bots and is_legitimate_bot:
                logger.debug(
                    "User agent matched legitimate bot pattern; skipping suspicion block"
                )
            else:
                return f"Pattern: {suspicious_match}"
        
        if is_legitimate_bot:
            return None
        
        # Check for very short user agents (likely fake)
        if len(user_agent) < 10:
            return "Too short"
        
        # Check for very long user agents (possibly malicious)
        if len(user_agent) > 500:
            return "Too long"
        
        return None
    
    def _check_header_combinations(self, headers: Dict[str, str], scope: Dict[str, Any]) -> Optional[str]:
        """Check for suspicious header combinations"""
        for combo in self.suspicious_combinations:
            try:
                if combo['condition'](headers, scope):
                    return combo['reason']
            except Exception as e:
                logger.debug(f"Error checking header combination: {e}")
                continue
        
        return None
    
    def _calculate_header_quality(self, headers: Dict[str, str]) -> int:
        """Calculate a quality score based on header completeness"""
        score = 0
        
        # Basic required headers (2 points each)
        if headers.get('user-agent'):
            score += 2
        if headers.get('accept'):
            score += 2
        
        # Browser-standard headers (1 point each)
        for header in self.BROWSER_HEADERS:
            if headers.get(header):
                score += 1
        
        # Bonus points for realistic combinations
        if headers.get('accept-language') and headers.get('accept-encoding'):
            score += 1
        
        if headers.get('connection') == 'keep-alive':
            score += 1
        
        # Check for realistic Accept header
        accept = headers.get('accept', '')
        if 'text/html' in accept and 'application/xml' in accept:
            score += 1
        
        return score
    
    def _block_request(self, ip: str, reason: str, path: str) -> Response:
        """Block the request and return error response"""
        if not self.block_suspicious:
            logger.warning(f"Would block {ip}: {reason} (Path: {path})")
            return JSONResponse(
                content={
                    "warning": "suspicious_headers", 
                    "message": "Request has suspicious headers but blocking is disabled",
                    "path": path
                },
                status_code=200  # Don't actually block
            )
        
        from ..storage import get_exemption_store
        exemption_store = get_exemption_store()
        
        # Double-check exemption before blocking
        if not exemption_store.is_exempted(ip):
            BlacklistManager.block(ip, f"Header validation: {reason}")
            
            # Check if actually blocked (exempted IPs won't be blocked)
            if BlacklistManager.is_blocked(ip):
                logger.warning(f"Blocked {ip}: {reason} (Path: {path})")
                return JSONResponse(
                    content={
                        "error": "blocked",
                        "message": "Request blocked due to suspicious headers",
                        "path": path
                    },
                    status_code=403
                )
        
        # If we get here, IP was exempted after the fact
        logger.info(f"IP {ip} exempted, not blocking: {reason}")
        return JSONResponse(
            content={
                "info": "exempted",
                "message": "Request flagged but IP is exempted",
                "path": path
            },
            status_code=200
        )
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get middleware statistics"""
        return {
            'enabled': self.enabled,
            'block_suspicious': self.block_suspicious,
            'quality_threshold': self.quality_threshold,
            'suspicious_pattern_count': len(self.suspicious_patterns),
            'legitimate_pattern_count': len(self.legitimate_patterns),
            'combination_check_count': len(self.suspicious_combinations)
        }
    
    def add_suspicious_pattern(self, pattern: str):
        """Add a custom suspicious user agent pattern"""
        if pattern not in self.suspicious_patterns:
            self.suspicious_patterns.append(pattern)
            logger.info(f"Added suspicious pattern: {pattern}")
    
    def add_legitimate_pattern(self, pattern: str):
        """Add a custom legitimate bot pattern"""
        if pattern not in self.legitimate_patterns:
            self.legitimate_patterns.append(pattern)
            logger.info(f"Added legitimate pattern: {pattern}")
    
    def remove_suspicious_pattern(self, pattern: str):
        """Remove a suspicious user agent pattern"""
        if pattern in self.suspicious_patterns:
            self.suspicious_patterns.remove(pattern)
            logger.info(f"Removed suspicious pattern: {pattern}")
    
    def remove_legitimate_pattern(self, pattern: str):
        """Remove a legitimate bot pattern"""
        if pattern in self.legitimate_patterns:
            self.legitimate_patterns.remove(pattern)
            logger.info(f"Removed legitimate pattern: {pattern}")
    
    def enable(self):
        """Enable the middleware"""
        self.enabled = True
        logger.info("Header validation middleware enabled")
    
    def disable(self):
        """Disable the middleware"""
        self.enabled = False
        logger.info("Header validation middleware disabled")
    
    def set_quality_threshold(self, threshold: int):
        """Set the header quality threshold"""
        self.quality_threshold = threshold
        logger.info(f"Header quality threshold set to {threshold}")
    
    def enable_blocking(self):
        """Enable blocking of suspicious requests"""
        self.block_suspicious = True
        logger.info("Header validation blocking enabled")
    
    def disable_blocking(self):
        """Disable blocking of suspicious requests (warning mode)"""
        self.block_suspicious = False
        logger.info("Header validation blocking disabled (warning mode)")
