"""
AIWAF - AI Web Application Firewall for FastAPI
A comprehensive security middleware suite for FastAPI applications
"""

from .core import AIWAF
from .middleware.header_validation import HeaderValidationMiddleware
from .config import AIWAFConfig

__version__ = "1.0.0"
__all__ = ["AIWAF", "HeaderValidationMiddleware", "AIWAFConfig"]