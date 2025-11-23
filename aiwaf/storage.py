"""
Storage backends for AIWAF - handling blacklists, exemptions, and persistent data
"""
import time
import json
import threading
from abc import ABC, abstractmethod
from typing import Set, Dict, Optional, List, Any
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class StorageBackend(ABC):
    """Abstract base class for storage backends."""
    
    @abstractmethod
    def get(self, key: str) -> Optional[Any]:
        """Get a value by key."""
        pass
    
    @abstractmethod
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set a value with optional TTL."""
        pass
    
    @abstractmethod
    def delete(self, key: str) -> bool:
        """Delete a key."""
        pass
    
    @abstractmethod
    def exists(self, key: str) -> bool:
        """Check if key exists."""
        pass
    
    @abstractmethod
    def get_all_keys(self, pattern: str = "*") -> List[str]:
        """Get all keys matching pattern."""
        pass


class MemoryStorage(StorageBackend):
    """In-memory storage backend with TTL support."""
    
    def __init__(self):
        self._data: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()
        self._cleanup_interval = 60  # seconds
        self._last_cleanup = time.time()
    
    def _cleanup_expired(self):
        """Remove expired entries."""
        current_time = time.time()
        if current_time - self._last_cleanup < self._cleanup_interval:
            return
        
        with self._lock:
            expired_keys = []
            for key, entry in self._data.items():
                if entry.get('expires_at') and current_time > entry['expires_at']:
                    expired_keys.append(key)
            
            for key in expired_keys:
                del self._data[key]
        
        self._last_cleanup = current_time
    
    def get(self, key: str) -> Optional[Any]:
        """Get a value by key."""
        self._cleanup_expired()
        
        with self._lock:
            entry = self._data.get(key)
            if not entry:
                return None
            
            # Check if expired
            if entry.get('expires_at') and time.time() > entry['expires_at']:
                del self._data[key]
                return None
            
            return entry['value']
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set a value with optional TTL."""
        with self._lock:
            entry = {'value': value}
            if ttl:
                entry['expires_at'] = time.time() + ttl
            
            self._data[key] = entry
            return True
    
    def delete(self, key: str) -> bool:
        """Delete a key."""
        with self._lock:
            if key in self._data:
                del self._data[key]
                return True
            return False
    
    def exists(self, key: str) -> bool:
        """Check if key exists."""
        return self.get(key) is not None
    
    def get_all_keys(self, pattern: str = "*") -> List[str]:
        """Get all keys matching pattern."""
        self._cleanup_expired()
        
        with self._lock:
            if pattern == "*":
                return list(self._data.keys())
            
            # Simple pattern matching (only supports * wildcard)
            import fnmatch
            return [key for key in self._data.keys() if fnmatch.fnmatch(key, pattern)]


class FileStorage(StorageBackend):
    """File-based storage backend."""
    
    def __init__(self, file_path: str = "aiwaf_data.json"):
        self.file_path = Path(file_path)
        self._data: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.RLock()
        self._load_data()
    
    def _load_data(self):
        """Load data from file."""
        if self.file_path.exists():
            try:
                with open(self.file_path, 'r') as f:
                    self._data = json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Failed to load data from {self.file_path}: {e}")
                self._data = {}
    
    def _save_data(self):
        """Save data to file."""
        try:
            # Create directory if it doesn't exist
            self.file_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Write to temporary file first, then rename (atomic operation)
            temp_path = self.file_path.with_suffix('.tmp')
            with open(temp_path, 'w') as f:
                json.dump(self._data, f, indent=2)
            
            temp_path.replace(self.file_path)
        except IOError as e:
            logger.error(f"Failed to save data to {self.file_path}: {e}")
    
    def get(self, key: str) -> Optional[Any]:
        """Get a value by key."""
        with self._lock:
            entry = self._data.get(key)
            if not entry:
                return None
            
            # Check if expired
            if entry.get('expires_at') and time.time() > entry['expires_at']:
                del self._data[key]
                self._save_data()
                return None
            
            return entry['value']
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set a value with optional TTL."""
        with self._lock:
            entry = {'value': value}
            if ttl:
                entry['expires_at'] = time.time() + ttl
            
            self._data[key] = entry
            self._save_data()
            return True
    
    def delete(self, key: str) -> bool:
        """Delete a key."""
        with self._lock:
            if key in self._data:
                del self._data[key]
                self._save_data()
                return True
            return False
    
    def exists(self, key: str) -> bool:
        """Check if key exists."""
        return self.get(key) is not None
    
    def get_all_keys(self, pattern: str = "*") -> List[str]:
        """Get all keys matching pattern."""
        with self._lock:
            # Clean up expired entries first
            current_time = time.time()
            expired_keys = []
            for key, entry in self._data.items():
                if entry.get('expires_at') and current_time > entry['expires_at']:
                    expired_keys.append(key)
            
            for key in expired_keys:
                del self._data[key]
            
            if expired_keys:
                self._save_data()
            
            if pattern == "*":
                return list(self._data.keys())
            
            # Simple pattern matching
            import fnmatch
            return [key for key in self._data.keys() if fnmatch.fnmatch(key, pattern)]


class ExemptionStore:
    """Manages exempted IPs and patterns."""
    
    def __init__(self, storage: StorageBackend):
        self.storage = storage
        self._exempt_ips: Set[str] = set()
        self._exempt_patterns: List[str] = []
        self._load_exemptions()
    
    def _load_exemptions(self):
        """Load exemptions from storage."""
        exempt_data = self.storage.get("exemptions")
        if exempt_data:
            self._exempt_ips = set(exempt_data.get('ips', []))
            self._exempt_patterns = exempt_data.get('patterns', [])
    
    def _save_exemptions(self):
        """Save exemptions to storage."""
        exempt_data = {
            'ips': list(self._exempt_ips),
            'patterns': self._exempt_patterns
        }
        self.storage.set("exemptions", exempt_data)
    
    def add_ip(self, ip: str, reason: str = "Manual exemption"):
        """Add an IP to exemption list."""
        self._exempt_ips.add(ip)
        self._save_exemptions()
        
        # Log the exemption
        exemption_log = self.storage.get("exemption_log") or []
        exemption_log.append({
            'ip': ip,
            'reason': reason,
            'timestamp': time.time()
        })
        self.storage.set("exemption_log", exemption_log)
        
        logger.info(f"IP {ip} added to exemption list: {reason}")
    
    def remove_ip(self, ip: str):
        """Remove an IP from exemption list."""
        if ip in self._exempt_ips:
            self._exempt_ips.remove(ip)
            self._save_exemptions()
            logger.info(f"IP {ip} removed from exemption list")
            return True
        return False
    
    def add_pattern(self, pattern: str, reason: str = "Manual exemption"):
        """Add an IP pattern to exemption list."""
        if pattern not in self._exempt_patterns:
            self._exempt_patterns.append(pattern)
            self._save_exemptions()
            logger.info(f"Pattern {pattern} added to exemption list: {reason}")
    
    def remove_pattern(self, pattern: str):
        """Remove a pattern from exemption list."""
        if pattern in self._exempt_patterns:
            self._exempt_patterns.remove(pattern)
            self._save_exemptions()
            logger.info(f"Pattern {pattern} removed from exemption list")
            return True
        return False
    
    def is_exempted(self, ip: str) -> bool:
        """Check if an IP is exempted."""
        # Check direct IP match
        if ip in self._exempt_ips:
            return True
        
        # Check pattern matches
        import fnmatch
        import ipaddress
        
        for pattern in self._exempt_patterns:
            # Simple wildcard matching
            if fnmatch.fnmatch(ip, pattern):
                return True
            
            # CIDR notation matching
            if '/' in pattern:
                try:
                    network = ipaddress.ip_network(pattern, strict=False)
                    if ipaddress.ip_address(ip) in network:
                        return True
                except ValueError:
                    continue
        
        return False
    
    def get_exempted_ips(self) -> Set[str]:
        """Get all exempted IPs."""
        return self._exempt_ips.copy()
    
    def get_exempted_patterns(self) -> List[str]:
        """Get all exempted patterns."""
        return self._exempt_patterns.copy()


class BlacklistStore:
    """Manages blacklisted IPs and their metadata."""
    
    def __init__(self, storage: StorageBackend):
        self.storage = storage
    
    def block_ip(self, ip: str, reason: str, duration: Optional[int] = None):
        """
        Block an IP address.
        
        Args:
            ip: IP address to block
            reason: Reason for blocking
            duration: Block duration in seconds (None for permanent)
        """
        block_data = {
            'ip': ip,
            'reason': reason,
            'blocked_at': time.time(),
            'duration': duration,
            'permanent': duration is None
        }
        
        # Store the block
        self.storage.set(f"blocked:{ip}", block_data, ttl=duration)
        
        # Add to block log
        block_log = self.storage.get("block_log") or []
        block_log.append(block_data)
        
        # Keep only last 1000 entries to prevent memory issues
        if len(block_log) > 1000:
            block_log = block_log[-1000:]
        
        self.storage.set("block_log", block_log)
        
        logger.warning(f"IP {ip} blocked: {reason}")
    
    def unblock_ip(self, ip: str) -> bool:
        """Unblock an IP address."""
        key = f"blocked:{ip}"
        if self.storage.exists(key):
            self.storage.delete(key)
            logger.info(f"IP {ip} unblocked")
            return True
        return False
    
    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is blocked."""
        return self.storage.exists(f"blocked:{ip}")
    
    def get_block_info(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get block information for an IP."""
        return self.storage.get(f"blocked:{ip}")
    
    def get_blocked_ips(self) -> List[str]:
        """Get all currently blocked IPs."""
        blocked_keys = self.storage.get_all_keys("blocked:*")
        return [key.replace("blocked:", "") for key in blocked_keys]
    
    def get_block_stats(self) -> Dict[str, Any]:
        """Get blocking statistics."""
        blocked_ips = self.get_blocked_ips()
        block_log = self.storage.get("block_log") or []
        
        # Count blocks by reason
        reason_counts = {}
        recent_blocks = []
        current_time = time.time()
        
        for entry in block_log:
            reason = entry.get('reason', 'unknown')
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
            
            # Recent blocks (last 24 hours)
            if current_time - entry.get('blocked_at', 0) < 86400:
                recent_blocks.append(entry)
        
        return {
            'total_blocked': len(blocked_ips),
            'total_blocks_all_time': len(block_log),
            'recent_blocks_24h': len(recent_blocks),
            'reason_counts': reason_counts,
            'blocked_ips': blocked_ips[:100]  # Limit for performance
        }


# Global storage instances
_storage_backend: Optional[StorageBackend] = None
_exemption_store: Optional[ExemptionStore] = None
_blacklist_store: Optional[BlacklistStore] = None


def initialize_storage(backend: str = "memory", **kwargs) -> StorageBackend:
    """Initialize storage backend."""
    global _storage_backend, _exemption_store, _blacklist_store
    
    if backend == "memory":
        _storage_backend = MemoryStorage()
    elif backend == "file":
        file_path = kwargs.get('file_path', 'aiwaf_data.json')
        _storage_backend = FileStorage(file_path)
    else:
        raise ValueError(f"Unknown storage backend: {backend}")
    
    _exemption_store = ExemptionStore(_storage_backend)
    _blacklist_store = BlacklistStore(_storage_backend)
    
    return _storage_backend


def get_storage() -> StorageBackend:
    """Get the current storage backend."""
    global _storage_backend
    if _storage_backend is None:
        initialize_storage()
    return _storage_backend


def get_exemption_store() -> ExemptionStore:
    """Get the exemption store."""
    global _exemption_store
    if _exemption_store is None:
        initialize_storage()
    return _exemption_store


def get_blacklist_store() -> BlacklistStore:
    """Get the blacklist store."""
    global _blacklist_store
    if _blacklist_store is None:
        initialize_storage()
    return _blacklist_store