"""
Pytest fixtures for AIWAF test suites.
"""
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aiwaf.storage import initialize_storage


@pytest.fixture(autouse=True)
def ensure_memory_storage():
    """
    Ensure each test gets a clean in-memory storage backend.
    """
    initialize_storage(backend="memory")
