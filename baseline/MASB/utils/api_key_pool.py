# -*- coding: utf-8 -*-
"""
API Key Pool Manager
Manages rotation of API keys for concurrent operations
"""

import os
import fcntl
import time
from pathlib import Path
from typing import Optional, List


class APIKeyPool:
    """Thread-safe API key pool for rotation"""

    def __init__(self, pool_file: Optional[Path] = None, index_file: Optional[Path] = None):
        """
        Initialize API key pool

        Args:
            pool_file: Path to pool file (default: ./api_keys.conf)
            index_file: Path to index file (default: /tmp/api_key_index.txt)
        """
        if pool_file is None:
            pool_file = Path("./api_keys.conf")

        if index_file is None:
            index_file = Path("/tmp/api_key_pool_index.txt")

        self.pool_file = pool_file
        self.index_file = index_file
        self.lock_file = Path("/tmp/api_key_pool.lock")

        # Initialize index file
        self.index_file.parent.mkdir(parents=True, exist_ok=True)
        if not self.index_file.exists():
            self.index_file.write_text("0")

    def load_keys(self) -> List[str]:
        """
        Load API keys from pool file

        Returns:
            List of API keys
        """
        if not self.pool_file.exists():
            return []

        keys = []
        with open(self.pool_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue
                # Extract key (handle format: "key" or "key|label")
                key = line.split('|')[0].strip()
                if key:
                    keys.append(key)

        return keys

    def get_next_key(self) -> Optional[str]:
        """
        Get next API key from pool (thread-safe)

        Returns:
            API key or None if pool is empty
        """
        keys = self.load_keys()
        if not keys:
            return None

        # Use file locking for thread safety
        with open(self.lock_file, 'w') as lock_fh:
            fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)

            try:
                # Read current index
                index = int(self.index_file.read_text().strip()) if self.index_file.exists() else 0

                # Get current key
                key = keys[index % len(keys)]

                # Update index
                next_index = (index + 1) % len(keys)
                self.index_file.write_text(str(next_index))

                return key

            finally:
                fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)

    def reset_index(self):
        """Reset index to 0"""
        self.index_file.write_text("0")

    def get_key_count(self) -> int:
        """
        Get number of keys in pool

        Returns:
            Number of keys
        """
        return len(self.load_keys())


def get_api_key(pool_file: Optional[Path] = None) -> Optional[str]:
    """
    Convenience function to get next API key

    Args:
        pool_file: Path to pool file

    Returns:
        API key or None
    """
    pool = APIKeyPool(pool_file)
    return pool.get_next_key()
