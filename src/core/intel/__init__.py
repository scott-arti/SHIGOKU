"""
Intel Package - 偵察モジュール群

Phase 6: 偵察機能強化
"""
import logging

logger = logging.getLogger(__name__)

# Helper to safely import modules
def _safe_import(module_names, package):
    try:
        # This is a simplified approach; in __init__.py we usually do direct imports.
        # Here we just wrap the direct imports.
        pass
    except ImportError as e:
        logger.warning(f"Failed to import {module_names}: {e}")

# 既存モジュール
try:
    from .cartographer import Cartographer
except ImportError as e:
    logger.debug(f"Optional import 'Cartographer' failed: {e}")
    Cartographer = None

try:
    from .fingerprinter import Fingerprinter
except ImportError as e:
    logger.debug(f"Optional import 'Fingerprinter' failed: {e}")
    Fingerprinter = None

try:
    from .commit_watcher import CommitWatcher
except ImportError as e:
    logger.debug(f"Optional import 'CommitWatcher' failed: {e}")
    CommitWatcher = None

try:
    from .dns_history import (
        DNSHistoryCollector,
        DNSHistoryResult,
        DNSRecord,
        create_dns_history_collector,
    )
except ImportError as e:
    logger.debug(f"Optional import 'DNSHistoryCollector' failed: {e}")

# TaggingFilter (New)
try:
    from .tagging_filter import TaggingFilter
except ImportError as e:
    logger.debug(f"Optional import 'TaggingFilter' failed: {e}")
    TaggingFilter = None


__all__ = [
    # 既存
    "Cartographer",
    "Fingerprinter",
    "CommitWatcher",
    # DNS History
    "DNSHistoryCollector",
    "DNSHistoryResult",
    "DNSRecord",
    "create_dns_history_collector",
    # Tagging
    "TaggingFilter",
]
