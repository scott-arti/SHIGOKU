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
    from .visual_filter import VisualFilter
except ImportError as e:
    logger.debug(f"Optional import 'VisualFilter' failed: {e}")
    VisualFilter = None

try:
    from .commit_watcher import CommitWatcher
except ImportError as e:
    logger.debug(f"Optional import 'CommitWatcher' failed: {e}")
    CommitWatcher = None

try:
    from .headless_crawler import HeadlessCrawler
except ImportError as e:
    logger.debug(f"Optional import 'HeadlessCrawler' failed: {e}")
    HeadlessCrawler = None

# Phase 6 新規モジュール
try:
    from .google_dorker import (
        GoogleDorker,
        DorkCategory,
        DorkResult,
        create_google_dorker,
    )
except ImportError as e:
    logger.debug(f"Optional import 'GoogleDorker' failed: {e}")

try:
    from .js_analyzer import (
        JSAnalyzer,
        JSAnalysisResult,
        create_js_analyzer,
    )
except ImportError as e:
    logger.debug(f"Optional import 'JSAnalyzer' failed: {e}")

try:
    from .wayback_integrator import (
        WaybackIntegrator,
        WaybackSnapshot,
        WaybackDiff,
        create_wayback_integrator,
    )
except ImportError as e:
    logger.debug(f"Optional import 'WaybackIntegrator' failed: {e}")

try:
    from .cve_explorer import (
        CVEExplorer,
        CVEInfo,
        CVESeverity,
        create_cve_explorer,
    )
except ImportError as e:
    logger.debug(f"Optional import 'CVEExplorer' failed: {e}")

try:
    from .email_harvester import (
        EmailHarvester,
        EmailInfo,
        create_email_harvester,
    )
except ImportError as e:
    logger.debug(f"Optional import 'EmailHarvester' failed: {e}")

try:
    from .asn_discoverer import (
        ASNDiscoverer,
        ASNInfo,
        IPRange,
        create_asn_discoverer,
    )
except ImportError as e:
    logger.debug(f"Optional import 'ASNDiscoverer' failed: {e}")

try:
    from .cert_transparency import (
        CertTransparency,
        CertInfo,
        create_cert_transparency,
    )
except ImportError as e:
    logger.debug(f"Optional import 'CertTransparency' failed: {e}")

try:
    from .shodan_integrator import (
        ShodanIntegrator,
        HostInfo,
        ServiceInfo,
        create_shodan_integrator,
    )
except ImportError as e:
    logger.debug(f"Optional import 'ShodanIntegrator' failed: {e}")

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
    "VisualFilter",
    "CommitWatcher",
    "HeadlessCrawler",
    # Phase 6
    "GoogleDorker",
    "DorkCategory",
    "DorkResult",
    "create_google_dorker",
    "JSAnalyzer",
    "JSAnalysisResult",
    "create_js_analyzer",
    "WaybackIntegrator",
    "WaybackSnapshot",
    "WaybackDiff",
    "create_wayback_integrator",
    "CVEExplorer",
    "CVEInfo",
    "CVESeverity",
    "create_cve_explorer",
    "EmailHarvester",
    "EmailInfo",
    "create_email_harvester",
    "ASNDiscoverer",
    "ASNInfo",
    "IPRange",
    "create_asn_discoverer",
    "CertTransparency",
    "CertInfo",
    "create_cert_transparency",
    "ShodanIntegrator",
    "HostInfo",
    "ServiceInfo",
    "create_shodan_integrator",
    # DNS History
    "DNSHistoryCollector",
    "DNSHistoryResult",
    "DNSRecord",
    "create_dns_history_collector",
    # Tagging
    "TaggingFilter",
]
