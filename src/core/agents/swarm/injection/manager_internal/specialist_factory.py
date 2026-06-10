"""InjectionManager 向け specialist lazy-import ファクトリ。

_initialize_specialists の実装本体。ImportError 時の warning 文言、
specialist key、初期化順を変更しない。
"""

import logging
from typing import Any, Dict, Optional

from src.core.agents.swarm.base import Specialist

logger = logging.getLogger(__name__)


def create_specialists(config: Optional[Dict[str, Any]] = None) -> Dict[str, Specialist]:
    specialists: Dict[str, Specialist] = {}

    try:
        from src.core.agents.swarm.injection.smart_sqli import SmartSQLiHunter
        specialists["sqli"] = SmartSQLiHunter(config=config)
    except ImportError:
        logger.warning("SmartSQLiHunter not available")

    try:
        from src.core.agents.swarm.injection.open_redirect import OpenRedirectSpecialist
        specialists["redirect"] = OpenRedirectSpecialist(config=config)
    except ImportError:
        logger.warning("OpenRedirectSpecialist not available")

    try:
        from src.core.agents.swarm.injection.smart_lfi import SmartLFIHunter
        specialists["lfi"] = SmartLFIHunter(config=config)
    except ImportError:
        logger.warning("SmartLFIHunter not available")

    try:
        from src.core.agents.swarm.injection.smart_xss import SmartXSSHunter
        specialists["xss"] = SmartXSSHunter(config=config)
    except ImportError:
        logger.warning("SmartXSSHunter not available")

    try:
        from src.core.agents.swarm.injection.smart_cmd_ssrf import SmartCmdSSRFHunter
        specialists["cmd_ssrf"] = SmartCmdSSRFHunter(config=config)
    except ImportError:
        logger.warning("SmartCmdSSRFHunter not available")

    try:
        from src.core.agents.swarm.injection.smart_ssrf import SmartSSRFHunter
        specialists["ssrf"] = SmartSSRFHunter(config=config)
    except ImportError:
        logger.warning("SmartSSRFHunter not available")

    try:
        from src.core.agents.swarm.injection.smart_ssti import SmartSSTIHunter
        specialists["ssti"] = SmartSSTIHunter(config=config)
    except ImportError:
        logger.warning("SmartSSTIHunter not available")

    try:
        from src.core.agents.swarm.injection.smart_cors import SmartCORSHunter
        specialists["cors"] = SmartCORSHunter(config=config)
    except ImportError:
        logger.warning("SmartCORSHunter not available")

    try:
        from src.core.agents.swarm.injection.smart_crlf import SmartCRLFHunter
        specialists["crlf"] = SmartCRLFHunter(config=config)
    except ImportError:
        logger.warning("SmartCRLFHunter not available")

    try:
        from src.core.agents.swarm.injection.smart_graphql import SmartGraphQLHunter
        specialists["graphql"] = SmartGraphQLHunter(config=config)
    except ImportError:
        logger.warning("SmartGraphQLHunter not available")

    return specialists
