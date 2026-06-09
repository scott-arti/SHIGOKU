"""Shared workspace stub for SGK-2026-0265 work scope."""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class SharedWorkspace:
    """Stub workspace for dependency resolution during refactoring."""

    def __init__(self, workspace_root: str = "") -> None:
        self.workspace_root: str = workspace_root

    def ingest_response(
        self, url: str, body: Any, role: str = "", *, stage: str = ""
    ) -> None:
        pass

    def get_pool_ids(
        self,
        endpoint_pattern: str = "",
        *,
        exclude: Optional[List[str]] = None,
        exclude_owner: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[str]:
        return []

    async def save_finding(self, finding: Any) -> Optional[str]:
        return None

    async def save_intel(self, type_name: str, data: Dict[str, Any]) -> Optional[str]:
        return None
