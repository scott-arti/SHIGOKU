"""Shared workspace stub for SGK-2026-0265 work scope."""

import json
import logging
import re
from pathlib import Path
from collections import defaultdict, OrderedDict
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

UUID_RE = re.compile(
    r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
)
UUID_PATH_RE = re.compile(r'/[0-9a-fA-F-]{36}')
NUMERIC_PATH_RE = re.compile(r'/\d+')


class SharedWorkspace:
    def __init__(self, workspace_root: str = "") -> None:
        self.workspace_root: str = workspace_root
        self._root: Path = Path(workspace_root) if workspace_root else Path(".")
        self.id_pool: Dict[str, OrderedDict[str, None]] = defaultdict(OrderedDict)
        self._owner_map: Dict[Tuple[str, str], str] = {}
        self._pending_approval: Dict[str, Dict[str, Any]] = {}

        if workspace_root:
            self._ensure_directories()

    @property
    def root(self) -> Path:
        return self._root

    def _ensure_directories(self) -> None:
        root = self._root
        (root / "findings").mkdir(parents=True, exist_ok=True)
        (root / "intel").mkdir(parents=True, exist_ok=True)

    def _normalize_url_pattern(self, url: str) -> str:
        pattern = UUID_PATH_RE.sub('/{uuid}', url)
        pattern = NUMERIC_PATH_RE.sub('/{id}', pattern)
        pattern = pattern.split("?")[0]
        return pattern

    def _extract_ids_from_text(self, text: str) -> List[str]:
        if not text:
            return []
        ids: List[str] = []
        uuid_ids = UUID_RE.findall(text)
        if uuid_ids:
            ids.extend(sorted(set(uuid_ids)))
        masked_text = UUID_RE.sub('', text)
        numeric_ids = set(re.findall(r'\b(\d+)\b', masked_text))
        ids.extend(sorted(numeric_ids))
        return ids

    def _matching_pool_keys(self, endpoint_pattern: str) -> List[str]:
        if not endpoint_pattern:
            return list(self.id_pool.keys())
        return [k for k in self.id_pool if endpoint_pattern in k]

    def register_ids(
        self,
        endpoint_pattern: str,
        ids: Iterable[str],
        owner: Optional[str] = None,
    ) -> None:
        for id_value in ids:
            self.id_pool[endpoint_pattern][id_value] = None
            if owner:
                self._owner_map[(endpoint_pattern, id_value)] = owner

    def get_pool_ids(
        self,
        endpoint_pattern: str = "",
        *,
        exclude: Optional[List[str]] = None,
        exclude_owner: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[str]:
        exclude_set = set(exclude) if exclude else set()
        pool_keys = self._matching_pool_keys(endpoint_pattern)

        result: List[str] = []
        for k in pool_keys:
            for id_value in self.id_pool[k]:
                if id_value in exclude_set:
                    continue
                if exclude_owner and self._id_belongs_to_owner(
                    id_value, exclude_owner, pool_keys
                ):
                    continue
                if id_value not in result:
                    result.append(id_value)

        result.sort()
        if limit is not None:
            result = result[:limit]
        return result

    def _id_belongs_to_owner(
        self, id_value: str, owner: str, pool_keys: List[str]
    ) -> bool:
        for k in pool_keys:
            if self._owner_map.get((k, id_value)) == owner:
                return True
        return False

    def stage_ids_for_approval(
        self,
        endpoint_pattern: str,
        ids: Iterable[str],
        reason: str = "",
        owner: Optional[str] = None,
    ) -> None:
        entry = self._pending_approval.setdefault(endpoint_pattern, {
            "ids": [],
            "owners": {},
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        existing: Set[str] = set(entry["ids"])
        for id_value in ids:
            if id_value not in existing:
                entry["ids"].append(id_value)
                existing.add(id_value)
                if owner:
                    entry["owners"][id_value] = owner

    def approve_staged_ids(self, endpoint_pattern: str) -> int:
        entry = self._pending_approval.pop(endpoint_pattern, None)
        if not entry:
            return 0
        ids: List[str] = entry.get("ids", [])
        owners: Dict[str, str] = entry.get("owners", {})
        for id_value in ids:
            owner = owners.get(id_value)
            self.register_ids(
                endpoint_pattern, [id_value], owner=owner
            )
        return len(ids)

    def get_pending_approval_report(self) -> Dict[str, Any]:
        return dict(self._pending_approval)

    def ingest_response(
        self, url: str, body: Any, role: str = "", *, stage: str = ""
    ) -> None:
        if not body:
            return
        text = body if isinstance(body, str) else str(body)
        extracted_ids = self._extract_ids_from_text(text)
        if not extracted_ids:
            return

        pattern = self._normalize_url_pattern(url)

        if stage:
            reason = f"BugBounty mode: staging {len(extracted_ids)} IDs from {url}"
            self.stage_ids_for_approval(
                pattern, extracted_ids, reason=reason, owner=role if role else None
            )
        else:
            self.register_ids(pattern, extracted_ids, owner=role if role else None)

    async def save_finding(self, finding: Any) -> Optional[str]:
        if not self.workspace_root:
            return None
        self._ensure_directories()
        findings_dir = self._root / "findings"
        finding_id = (
            finding.get("id")
            if isinstance(finding, dict)
            else getattr(finding, "id", None)
        )
        filename = f"{finding_id}.json" if finding_id else f"finding_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S_%f')}.json"
        filepath = findings_dir / filename
        data = finding if isinstance(finding, dict) else vars(finding)
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2, default=str)
        return str(filepath)

    async def save_intel(self, type_name: str, data: Dict[str, Any]) -> Optional[str]:
        if not self.workspace_root:
            return None
        self._ensure_directories()
        intel_dir = self._root / "intel"
        filename = f"{type_name}.jsonl"
        filepath = intel_dir / filename
        record = {
            "type": type_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data,
        }
        with open(filepath, "a") as f:
            f.write(json.dumps(record, default=str) + "\n")
        return str(filepath)
