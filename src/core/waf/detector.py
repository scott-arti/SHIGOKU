from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
import json
import logging


logger = logging.getLogger(__name__)


@dataclass
class WAFDetectionResult:
    waf_name: Optional[str]
    confidence: float
    is_blocked: bool
    reason: str
    matched_signals: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "waf_name": self.waf_name,
            "confidence": self.confidence,
            "is_blocked": self.is_blocked,
            "reason": self.reason,
            "matched_signals": self.matched_signals,
        }


class WAFDetector:
    """
    Signature-based WAF detector.

    Uses `data/waf_signatures.json` (if present) and safely falls back to
    embedded defaults when the DB is missing or malformed.
    """

    def __init__(
        self,
        signatures_path: str = "data/waf_signatures.json",
        threshold: float = 0.35,
    ) -> None:
        self.signatures_path = Path(signatures_path)
        self.threshold = max(0.0, min(1.0, float(threshold)))
        self._signatures = self._load_signatures()

    def detect(
        self,
        status_code: int,
        headers: Optional[dict[str, str]] = None,
        body: str = "",
    ) -> WAFDetectionResult:
        normalized_headers = {str(k).lower(): str(v).lower() for k, v in (headers or {}).items()}
        body_lower = (body or "").lower()
        blocked_by_status = status_code in (403, 406, 429, 451, 503)

        best_name: Optional[str] = None
        best_score = 0.0
        best_signals: list[str] = []

        for waf_name, sig in self._signatures.items():
            score = 0.0
            signals: list[str] = []

            for h in sig.get("header_contains", []):
                h_low = h.lower()
                if any(h_low in hk or h_low in hv for hk, hv in normalized_headers.items()):
                    score += 0.35
                    signals.append(f"header:{h}")

            for b in sig.get("body_contains", []):
                b_low = b.lower()
                if b_low and b_low in body_lower:
                    score += 0.3
                    signals.append(f"body:{b}")

            for s in sig.get("status_codes", []):
                if int(s) == int(status_code):
                    score += 0.2
                    signals.append(f"status:{s}")
                    break

            if score > best_score:
                best_score = score
                best_name = waf_name
                best_signals = signals

        confidence = round(min(1.0, best_score), 3)
        waf_name = best_name if confidence >= self.threshold else None

        if waf_name:
            reason = "signature_match"
        elif blocked_by_status:
            reason = "block_status_without_signature"
        else:
            reason = "no_waf_signal"

        return WAFDetectionResult(
            waf_name=waf_name,
            confidence=confidence,
            is_blocked=bool(blocked_by_status),
            reason=reason,
            matched_signals=best_signals if waf_name else [],
        )

    def _load_signatures(self) -> dict[str, dict[str, Any]]:
        default = _default_signatures()
        path = self.signatures_path

        if not path.exists():
            return default

        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            signatures = raw.get("signatures", raw)
            if not isinstance(signatures, dict):
                return default

            normalized: dict[str, dict[str, Any]] = {}
            for name, sig in signatures.items():
                if not isinstance(sig, dict):
                    continue
                normalized[str(name).lower()] = {
                    "header_contains": list(sig.get("header_contains", [])),
                    "body_contains": list(sig.get("body_contains", [])),
                    "status_codes": list(sig.get("status_codes", [])),
                }
            return normalized or default
        except (OSError, TypeError, ValueError) as exc:
            logger.warning("WAF signatures load failed (%s): %s", path, exc)
            return default


def _default_signatures() -> dict[str, dict[str, Any]]:
    return {
        "cloudflare": {
            "header_contains": ["cf-ray", "cf-cache-status", "cloudflare"],
            "body_contains": ["attention required", "cloudflare"],
            "status_codes": [403, 429],
        },
        "aws_waf": {
            "header_contains": ["x-amzn-requestid", "x-amz-cf-id", "awswaf"],
            "body_contains": ["aws waf", "request blocked"],
            "status_codes": [403, 406],
        },
        "akamai": {
            "header_contains": ["akamai", "x-akamai"],
            "body_contains": ["akamai ghost"],
            "status_codes": [403],
        },
        "imperva": {
            "header_contains": ["incap_ses", "visid_incap", "imperva"],
            "body_contains": ["incapsula", "imperva"],
            "status_codes": [403],
        },
        "modsecurity": {
            "header_contains": ["mod_security", "modsec", "owasp"],
            "body_contains": ["modsecurity", "access denied"],
            "status_codes": [403, 406],
        },
    }

