#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.reporting.report_session_consistency import verify_report_session_consistency


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify consistency between a haddix report and its source session.",
    )
    parser.add_argument(
        "--report",
        required=True,
        help="Absolute or relative path to haddix_report_*.md",
    )
    parser.add_argument(
        "--session",
        help="Optional explicit session file path (session_*.json)",
    )
    parser.add_argument(
        "--sessions-dir",
        help="Optional sessions directory path when --session is not provided",
    )
    parser.add_argument(
        "--vdp-key-registry",
        help=(
            "Optional VDP key registry JSON (public keys only) so confirmed "
            "verdict proofs can be verified. SGK-2026-0423: without it, "
            "proof-bearing confirmed verdicts are fail-closed unverifiable."
        ),
    )
    args = parser.parse_args()

    verdict = verify_report_session_consistency(
        Path(args.report),
        session_path=Path(args.session) if args.session else None,
        sessions_dir=Path(args.sessions_dir) if args.sessions_dir else None,
        public_key_provider=_load_vdp_key_provider(args.vdp_key_registry),
    )
    print(json.dumps(verdict, ensure_ascii=False, indent=2))

    status = str(verdict.get("status", "") or "").strip().lower()
    if status == "consistent":
        return 0
    if status == "inconsistent":
        return 3
    return 2


def _load_vdp_key_provider(path: str | None) -> dict | None:
    """Load a public-key-only provider dict {key_id: bytes} from a VDP key
    registry JSON (SGK-2026-0423 close-out; additive CLI flag).

    The registry serialization is public data (``{"schema_version": 1,
    "keys": {key_id: {"public_key": <hex>}}}``) — parsed directly so the
    script never imports engine modules (0422 structural boundary). Missing
    file or malformed content → None (fail-closed: proofs stay
    unverifiable, never trusted without the key).
    """
    if not path:
        return None
    registry_path = Path(path)
    if not registry_path.exists():
        return None
    try:
        data = json.loads(registry_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    keys = data.get("keys") if isinstance(data, dict) else None
    if not isinstance(keys, dict) or not keys:
        return None
    provider: dict = {}
    for key_id, entry in keys.items():
        if not isinstance(entry, dict):
            continue
        raw = str(entry.get("public_key", "") or "")
        try:
            provider[str(key_id)] = bytes.fromhex(raw)
        except ValueError:
            continue
    return provider or None


if __name__ == "__main__":
    raise SystemExit(main())
