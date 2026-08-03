"""
VDP Atomic Session Writer — SGK-2026-0419 Item 7.

Atomic session save with proper error handling:
- ``atomic_session_save``: temp-file + os.replace, raises on any I/O error (no silent ignore).
- ``safe_read_session``: reads with proper error handling, None only for FileNotFoundError.
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


def atomic_session_save(payload: Dict[str, Any], path: Path) -> None:
    """Atomically write a session payload to disk using temp-file + os.replace.

    On PermissionError, OSError, or IOError: raise (do NOT silently ignore).
    On success: the target file is atomically replaced.

    Args:
        payload: Session dict to persist.
        path: Target file path.

    Raises:
        PermissionError: If the process lacks permission to write/rename.
        OSError: For any other OS-level I/O failure.
        IOError: For general I/O failures.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(
        suffix=".tmp",
        prefix=".vdp_session_",
        dir=str(path.parent),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2, default=str)
        os.replace(tmp_path, str(path))
    except (PermissionError, OSError, IOError):
        # Clean up temp file on failure, then re-raise
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def safe_read_session(path: Path) -> Optional[Dict[str, Any]]:
    """Read a session file with proper error handling.

    - Returns None only for FileNotFoundError.
    - Raises on PermissionError.
    - Returns None for corrupt JSON (with logged warning).

    Args:
        path: Path to the session JSON file.

    Returns:
        Parsed session dict, or None if file not found or JSON is corrupt.

    Raises:
        PermissionError: If the process lacks permission to read the file.
    """
    path = Path(path)
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except PermissionError:
        raise

    try:
        data: Dict[str, Any] = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(
            "Corrupt session JSON in %s: %s", path, e, exc_info=False
        )
        return None

    return data
