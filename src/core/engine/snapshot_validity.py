"""
Snapshot validity check for the 3-point stale task detection.

Phase 6 M5 (SGK-2026-0315): Enqueue / dequeue / start-before check
that rejects pending tasks whose recon or auth snapshots have become
stale since the task was created.
"""
from typing import Any, Tuple


def check_snapshot_validity(
    task: Any,
    current_recon_version: int,
    current_auth_version: int,
) -> Tuple[bool, str]:
    """
    Check if a task's snapshot versions are still valid.

    A task is considered stale if its recorded snapshot version(s) are
    strictly lower than the current version(s).

    Args:
        task: The task object (must have a .metadata dict attribute).
        current_recon_version: The current recon snapshot version.
        current_auth_version: The current auth context version.

    Returns:
        (is_valid: bool, reason: str)
        - (True, "") if the task's snapshots are still current.
        - (False, "stale_recon_snapshot") if recon snapshot is old.
        - (False, "stale_auth_context") if auth context is old.
        - (False, "stale_snapshot") if both are old.
    """
    metadata = getattr(task, "metadata", None) or {}

    task_recon = metadata.get("recon_snapshot_version")
    task_auth = metadata.get("auth_context_version")

    stale_recon = (
        task_recon is not None
        and isinstance(task_recon, int)
        and current_recon_version > 0
        and task_recon < current_recon_version
    )
    stale_auth = (
        task_auth is not None
        and isinstance(task_auth, int)
        and current_auth_version > 0
        and task_auth < current_auth_version
    )

    if stale_recon and stale_auth:
        return (False, "stale_snapshot")
    if stale_recon:
        return (False, "stale_recon_snapshot")
    if stale_auth:
        return (False, "stale_auth_context")
    return (True, "")
