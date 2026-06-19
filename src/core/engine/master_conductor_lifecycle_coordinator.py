"""
MasterConductor lifecycle coordinator (SGK-2026-0295).

Handles shutdown, checkpoint, session resume, and execution summary.
Takes facade reference as parameter. Does NOT hold MasterConductor instance.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any

from src.core.domain.model.task import TaskState
from src.core.engine.master_conductor_session_service import (
    apply_restored_session_state, build_async_session_payload,
    build_checkpoint_session_state, restore_legacy_resume_session_state,
)

_log = logging.getLogger(__name__)


async def shutdown_coordinator(facade: Any) -> None:
    """Graceful shutdown. Extracted from facade._async_shutdown."""
    if facade._shutdown_requested:
        return
    facade._shutdown_requested = True
    _log.warning("Graceful shutdown initiated...")

    try:
        if hasattr(facade, "resource_manager") and facade.resource_manager:
            facade.resource_manager.stop()
    except Exception as e:
        _log.error("Failed to stop ResourceManager: %s", e)

    try:
        if hasattr(facade, "event_bus") and facade.event_bus:
            await facade.event_bus.stop()
    except Exception as e:
        _log.error("Failed to stop EventBus: %s", e)

    try:
        from src.core.notifications.notification_service import get_notification_service
        await get_notification_service().stop()
    except Exception as e:
        _log.error("Failed to stop NotificationService: %s", e)

    try:
        from src.core.utils.oob_listener import get_oob_listener
        await get_oob_listener().stop()
    except Exception as e:
        try:
            if hasattr(facade, "network_client") and facade.network_client:
                await facade.network_client.close()
        except Exception:
            pass

    try:
        await facade.writer.stop()
    except Exception as e:
        _log.error("Failed to stop AsyncWriter: %s", e)

    if not facade._finished_normally:
        try:
            from datetime import datetime
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            await facade.async_save_session(filepath=f"session_interrupted_{ts}.json")
        except Exception as e:
            _log.error("Failed to save session during shutdown: %s", e)

    try:
        from src.core.notifications.notifier import get_notifier
        get_notifier().notify("SHIGOKU Interrupted: Conductor is shutting down.")
    except Exception:
        pass

    try:
        from src.core.utils.async_utils import SharedLoopManager
        loop_manager = SharedLoopManager.get_instance()
        if loop_manager._loop:
            try:
                pending = asyncio.all_tasks(loop_manager._loop)
                for task_obj in pending:
                    task_obj.cancel()
            except Exception:
                pass
        loop_manager.stop()
    except Exception as e:
        _log.error("Failed to stop SharedLoopManager: %s", e)

    from src.commands import print_step
    print_step("MasterConductor shutdown complete.")


def finalize_summary_coordinator(facade: Any, executed: int, normal_completion: bool = True) -> dict:
    """Build execution summary. Extracted from facade._finalize_execution_summary."""
    from src.core.engine.master_conductor_summary_service import (
        compute_failure_aggregation, compute_duration_percentile,
    )
    import time

    if facade.context.metrics["end_time"] is None:
        facade.context.metrics["end_time"] = time.time()
    facade.context.metrics["total_duration"] = (
        facade.context.metrics["end_time"] - facade.context.metrics.get("start_time", facade.context.metrics["end_time"])
    )

    failure_agg = compute_failure_aggregation(facade.completed_tasks)
    p50, p95 = compute_duration_percentile(facade.completed_tasks)

    return {
        "executed": executed,
        "completed": len(facade.completed_tasks),
        "successful": facade.context.successful_attempts,
        "failed": facade.context.total_attempts - facade.context.successful_attempts,
        "normal_completion": normal_completion,
        "total_duration_seconds": round(facade.context.metrics["total_duration"], 1),
        "failure_aggregation": failure_agg,
        "duration_p50_seconds": round(p50, 1),
        "duration_p95_seconds": round(p95, 1),
        "discovered_assets": len(facade.context.discovered_assets),
        "bypass_methods": facade.context.bypass_methods,
    }


def checkpoint_coordinator(facade: Any) -> None:
    """Save session checkpoint. Extracted from facade._checkpoint."""
    from src.core.engine.master_conductor_session_service import (
        serialize_legacy_session_task_queue, build_checkpoint_session_state,
    )
    import json
    import os

    if not facade._session_manager or not facade._current_session:
        return

    serialized_queue = serialize_legacy_session_task_queue(facade.task_queue)
    completed_targets, metadata = build_checkpoint_session_state(
        facade.task_queue, facade.completed_tasks, facade.context, facade.pending_hitl,
    )[1:] if len(build_checkpoint_session_state(
        facade.task_queue, facade.completed_tasks, facade.context, facade.pending_hitl,
    )) > 2 else ([], {})

    facade._current_session.update(
        pending_targets=serialized_queue,
        completed_targets=facade.completed_tasks,
        metadata=metadata,
    )
    facade._session_manager.save_session(facade._current_session)
    _log.debug("Checkpoint saved: %d pending, %d completed",
               len(facade.task_queue), len(facade.completed_tasks))


def resume_session_coordinator(facade: Any, session_id: str) -> bool:
    """Resume from saved session. Extracted from facade.resume_session."""
    if not facade._session_manager:
        _log.error("SessionManager not configured")
        return False

    session = facade._session_manager.resume_session(session_id)
    if not session:
        _log.error("Session not found: %s", session_id)
        return False

    facade._current_session = session
    restored = restore_legacy_resume_session_state(session)
    failed_tasks = apply_restored_session_state(
        restored=restored,
        context=facade.context, pending_hitl=facade.pending_hitl,
        task_queue=facade.task_queue,
    )
    if failed_tasks:
        _log.warning("%d tasks could not be restored", len(failed_tasks))

    if session.target_url:
        facade.initialize_workspace(session.target_url)

    _log.info("Session resumed: %s with %d pending tasks", session_id, len(facade.task_queue))
    return True


def checkpoint_coordinator(facade: Any) -> None:
    """Save session checkpoint. Extracted from facade._checkpoint."""
    from src.core.engine.master_conductor_session_service import (
        serialize_legacy_session_task_queue, build_checkpoint_session_state,
    )

    if not facade._session_manager or not facade._current_session:
        return

    serialized = serialize_legacy_session_task_queue(facade.task_queue)
    state = build_checkpoint_session_state(
        facade.task_queue, facade.completed_tasks, facade.context,
        getattr(facade, "pending_hitl", []),
    )
    pending_targets, completed_targets = state[0], state[1]
    metadata = state[2] if len(state) > 2 else {}

    facade._current_session.pending_targets = pending_targets
    facade._current_session.completed_targets = completed_targets
    facade._current_session.metadata = metadata
    facade._session_manager.save_session(facade._current_session)
    _log.debug("Checkpoint saved: %d pending, %d completed",
               len(facade.task_queue), len(facade.completed_tasks))


def resume_session_coordinator(facade: Any, session_id: str) -> bool:
    """Resume from saved session. Extracted from facade.resume_session."""
    from src.core.engine.master_conductor_session_service import (
        apply_restored_session_state, restore_legacy_resume_session_state,
    )

    if not facade._session_manager:
        _log.error("SessionManager not configured")
        return False

    session = facade._session_manager.resume_session(session_id)
    if not session:
        _log.error("Session not found: %s", session_id)
        return False

    facade._current_session = session
    restored = restore_legacy_resume_session_state(session)
    failed_tasks = apply_restored_session_state(
        restored=restored,
        context=facade.context, pending_hitl=facade.pending_hitl,
        task_queue=facade.task_queue,
    )
    if failed_tasks:
        _log.warning("%d tasks could not be restored", len(failed_tasks))

    if session.target_url:
        facade.initialize_workspace(session.target_url)

    _log.info("Session resumed: %s with %d pending tasks", session_id, len(facade.task_queue))
    return True
