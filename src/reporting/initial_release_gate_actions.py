from __future__ import annotations

from pathlib import Path
from typing import Any

from src.reporting.initial_release_gate_policy import _DEFERRED_SCENARIO_PLAYBOOK


def _build_deferred_scenarios(
    *,
    allowed_missing: list[str],
    actual_missing: list[str],
) -> list[dict[str, Any]]:
    allowed_set = {str(token or "").strip().lower() for token in allowed_missing if str(token or "").strip()}
    deferred_ids = sorted(
        {
            str(token or "").strip().lower()
            for token in actual_missing
            if str(token or "").strip() and str(token or "").strip().lower() in allowed_set
        }
    )
    deferred: list[dict[str, Any]] = []
    for sid in deferred_ids:
        playbook = _DEFERRED_SCENARIO_PLAYBOOK.get(sid, {})
        deferred.append(
            {
                "scenario_id": sid,
                "title": str(playbook.get("title", sid) or sid),
                "route": str(playbook.get("route", "human_preferred") or "human_preferred"),
                "why_deferred": str(
                    playbook.get(
                        "why_deferred",
                        "Deferred to post-release high-friction track due to low automation efficiency.",
                    )
                ),
                "trigger": str(playbook.get("trigger", "Initial release gate passed while scenario remained missing.")),
                "operator_input": str(playbook.get("operator_input", "Provide domain context and approval constraints.")),
                "success_criteria": str(playbook.get("success_criteria", "Produce reproducible evidence and risk narrative.")),
            }
        )
    return deferred


def _build_recommended_actions(
    *,
    status: str,
    reason_codes: list[str],
    report_path: Path,
    allowed_missing: list[str],
    confirmed_min: int,
    candidate_max: int,
    confirmed_poc_missing_max: int,
    reason_code_missing_max: int,
    required_confirmed_classes: list[str],
    required_class_confirmed_min: int,
    unexpected_missing: list[str],
    missing_required_detection_classes: list[str],
    deferred_scenarios: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    normalized_codes = {str(code or "").strip().lower() for code in reason_codes if str(code or "").strip()}
    actions: list[dict[str, Any]] = []

    def _add(
        action_id: str,
        *,
        priority: str,
        owner: str,
        summary: str,
        command_hint: str,
        applies_when: list[str],
    ) -> None:
        if any(existing.get("id") == action_id for existing in actions):
            return
        actions.append(
            {
                "id": action_id,
                "priority": priority,
                "owner": owner,
                "summary": summary,
                "command_hint": command_hint,
                "applies_when_reason_codes": applies_when,
            }
        )

    if status == "pass":
        required_classes_arg = ",".join(required_confirmed_classes)
        required_flags = ""
        if required_classes_arg:
            required_flags = (
                f" --required-confirmed-classes {required_classes_arg}"
                f" --required-class-confirmed-min {int(required_class_confirmed_min)}"
            )
        _add(
            "proceed_release_candidate",
            priority="info",
            owner="operator",
            summary="Initial-release gate passed. Keep allowed deferred exceptions and proceed.",
            command_hint=(
                f"python3 /app/scripts/check_initial_release_gate.py --report \"{report_path}\" "
                f"--allowed-missing {','.join(allowed_missing)} "
                f"--confirmed-min {int(confirmed_min)} --candidate-max {int(candidate_max)} "
                f"--confirmed-poc-missing-max {int(confirmed_poc_missing_max)} "
                f"--reason-code-missing-max {int(reason_code_missing_max)}"
                f"{required_flags}"
            ),
            applies_when=[],
        )
        if deferred_scenarios:
            scenario_ids = ",".join(
                sorted(
                    {
                        str(item.get("scenario_id", "") or "").strip().lower()
                        for item in deferred_scenarios
                        if isinstance(item, dict) and str(item.get("scenario_id", "") or "").strip()
                    }
                )
            )
            _add(
                "run_deferred_scenario_track",
                priority="medium",
                owner="operator",
                summary=(
                    "Start deferred high-friction track after initial release gate pass "
                    f"(scenarios: {scenario_ids or '-'})"
                ),
                command_hint=f"python3 /app/scripts/check_initial_release_gate.py --report \"{report_path}\"",
                applies_when=[],
            )
        return actions

    if "consistency_blocked" in normalized_codes or "consistency_inconsistent" in normalized_codes:
        _add(
            "resolve_report_session_consistency",
            priority="high",
            owner="operator",
            summary="Resolve report/session mismatch before any rerun decision.",
            command_hint=f"python3 /app/scripts/verify_report_session_consistency.py --report \"{report_path}\"",
            applies_when=["consistency_blocked", "consistency_inconsistent"],
        )

    if "family_gate_not_passed" in normalized_codes or "family_gate_not_found" in normalized_codes:
        _add(
            "improve_family_gate_coverage",
            priority="high",
            owner="shigoku",
            summary="Re-run scan with coverage-backfill tasks enabled to satisfy vulnerability-family gate.",
            command_hint="python3 -m src.main --target <TARGET> --skip-initial-recon",
            applies_when=["family_gate_not_passed", "family_gate_not_found"],
        )

    if "confirmed_below_minimum" in normalized_codes:
        _add(
            "increase_confirmed_density",
            priority="high",
            owner="shigoku",
            summary="Increase confirmed findings by strengthening auth/id/params seed surfaces first.",
            command_hint=(
                "python3 -m src.main --focus-tests --focus-group density "
                "&& python3 -m src.main --target <TARGET> --skip-initial-recon"
            ),
            applies_when=["confirmed_below_minimum"],
        )

    if "required_detection_class_below_minimum" in normalized_codes:
        class_hint = ",".join(missing_required_detection_classes) if missing_required_detection_classes else "<CLASS_LIST>"
        _add(
            "expand_detection_class_coverage",
            priority="high",
            owner="shigoku",
            summary=(
                "Required detection classes are below minimum confirmed threshold. "
                "Expand probes for missing classes and re-run gate."
            ),
            command_hint=(
                "python3 -m src.main --focus-tests --focus-group density "
                "&& python3 -m src.main --target <TARGET> --skip-initial-recon "
                f"# prioritize classes: {class_hint}"
            ),
            applies_when=["required_detection_class_below_minimum"],
        )

    if "candidate_above_maximum" in normalized_codes:
        _add(
            "drain_candidate_queue",
            priority="medium",
            owner="operator",
            summary="Reduce candidate findings by manual verification or stricter promotion thresholds.",
            command_hint=(
                "python3 -m src.main --hitl-list --target <TARGET> "
                "&& python3 -m src.main --hitl-approve <TICKET_ID> --hitl-run --target <TARGET>"
            ),
            applies_when=["candidate_above_maximum"],
        )

    if "confirmed_poc_missing_above_maximum" in normalized_codes or "confirmed_poc_missing_not_found" in normalized_codes:
        _add(
            "enforce_confirmed_poc_artifacts",
            priority="high",
            owner="shigoku",
            summary="Ensure confirmed findings always include PoC request/response evidence artifacts.",
            command_hint=(
                "python3 -m src.main --focus-tests --focus-group report "
                "&& python3 -m src.main --report --format haddix --target <PROJECT_OR_TARGET>"
            ),
            applies_when=["confirmed_poc_missing_above_maximum", "confirmed_poc_missing_not_found"],
        )

    if "reason_code_missing_above_maximum" in normalized_codes or "reason_code_missing_not_found" in normalized_codes:
        _add(
            "enforce_candidate_reason_codes",
            priority="high",
            owner="shigoku",
            summary="Ensure every candidate/failed finding includes standardized reason codes.",
            command_hint=(
                "python3 -m src.main --focus-tests --focus-group report "
                "&& python3 -m src.main --report --format haddix --target <PROJECT_OR_TARGET>"
            ),
            applies_when=["reason_code_missing_above_maximum", "reason_code_missing_not_found"],
        )

    if "unexpected_missing_scenarios" in normalized_codes:
        missing_hint = ",".join(unexpected_missing) if unexpected_missing else "<SCN_ID_LIST>"
        _add(
            "close_unexpected_scenario_gaps",
            priority="high",
            owner="shigoku",
            summary="Unexpected missing scenarios exist. Cover them before initial release.",
            command_hint=(
                "python3 -m src.main --target <TARGET> --skip-initial-recon "
                f"# prioritize missing scenarios: {missing_hint}"
            ),
            applies_when=["unexpected_missing_scenarios"],
        )

    if "findings_summary_not_found" in normalized_codes:
        _add(
            "regenerate_haddix_report",
            priority="medium",
            owner="operator",
            summary="Report format is missing findings summary line; regenerate Haddix report from source session.",
            command_hint="python3 -m src.main --report --format haddix --target <PROJECT_OR_TARGET>",
            applies_when=["findings_summary_not_found"],
        )

    if not actions:
        _add(
            "inspect_reason_codes",
            priority="medium",
            owner="operator",
            summary="Inspect reason_codes and apply targeted remediation.",
            command_hint=f"python3 /app/scripts/check_initial_release_gate.py --report \"{report_path}\"",
            applies_when=sorted(normalized_codes),
        )

    return actions
