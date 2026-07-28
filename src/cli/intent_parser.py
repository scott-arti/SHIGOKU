from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, TYPE_CHECKING

from src.core.models.ops_artifacts import IntentCommand, load_attack_target_bundle
from src.core.utils.json_utils import safe_json_loads
from src.reporting.endpoint_extractor import extract_attack_targets_from_session
from src.reporting.report_session_consistency import verify_report_session_consistency

if TYPE_CHECKING:
    from src.core.models.llm import LLMClient

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BUDGET_FILE = Path.home() / ".shigoku" / "ops_intent_budget.json"
_ATTACK_COMMANDS = {IntentCommand.MAIN_ATTACK_TARGETS}
_RESUME_PATTERNS = (
    r"step\s*(\d+)",
    r"ステップ\s*(\d+)",
    r"(\d+)\s*(?:から|より)\s*再開",
)


@dataclass
class OpsIntentSettings:
    llm_parse_timeout_sec: int = 15
    command_timeout_sec: int = 900
    retry_budget: int = 0
    max_attack_targets_per_run: int = 25
    non_tty_policy: str = "fail_closed"
    kill_switch: bool = False
    feature_flag: bool = True
    daily_llm_budget: int = 25

    def to_dict(self) -> dict[str, Any]:
        return {
            "llm_parse_timeout_sec": int(self.llm_parse_timeout_sec),
            "command_timeout_sec": int(self.command_timeout_sec),
            "retry_budget": int(self.retry_budget),
            "max_attack_targets_per_run": int(self.max_attack_targets_per_run),
            "non_tty_policy": str(self.non_tty_policy),
            "kill_switch": bool(self.kill_switch),
            "feature_flag": bool(self.feature_flag),
            "daily_llm_budget": int(self.daily_llm_budget),
        }


@dataclass
class OperatorIntent:
    status: str
    correlation_id: str
    intent_hash: str
    raw_intent: str
    command: IntentCommand | None = None
    target: str | None = None
    report_path: str | None = None
    session_path: str | None = None
    attack_targets_file: str | None = None
    wordlist_path: str | None = None
    mode: str = "bugbounty"
    recon_start_step: int | None = None
    recon_end_step: int | None = None
    requires_confirmation: bool = False
    reason_codes: list[str] = field(default_factory=list)
    missing_requirements: list[str] = field(default_factory=list)
    llm_used: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "correlation_id": self.correlation_id,
            "intent_hash": self.intent_hash,
            "raw_intent": self.raw_intent,
            "command": self.command.value if isinstance(self.command, IntentCommand) else None,
            "target": self.target,
            "report_path": self.report_path,
            "session_path": self.session_path,
            "attack_targets_file": self.attack_targets_file,
            "wordlist_path": self.wordlist_path,
            "mode": self.mode,
            "recon_start_step": self.recon_start_step,
            "recon_end_step": self.recon_end_step,
            "requires_confirmation": self.requires_confirmation,
            "reason_codes": list(self.reason_codes),
            "missing_requirements": list(self.missing_requirements),
            "llm_used": bool(self.llm_used),
        }


@dataclass
class PreviewStep:
    intent_command: str
    description: str
    command: list[str]
    requires_confirmation: bool = False
    mutating: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "intent_command": self.intent_command,
            "description": self.description,
            "command": list(self.command),
            "requires_confirmation": bool(self.requires_confirmation),
            "mutating": bool(self.mutating),
        }


@dataclass
class ExecutionPreview:
    status: str
    steps: list[PreviewStep] = field(default_factory=list)
    reason_codes: list[str] = field(default_factory=list)
    missing_requirements: list[str] = field(default_factory=list)
    inferred_target: str | None = None
    attack_target_count: int | None = None
    output_dir: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason_codes": list(self.reason_codes),
            "missing_requirements": list(self.missing_requirements),
            "inferred_target": self.inferred_target,
            "attack_target_count": self.attack_target_count,
            "output_dir": self.output_dir,
            "preview_steps": [step.to_dict() for step in self.steps],
        }


def load_ops_intent_settings(config_path: str | Path | None = None) -> OpsIntentSettings:
    raw_path = Path(config_path).expanduser().resolve() if config_path else PROJECT_ROOT / "config" / "shigoku.yaml"
    if not raw_path.exists():
        return OpsIntentSettings()
    try:
        import yaml
    except Exception:
        return OpsIntentSettings()
    try:
        payload = yaml.safe_load(raw_path.read_text(encoding="utf-8")) or {}
    except Exception:
        return OpsIntentSettings()
    section = payload.get("ops_intent", {}) if isinstance(payload, dict) else {}
    if not isinstance(section, dict):
        return OpsIntentSettings()
    return OpsIntentSettings(
        llm_parse_timeout_sec=int(section.get("llm_parse_timeout_sec", 15) or 15),
        command_timeout_sec=int(section.get("command_timeout_sec", 900) or 900),
        retry_budget=max(0, int(section.get("retry_budget", 0) or 0)),
        max_attack_targets_per_run=max(0, int(section.get("max_attack_targets_per_run", 25) or 25)),
        non_tty_policy=str(section.get("non_tty_policy", "fail_closed") or "fail_closed").strip() or "fail_closed",
        kill_switch=bool(section.get("kill_switch", False)),
        feature_flag=bool(section.get("feature_flag", True)),
        daily_llm_budget=max(0, int(section.get("daily_llm_budget", 25) or 25)),
    )


def parse_operator_intent(
    raw_intent: str,
    *,
    target: str | None = None,
    report_path: str | None = None,
    session_path: str | None = None,
    attack_targets_file: str | None = None,
    wordlist_path: str | None = None,
    mode: str | None = None,
    settings: OpsIntentSettings | None = None,
    llm_client: "LLMClient" | None = None,
) -> OperatorIntent:
    cfg = settings or OpsIntentSettings()
    normalized_intent = str(raw_intent or "").strip()
    correlation_id = f"ops-{uuid.uuid4().hex[:12]}"
    intent_hash = hashlib.sha256(normalized_intent.encode("utf-8")).hexdigest()

    parsed = _parse_with_heuristics(
        normalized_intent,
        target=target,
        report_path=report_path,
        session_path=session_path,
        attack_targets_file=attack_targets_file,
        wordlist_path=wordlist_path,
        mode=mode,
        correlation_id=correlation_id,
        intent_hash=intent_hash,
    )
    if parsed.command is None and normalized_intent and _llm_fallback_enabled(llm_client):
        parsed = _maybe_parse_with_llm(
            parsed,
            settings=cfg,
            llm_client=llm_client,
        )
    parsed.missing_requirements = _missing_requirements(parsed)
    if parsed.command is None:
        parsed.status = "blocked"
        if "intent_unresolved" not in parsed.reason_codes:
            parsed.reason_codes.append("intent_unresolved")
    elif parsed.missing_requirements:
        parsed.status = "needs_input"
    else:
        parsed.status = "ok"
    return parsed


def build_execution_preview(
    intent: OperatorIntent,
    *,
    settings: OpsIntentSettings,
    python_bin: str,
    output_dir: str | Path | None = None,
    max_records: int = 500,
    ttl_days: int = 7,
    main_dry_run: bool = False,
) -> ExecutionPreview:
    if intent.command is None:
        return ExecutionPreview(
            status="blocked",
            reason_codes=list(intent.reason_codes or ["intent_unresolved"]),
            missing_requirements=list(intent.missing_requirements),
        )
    if intent.missing_requirements:
        return ExecutionPreview(
            status="needs_input",
            reason_codes=list(intent.reason_codes),
            missing_requirements=list(intent.missing_requirements),
        )

    destination = Path(output_dir).expanduser().resolve() if output_dir else PROJECT_ROOT / "tmp" / "ops_intent" / intent.correlation_id
    preview = ExecutionPreview(status="ok", output_dir=str(destination))

    if intent.command == IntentCommand.MAIN_RECON_RESUME:
        command = [
            python_bin,
            "-m",
            "src.main",
            "--recon",
            str(intent.target),
            "--recon-start-step",
            str(intent.recon_start_step or 1),
            "--mode",
            str(intent.mode or "bugbounty"),
        ]
        if intent.recon_end_step is not None:
            command.extend(["--recon-end-step", str(intent.recon_end_step)])
        if main_dry_run:
            command.append("--dry-run")
        preview.steps.append(
            PreviewStep(
                intent_command=intent.command.value,
                description="Resume recon from the requested step.",
                command=command,
                requires_confirmation=True,
                mutating=True,
            )
        )
        return preview

    if intent.command == IntentCommand.MAIN_ATTACK_TARGETS:
        analysis = _analyze_attack_source(
            intent,
            settings=settings,
            max_records=max_records,
        )
        preview.reason_codes.extend(list(analysis.get("reason_codes", [])))
        if analysis.get("status") != "ok":
            preview.status = str(analysis.get("status") or "blocked")
            preview.missing_requirements.extend(list(analysis.get("missing_requirements", [])))
            return preview

        preview.inferred_target = str(analysis.get("target") or "")
        preview.attack_target_count = int(analysis.get("attack_target_count", 0) or 0)
        resolved_attack_targets = str(analysis.get("attack_targets_file") or "")
        max_export_records = int(analysis.get("max_records", max_records) or max_records)

        if intent.report_path:
            preview.steps.append(
                PreviewStep(
                    intent_command=IntentCommand.REPORT_EXPORT_TARGETS.value,
                    description="Export structured attack targets from the report's resolved session.",
                    command=[
                        "python3",
                        "scripts/shigoku_ops_cli.py",
                        "--json",
                        "report",
                        "export-targets",
                        "--report",
                        str(intent.report_path),
                        "--output-dir",
                        str(destination),
                        "--max-records",
                        str(max_export_records),
                        "--ttl-days",
                        str(max(0, int(ttl_days))),
                        "--overwrite",
                    ],
                    mutating=True,
                )
            )
        elif intent.session_path:
            preview.steps.append(
                PreviewStep(
                    intent_command=IntentCommand.SESSION_EXPORT_TARGETS.value,
                    description="Export structured attack targets from the session.",
                    command=[
                        "python3",
                        "scripts/shigoku_ops_cli.py",
                        "--json",
                        "session",
                        "export-targets",
                        "--session",
                        str(intent.session_path),
                        "--output-dir",
                        str(destination),
                        "--max-records",
                        str(max_export_records),
                        "--ttl-days",
                        str(max(0, int(ttl_days))),
                        "--overwrite",
                    ],
                    mutating=True,
                )
            )

        command = [
            python_bin,
            "-m",
            "src.main",
            "--target",
            str(analysis.get("target")),
            "--attack-targets",
            resolved_attack_targets,
            "--mode",
            str(intent.mode or "bugbounty"),
        ]
        if intent.wordlist_path:
            command.extend(["--wordlist", str(intent.wordlist_path)])
        if main_dry_run:
            command.append("--dry-run")
        preview.steps.append(
            PreviewStep(
                intent_command=intent.command.value,
                description="Run SHIGOKU attack flow against the structured targets.",
                command=command,
                requires_confirmation=True,
                mutating=True,
            )
        )
        return preview

    if intent.command in {IntentCommand.REPORT_CONSISTENCY, IntentCommand.REPORT_LOOP, IntentCommand.REPORT_EXPORT_TARGETS}:
        action = intent.command.value.split(".", 1)[1]
        preview.steps.append(
            PreviewStep(
                intent_command=intent.command.value,
                description="Run the requested report operation.",
                command=[
                    "python3",
                    "scripts/shigoku_ops_cli.py",
                    "--json",
                    "report",
                    action,
                    "--report",
                    str(intent.report_path),
                ],
                mutating=action == "export-targets",
            )
        )
        return preview

    if intent.command in {IntentCommand.SESSION_FINDINGS, IntentCommand.SESSION_EXPORT_TARGETS}:
        action = intent.command.value.split(".", 1)[1]
        preview.steps.append(
            PreviewStep(
                intent_command=intent.command.value,
                description="Run the requested session operation.",
                command=[
                    "python3",
                    "scripts/shigoku_ops_cli.py",
                    "--json",
                    "session",
                    action,
                    "--session",
                    str(intent.session_path),
                ],
                mutating=action == "export-targets",
            )
        )
        return preview

    return ExecutionPreview(
        status="blocked",
        reason_codes=["intent_command_not_supported"],
    )


def _parse_with_heuristics(
    raw_intent: str,
    *,
    target: str | None,
    report_path: str | None,
    session_path: str | None,
    attack_targets_file: str | None,
    wordlist_path: str | None,
    mode: str | None,
    correlation_id: str,
    intent_hash: str,
) -> OperatorIntent:
    text = str(raw_intent or "").strip()
    lowered = text.lower()
    command: IntentCommand | None = None
    reason_codes: list[str] = []
    recon_start_step: int | None = None

    if any(token in lowered for token in ("consistency", "整合性")) and report_path:
        command = IntentCommand.REPORT_CONSISTENCY
        reason_codes.append("intent_report_consistency")
    elif any(token in lowered for token in ("loop", "gate", "ゲート")) and report_path:
        command = IntentCommand.REPORT_LOOP
        reason_codes.append("intent_report_loop")
    elif any(token in lowered for token in ("export", "抽出", "一覧", "endpoints", "endpoint", "targets", "ターゲット")):
        if report_path:
            command = IntentCommand.REPORT_EXPORT_TARGETS
            reason_codes.append("intent_report_export_targets")
        elif session_path:
            command = IntentCommand.SESSION_EXPORT_TARGETS
            reason_codes.append("intent_session_export_targets")

    if command is None and any(token in lowered for token in ("findings", "脆弱性", "finding")) and session_path:
        command = IntentCommand.SESSION_FINDINGS
        reason_codes.append("intent_session_findings")

    if command is None and any(token in lowered for token in ("attack", "fuzz", "攻撃", "叩")):
        command = IntentCommand.MAIN_ATTACK_TARGETS
        reason_codes.append("intent_attack_targets")

    if command is None and any(token in lowered for token in ("resume", "再開", "step", "ステップ")):
        for pattern in _RESUME_PATTERNS:
            match = re.search(pattern, lowered)
            if match:
                recon_start_step = int(match.group(1))
                break
        command = IntentCommand.MAIN_RECON_RESUME
        reason_codes.append("intent_recon_resume")

    requires_confirmation = command in _ATTACK_COMMANDS or command == IntentCommand.MAIN_RECON_RESUME
    return OperatorIntent(
        status="blocked",
        correlation_id=correlation_id,
        intent_hash=intent_hash,
        raw_intent=text,
        command=command,
        target=str(target or "").strip() or None,
        report_path=str(report_path or "").strip() or None,
        session_path=str(session_path or "").strip() or None,
        attack_targets_file=str(attack_targets_file or "").strip() or None,
        wordlist_path=str(wordlist_path or "").strip() or None,
        mode=str(mode or "bugbounty").strip() or "bugbounty",
        recon_start_step=recon_start_step,
        requires_confirmation=requires_confirmation,
        reason_codes=reason_codes,
    )


def _maybe_parse_with_llm(
    parsed: OperatorIntent,
    *,
    settings: OpsIntentSettings,
    llm_client: "LLMClient" | None,
) -> OperatorIntent:
    if not settings.feature_flag:
        return parsed
    if not _consume_llm_budget(settings):
        parsed.reason_codes.append("daily_llm_budget_exceeded")
        return parsed

    if llm_client is None:
        try:
            from src.core.models.llm import LLMClient as _LLMClient
        except Exception:
            parsed.reason_codes.append("intent_llm_unavailable")
            return parsed

        try:
            client = _LLMClient(role="ops_intent")
        except Exception:
            parsed.reason_codes.append("intent_llm_unavailable")
            return parsed
    else:
        client = llm_client
    prompt = {
        "instruction": "Translate the operator intent into one allowlisted command only.",
        "allowlist": IntentCommand.allowlist(),
        "intent": parsed.raw_intent,
        "current_context": {
            "target": parsed.target,
            "report_path": parsed.report_path,
            "session_path": parsed.session_path,
            "attack_targets_file": parsed.attack_targets_file,
            "wordlist_path": parsed.wordlist_path,
            "mode": parsed.mode,
        },
    }
    try:
        response = client.generate(
            [{"role": "user", "content": json.dumps(prompt, ensure_ascii=False)}],
            temperature=0,
            timeout=max(1, int(settings.llm_parse_timeout_sec)),
        )
        raw_content = response.choices[0].message.content if hasattr(response, "choices") and response.choices else ""
        payload = safe_json_loads(_strip_code_fence(raw_content), default={}, context="ops_intent_llm")
    except Exception:
        parsed.reason_codes.append("intent_llm_unavailable")
        return parsed

    if not isinstance(payload, dict):
        parsed.reason_codes.append("intent_llm_invalid_payload")
        return parsed
    command_token = str(payload.get("command", "") or "").strip()
    if command_token not in IntentCommand.allowlist():
        parsed.reason_codes.append("intent_llm_invalid_command")
        return parsed

    parsed.command = IntentCommand(command_token)
    parsed.target = str(payload.get("target", "") or "").strip() or parsed.target
    parsed.report_path = str(payload.get("report_path", "") or "").strip() or parsed.report_path
    parsed.session_path = str(payload.get("session_path", "") or "").strip() or parsed.session_path
    parsed.attack_targets_file = str(payload.get("attack_targets_file", "") or "").strip() or parsed.attack_targets_file
    parsed.wordlist_path = str(payload.get("wordlist_path", "") or "").strip() or parsed.wordlist_path
    raw_step = payload.get("recon_start_step")
    if raw_step not in (None, ""):
        try:
            parsed.recon_start_step = int(raw_step)
        except Exception:
            pass
    parsed.requires_confirmation = parsed.command in _ATTACK_COMMANDS or parsed.command == IntentCommand.MAIN_RECON_RESUME
    parsed.reason_codes.extend(
        str(token or "").strip()
        for token in list(payload.get("reason_codes", []) or [])
        if str(token or "").strip()
    )
    parsed.reason_codes.append("intent_llm_fallback")
    parsed.llm_used = True
    return parsed


def _missing_requirements(intent: OperatorIntent) -> list[str]:
    missing: list[str] = []
    if intent.command in {
        IntentCommand.REPORT_CONSISTENCY,
        IntentCommand.REPORT_LOOP,
        IntentCommand.REPORT_EXPORT_TARGETS,
    } and not intent.report_path:
        missing.append("report_path")
    if intent.command in {
        IntentCommand.SESSION_FINDINGS,
        IntentCommand.SESSION_EXPORT_TARGETS,
    } and not intent.session_path:
        missing.append("session_path")
    if intent.command == IntentCommand.MAIN_RECON_RESUME and not intent.target:
        missing.append("target")
    if intent.command == IntentCommand.MAIN_ATTACK_TARGETS and not any(
        [intent.attack_targets_file, intent.report_path, intent.session_path]
    ):
        missing.append("attack_targets_or_source")
    return sorted(set(missing))


def _analyze_attack_source(
    intent: OperatorIntent,
    *,
    settings: OpsIntentSettings,
    max_records: int,
) -> dict[str, Any]:
    reason_codes: list[str] = []
    target = intent.target
    attack_targets_file = intent.attack_targets_file
    session_path = intent.session_path
    report_path = intent.report_path
    attack_target_count: int | None = None

    if attack_targets_file:
        bundle = load_attack_target_bundle(attack_targets_file)
        attack_target_count = len(bundle.targets)
        if not target:
            target = _infer_target_from_hosts(bundle.manifest.allowed_hosts, [item.url for item in bundle.targets])
        resolved_attack_targets = str(Path(attack_targets_file).expanduser().resolve())
    else:
        if report_path:
            verdict = verify_report_session_consistency(Path(report_path))
            if str(verdict.get("status", "") or "").strip().lower() != "consistent":
                return {
                    "status": "blocked",
                    "reason_codes": ["report_consistency_inconsistent", *list(verdict.get("reason_codes", []) or [])],
                    "missing_requirements": [],
                }
            session_info = verdict.get("session", {}) if isinstance(verdict.get("session"), dict) else {}
            session_path = str(session_info.get("path", "") or "").strip() or session_path
            reason_codes.append("attack_source_report_consistent")
        if not session_path:
            return {
                "status": "needs_input",
                "reason_codes": reason_codes,
                "missing_requirements": ["session_path"],
            }
        resolved_session_path = Path(session_path).expanduser().resolve()
        targets = extract_attack_targets_from_session(resolved_session_path, max_records=max_records + 1)
        attack_target_count = len(targets)
        if attack_target_count <= 0:
            return {
                "status": "blocked",
                "reason_codes": ["empty_export"],
                "missing_requirements": [],
            }
        if settings.max_attack_targets_per_run > 0 and attack_target_count > settings.max_attack_targets_per_run:
            return {
                "status": "blocked",
                "reason_codes": ["attack_target_limit_exceeded"],
                "missing_requirements": [],
            }
        if not target:
            target = _infer_target_from_hosts(
                sorted({item.host for item in targets if str(item.host or "").strip()}),
                [item.url for item in targets],
            )
        resolved_attack_targets = str(PROJECT_ROOT / "tmp" / "ops_intent" / intent.correlation_id / "attack_targets.json")

    if settings.max_attack_targets_per_run > 0 and attack_target_count and attack_target_count > settings.max_attack_targets_per_run:
        return {
            "status": "blocked",
            "reason_codes": ["attack_target_limit_exceeded"],
            "missing_requirements": [],
        }
    if not target:
        return {
            "status": "needs_input",
            "reason_codes": reason_codes,
            "missing_requirements": ["target"],
        }
    return {
        "status": "ok",
        "reason_codes": reason_codes,
        "target": target,
        "attack_targets_file": resolved_attack_targets,
        "attack_target_count": attack_target_count,
        "max_records": min(max_records, settings.max_attack_targets_per_run or max_records),
    }


def _infer_target_from_hosts(hosts: list[str], urls: list[str]) -> str | None:
    normalized_hosts = [str(host or "").strip() for host in hosts if str(host or "").strip()]
    if len(normalized_hosts) == 1:
        sample_url = next((str(item or "").strip() for item in urls if str(item or "").strip()), "")
        if sample_url.startswith("http://"):
            return f"http://{normalized_hosts[0]}"
        return f"https://{normalized_hosts[0]}"
    return None


def _strip_code_fence(text: str) -> str:
    raw = str(text or "").strip()
    if raw.startswith("```"):
        raw = re.sub(r"^```[a-zA-Z0-9_-]*\n?", "", raw)
        raw = re.sub(r"\n?```$", "", raw)
    return raw.strip()


def _consume_llm_budget(settings: OpsIntentSettings) -> bool:
    budget = max(0, int(settings.daily_llm_budget))
    if budget == 0:
        return True
    today = date.today().isoformat()
    payload = {"date": today, "used": 0}
    if DEFAULT_BUDGET_FILE.exists():
        existing = safe_json_loads(
            DEFAULT_BUDGET_FILE.read_text(encoding="utf-8"),
            default=payload,
            context="ops_intent_budget",
        )
        if isinstance(existing, dict):
            payload.update(existing)
    if str(payload.get("date", "")) != today:
        payload = {"date": today, "used": 0}
    used = int(payload.get("used", 0) or 0)
    if used >= budget:
        return False
    payload["used"] = used + 1
    DEFAULT_BUDGET_FILE.parent.mkdir(parents=True, exist_ok=True)
    DEFAULT_BUDGET_FILE.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return True


def _llm_fallback_enabled(llm_client: "LLMClient" | None) -> bool:
    if llm_client is not None:
        return True
    return any(
        str(os.getenv(env_name, "") or "").strip()
        for env_name in ("DEEPSEEK_API_KEY", "OPENAI_API_KEY", "ANY_LLM_API_KEY")
    )
