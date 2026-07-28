"""
AttackReviewFormatter: attack_review data → Markdown artifact.

Produces attack_review.md with sections:
  1. 今回わかったこと (from target_system_profile + trail)
  2. 根拠つきレビュー履歴 (from attack_review_trail entries)
  3. 未確認 (from status/degraded/reason_codes)
  4. 次にやる候補 (from scenario_candidates)
  5. 制約 / 不完全情報 (from reason_codes + metadata)
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from src.reporting.attack_review_builder import build_all_review_fields

try:
    from zoneinfo import ZoneInfo
except Exception:
    ZoneInfo = None


def _now_jst() -> datetime:
    if ZoneInfo is not None:
        try:
            return datetime.now(ZoneInfo("Asia/Tokyo"))
        except Exception:
            pass
    return datetime.now(timezone(timedelta(hours=9)))


def _safe_dict(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def _safe_list(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    return []


def _safe_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value)


def _truncate(text: str, max_len: int = 80) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len - 3] + "..."


def _no_data_section(name: str) -> str:
    return f"{name}なし (No data available)"


# ===================================================================
# Section builders
# ===================================================================


def _section_1_overview(profile: dict | None, trail: dict | None) -> str:
    lines: List[str] = []
    lines.append("## 1. 今回わかったこと")
    lines.append("")

    has_data = False

    if profile:
        lines.append("### ターゲット概要")
        lines.append("")
        host = _safe_str(profile.get("target_host", ""))
        if host:
            lines.append(f"- ターゲットホスト: `{host}`")
            lines.append(f"  - source: target_system_profile.target_host")
            has_data = True

        auth_methods = _safe_list(profile.get("auth_methods", []))
        if auth_methods:
            lines.append(f"- 認証方式: {', '.join(f'`{am}`' for am in auth_methods)}")
            lines.append(f"  - source: target_system_profile.auth_methods")
            has_data = True

        tech_stack = _safe_dict(profile.get("tech_stack", {}))
        if tech_stack:
            lines.append("- 技術スタック:")
            for k, v in tech_stack.items():
                lines.append(f"  - {k}: `{v}`")
            lines.append(f"  - source: target_system_profile.tech_stack")
            has_data = True

        key_features = _safe_list(profile.get("key_features", []))
        if key_features:
            lines.append(f"- 実行したタスク種別: {', '.join(f'`{f}`' for f in key_features)}")
            lines.append(f"  - source: target_system_profile.key_features")
            has_data = True

        source_refs = _safe_list(profile.get("source_refs", []))
        if source_refs:
            lines.append("- データソース:")
            for sr in source_refs:
                lines.append(f"  - `{sr}`")
            has_data = True

    if trail:
        status = _safe_str(trail.get("status", ""))
        reason_codes = _safe_list(trail.get("reason_codes", []))
        lines.append("")
        lines.append(f"### レビュートレイル ステータス")
        lines.append("")
        lines.append(f"- ステータス: `{status}`")
        if reason_codes:
            lines.append(f"- 理由コード: {', '.join(f'`{rc}`' for rc in reason_codes)}")
        lines.append(f"  - source: attack_review_trail.status")
        has_data = True

    if not has_data:
        lines.append(_no_data_section("概要情報"))
        lines.append("")

    lines.append("")
    return "\n".join(lines)


def _section_2_review_trail(trail: dict | None) -> str:
    lines: List[str] = []
    lines.append("## 2. 根拠つきレビュー履歴")
    lines.append("")

    if not trail:
        lines.append(_no_data_section("レビュー履歴"))
        lines.append("")
        return "\n".join(lines)

    entries = _safe_list(trail.get("entries", []))

    if not entries:
        lines.append("履歴エントリなし")
        lines.append("")
        return "\n".join(lines)

    # Table header
    lines.append("| # | フェーズ | アクション | 観測/結果 | source_refs |")
    lines.append("|---|----------|------------|-----------|-------------|")

    for i, entry in enumerate(entries[:200]):
        if not isinstance(entry, dict):
            continue
        trail_id = _safe_str(entry.get("trail_id", str(i)))
        phase = _truncate(_safe_str(entry.get("phase", "")), 20)
        action = _truncate(_safe_str(entry.get("action", "")), 30)
        observation = _truncate(_safe_str(entry.get("observation", entry.get("result", ""))), 40)
        source_refs = ", ".join(f"`{sr}`" for sr in _safe_list(entry.get("source_refs", []))[:3])

        lines.append(f"| {trail_id} | {phase} | {action} | {observation} | {source_refs} |")

    lines.append("")
    lines.append(f"**総エントリ数:** {len(entries)}")
    lines.append("")

    return "\n".join(lines)


def _section_3_unverified(trail: dict | None) -> str:
    lines: List[str] = []
    lines.append("## 3. 未確認")
    lines.append("")

    has_data = False

    if trail:
        status = _safe_str(trail.get("status", ""))
        reason_codes = _safe_list(trail.get("reason_codes", []))

        if status == "degraded":
            lines.append(f"- トレイルデータが切り詰められています (status: `degraded`)")
            has_data = True
        elif status == "empty":
            lines.append(f"- トレイルデータが存在しません (status: `empty`)")
            has_data = True
        elif status == "partial":
            lines.append(f"- トレイルデータが不完全です (status: `partial`)")
            lines.append(f"  - source: attack_review_trail.status")
            has_data = True

        if reason_codes:
            lines.append(f"- 理由コード: {', '.join(f'`{rc}`' for rc in reason_codes)}")
            lines.append(f"  - source: attack_review_trail.reason_codes")
            has_data = True

    if not has_data:
        lines.append("未確認項目なし")
        lines.append("")

    lines.append("")
    return "\n".join(lines)


def _section_4_candidates(candidates: list | None) -> str:
    lines: List[str] = []
    lines.append("## 4. 次にやる候補")
    lines.append("")

    if not candidates:
        lines.append("次回候補なし")
        lines.append("")
        return "\n".join(lines)

    lines.append("| 候補ID | タイトル | リスク | ステータス | 根拠 | source_refs |")
    lines.append("|--------|----------|--------|-----------|------|-------------|")

    for c in candidates[:50]:
        if not isinstance(c, dict):
            continue
        cid = _safe_str(c.get("candidate_id", ""))
        title = _truncate(_safe_str(c.get("title", "")), 50)
        risk = _safe_str(c.get("risk_level", "medium"))
        status = _safe_str(c.get("adoption_status", "candidate"))
        rationale = _truncate(_safe_str(c.get("rationale", "")), 40)
        source_refs = ", ".join(f"`{sr}`" for sr in _safe_list(c.get("source_refs", []))[:3])

        lines.append(f"| {cid} | {title} | {risk} | {status} | {rationale} | {source_refs} |")

    lines.append("")
    lines.append(f"**候補総数:** {len(candidates)}")
    lines.append("")

    return "\n".join(lines)


def _section_5_constraints(
    profile: dict | None,
    trail: dict | None,
    candidates: list | None,
) -> str:
    lines: List[str] = []
    lines.append("## 5. 制約 / 不完全情報")
    lines.append("")

    has_data = False

    # Profile status
    if profile:
        p_status = _safe_str(profile.get("status", ""))
        p_reason_codes = _safe_list(profile.get("reason_codes", []))
        if p_status != "complete":
            lines.append(f"- プロファイルステータス: `{p_status}` (不完全)")
            has_data = True
        if p_reason_codes:
            lines.append(f"- プロファイル理由コード: {', '.join(f'`{rc}`' for rc in p_reason_codes)}")
            has_data = True

    # Trail status
    if trail:
        t_status = _safe_str(trail.get("status", ""))
        t_reason_codes = _safe_list(trail.get("reason_codes", []))
        entry_count = len(_safe_list(trail.get("entries", [])))
        lines.append(f"- トレイルエントリ数: {entry_count}")
        has_data = True
        if t_status != "complete":
            lines.append(f"- トレイルステータス: `{t_status}` (制限あり)")
            has_data = True
        if t_reason_codes:
            lines.append(f"- トレイル理由コード: {', '.join(f'`{rc}`' for rc in t_reason_codes)}")
            has_data = True

    # Candidate count
    if candidates:
        lines.append(f"- 次回候補数: {len(candidates)}")
        has_data = True

    if not has_data:
        lines.append("利用可能なメタデータなし")
        lines.append("")

    lines.append("")
    return "\n".join(lines)


# ===================================================================
# Main formatter
# ===================================================================


def format_attack_review(
    session_data: dict,
    profile: dict | None = None,
    trail: dict | None = None,
    candidates: list | None = None,
) -> str:
    """Generate attack_review.md from session data and review fields.

    Args:
        session_data: The finalized session payload dict.
        profile: Optional pre-built target_system_profile.
        trail: Optional pre-built attack_review_trail.
        candidates: Optional pre-built scenario_candidates.

    Returns:
        Markdown string for attack_review.md.
    """
    session_id = _safe_str(session_data.get("session_id", "unknown"))
    run_id = _safe_str(session_data.get("run_id", "unknown"))

    # ---- auto-resolution: pull review fields from session_data when not explicitly passed ----
    if profile is None:
        profile = _safe_dict(session_data.get("target_system_profile", {})) or None
    if trail is None:
        trail = _safe_dict(session_data.get("attack_review_trail", {})) or None
    if candidates is None:
        candidates = _safe_list(session_data.get("scenario_candidates", [])) or None

    # ---- backward-compatible fallback: build missing review fields from raw session data ----
    if profile is None or trail is None or candidates is None:
        fields = build_all_review_fields(session_data)
        if profile is None:
            profile = fields.get("target_system_profile")
        if trail is None:
            trail = fields.get("attack_review_trail")
        if candidates is None:
            candidates = fields.get("scenario_candidates")

    generated = _now_jst()

    lines: List[str] = []
    lines.append("# 攻撃レビューレポート (Attack Review)")
    lines.append("")
    lines.append(f"**セッションID:** `{session_id}`")
    lines.append(f"**ランID:** `{run_id}`")
    lines.append(f"**生成日時:** {generated.strftime('%Y-%m-%d %H:%M:%S')} JST")
    lines.append(f"**生成ツール:** SHIGOKU - Attack Review Formatter")
    lines.append("")

    lines.append(_section_1_overview(profile, trail))
    lines.append(_section_2_review_trail(trail))
    lines.append(_section_3_unverified(trail))
    lines.append(_section_4_candidates(candidates))
    lines.append(_section_5_constraints(profile, trail, candidates))

    return "\n".join(lines)
