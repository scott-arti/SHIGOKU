"""
Dashboard FastAPI Main

SHIGOKU WebダッシュボードのFastAPIバックエンド
"""

import logging
import asyncio
from pathlib import Path
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from src.core.project.project_manager import ProjectManager
from src.core.infra.knowledge_graph import KnowledgeGraph
from src.core.infra.event_bus import get_event_bus, EventType, Event
from src.dashboard.api.models import (
    ProjectInfo,
    FindingResponse,
    VulnerabilityScore,
    TargetInfo,
    HuntingLogEntry,
    SessionMetrics,
    PerformanceData,
)
from src.core.engine.skip_reason_registry import KNOWN_SKIP_REASONS, normalize_skip_reason

logger = logging.getLogger(__name__)

# FastAPIアプリケーション
app = FastAPI(
    title="SHIGOKU Dashboard API",
    description="Autonomous Bug Bounty Hunter Dashboard",
    version="1.0.0",
)


def _aggregate_skip_reason_counts(session_data: dict) -> dict:
    """
    completed_tasks[*].result(data).execution_log から skip_reason_counts を集計する。
    既存セッション互換のため、summary未保持時は url_results から復元する。
    """
    completed_tasks = session_data.get("completed_tasks", [])
    if not isinstance(completed_tasks, list):
        return {}

    totals: dict[str, int] = {}
    for task in completed_tasks:
        if not isinstance(task, dict):
            continue
        result_obj = task.get("result", {})
        if not isinstance(result_obj, dict):
            continue
        data = result_obj.get("data", result_obj)
        if not isinstance(data, dict):
            continue
        execution_log = data.get("execution_log", [])
        if not isinstance(execution_log, list):
            continue
        for entry in execution_log:
            if not isinstance(entry, dict):
                continue
            counts = entry.get("skip_reason_counts", {})
            if not isinstance(counts, dict):
                counts = {}
            if not counts:
                # backward-compatible fallback
                url_results = entry.get("url_results", [])
                if isinstance(url_results, list):
                    for item in url_results:
                        if not isinstance(item, dict):
                            continue
                        if str(item.get("status", "")).lower() != "skipped":
                            continue
                        normalized = normalize_skip_reason(item.get("skip_reason", ""))
                        reason = normalized if normalized in KNOWN_SKIP_REASONS else "other"
                        totals[reason] = int(totals.get(reason, 0) or 0) + 1
                continue
            for reason, count in counts.items():
                key = str(reason or "").strip().lower() or "other"
                try:
                    value = int(count or 0)
                except (TypeError, ValueError):
                    value = 0
                totals[key] = int(totals.get(key, 0) or 0) + max(0, value)
    return totals


def _aggregate_skip_reason_unknown_counts(session_data: dict) -> dict:
    """
    known語彙外の skip_reason を raw 値で集計する。
    summaryに unknown 集計がある場合はそれを優先する。
    """
    completed_tasks = session_data.get("completed_tasks", [])
    if not isinstance(completed_tasks, list):
        return {}

    totals: dict[str, int] = {}
    for task in completed_tasks:
        if not isinstance(task, dict):
            continue
        result_obj = task.get("result", {})
        if not isinstance(result_obj, dict):
            continue
        data = result_obj.get("data", result_obj)
        if not isinstance(data, dict):
            continue
        execution_log = data.get("execution_log", [])
        if not isinstance(execution_log, list):
            continue
        for entry in execution_log:
            if not isinstance(entry, dict):
                continue
            counts = entry.get("skip_reason_unknown_counts", {})
            if isinstance(counts, dict) and counts:
                for reason, count in counts.items():
                    key = str(reason or "").strip().lower() or "unknown"
                    try:
                        value = int(count or 0)
                    except (TypeError, ValueError):
                        value = 0
                    totals[key] = int(totals.get(key, 0) or 0) + max(0, value)
                continue

            # backward-compatible fallback
            url_results = entry.get("url_results", [])
            if not isinstance(url_results, list):
                continue
            for item in url_results:
                if not isinstance(item, dict):
                    continue
                if str(item.get("status", "")).lower() != "skipped":
                    continue
                reason = normalize_skip_reason(item.get("skip_reason", ""))
                if reason in KNOWN_SKIP_REASONS:
                    continue
                totals[reason] = int(totals.get(reason, 0) or 0) + 1
    return totals


def _aggregate_skip_reason_timeline(session_data: dict) -> list[dict]:
    """
    completed_tasks 順に skip_reason の累積推移を返す。
    時刻情報が無いセッション形式向けに task_index を時系列代替として使う。
    """
    completed_tasks = session_data.get("completed_tasks", [])
    if not isinstance(completed_tasks, list):
        return []

    timeline: list[dict] = []
    running: dict[str, int] = {}

    for idx, task in enumerate(completed_tasks, start=1):
        if not isinstance(task, dict):
            continue
        result_obj = task.get("result", {})
        if not isinstance(result_obj, dict):
            continue
        data = result_obj.get("data", result_obj)
        if not isinstance(data, dict):
            continue
        execution_log = data.get("execution_log", [])
        if not isinstance(execution_log, list):
            continue

        delta: dict[str, int] = {}
        for entry in execution_log:
            if not isinstance(entry, dict):
                continue
            counts = entry.get("skip_reason_counts", {})
            if isinstance(counts, dict) and counts:
                for reason, count in counts.items():
                    key = str(reason or "").strip().lower() or "other"
                    try:
                        value = int(count or 0)
                    except (TypeError, ValueError):
                        value = 0
                    if value > 0:
                        delta[key] = int(delta.get(key, 0) or 0) + value
                continue

            # backward-compatible fallback
            url_results = entry.get("url_results", [])
            if not isinstance(url_results, list):
                continue
            for item in url_results:
                if not isinstance(item, dict):
                    continue
                if str(item.get("status", "")).lower() != "skipped":
                    continue
                normalized = normalize_skip_reason(item.get("skip_reason", ""))
                reason = normalized if normalized in KNOWN_SKIP_REASONS else "other"
                delta[reason] = int(delta.get(reason, 0) or 0) + 1

        if not delta:
            continue

        for reason, value in delta.items():
            running[reason] = int(running.get(reason, 0) or 0) + int(value)

        timeline.append(
            {
                "task_index": idx,
                "task_id": str(task.get("id", "") or ""),
                "task_name": str(task.get("name", "") or ""),
                "delta": dict(delta),
                "cumulative": dict(running),
            }
        )

    return timeline


def _aggregate_low_ssrf_score_breakdown(session_data: dict) -> dict:
    """
    completed_tasks[*].result(data).execution_log から
    low_ssrf_score の不足特徴内訳を集計する。
    既存セッション互換のため、summary未保持時は url_results から復元する。
    """
    completed_tasks = session_data.get("completed_tasks", [])
    if not isinstance(completed_tasks, list):
        return {}

    totals: dict[str, int] = {}
    for task in completed_tasks:
        if not isinstance(task, dict):
            continue
        result_obj = task.get("result", {})
        if not isinstance(result_obj, dict):
            continue
        data = result_obj.get("data", result_obj)
        if not isinstance(data, dict):
            continue
        execution_log = data.get("execution_log", [])
        if not isinstance(execution_log, list):
            continue
        for entry in execution_log:
            if not isinstance(entry, dict):
                continue
            summary_breakdown = entry.get("low_ssrf_score_breakdown", {})
            if isinstance(summary_breakdown, dict) and summary_breakdown:
                for feature, count in summary_breakdown.items():
                    key = str(feature or "").strip().lower() or "other"
                    try:
                        value = int(count or 0)
                    except (TypeError, ValueError):
                        value = 0
                    totals[key] = int(totals.get(key, 0) or 0) + max(0, value)
                continue

            # backward-compatible fallback
            url_results = entry.get("url_results", [])
            if not isinstance(url_results, list):
                continue
            for item in url_results:
                if not isinstance(item, dict):
                    continue
                if str(item.get("status", "")).lower() != "skipped":
                    continue
                if normalize_skip_reason(item.get("skip_reason", "")) != "low_ssrf_score":
                    continue
                score_breakdown = item.get("score_breakdown", {})
                if not isinstance(score_breakdown, dict):
                    score_breakdown = {}
                for feature, raw_value in score_breakdown.items():
                    key = str(feature or "").strip().lower() or "other"
                    try:
                        value = int(raw_value or 0)
                    except (TypeError, ValueError):
                        value = 0
                    if value <= 0:
                        totals[key] = int(totals.get(key, 0) or 0) + 1
    return totals


def _calculate_skip_reason_other_ratio(skip_reason_counts: dict) -> float:
    if not isinstance(skip_reason_counts, dict) or not skip_reason_counts:
        return 0.0
    total = 0
    other = 0
    for reason, count in skip_reason_counts.items():
        try:
            value = int(count or 0)
        except (TypeError, ValueError):
            value = 0
        if value <= 0:
            continue
        total += value
        if str(reason or "").strip().lower() == "other":
            other += value
    return (other / total) if total > 0 else 0.0


def _extract_low_ssrf_top_missing_feature(breakdown: dict) -> str:
    if not isinstance(breakdown, dict) or not breakdown:
        return ""
    best_key = ""
    best_val = -1
    for feature, count in breakdown.items():
        try:
            value = int(count or 0)
        except (TypeError, ValueError):
            value = 0
        if value > best_val:
            best_val = value
            best_key = str(feature or "").strip().lower()
    return best_key if best_val > 0 else ""


def _calculate_unknown_skip_reason_alert(skip_reason_counts: dict, unknown_counts: dict) -> dict:
    """
    Unknown skip reasons surge alert.
    Gate when both absolute count and ratio are high to reduce false positives.
    """
    known_total = 0
    unknown_total = 0
    for value in (skip_reason_counts or {}).values():
        try:
            known_total += max(0, int(value or 0))
        except (TypeError, ValueError):
            continue
    for value in (unknown_counts or {}).values():
        try:
            unknown_total += max(0, int(value or 0))
        except (TypeError, ValueError):
            continue
    total = known_total + unknown_total
    ratio = (unknown_total / total) if total > 0 else 0.0
    threshold_count = 5
    threshold_ratio = 0.20
    triggered = unknown_total >= threshold_count and ratio >= threshold_ratio
    return {
        "triggered": bool(triggered),
        "unknown_count": unknown_total,
        "total_skip_count": total,
        "unknown_ratio": ratio,
        "threshold_count": threshold_count,
        "threshold_ratio": threshold_ratio,
    }

# CORS設定（開発用）
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root():
    """ルートエンドポイント"""
    return {"message": "SHIGOKU Dashboard API", "version": "1.0.0"}


@app.get("/api/health")
async def health_check():
    """ヘルスチェック"""
    return {"status": "ok"}


@app.get("/api/projects", response_model=List[ProjectInfo])
def list_projects():
    """
    プロジェクト一覧を取得
    
    Returns:
        プロジェクト情報のリスト
    """
    projects_dir = Path("workspace/projects")
    if not projects_dir.exists():
        return []
    
    projects = []
    for project_path in projects_dir.iterdir():
        if not project_path.is_dir():
            continue
        
        pm = ProjectManager(project_path.name)
        config = pm.load_meta()
        
        if config:
            # Findings数をカウント
            findings_dir = pm.project_dir / "findings"
            total_findings = len(list(findings_dir.glob("*.json"))) if findings_dir.exists() else 0
            
            projects.append(ProjectInfo(
                project_name=config.project_name,
                target_url=config.target_url,
                program_name=config.program_name,
                description=config.description,
                created_at=config.created_at,
                last_scan_at=config.last_scan_at,
                tags=config.tags,
                total_findings=total_findings,
            ))
    
    return projects


@app.get("/api/projects/{project_name}/findings", response_model=List[FindingResponse])
def get_project_findings(
    project_name: str,
    severity: Optional[str] = Query(None, description="Severity filter"),
    vuln_type: Optional[str] = Query(None, description="Vulnerability type filter"),
    min_confidence: Optional[float] = Query(None, ge=0.0, le=1.0),
):
    """
    プロジェクトのFinding一覧を取得
    
    Args:
        project_name: プロジェクト名
        severity: 深刻度フィルタ
        vuln_type: 脆弱性タイプフィルタ
        min_confidence: 最小確信度
    
    Returns:
        Finding一覧
    """
    import json
    
    pm = ProjectManager(project_name)
    findings_dir = pm.project_dir / "findings"
    
    if not findings_dir.exists():
        return []
    
    findings = []
    for finding_file in findings_dir.glob("*.json"):
        try:
            with open(finding_file, encoding="utf-8") as f:
                data = json.load(f)
            
            # フィルタリング
            if severity and data.get("severity") != severity:
                continue
            if vuln_type and data.get("vuln_type") != vuln_type:
                continue
            if min_confidence and data.get("confidence", 0) < min_confidence:
                continue
            
            findings.append(FindingResponse(**data))
        except (json.JSONDecodeError, OSError) as e:
            logger.error("Error loading finding %s: %s", finding_file, e)
    
    # 日時でソート（新しい順）
    findings.sort(key=lambda x: x.discovered_at, reverse=True)
    
    return findings


@app.get("/api/projects/{project_name}/score", response_model=VulnerabilityScore)
def get_vulnerability_score(project_name: str):
    """
    プロジェクトの脆弱度スコアを計算
    
    Args:
        project_name: プロジェクト名
    
    Returns:
        脆弱度スコア (0-10点)
    """
    import json
    
    pm = ProjectManager(project_name)
    findings_dir = pm.project_dir / "findings"
    
    if not findings_dir.exists():
        return VulnerabilityScore(
            total_score=0.0,
            cvss_avg=0.0,
            findings_count=0,
            severity_breakdown={},
            recommendations=["まだスキャンが実行されていません"],
        )
    
    findings = []
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    cvss_scores = []
    
    for finding_file in findings_dir.glob("*.json"):
        try:
            with open(finding_file, encoding="utf-8") as f:
                data = json.load(f)
            
            findings.append(data)
            severity = data.get("severity", "info")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            if data.get("cvss_score"):
                cvss_scores.append(data["cvss_score"])
        except (json.JSONDecodeError, OSError) as e:
            logger.error("Error loading finding %s: %s", finding_file, e)
    
    if not findings:
        return VulnerabilityScore(
            total_score=0.0,
            cvss_avg=0.0,
            findings_count=0,
            severity_breakdown={},
            recommendations=["脆弱性が見つかりませんでした"],
        )
    
    # スコア計算
    cvss_avg = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 5.0
    findings_count = len(findings)
    
    return VulnerabilityScore(
        total_score=min(10.0, cvss_avg + (findings_count * 0.5)),
        cvss_avg=cvss_avg,
        findings_count=findings_count,
        severity_breakdown=severity_counts,
        recommendations=["深刻度の高い脆弱性から優先的に修正してください"]
    )


@app.get("/api/projects/{project_name}/metrics", response_model=SessionMetrics)
def get_project_metrics(project_name: str):
    """
    プロジェクトの実行メトリクスを取得
    """
    import json
    import time
    from datetime import datetime
    
    pm = ProjectManager(project_name)
    session_file = pm.project_dir / "sessions" / "latest.json"
    
    if not session_file.exists():
        # 代わりのセッションファイルを探す
        sessions_dir = pm.project_dir / "sessions"
        if sessions_dir.exists():
            all_sessions = sorted(list(sessions_dir.glob("session_*.json")), reverse=True)
            if all_sessions:
                session_file = all_sessions[0]
                
    if not session_file.exists():
        raise HTTPException(status_code=404, detail="No session data found")

    try:
        with open(session_file, encoding="utf-8") as f:
            session_data = json.load(f)
            
        metrics_data = session_data.get("metrics", {})
        completed_tasks = session_data.get("completed_tasks", [])
        
        success_count = len([t for t in completed_tasks if t.get("state") == "success"])
        failed_count = len([t for t in completed_tasks if t.get("state") == "failed"])
        total_count = len(completed_tasks)
        
        start_time_ts = metrics_data.get("start_time")
        start_time_str = datetime.fromtimestamp(start_time_ts).isoformat() if start_time_ts else "unknown"
        
        end_time_ts = metrics_data.get("end_time")
        end_time_str = datetime.fromtimestamp(end_time_ts).isoformat() if end_time_ts else None
        
        duration = metrics_data.get("total_duration", 0)
        if not duration and start_time_ts and end_time_ts:
            duration = end_time_ts - start_time_ts
            
        tpm = (total_count / (duration / 60)) if duration > 0 else 0
        
        performance = PerformanceData(
            total_duration=duration,
            estimated_cost=metrics_data.get("estimated_cost", 0.0),
            tasks_per_minute=tpm,
            success_rate=(success_count / total_count) if total_count > 0 else 0,
            total_tasks=total_count,
            successful_tasks=success_count,
            failed_tasks=failed_count
        )
        
        skip_reason_counts = _aggregate_skip_reason_counts(session_data)
        skip_reason_unknown_counts = _aggregate_skip_reason_unknown_counts(session_data)
        low_ssrf_score_breakdown = _aggregate_low_ssrf_score_breakdown(session_data)
        unknown_alert = _calculate_unknown_skip_reason_alert(skip_reason_counts, skip_reason_unknown_counts)
        return SessionMetrics(
            project_name=project_name,
            session_id=Path(session_file).stem,
            start_time=start_time_str,
            end_time=end_time_str,
            performance=performance,
            phase_breakdown=metrics_data.get("phase_durations", {}),
            token_usage=metrics_data.get("token_usage", {}),
            skip_reason_counts=skip_reason_counts,
            skip_reason_unknown_counts=skip_reason_unknown_counts,
            low_ssrf_score_breakdown=low_ssrf_score_breakdown,
            skip_reason_other_ratio=_calculate_skip_reason_other_ratio(skip_reason_counts),
            low_ssrf_top_missing_feature=_extract_low_ssrf_top_missing_feature(low_ssrf_score_breakdown),
            skip_reason_unknown_alert=unknown_alert,
            skip_reason_timeline=_aggregate_skip_reason_timeline(session_data),
        )
        
    except Exception as e:
        logger.error("Error loading metrics for %s: %s", project_name, e)
        raise HTTPException(status_code=500, detail=str(e))
    
    # 発見数ボーナス（最大2.0点）
    findings_bonus = min(findings_count * 0.1, 2.0)
    
    # 総合スコア
    total_score = min(cvss_avg + findings_bonus, 10.0)
    
    # 推奨事項生成
    recommendations = []
    if severity_counts["critical"] > 0:
        recommendations.append(f"🔴 Critical脆弱性が{severity_counts['critical']}件あります。最優先で修正してください。")
    if severity_counts["high"] > 0:
        recommendations.append(f"🟠 High脆弱性が{severity_counts['high']}件あります。早急な対応が必要です。")
    if total_score >= 7.0:
        recommendations.append("⚠️ 総合スコアが高いため、包括的なセキュリティレビューを推奨します。")
    
    if not recommendations:
        recommendations.append("✅ 重大な脆弱性は検出されませんでしたが、定期的なスキャンを推奨します。")
    
    return VulnerabilityScore(
        total_score=round(total_score, 2),
        cvss_avg=round(cvss_avg, 2),
        findings_count=findings_count,
        severity_breakdown=severity_counts,
        recommendations=recommendations,
    )


@app.get("/api/projects/{project_name}/info", response_model=TargetInfo)
def get_target_info(project_name: str):
    """
    ターゲット環境情報を取得
    
    Args:
        project_name: プロジェクト名
    
    Returns:
        ターゲット環境情報
    """
    pm = ProjectManager(project_name)
    config = pm.load_meta()
    
    if not config:
        raise HTTPException(status_code=404, detail="Project not found")
    
    # Neo4jから技術スタック情報を取得
    try:
        # Note: パスワードは環境変数管理推奨だが、現状のDocker設定に合わせて指定
        kg = KnowledgeGraph(password="shigoku2024")
        tech_data = kg.get_tech_stack(config.target_url)
        kg.close()
        
        if tech_data:
            tech_stack = [f"{t['name']} ({t['category']})" for t in tech_data]
        else:
            tech_stack = ["検出なし"]
    except Exception:
        tech_stack = ["取得エラー"]

    return TargetInfo(
        target_url=config.target_url,
        ip_addresses=[],
        domains=[],
        tech_stack=tech_stack,
        detected_services=[],
        fingerprint_metadata={},
    )


@app.get("/api/projects/{project_name}/hunting-log", response_model=List[HuntingLogEntry])
def get_hunting_log(
    project_name: str,
    limit: int = Query(100, ge=1, le=1000),
):
    """
    ハンティングログを取得
    
    Args:
        project_name: プロジェクト名
        limit: 取得件数上限
    
    Returns:
        ハンティングログエントリのリスト
    """
    import json
    
    pm = ProjectManager(project_name)
    hunting_log_dir = pm.project_dir / "hunting_log"
    
    if not hunting_log_dir.exists():
        return []
    
    entries = []
    for log_file in sorted(hunting_log_dir.glob("*.json"), reverse=True):
        try:
            with open(log_file, encoding="utf-8") as f:
                data = json.load(f)
            
            for entry_data in data:
                if len(entries) >= limit:
                    break
                entries.append(HuntingLogEntry(**entry_data))
            
            if len(entries) >= limit:
                break
        except (json.JSONDecodeError, OSError) as e:
            logger.error("Error loading log %s: %s", log_file, e)
    
    return entries[:limit]


@app.websocket("/api/ws/logs")
async def websocket_logs(websocket: WebSocket):
    """EventBusのログイベントをリアルタイムに送信するWebSocketエンドポイント"""
    await websocket.accept()
    
    queue = asyncio.Queue()
    
    async def log_handler(event: Event):
        await queue.put(event)
        
    event_bus = get_event_bus()
    event_bus.subscribe(EventType.LOG_MESSAGE, log_handler)
    
    try:
        while True:
            # クライアントからの切断を検知するためのダミータスク
            # recv()が例外を吐けばクライアントがいなくなったことがわかる
            receive_task = asyncio.create_task(websocket.receive_text())
            # キューからの取得
            queue_task = asyncio.create_task(queue.get())
            
            done, pending = await asyncio.wait(
                [receive_task, queue_task], 
                return_when=asyncio.FIRST_COMPLETED
            )
            
            if receive_task in done:
                # クライアントからメッセージを受信した（あるいは切断された）
                # 特にこのユースケースでは受信するものは無いので無視するか、切断とみなす
                receive_task.result() # raises exception if disconnected
                queue_task.cancel()
                
            if queue_task in done:
                receive_task.cancel()
                event = queue_task.result()
                # WebSocketへ送信
                import json
                await websocket.send_text(json.dumps({
                    "timestamp": event.timestamp.isoformat(),
                    "level": event.payload.get("level", "info"),
                    "message": event.payload.get("message", ""),
                    "target": event.payload.get("target", "")
                }))
                
    except WebSocketDisconnect:
        logger.info("WebSocket disconnected")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        event_bus.unsubscribe(EventType.LOG_MESSAGE, log_handler)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
