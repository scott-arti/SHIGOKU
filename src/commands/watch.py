"""
Sentinel Watch Mode Command
"""
import logging
import time
from datetime import datetime
from src.commands import print_header, print_step, print_finding
from src.core.notifications.finding_notification_router import FindingNotificationRouter

logger = logging.getLogger(__name__)


def _secret_finding_to_dict(finding, repo: str) -> dict:
    """
    Convert a CommitWatcher SecretFinding to a safe dict for router normalization.
    
    CRITICAL: Never include raw matched_value or context in notification fields.
    Secret values only go to local report files (reporter.save_report).
    Notification gets only pattern_name + file location.
    """
    vuln_type = finding.vuln_type.value if hasattr(finding.vuln_type, 'value') else str(finding.vuln_type)
    severity = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
    location = f"{repo}/{finding.file_path}#L{finding.line_number}"
    
    return {
        "title": f"{finding.pattern_name} を検出: {finding.file_path}:{finding.line_number}",
        "vuln_type": vuln_type,
        "type": vuln_type,
        "severity": severity,
        "target_url": location,
        "target": location,
        "description": (
            f"{finding.file_path}:{finding.line_number} のコミット {finding.commit_sha[:7]} で "
            f"{finding.pattern_name} を検出しました。"
            f"詳細はローカルレポートを参照してください。"
        ),
        "source_agent": "commit_watcher",
        "confidence": 0.85,
        "evidence_summary": (
            f"種別: {finding.pattern_name} / "
            f"場所: {finding.file_path}:{finding.line_number}"
        ),
    }


def run_sentinel_watch(repo: str):
    """
    Sentinel Watch Mode
    
    GitHubリポジトリを監視し、シークレット漏洩を検知。
    """
    from src.core.intel.commit_watcher import CommitWatcher
    from src.core.reports.auto_reporter import AutoReporter
    
    print_header("👁️ SENTINEL WATCH MODE")
    print_step("📦", f"Repository: {repo}")
    print_step("🔄", "Starting continuous monitoring...")
    print_step("⏹️", "Press Ctrl+C to stop")
    print()
    
    watcher = CommitWatcher()
    reporter = AutoReporter()
    
    # Initialize notification router (Phase B / SGK-2026-0297)
    finding_router = FindingNotificationRouter(run_id=f"watch-{repo}-{datetime.now().strftime('%Y%m%d-%H%M%S')}")
    
    # Track notification statistics
    total_notify_failures = 0
    total_notify_successes = 0
    consecutive_notify_failures = 0  # resets on success
    MAX_NOTIFIES_PER_CYCLE = 10  # 1巡回あたりの最大通知数
    
    seen_commits = set()
    check_interval = 60  # 60秒ごとにチェック
    cycle_count = 0
    
    try:
        while True:
            cycle_notify_attempts = 0  # reset per-cycle counter
            print(f"\r  🔍 Checking for new commits... [{datetime.now().strftime('%H:%M:%S')}]", end="", flush=True)
            
            try:
                commits = watcher.get_recent_commits(repo, limit=10)
                
                for commit in commits:
                    commit_sha = commit.get("sha", "")
                    if commit_sha in seen_commits:
                        continue
                    
                    seen_commits.add(commit_sha)
                    
                    # コミットをスキャン
                    diff = watcher.get_commit_diff(repo, commit_sha)
                    findings = watcher.scan_content(diff, source=f"{repo}@{commit_sha[:7]}")
                    
                    if findings:
                        print()
                        print_header("🚨 SECRETS DETECTED!")
                        print_step("📝", f"Commit: {commit_sha[:7]}")
                        print_step("👤", f"Author: {commit.get('author', {}).get('login', 'unknown')}")
                        
                        for finding in findings:
                            print_finding(finding)
                            report_path = reporter.save_report(finding)
                            print_step("📄", f"Report: {report_path}")
                            
                            # Notification via router (with per-cycle limit)
                            if cycle_notify_attempts < MAX_NOTIFIES_PER_CYCLE:
                                try:
                                    finding_dict = _secret_finding_to_dict(finding, repo)
                                    result = finding_router.route_and_notify(
                                        finding_dict,
                                        source_component="watch",
                                        ingress_path="run_sentinel_watch",
                                    )
                                    cycle_notify_attempts += 1
                                    if result.get("notified"):
                                        total_notify_successes += 1
                                        consecutive_notify_failures = 0  # reset on success
                                    elif result.get("error"):
                                        total_notify_failures += 1
                                        consecutive_notify_failures += 1
                                        logger.debug("Watch notification failed: %s", result["error"])
                                except Exception as e:
                                    cycle_notify_attempts += 1
                                    total_notify_failures += 1
                                    consecutive_notify_failures += 1
                                    logger.warning("Watch notification exception: %s", e)
                        
                        if cycle_notify_attempts >= MAX_NOTIFIES_PER_CYCLE:
                            logger.info(
                                "Watch cycle limit reached: %d notification attempts this cycle. "
                                "Skipping remaining findings until next cycle.",
                                cycle_notify_attempts,
                            )
                        
                        # Aggregate failure logging (consecutive failures)
                        if consecutive_notify_failures >= 3:
                            logger.warning(
                                "Watch: %d consecutive notification failures detected",
                                consecutive_notify_failures,
                            )
                        
                        print()
                
            except Exception as e:
                print(f"\r  ⚠️ Error checking commits: {e}", end="", flush=True)
            
            cycle_count += 1
            if cycle_count % 10 == 0:
                summary = finding_router.get_summary()
                logger.info(
                    "Watch cycle %d summary: total_sent=%d dedup_skipped=%d "
                    "total_notify_failures=%d consecutive_notify_failures=%d",
                    cycle_count,
                    summary.get("total_sent", 0),
                    summary.get("dedup_skipped", 0),
                    total_notify_failures,
                    consecutive_notify_failures,
                )
            time.sleep(check_interval)
            
    except KeyboardInterrupt:
        print("\n")
        print_step("⏹️", "Monitoring stopped")
