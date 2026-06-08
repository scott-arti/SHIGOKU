"""
Sentinel Watch Mode Command
"""
import time
from datetime import datetime
from src.commands import print_header, print_step, print_finding

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
    
    seen_commits = set()
    check_interval = 60  # 60秒ごとにチェック
    
    try:
        while True:
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
                        
                        print()
                
            except Exception as e:
                print(f"\r  ⚠️ Error checking commits: {e}", end="", flush=True)
            
            time.sleep(check_interval)
            
    except KeyboardInterrupt:
        print("\n")
        print_step("⏹️", "Monitoring stopped")
