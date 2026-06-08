"""
CommitWatcher: GitHubコミット監視とシークレット検出

リポジトリの新規コミットを監視し、シークレット漏洩や
危険な設定変更を検出する。攻撃のトリガーとなる情報を提供。
"""

import re
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from pathlib import Path

from src.core.models.finding import Finding, Evidence, Severity, VulnType


@dataclass
class SecretPattern:
    """シークレット検出パターン"""
    name: str
    pattern: str
    severity: Severity
    vuln_type: VulnType
    description: str
    compiled: re.Pattern = field(init=False, repr=False)
    
    def __post_init__(self):
        self.compiled = re.compile(self.pattern, re.IGNORECASE | re.MULTILINE)


@dataclass
class CommitInfo:
    """コミット情報"""
    sha: str
    message: str
    author: str
    date: datetime
    files_changed: list[str] = field(default_factory=list)
    url: str = ""


@dataclass
class SecretFinding:
    """検出されたシークレット"""
    pattern_name: str
    matched_value: str
    file_path: str
    line_number: int
    commit_sha: str
    context: str  # 前後の行を含むコンテキスト
    severity: Severity
    vuln_type: VulnType


class CommitWatcher:
    """
    GitHubリポジトリのコミットを監視し、シークレット漏洩を検出。
    
    機能:
    1. GitHub APIでコミット履歴を取得
    2. 変更ファイルをスキャン
    3. シークレットパターンマッチング
    4. Findingオブジェクトを生成
    """
    
    # シークレット検出パターン
    SECRET_PATTERNS: list[SecretPattern] = [
        # JWT関連（優先度高）
        SecretPattern(
            name="JWT Secret",
            pattern=r"(?:jwt[_-]?secret|jwt[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9+/=_-]{16,})['\"]?",
            severity=Severity.CRITICAL,
            vuln_type=VulnType.SECRET_LEAK,
            description="JWT signing secret exposed",
        ),
        SecretPattern(
            name="JWT Private Key",
            pattern=r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
            severity=Severity.CRITICAL,
            vuln_type=VulnType.SECRET_LEAK,
            description="Private key for JWT signing exposed",
        ),
        
        # API Keys
        SecretPattern(
            name="Generic API Key",
            pattern=r"(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['\"]?([A-Za-z0-9_-]{20,})['\"]?",
            severity=Severity.HIGH,
            vuln_type=VulnType.API_KEY_EXPOSURE,
            description="API key exposed in code",
        ),
        SecretPattern(
            name="AWS Access Key",
            pattern=r"AKIA[0-9A-Z]{16}",
            severity=Severity.CRITICAL,
            vuln_type=VulnType.SECRET_LEAK,
            description="AWS Access Key ID exposed",
        ),
        SecretPattern(
            name="AWS Secret Key",
            pattern=r"(?:aws[_-]?secret|secret[_-]?access[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9+/=]{40})['\"]?",
            severity=Severity.CRITICAL,
            vuln_type=VulnType.SECRET_LEAK,
            description="AWS Secret Access Key exposed",
        ),
        SecretPattern(
            name="GitHub Token",
            pattern=r"gh[pousr]_[A-Za-z0-9_]{36,}",
            severity=Severity.HIGH,
            vuln_type=VulnType.SECRET_LEAK,
            description="GitHub Personal Access Token exposed",
        ),
        
        # Database
        SecretPattern(
            name="Database Connection String",
            pattern=r"(?:mongodb|postgres|mysql|redis)://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+",
            severity=Severity.CRITICAL,
            vuln_type=VulnType.SECRET_LEAK,
            description="Database connection string with credentials exposed",
        ),
        SecretPattern(
            name="Database Password",
            pattern=r"(?:db[_-]?pass(?:word)?|database[_-]?password)\s*[:=]\s*['\"]?([^\s'\"]{8,})['\"]?",
            severity=Severity.HIGH,
            vuln_type=VulnType.SECRET_LEAK,
            description="Database password exposed",
        ),
        
        # OAuth
        SecretPattern(
            name="OAuth Client Secret",
            pattern=r"(?:client[_-]?secret|oauth[_-]?secret)\s*[:=]\s*['\"]?([A-Za-z0-9_-]{20,})['\"]?",
            severity=Severity.HIGH,
            vuln_type=VulnType.SECRET_LEAK,
            description="OAuth client secret exposed",
        ),
        
        # Encryption
        SecretPattern(
            name="Encryption Key",
            pattern=r"(?:encryption[_-]?key|secret[_-]?key|aes[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9+/=]{16,})['\"]?",
            severity=Severity.CRITICAL,
            vuln_type=VulnType.SECRET_LEAK,
            description="Encryption key exposed",
        ),
        
        # Dangerous Config
        SecretPattern(
            name="Debug Mode Enabled",
            pattern=r"(?:debug|dev[_-]?mode)\s*[:=]\s*(?:true|1|yes|on)",
            severity=Severity.MEDIUM,
            vuln_type=VulnType.DEBUG_ENABLED,
            description="Debug mode enabled in configuration",
        ),
    ]
    
    def __init__(self, github_token: Optional[str] = None):
        self.github_token = github_token or os.environ.get("GITHUB_TOKEN")
        self._session = None
    
    def _get_session(self):
        """HTTPセッションを取得（遅延初期化）"""
        if self._session is None:
            import httpx
            self._session = httpx.Client()
            if self.github_token:
                self._session.headers["Authorization"] = f"token {self.github_token}"
            self._session.headers["Accept"] = "application/vnd.github.v3+json"
        return self._session
    
    def get_recent_commits(
        self,
        owner: str,
        repo: str,
        since: Optional[datetime] = None,
        limit: int = 30,
    ) -> list[CommitInfo]:
        """
        リポジトリの最近のコミットを取得
        
        Args:
            owner: リポジトリオーナー
            repo: リポジトリ名
            since: この日時以降のコミットを取得
            limit: 取得するコミット数の上限
        """
        session = self._get_session()
        url = f"https://api.github.com/repos/{owner}/{repo}/commits"
        
        params = {"per_page": min(limit, 100)}
        if since:
            params["since"] = since.isoformat()
        
        try:
            response = session.get(url, params=params, follow_redirects=True)
            response.raise_for_status()
            data = response.json()
        except Exception as e:
            print(f"Error fetching commits: {e}")
            return []
        
        commits = []
        for item in data[:limit]:
            commit_date = datetime.fromisoformat(
                item["commit"]["author"]["date"].replace("Z", "+00:00")
            )
            commits.append(CommitInfo(
                sha=item["sha"],
                message=item["commit"]["message"],
                author=item["commit"]["author"]["name"],
                date=commit_date,
                url=item["html_url"],
            ))
        
        return commits
    
    def get_commit_diff(self, owner: str, repo: str, sha: str) -> dict:
        """コミットの差分を取得"""
        session = self._get_session()
        url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
        
        try:
            response = session.get(url, follow_redirects=True)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            print(f"Error fetching commit {sha}: {e}")
            return {}
    
    def scan_content(self, content: str, file_path: str = "", commit_sha: str = "") -> list[SecretFinding]:
        """
        コンテンツをスキャンしてシークレットを検出
        
        Args:
            content: スキャン対象のテキスト
            file_path: ファイルパス（コンテキスト用）
            commit_sha: コミットSHA（コンテキスト用）
        """
        findings: list[SecretFinding] = []
        lines = content.split("\n")
        
        for pattern in self.SECRET_PATTERNS:
            for match in pattern.compiled.finditer(content):
                # マッチした行番号を特定
                start_pos = match.start()
                line_number = content[:start_pos].count("\n") + 1
                
                # コンテキスト（前後2行）を取得
                start_line = max(0, line_number - 3)
                end_line = min(len(lines), line_number + 2)
                context = "\n".join(lines[start_line:end_line])
                
                # マッチした値を取得（グループがあればそれを、なければ全体）
                matched_value = match.group(1) if match.lastindex else match.group(0)
                
                findings.append(SecretFinding(
                    pattern_name=pattern.name,
                    matched_value=matched_value[:50] + "..." if len(matched_value) > 50 else matched_value,
                    file_path=file_path,
                    line_number=line_number,
                    commit_sha=commit_sha,
                    context=context,
                    severity=pattern.severity,
                    vuln_type=pattern.vuln_type,
                ))
        
        return findings
    
    def scan_commit(self, owner: str, repo: str, sha: str) -> list[SecretFinding]:
        """コミットの変更ファイルをスキャン"""
        commit_data = self.get_commit_diff(owner, repo, sha)
        if not commit_data:
            return []
        
        findings: list[SecretFinding] = []
        
        for file_info in commit_data.get("files", []):
            # 追加・変更されたファイルのみ
            if file_info.get("status") not in ("added", "modified"):
                continue
            
            # パッチ（差分）をスキャン
            patch = file_info.get("patch", "")
            if patch:
                file_findings = self.scan_content(patch, file_info["filename"], sha)
                findings.extend(file_findings)
        
        return findings
    
    def watch_repo(
        self,
        owner: str,
        repo: str,
        since: Optional[datetime] = None,
    ) -> list[Finding]:
        """
        リポジトリを監視してFindingを生成
        
        Args:
            owner: リポジトリオーナー
            repo: リポジトリ名
            since: この日時以降のコミットをチェック
        """
        # デフォルトは24時間前
        if since is None:
            from datetime import timedelta
            since = datetime.now(timezone.utc) - timedelta(hours=24)
        
        print(f"🔍 Watching {owner}/{repo} since {since.isoformat()}")
        
        commits = self.get_recent_commits(owner, repo, since)
        print(f"   Found {len(commits)} commits")
        
        all_findings: list[Finding] = []
        
        for commit in commits:
            secret_findings = self.scan_commit(owner, repo, commit.sha)
            
            for sf in secret_findings:
                finding = Finding(
                    vuln_type=sf.vuln_type,
                    severity=sf.severity,
                    title=f"{sf.pattern_name} in {sf.file_path}",
                    description=f"Detected {sf.pattern_name} in commit {sf.commit_sha[:7]}",
                    target_url=f"https://github.com/{owner}/{repo}/commit/{sf.commit_sha}",
                    target_program=repo,
                    evidence=Evidence(
                        request_url=f"https://github.com/{owner}/{repo}/blob/{sf.commit_sha}/{sf.file_path}",
                        response_body=sf.context,
                    ),
                    reproduction_steps=[
                        f"1. Navigate to https://github.com/{owner}/{repo}/commit/{sf.commit_sha}",
                        f"2. Locate file: {sf.file_path}",
                        f"3. View line {sf.line_number}",
                        f"4. Observe the exposed {sf.pattern_name}",
                    ],
                    impact=f"Exposed {sf.pattern_name} could allow unauthorized access or privilege escalation.",
                    source_agent="commit_watcher",
                    confidence=0.9,
                    additional_info={
                        "commit_sha": sf.commit_sha,
                        "commit_message": commit.message,
                        "commit_author": commit.author,
                        "file_path": sf.file_path,
                        "line_number": sf.line_number,
                        "matched_value": sf.matched_value,
                    },
                )
                all_findings.append(finding)
        
        print(f"   Generated {len(all_findings)} findings")
        return all_findings
    
    def scan_local_file(self, file_path: str) -> list[SecretFinding]:
        """ローカルファイルをスキャン（テスト用）"""
        path = Path(file_path)
        if not path.exists():
            print(f"File not found: {file_path}")
            return []
        
        content = path.read_text(encoding="utf-8", errors="ignore")
        return self.scan_content(content, str(path))


# ===== Convenience Functions =====

_watcher_instance: Optional[CommitWatcher] = None


def get_commit_watcher() -> CommitWatcher:
    """CommitWatcherのシングルトンインスタンスを取得"""
    global _watcher_instance
    if _watcher_instance is None:
        _watcher_instance = CommitWatcher()
    return _watcher_instance
