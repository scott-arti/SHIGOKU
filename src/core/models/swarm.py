"""
SwarmResult: Swarm実行結果を表現するモデル

Swarm ManagerがMasterConductorへ返す結果の統一フォーマット。
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

from src.core.models.finding import Finding


@dataclass
class SwarmResult:
    """
    Swarm実行結果
    
    Swarm Managerが全Specialist実行後にMCへ返す。
    """
    # 発見した脆弱性リスト
    findings: List[Finding] = field(default_factory=list)
    
    # 実行ステータス
    status: str = "success"  # "success", "partial_success", "failed"
    
    # 実行ログ（各Specialistの結果）
    execution_log: List[dict] = field(default_factory=list)
    
    # メタデータ
    swarm_name: str = ""
    total_specialists: int = 0
    successful_specialists: int = 0
    failed_specialists: int = 0
    execution_time_seconds: float = 0.0
    
    # タグ情報 (tag flow consistency)
    input_tags: List[str] = field(default_factory=list)  # 入力時のタグ
    output_tags: List[str] = field(default_factory=list)  # 出力時の推奨タグ (次タスク用)

    # Phase 8 Step 2: Shadow parallel decisions (recording only, no execution change)
    shadow_decisions: List[dict] = field(default_factory=list)
    
    def add_finding(self, finding: Finding) -> None:
        """Findingを追加"""
        self.findings.append(finding)
    
    def add_log(self, specialist: str, status: str, error: str = "") -> None:
        """実行ログを追加"""
        self.execution_log.append({
            "specialist": specialist,
            "status": status,
            "error": error,
        })
        if status == "success":
            self.successful_specialists += 1
        else:
            self.failed_specialists += 1
    
    def to_dict(self) -> dict:
        """辞書形式で出力"""
        return {
            "swarm_name": self.swarm_name,
            "status": self.status,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "execution_log": self.execution_log,
            "total_specialists": self.total_specialists,
            "successful_specialists": self.successful_specialists,
            "failed_specialists": self.failed_specialists,
            "execution_time_seconds": self.execution_time_seconds,
            "input_tags": self.input_tags,
            "output_tags": self.output_tags,
            # Phase 8 Step 2: replay artifact / deterministic replay
            "shadow_decisions": list(self.shadow_decisions),
        }
    
    def has_critical_findings(self) -> bool:
        """Critical/High の Finding があるか"""
        from src.core.models.finding import Severity
        return any(
            f.severity in [Severity.CRITICAL, Severity.HIGH]
            for f in self.findings
        )


@dataclass
class PerUrlSubResult:
    """Phase 8 Step 4: Per-URL sub-result for Injection URL worker isolation.

    Each URL worker returns this instead of directly mutating shared
    current_context. Post-join deterministic merge assembles final result.

    LB-5 constraint: worker は findings, url_result, tested_params,
    request_fingerprint, payload_fingerprint, error, budget_decision を返し、
    共有 current_context へ直接 append しない。
    """
    source_url: str = ""
    origin_key: str = ""

    # Results
    findings: List[Finding] = field(default_factory=list)
    url_result: Dict[str, Any] = field(default_factory=dict)
    tested_params: List[str] = field(default_factory=list)

    # Fingerprints for deterministic replay
    request_fingerprint: str = ""
    payload_fingerprint: str = ""

    # Error tracking
    error: Optional[str] = None

    # Budget decision (was this URL executed, skipped, or rejected?)
    budget_decision: Dict[str, Any] = field(default_factory=dict)

    # Status
    status: str = "pending"  # "success", "skipped", "rejected", "failed"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_url": self.source_url,
            "origin_key": self.origin_key,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "url_result": self.url_result,
            "tested_params": self.tested_params,
            "request_fingerprint": self.request_fingerprint,
            "payload_fingerprint": self.payload_fingerprint,
            "error": self.error,
            "budget_decision": self.budget_decision,
            "status": self.status,
        }

    @property
    def is_success(self) -> bool:
        return self.status == "success"

    @property
    def is_skipped_or_rejected(self) -> bool:
        return self.status in ("skipped", "rejected")
