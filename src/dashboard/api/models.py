"""
Dashboard API Models

Pydanticモデルを定義し、APIのリクエスト/レスポンス型を明確化
"""

from typing import List, Optional
from pydantic import BaseModel, Field


class ProjectInfo(BaseModel):
    """プロジェクト情報"""
    project_name: str
    target_url: str
    program_name: str = ""
    description: str = ""
    created_at: str
    last_scan_at: str = ""
    tags: List[str] = Field(default_factory=list)
    total_findings: int = 0


class FindingResponse(BaseModel):
    """Finding APIレスポンス"""
    id: str
    vuln_type: str
    severity: str
    title: str
    description: str
    target_url: str
    discovered_at: str
    source_agent: str
    confidence: float
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    
    class Config:
        from_attributes = True


class VulnerabilityScore(BaseModel):
    """脆弱度スコア"""
    total_score: float = Field(..., ge=0.0, le=10.0, description="総合スコア (0-10)")
    cvss_avg: float = Field(..., description="CVSS平均スコア")
    findings_count: int = Field(..., description="発見数")
    severity_breakdown: dict = Field(default_factory=dict, description="深刻度別内訳")
    recommendations: List[str] = Field(default_factory=list, description="改善推奨")


class TargetInfo(BaseModel):
    """ターゲット環境情報"""
    target_url: str
    ip_addresses: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    tech_stack: List[str] = Field(default_factory=list, description="検出された技術スタック")
    detected_services: List[str] = Field(default_factory=list)
    fingerprint_metadata: dict = Field(default_factory=dict)


class HuntingLogEntry(BaseModel):
    """ハンティングログエントリ"""
    timestamp: str
    phase: str
    content: str
    reasoning: str = ""
    confidence: float = 0.0
    agent_name: str = ""
    target_url: str = ""
    evidence_paths: List[str] = Field(default_factory=list)


class PerformanceData(BaseModel):
    """パフォーマンスメトリクス"""
    total_duration: float
    estimated_cost: float
    tasks_per_minute: float = 0.0
    success_rate: float
    total_tasks: int
    successful_tasks: int
    failed_tasks: int


class SessionMetrics(BaseModel):
    """セッション横断メトリクス"""
    project_name: str
    session_id: str
    start_time: str
    end_time: Optional[str] = None
    performance: PerformanceData
    phase_breakdown: dict = Field(default_factory=dict) # Phase -> seconds
    token_usage: dict = Field(default_factory=dict)
    skip_reason_counts: dict = Field(default_factory=dict)
    skip_reason_unknown_counts: dict = Field(default_factory=dict)
    low_ssrf_score_breakdown: dict = Field(default_factory=dict)
    skip_reason_other_ratio: float = 0.0
    low_ssrf_top_missing_feature: str = ""
    skip_reason_unknown_alert: dict = Field(default_factory=dict)
    skip_reason_timeline: List[dict] = Field(default_factory=list)
