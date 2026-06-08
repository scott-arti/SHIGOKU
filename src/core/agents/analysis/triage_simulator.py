"""
Triage Simulator Agent

審査員(Triager)視点でレポートを評価し、却下リスクを予測するエージェント。
"""

from dataclasses import dataclass, field
from typing import List, Optional, Any
import logging

logger = logging.getLogger(__name__)


@dataclass
class TriageIssue:
    """トリアージ問題点"""
    category: str  # quality, duplicate, policy, poc
    message: str
    penalty: int  # 減点数
    severity: str = "medium"  # low, medium, high


@dataclass
class TriageResult:
    """トリアージシミュレーション結果"""
    score: float  # 0-100 採択予測スコア
    rejection_risk: float  # 0-1 却下確率
    issues: List[TriageIssue] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)
    estimated_bounty_modifier: float = 1.0  # 報酬予測係数
    duplicate_similarity: float = 0.0


class TriageSimulator:
    """
    トリアージシミュレータ
    
    提出前にレポートを審査員視点で評価し、改善点を提案。
    """
    
    # 品質チェック基準
    QUALITY_RULES = {
        "title_too_short": {"min_length": 20, "penalty": 10},
        "description_too_short": {"min_length": 100, "penalty": 15},
        "no_reproduction_steps": {"penalty": 20},
        "no_impact": {"penalty": 15},
        "no_evidence": {"penalty": 25},
    }
    
    # PoCチェック基準
    POC_RULES = {
        "no_poc": {"penalty": 30},
        "no_request_evidence": {"penalty": 15},
        "no_response_evidence": {"penalty": 10},
    }
    
    def __init__(self, rag=None):
        """
        Args:
            rag: KnowledgeIngester (重複検出用)
        """
        self.rag = rag
    
    def simulate(self, finding) -> TriageResult:
        """
        Findingをトリアージシミュレーション
        
        Args:
            finding: Finding オブジェクト
        
        Returns:
            TriageResult
        """
        issues: List[TriageIssue] = []
        
        # 1. 品質チェック
        issues.extend(self._check_quality(finding))
        
        # 2. PoCチェック
        issues.extend(self._check_poc(finding))
        
        # 3. 重複リスクチェック
        duplicate_sim = self._check_duplicate_risk(finding)
        if duplicate_sim > 0.8:
            issues.append(TriageIssue(
                category="duplicate",
                message="類似レポートが存在する可能性が高い (>80%)",
                penalty=40,
                severity="high"
            ))
        elif duplicate_sim > 0.6:
            issues.append(TriageIssue(
                category="duplicate",
                message="類似レポートが存在する可能性あり (60-80%)",
                penalty=20,
                severity="medium"
            ))
        
        # スコア計算
        total_penalty = sum(i.penalty for i in issues)
        score = max(0, 100 - total_penalty)
        rejection_risk = min(1.0, total_penalty / 100)
        
        # 改善提案生成
        suggestions = self._suggest_improvements(issues)
        
        return TriageResult(
            score=score,
            rejection_risk=rejection_risk,
            issues=issues,
            suggestions=suggestions,
            duplicate_similarity=duplicate_sim,
            estimated_bounty_modifier=1.0 - (rejection_risk * 0.3)
        )
    
    def to_dict(self, result: TriageResult) -> dict:
        """結果を辞書形式に変換"""
        return {
            "score": result.score,
            "rejection_risk": result.rejection_risk,
            "duplicate_similarity": result.duplicate_similarity,
            "issues": [
                {
                    "category": i.category,
                    "message": i.message,
                    "penalty": i.penalty,
                    "severity": i.severity
                }
                for i in result.issues
            ],
            "suggestions": result.suggestions,
            "estimated_bounty_modifier": result.estimated_bounty_modifier
        }

    async def run_as_tool(self, finding_data: dict | Any) -> dict:
        """
        Manager/Conductorから呼び出し可能なToolメソッド
        
        Args:
            finding_data: Findingオブジェクト、またはその辞書表現
            
        Returns:
            dict: TriageResultの辞書表現
        """
        # Findingオブジェクトの復元または適合
        finding = finding_data
        if isinstance(finding_data, dict):
            # 簡易的なオブジェクト変換 (シミュレーションに必要な属性のみ)
            # 本来は Finding(**finding_data) だが、依存関係や完全性を避けるためダミーオブジェクト等を使うか、
            # Logic側で dict.get を使うように修正するのが安全。
            # ここでは Logic側 (_check_quality, _check_poc) が getattr を使っているので、
            # SimpleNamespace等でラップする。
            from types import SimpleNamespace
            
            # Evidenceのネスト対応
            evidence_data = finding_data.get("evidence", {})
            if isinstance(evidence_data, dict):
                evidence_obj = SimpleNamespace(**evidence_data)
                finding_data["evidence"] = evidence_obj
            
            finding = SimpleNamespace(**finding_data)

        result = self.simulate(finding)
        return self.to_dict(result)

    def _check_quality(self, finding) -> List[TriageIssue]:
        """レポート品質チェック"""
        issues = []
        
        # タイトルチェック
        title = getattr(finding, 'title', '') or ''
        if len(title) < self.QUALITY_RULES["title_too_short"]["min_length"]:
            issues.append(TriageIssue(
                category="quality",
                message="タイトルが短すぎます（20文字以上推奨）",
                penalty=self.QUALITY_RULES["title_too_short"]["penalty"]
            ))
        
        # 説明チェック
        desc = getattr(finding, 'description', '') or ''
        if len(desc) < self.QUALITY_RULES["description_too_short"]["min_length"]:
            issues.append(TriageIssue(
                category="quality",
                message="説明が不十分です（100文字以上推奨）",
                penalty=self.QUALITY_RULES["description_too_short"]["penalty"]
            ))
        
        # 再現手順チェック
        steps = getattr(finding, 'reproduction_steps', None)
        if not steps:
            issues.append(TriageIssue(
                category="quality",
                message="再現手順が記載されていません",
                penalty=self.QUALITY_RULES["no_reproduction_steps"]["penalty"],
                severity="high"
            ))
        
        # 影響説明チェック
        impact = getattr(finding, 'impact', '') or ''
        if not impact or len(impact) < 20:
            issues.append(TriageIssue(
                category="quality",
                message="影響(Impact)の説明が不足しています",
                penalty=self.QUALITY_RULES["no_impact"]["penalty"]
            ))
        
        return issues
    
    def _check_poc(self, finding) -> List[TriageIssue]:
        """PoC品質チェック"""
        issues = []
        
        evidence = getattr(finding, 'evidence', None)
        
        if not evidence:
            issues.append(TriageIssue(
                category="poc",
                message="証拠(Evidence)がありません",
                penalty=self.POC_RULES["no_poc"]["penalty"],
                severity="high"
            ))
            return issues
        
        # Evidenceがオブジェクト(Dataclass)か辞書か判定
        # Phase 2 Finding model defines evidence as Evidence dataclass
        
        req = None
        res = None
        
        if hasattr(evidence, 'request_url'): # Dataclass or SimpleNamespace
            if getattr(evidence, 'request_url', '') or getattr(evidence, 'request_method', ''):
                req = True
            if getattr(evidence, 'response_status', 0) or getattr(evidence, 'response_body', ''):
                res = True
        elif isinstance(evidence, dict):
            if evidence.get('request') or evidence.get('request_url'):
                req = True
            if evidence.get('response') or evidence.get('response_status'):
                res = True
        
        if not req:
            issues.append(TriageIssue(
                category="poc",
                message="リクエスト情報がありません",
                penalty=self.POC_RULES["no_request_evidence"]["penalty"]
            ))
        
        if not res:
            issues.append(TriageIssue(
                category="poc",
                message="レスポンス情報がありません",
                penalty=self.POC_RULES["no_response_evidence"]["penalty"]
            ))
        
        return issues
    
    def _check_duplicate_risk(self, finding) -> float:
        """重複リスクチェック (RAG使用)"""
        if not self.rag:
            return 0.0
        
        try:
            title = getattr(finding, 'title', '')
            desc = getattr(finding, 'description', '')
            query = f"{title} {desc}"
            
            results = self.rag.query(query, n_results=3)
            
            if results and len(results) > 0:
                # 最も類似度の高いものを返す
                top_result = results[0]
                # ChromaDBはdistanceを返すので、類似度に変換
                distance = top_result.get('distance', 1.0)
                similarity = max(0, 1 - distance)
                return similarity
        except Exception as e:
            logger.warning("Duplicate check failed: %s", e)
        
        return 0.0
    
    def _suggest_improvements(self, issues: List[TriageIssue]) -> List[str]:
        """改善提案を生成"""
        suggestions = []
        
        for issue in issues:
            if issue.category == "quality":
                if "タイトル" in issue.message:
                    suggestions.append("タイトルに脆弱性の種類と影響範囲を含めてください（例: 'SQL Injection in /api/users leads to data disclosure'）")
                elif "説明" in issue.message:
                    suggestions.append("説明に技術的な詳細と発見経緯を含めてください")
                elif "再現手順" in issue.message:
                    suggestions.append("番号付きリストで再現手順を記載してください（例: 1. Navigate to... 2. Enter...）")
                elif "影響" in issue.message:
                    suggestions.append("ビジネスインパクト（機密データ漏洩、アカウント乗っ取り等）を明記してください")
            
            elif issue.category == "poc":
                if "証拠" in issue.message:
                    suggestions.append("curlコマンドまたはHTTPリクエスト/レスポンスを含めてください")
                elif "リクエスト" in issue.message:
                    suggestions.append("完全なHTTPリクエスト（ヘッダー含む）を記載してください")
                elif "レスポンス" in issue.message:
                    suggestions.append("脆弱性を証明するレスポンスの該当部分を引用してください")
            
            elif issue.category == "duplicate":
                suggestions.append("類似レポートを確認し、新規性がある点を明確に記載してください")
        
        return list(set(suggestions))  # 重複除去
    
    def format_report(self, result: TriageResult) -> str:
        """結果を人間可読形式でフォーマット"""
        lines = [
            "=" * 50,
            "🎯 トリアージシミュレーション結果",
            "=" * 50,
            "",
            f"📊 採択予測スコア: {result.score:.0f}/100",
            f"⚠️ 却下リスク: {result.rejection_risk:.0%}",
            f"📑 重複類似度: {result.duplicate_similarity:.0%}",
            "",
        ]
        
        if result.issues:
            lines.append("❌ 問題点:")
            for issue in result.issues:
                severity_icon = {"high": "🔴", "medium": "🟡", "low": "🟢"}.get(issue.severity, "⚪")
                lines.append(f"  {severity_icon} [{issue.category}] {issue.message} (-{issue.penalty})")
            lines.append("")
        
        if result.suggestions:
            lines.append("💡 改善提案:")
            for i, suggestion in enumerate(result.suggestions, 1):
                lines.append(f"  {i}. {suggestion}")
            lines.append("")
        
        return "\n".join(lines)


def create_triage_simulator(rag=None) -> TriageSimulator:
    """TriageSimulator作成ヘルパー"""
    return TriageSimulator(rag=rag)
