"""
PhaseGate: フェーズベースのタスク生成許可制御

フェーズは「ゲート」として機能し、タスク生成の許可条件を管理する。
- アンロック/ロック状態の管理
- フェーズごとのデータ蓄積
- タスク生成の許可判定
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
import time
import logging

logger = logging.getLogger(__name__)


class Phase(str, Enum):
    """実行フェーズ"""
    INIT = "init"
    RECON = "recon"
    ATTACK = "attack"
    REPORT = "report"


@dataclass
class PhaseData:
    """フェーズごとのデータ"""
    unlocked_at: Optional[float] = None
    discovered_assets: List[str] = field(default_factory=list)
    tech_stack: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    classified_files: Dict[str, Dict] = field(default_factory=dict)
    # P2b: 細粒度ゲート判定用フィールド
    auth_required_endpoints: List[str] = field(default_factory=list)
    public_endpoints: List[str] = field(default_factory=list)
    scope_status: str = ""  # e.g. "in_scope", "out_of_scope", "unknown"
    budget_remaining: float = 0.0
    critical_findings: List[str] = field(default_factory=list)
    import_provenance: Dict[str, Any] = field(default_factory=dict)
    gate_reasons: List[str] = field(default_factory=list)
    
    @property
    def is_unlocked(self) -> bool:
        """アンロックされているか"""
        return self.unlocked_at is not None


class PhaseGate:
    """
    フェーズゲート: タスク生成の許可条件を管理
    
    - フェーズのアンロック/ロック
    - フェーズごとのデータ蓄積
    - タスク生成の許可判定
    
    使用例:
        gate = PhaseGate()
        gate.unlock(Phase.ATTACK)
        can_create, reason = gate.can_create_task(Phase.ATTACK)
        if can_create:
            # タスク生成
    """
    
    # フェーズ → 許可されるタグのマッピング
    PHASE_TAGS: Dict[Phase, List[str]] = {
        Phase.INIT: ["all", "utils"],
        Phase.RECON: ["recon", "scope", "visual", "network"],
        Phase.ATTACK: ["attack", "auth", "exploit", "web", "network"],
        Phase.REPORT: ["report", "utils"],
    }
    
    def __init__(self):
        self._phases: Dict[Phase, PhaseData] = {
            phase: PhaseData() for phase in Phase
        }
        # INIT と RECON は最初からアンロック
        self._phases[Phase.INIT].unlocked_at = time.time()
        self._phases[Phase.RECON].unlocked_at = time.time()
        logger.debug("PhaseGate initialized. INIT and RECON unlocked.")
    
    def unlock(self, phase: Phase) -> None:
        """
        フェーズをアンロック
        
        Args:
            phase: アンロックするフェーズ
        """
        if not self._phases[phase].is_unlocked:
            self._phases[phase].unlocked_at = time.time()
            logger.info(f"Phase {phase.value} unlocked")
    
    def is_unlocked(self, phase: Phase) -> bool:
        """
        フェーズがアンロックされているか
        
        Args:
            phase: チェックするフェーズ
            
        Returns:
            アンロックされていれば True
        """
        return self._phases[phase].is_unlocked
    
    def can_create_task(self, phase: Phase, context: Optional[Dict[str, Any]] = None) -> tuple[bool, str]:
        """
        タスク生成が許可されているか（後方互換: context=None で従来の lock/unlock 判定）

        Args:
            phase: チェックするフェーズ
            context: 追加の判定context（省略時は従来のバイナリ判定）

        Returns:
            (許可されているか, 理由)
        """
        if not self.is_unlocked(phase):
            return False, f"Phase {phase.value} is locked"
        if context is None:
            return True, "OK"
        # With context, delegate to category-level helper for ATTACK phase
        if phase == Phase.ATTACK:
            category = context.get("category")
            if category:
                return self.can_create_attack_task(str(category), context.get("metadata"))
        return True, "OK"
    
    def get_allowed_tags(self, phase: Phase) -> List[str]:
        """
        フェーズで許可されているタグを取得
        
        Args:
            phase: 対象フェーズ
            
        Returns:
            許可されているタグのリスト
        """
        return self.PHASE_TAGS.get(phase, ["all"])

    def can_create_attack_task(
        self, category: str, metadata: Optional[Dict[str, Any]] = None
    ) -> tuple[bool, str]:
        """カテゴリ単位で Attack タスク生成可否を判定する。

        Args:
            category: Recon 分類カテゴリ名（例: "auth", "id_param", "admin"）
            metadata: 追加の判定情報（auth_required, scope, budget, etc.）

        Returns:
            (許可されているか, 拒否理由または "OK")
        """
        data = self._phases[Phase.ATTACK]
        metadata = metadata or {}

        # 1) scope 外チェック
        scope_status = data.scope_status or metadata.get("scope_status", "")
        if scope_status == "out_of_scope":
            reason = f"Category '{category}' is out of scope"
            data.gate_reasons.append(reason)
            return False, reason

        # 2) budget チェック（明示的に指定された場合のみ制約として適用）
        meta_budget = metadata.get("budget_remaining")
        if meta_budget is not None and meta_budget <= 0.0:
            reason = f"Budget exhausted for category '{category}' (explicit budget={meta_budget})"
            data.gate_reasons.append(reason)
            return False, reason

        # 3) auth 必須チェック（認証情報なしで auth_required endpoint をスキップ）
        is_auth_required = category in data.auth_required_endpoints or metadata.get("auth_required", False)
        has_auth = bool(metadata.get("has_auth_credentials", False))
        if is_auth_required and not has_auth:
            reason = f"Category '{category}' requires auth but no credentials available"
            data.gate_reasons.append(reason)
            return False, reason

        # 4) stale import チェック
        import_prov = data.import_provenance or metadata.get("import_provenance", {})
        if import_prov.get("all_rejected"):
            reason = f"Category '{category}' from import rejected (all artifacts stale/mismatched)"
            data.gate_reasons.append(reason)
            return False, reason
        if import_prov.get("stale_artifact"):
            reason = f"Category '{category}' from stale imported artifact"
            data.gate_reasons.append(reason)
            return False, reason

        # 5) critical finding 優先: 一旦カテゴリ自体を抑制するのではなく
        #    reason に critical_finding 有無を残して呼び出し側に判断させる
        critical = data.critical_findings or metadata.get("critical_findings", [])
        if critical:
            logger.info(
                "Category '%s': critical findings present (%s) – consider Report/HITL priority",
                category, ", ".join(critical[:3]),
            )

        return True, "OK"
    
    def add_asset(self, phase: Phase, asset: str) -> None:
        """
        アセットを追加
        
        Args:
            phase: 対象フェーズ
            asset: アセット (URL, サブドメインなど)
        """
        data = self._phases[phase]
        if asset not in data.discovered_assets:
            data.discovered_assets.append(asset)
            logger.debug(f"Added asset to {phase.value}: {asset}")
    
    def add_tech(self, phase: Phase, tech: str) -> None:
        """
        技術スタックを追加
        
        Args:
            phase: 対象フェーズ
            tech: 技術名 (例: "WordPress", "nginx")
        """
        data = self._phases[phase]
        if tech not in data.tech_stack:
            data.tech_stack.append(tech)
            logger.debug(f"Added tech to {phase.value}: {tech}")
    
    def add_finding(self, phase: Phase, finding_id: str) -> None:
        """
        Finding を追加
        
        Args:
            phase: 対象フェーズ
            finding_id: Finding の ID
        """
        data = self._phases[phase]
        if finding_id not in data.findings:
            data.findings.append(finding_id)
            logger.info(f"Added finding to {phase.value}: {finding_id}")
    
    def set_classified_files(self, phase: Phase, files: Dict[str, Dict]) -> None:
        """
        分類ファイルを設定
        
        Args:
            phase: 対象フェーズ
            files: 分類ファイルの辞書 (例: {"with_auth": {"file": "...", "count": 5}})
        """
        self._phases[phase].classified_files = files
        logger.debug(f"Set classified files for {phase.value}: {len(files)} categories")
    
    def get_phase_data(self, phase: Phase) -> PhaseData:
        """
        フェーズデータを取得
        
        Args:
            phase: 対象フェーズ
            
        Returns:
            PhaseData
        """
        return self._phases[phase]
    
    def get_all_assets(self) -> List[str]:
        """
        全フェーズのアセットを取得
        
        Returns:
            全アセットのリスト (重複排除済み)
        """
        assets = []
        for data in self._phases.values():
            assets.extend(data.discovered_assets)
        return list(set(assets))
    
    def get_all_tech_stack(self) -> List[str]:
        """
        全フェーズの技術スタックを取得
        
        Returns:
            全技術のリスト (重複排除済み)
        """
        techs = []
        for data in self._phases.values():
            techs.extend(data.tech_stack)
        return list(set(techs))
    
    def get_summary(self) -> Dict:
        """
        全フェーズのサマリーを取得（P2b: gate_reason_count を含む）
        
        Returns:
            サマリー辞書
        """
        attack_data = self._phases.get(Phase.ATTACK)
        gate_reason_count = len(attack_data.gate_reasons) if attack_data else 0
        return {
            "unlocked_phases": [p.value for p, d in self._phases.items() if d.is_unlocked],
            "total_assets": len(self.get_all_assets()),
            "total_tech_stack": len(self.get_all_tech_stack()),
            "total_findings": sum(len(d.findings) for d in self._phases.values()),
            "gate_reason_count": gate_reason_count,
            "gate_reasons": attack_data.gate_reasons[:10] if attack_data else [],
        }


# シングルトン
_gate_instance: Optional[PhaseGate] = None


def get_phase_gate() -> PhaseGate:
    """
    PhaseGate のシングルトンインスタンスを取得
    
    Returns:
        PhaseGate インスタンス
    """
    global _gate_instance
    if _gate_instance is None:
        _gate_instance = PhaseGate()
    return _gate_instance
