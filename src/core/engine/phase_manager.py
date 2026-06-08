"""
PhaseManager: フェーズ別エージェント分割管理

Recon→Attack→Reportのフェーズ遷移を管理し、
各フェーズの状態とマニフェストを保持する。
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class ExecutionPhase(str, Enum):
    """実行フェーズ"""
    INIT = "init"           # 初期化
    RECON = "recon"         # 偵察フェーズ
    ATTACK = "attack"       # 攻撃フェーズ
    REPORT = "report"       # レポートフェーズ
    COMPLETE = "complete"   # 完了


@dataclass
class PhaseManifest:
    """フェーズマニフェスト（引き継ぎ情報）"""
    phase: ExecutionPhase
    started_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None
    
    # フェーズ固有のデータ
    discovered_assets: list[str] = field(default_factory=list)
    tech_stack: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)  # Finding IDs
    attack_surface: dict = field(default_factory=dict)
    
    # メトリクス
    tasks_completed: int = 0
    tasks_failed: int = 0
    
    @property
    def duration_seconds(self) -> float:
        """フェーズの所要時間"""
        end_time = self.completed_at or time.time()
        return end_time - self.started_at

    def to_dict(self) -> dict:
        """辞書形式に変換"""
        return {
            "phase": self.phase.value,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_seconds": self.duration_seconds,
            "discovered_assets": self.discovered_assets,
            "tech_stack": self.tech_stack,
            "findings": self.findings,
            "attack_surface": self.attack_surface,
            "tasks_completed": self.tasks_completed,
            "tasks_failed": self.tasks_failed,
        }


@dataclass
class PhaseTransition:
    """フェーズ遷移条件"""
    from_phase: ExecutionPhase
    to_phase: ExecutionPhase
    condition: str  # 条件の説明
    auto_transition: bool = True  # 自動遷移するか


class PhaseManager:
    """
    フェーズ管理
    
    フェーズ遷移ルール:
    - INIT → RECON: 常に許可
    - RECON → ATTACK: アセット発見済み
    - ATTACK → REPORT: 攻撃完了 or Findings発見
    - REPORT → COMPLETE: レポート生成完了
    
    使用例:
        manager = PhaseManager()
        
        # フェーズ開始
        manager.start_phase(ExecutionPhase.RECON)
        
        # アセット追加
        manager.add_discovered_asset("api.example.com")
        
        # フェーズ完了と遷移
        manager.complete_current_phase()
        manager.transition_to(ExecutionPhase.ATTACK)
    """

    # 許可される遷移
    ALLOWED_TRANSITIONS = {
        ExecutionPhase.INIT: [ExecutionPhase.RECON],
        ExecutionPhase.RECON: [ExecutionPhase.ATTACK, ExecutionPhase.REPORT],
        ExecutionPhase.ATTACK: [ExecutionPhase.REPORT, ExecutionPhase.RECON],  # 追加偵察の可能性
        ExecutionPhase.REPORT: [ExecutionPhase.COMPLETE, ExecutionPhase.ATTACK],  # 追加攻撃の可能性
        ExecutionPhase.COMPLETE: [],
    }

    def __init__(self):
        self._current_phase = ExecutionPhase.INIT
        self._manifests: dict[ExecutionPhase, PhaseManifest] = {}
        self._transition_history: list[tuple[ExecutionPhase, ExecutionPhase, float]] = []

    @property
    def current_phase(self) -> ExecutionPhase:
        """現在のフェーズ"""
        return self._current_phase

    @property
    def current_manifest(self) -> Optional[PhaseManifest]:
        """現在のフェーズのマニフェスト"""
        return self._manifests.get(self._current_phase)

    def start_phase(self, phase: ExecutionPhase) -> PhaseManifest:
        """
        新しいフェーズを開始
        
        Args:
            phase: 開始するフェーズ
            
        Returns:
            新しいPhaseManifest
        """
        # 遷移チェック
        if phase not in self.ALLOWED_TRANSITIONS.get(self._current_phase, []):
            if self._current_phase != ExecutionPhase.INIT or phase != ExecutionPhase.RECON:
                logger.warning(
                    "Invalid phase transition: %s -> %s",
                    self._current_phase.value,
                    phase.value
                )

        # 現在のフェーズを完了
        if self._current_phase in self._manifests:
            self._manifests[self._current_phase].completed_at = time.time()

        # 新しいマニフェスト作成
        manifest = PhaseManifest(phase=phase)
        self._manifests[phase] = manifest
        
        # 前フェーズからのデータ引き継ぎ
        self._inherit_from_previous(phase)

        self._transition_history.append((self._current_phase, phase, time.time()))
        self._current_phase = phase
        
        logger.info("Phase started: %s", phase.value)
        return manifest

    def _inherit_from_previous(self, new_phase: ExecutionPhase) -> None:
        """前フェーズからデータを引き継ぐ"""
        # RECONからの引き継ぎ
        if new_phase == ExecutionPhase.ATTACK:
            recon_manifest = self._manifests.get(ExecutionPhase.RECON)
            if recon_manifest:
                current = self._manifests[new_phase]
                current.discovered_assets = recon_manifest.discovered_assets.copy()
                current.tech_stack = recon_manifest.tech_stack.copy()
                current.attack_surface = recon_manifest.attack_surface.copy()

        # ATTACKからの引き継ぎ
        elif new_phase == ExecutionPhase.REPORT:
            attack_manifest = self._manifests.get(ExecutionPhase.ATTACK)
            if attack_manifest:
                current = self._manifests[new_phase]
                current.findings = attack_manifest.findings.copy()
                current.discovered_assets = attack_manifest.discovered_assets.copy()

    def complete_current_phase(self) -> PhaseManifest:
        """現在のフェーズを完了"""
        if self._current_phase in self._manifests:
            self._manifests[self._current_phase].completed_at = time.time()
            logger.info(
                "Phase completed: %s (duration: %.2fs)",
                self._current_phase.value,
                self._manifests[self._current_phase].duration_seconds
            )
        return self._manifests.get(self._current_phase, PhaseManifest(phase=self._current_phase))

    def transition_to(self, phase: ExecutionPhase) -> bool:
        """
        指定フェーズに遷移
        
        Args:
            phase: 遷移先フェーズ
            
        Returns:
            遷移成功ならTrue
        """
        allowed = self.ALLOWED_TRANSITIONS.get(self._current_phase, [])
        if phase not in allowed:
            logger.error(
                "Cannot transition from %s to %s. Allowed: %s",
                self._current_phase.value,
                phase.value,
                [p.value for p in allowed]
            )
            return False

        self.start_phase(phase)
        return True

    def can_transition_to(self, phase: ExecutionPhase) -> tuple[bool, str]:
        """
        遷移可能かチェック
        
        Returns:
            (可能か, 理由)
        """
        allowed = self.ALLOWED_TRANSITIONS.get(self._current_phase, [])
        
        if phase not in allowed:
            return False, f"Not allowed from {self._current_phase.value}"

        # 条件チェック
        if phase == ExecutionPhase.ATTACK:
            manifest = self._manifests.get(ExecutionPhase.RECON)
            if not manifest or not manifest.discovered_assets:
                return False, "No assets discovered in RECON phase"

        return True, "OK"

    def add_discovered_asset(self, asset: str) -> None:
        """発見したアセットを追加"""
        if self.current_manifest:
            if asset not in self.current_manifest.discovered_assets:
                self.current_manifest.discovered_assets.append(asset)

    def add_tech_stack(self, tech: str) -> None:
        """技術スタックを追加"""
        if self.current_manifest:
            if tech not in self.current_manifest.tech_stack:
                self.current_manifest.tech_stack.append(tech)

    def add_finding(self, finding_id: str) -> None:
        """Findingを追加"""
        if self.current_manifest:
            if finding_id not in self.current_manifest.findings:
                self.current_manifest.findings.append(finding_id)

    def update_attack_surface(self, key: str, value: any) -> None:
        """攻撃対象情報を更新"""
        if self.current_manifest:
            self.current_manifest.attack_surface[key] = value

    def increment_tasks(self, success: bool) -> None:
        """タスク完了数を更新"""
        if self.current_manifest:
            if success:
                self.current_manifest.tasks_completed += 1
            else:
                self.current_manifest.tasks_failed += 1

    def get_manifest(self, phase: ExecutionPhase) -> Optional[PhaseManifest]:
        """特定フェーズのマニフェストを取得"""
        return self._manifests.get(phase)

    def get_all_manifests(self) -> dict[str, dict]:
        """全マニフェストを取得"""
        return {
            phase.value: manifest.to_dict()
            for phase, manifest in self._manifests.items()
        }

    def get_summary(self) -> dict:
        """実行サマリーを取得"""
        total_assets = set()
        total_findings = set()
        total_tasks = 0
        total_failed = 0

        for manifest in self._manifests.values():
            total_assets.update(manifest.discovered_assets)
            total_findings.update(manifest.findings)
            total_tasks += manifest.tasks_completed
            total_failed += manifest.tasks_failed

        return {
            "current_phase": self._current_phase.value,
            "total_assets": len(total_assets),
            "total_findings": len(total_findings),
            "tasks_completed": total_tasks,
            "tasks_failed": total_failed,
            "phases_completed": [
                p.value for p, m in self._manifests.items() if m.completed_at
            ],
        }

    def reset(self) -> None:
        """状態をリセット"""
        self._current_phase = ExecutionPhase.INIT
        self._manifests.clear()
        self._transition_history.clear()
        logger.info("PhaseManager reset")


# シングルトンインスタンス
_manager_instance: Optional[PhaseManager] = None


def get_phase_manager() -> PhaseManager:
    """PhaseManagerのシングルトンインスタンスを取得"""
    global _manager_instance
    if _manager_instance is None:
        _manager_instance = PhaseManager()
    return _manager_instance
