"""Recon Execution Service

ReconPipeline 実行と PhaseGate 反映の分割先候補。

注意: 本サービスは手順7/8で ReconPipeline 実行切り出し後に本格移行予定。
現時点では依存束ね用の構造定義のみ。
"""

from __future__ import annotations


class ReconExecutionService:
    """ReconPipeline 実行境界。PhaseGate 更新完了後のみ planner を呼ぶ。"""

    pass
