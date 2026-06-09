"""Dispatch Service

_dispatch と agent routing の分割先候補。
scope guard / worker route / swarm fallback / recon duplicate skip /
AgentFactory fallback / recipe dispatch を含む。

注意: 本サービスは手順6/8で safety character tests を追加後に本格移行予定。
現時点では依存束ね用の構造定義のみ。
"""

from __future__ import annotations


class DispatchService:
    """タスクの agent routing / dispatch 境界。"""

    pass
