"""
CriticalPathAnalyzer - 重要発見時の自動優先度調整

脆弱性スキャン中に「決定的な手がかり」（Admin Panel, JWT, API Keyなど）を発見した場合、
それに関連する攻撃タスクの優先度を動的かつ大幅に引き上げ、攻撃の効率を最大化する戦略モジュール。
"""

import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class CriticalAction:
    """分析結果としてのアクション"""
    action_type: str  # "boost_priority", "add_task", "notify"
    target_filter: Dict[str, Any]      # タスク検索フィルタ (例: {"tags": ["auth"]})
    params: Dict[str, Any]             # アクション用パラメータ (例: {"priority": 999})
    reason: str                        # 理由説明


class CriticalPathAnalyzer:
    """
    Findingの内容を分析し、クリティカルパス（重要攻撃ルート）を特定する。
    """
    
    # トリガールール定義
    # keyword: partial match in target_url or evidence
    # boost_tags: boosting target tags
    # score: new priority score
    CRITICAL_TRIGGERS = [
        # Admin Panel: 最優先攻略対象
        {
            "keyword": "admin",
            "boost_tags": ["auth", "fuzz", "admin_bypass"],
            "score": 999,
            "reason": "Admin Panel Discovered"
        },
        # Login Page: 認証試行を優先
        {
            "keyword": "login",
            "boost_tags": ["auth", "bruteforce"],
            "score": 800,
            "reason": "Login Page Discovered"
        },
        # JWT Token: トークン攻撃へ移行
        {
            "keyword": "jwt",
            "boost_tags": ["jwt_attack", "auth_escalation"],
            "score": 950,
            "reason": "JWT Token Leakage Detected"
        },
        # API Key: キーの権限確認へ
        {
            "keyword": "api_key",
            "boost_tags": ["api_abuse"],
            "score": 900,
            "reason": "API Key Discovered"
        },
        # Upload Form: RCE狙い
        {
            "keyword": "upload",
            "boost_tags": ["file_upload", "rce"],
            "score": 850,
            "reason": "File Upload Feature Detected"
        },
        # Debug/Actuator: 情報漏洩・RCE
        {
            "keyword": "actuator",
            "boost_tags": ["info_leak", "rce_probe"],
            "score": 900,
            "reason": "Spring Actuator Detected"
        },
        {
            "keyword": "debug",
            "boost_tags": ["info_leak", "debug_probe"],
            "score": 850,
            "reason": "Debug Endpoint Discovered"
        },
    ]

    def analyze(self, finding: Any) -> List[CriticalAction]:
        """
        Finding（辞書形式またはFindingオブジェクト）を分析し、必要なアクションのリストを返す。
        
        Args:
            finding: Finding情報の辞書またはFindingオブジェクト
            
        Returns:
            List[CriticalAction]: 推奨アクションリスト
        """
        # オブジェクトの場合は辞書に変換
        if hasattr(finding, 'to_dict') and callable(finding.to_dict):
            finding = finding.to_dict()
        elif not isinstance(finding, dict):
            logger.warning("CriticalPathAnalyzer.analyze received unexpected type: %s", type(finding))
            return []

        actions: List[CriticalAction] = []
        
        # ターゲットURLと証拠(evidence)をテキストとして評価
        target = str(finding.get("target", "")).lower()
        evidence = str(finding.get("evidence", "")).lower()
        finding_type = str(finding.get("type", "")).lower()
        
        # 1. キーワードベースのトリガーチェック
        for trigger in self.CRITICAL_TRIGGERS:
            keyword = trigger["keyword"]
            
            # URL, Evidence, Type いずれかにキーワードが含まれるか
            if (keyword in target) or (keyword in evidence) or (keyword in finding_type):
                
                # Boost Priority Action
                action = CriticalAction(
                    action_type="boost_priority",
                    target_filter={"tags": trigger["boost_tags"]},
                    params={"priority": trigger["score"]},
                    reason=f"{trigger['reason']} (match: '{keyword}')"
                )
                actions.append(action)
                
                logger.info(
                    "Critical Path Identified: %s -> Boost %s to %d",
                    action.reason, trigger["boost_tags"], trigger["score"]
                )
        
        # 2. その他の特殊ロジック（必要に応じて追加）
        # 例: Critical Severity ならば即時通知
        severity = str(finding.get("severity", "")).lower()
        if severity in ["critical", "high"]:
            actions.append(CriticalAction(
                action_type="notify",
                target_filter={},
                params={"level": "urgent"},
                reason=f"High Severity Finding: {finding_type}"
            ))

        return actions
