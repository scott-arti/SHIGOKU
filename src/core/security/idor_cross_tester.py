"""
IDOR Cross-Tester - IDORクロステスト実行モジュール

マルチアカウントセッションを使用して、IDOR候補を確実に検証する。

検証フロー:
1. Victimセッションで対象エンドポイントにアクセスし、リソースIDを収集
2. Attackerセッションで同じリソースにアクセス
3. 成功 = IDOR確定、失敗(403/401) = 正常

Usage:
    session_manager = create_session_manager(Path("sessions.json"))
    cross_tester = IDORCrossTester(session_manager)
    results = cross_tester.run_full_test(candidates)
"""

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Any
from urllib.parse import urlparse, parse_qs

from src.core.models.finding import Evidence, Finding, Severity, VulnType
from src.core.security.ethics_guard import ActionResult, ActionType, get_ethics_guard
from src.core.security.multi_account_session import MultiAccountSessionManager
from src.intelligence.proxy_log_analyzer import FindingCandidate, SmellType

logger = logging.getLogger(__name__)


class CrossTestResult(Enum):
    """クロステスト結果"""
    IDOR_CONFIRMED = "idor_confirmed"      # 確実なIDOR
    ACCESS_DENIED = "access_denied"        # 正常にブロック（脆弱性なし）
    INCONCLUSIVE = "inconclusive"          # 判定不能（レスポンスが曖昧）
    ERROR = "error"                        # エラー発生
    NOT_CONFIGURED = "not_configured"      # セッション未設定


@dataclass
class IDORTestCandidate:
    """クロステスト対象"""
    endpoint: str                          # テスト対象エンドポイント
    id_param_type: str = "path"            # "path" or "query"
    id_param_name: str = ""                # クエリパラメータの場合のパラメータ名
    victim_id: Optional[str] = None        # VictimのリソースID
    original_candidate: Optional[FindingCandidate] = None


@dataclass
class CrossTestReport:
    """クロステスト結果レポート"""
    result: CrossTestResult
    candidate: IDORTestCandidate
    victim_response_status: int = 0
    victim_response_body: str = ""
    attacker_response_status: int = 0
    attacker_response_body: str = ""
    finding: Optional[Finding] = None
    details: dict = field(default_factory=dict)
    tested_at: str = field(default_factory=lambda: datetime.now().isoformat())


class IDORCrossTester:
    """
    IDOR クロステスト実行
    
    マルチアカウントセッションを使用して、
    「Victimのリソースに対してAttackerがアクセスできるか」を検証する。
    """
    
    # レスポンスからIDを抽出するパターン
    ID_EXTRACTION_PATTERNS = [
        r'"id"\s*:\s*(\d+)',                    # {"id": 123}
        r'"id"\s*:\s*"([^"]+)"',                # {"id": "abc-123"}
        r'"user_id"\s*:\s*(\d+)',               # {"user_id": 123}
        r'"userId"\s*:\s*(\d+)',                # {"userId": 123}
        r'"resource_id"\s*:\s*"?([^",\s]+)"?',  # {"resource_id": "xyz"}
    ]
    
    # IDOR判定のためのPIIキーワード
    PII_KEYWORDS = ["email", "name", "phone", "address", "ssn", "password", "credit"]
    
    def __init__(
        self,
        session_manager: MultiAccountSessionManager,
        program_name: str = "",
        workspace: Optional[Any] = None,
    ):
        """
        Args:
            session_manager: マルチアカウントセッションマネージャー
            program_name: レポート用プログラム名
            workspace: 共有ワークスペース（IDプール用）
        """
        self.session_manager = session_manager
        self.program_name = program_name
        self.workspace = workspace
        self._guard = get_ethics_guard()
        self._test_history: list[CrossTestReport] = []
    
    def collect_victim_resource_ids(
        self,
        endpoint: str,
        method: str = "GET",
    ) -> list[str]:
        """
        Victimセッションでエンドポイントにアクセスし、
        レスポンスからリソースIDを抽出
        
        Args:
            endpoint: アクセスするエンドポイント（例: /api/users/me/notes）
            method: HTTPメソッド
        
        Returns:
            抽出されたIDのリスト
        """
        if not self.session_manager.is_configured():
            logger.warning("Session manager not configured")
            return []
        
        # EthicsGuardチェック
        is_allowed, reason = self._guard.check_action(ActionType.HTTP_REQUEST, endpoint)
        if is_allowed != ActionResult.ALLOWED:
            logger.warning("Request blocked by EthicsGuard: %s", reason)
            return []
        
        response = self.session_manager.make_request_as("victim", method, endpoint)
        if not response:
            return []
        
        if response.status_code != 200:
            logger.debug("Victim request returned %d", response.status_code)
            return []
        
        # レスポンスからIDを抽出
        ids = []
        body = response.text
        
        for pattern in self.ID_EXTRACTION_PATTERNS:
            matches = re.findall(pattern, body)
            ids.extend(matches)
        
        # 重複除去
        unique_ids = list(dict.fromkeys(ids))
        logger.info("Collected %d resource IDs from victim session", len(unique_ids))
        
        # 共有ワークスペースのIDプールに登録
        if self.workspace and unique_ids:
            # パターン化 (e.g. /api/users/123 -> /api/users/{id})
            path = urlparse(endpoint).path
            path_pattern = re.sub(r'/\d+', '/{id}', path)
            path_pattern = re.sub(r'/[0-9a-fA-F-]{36}', '/{uuid}', path_pattern)
            
            # CrossTester での収集は「正当な所有者のID」なので
            # BugBountyモードでも承認フローを通さず登録して良いか？
            # 計画では「有効IDを使うのは人間判断」なので、ここでも stage させるのが安全
            usage_context = f"Collected via IDORCrossTester from victim session at {endpoint}"
            
            # モード判定（session_managerやconfigから取得できない場合はデフォルトBB）
            # ここでは安全側に倒して常にステージングする
            self.workspace.stage_ids_for_approval(path_pattern, unique_ids, usage_context)
        
        return unique_ids
    
    def execute_cross_test(
        self,
        candidate: IDORTestCandidate,
    ) -> CrossTestReport:
        """
        単一候補に対してクロステストを実行
        
        1. Victimセッションで正規アクセス（ベースライン取得）
        2. Attackerセッションで同じリソースにアクセス
        3. レスポンス比較でIDOR判定
        
        Args:
            candidate: テスト対象候補
        
        Returns:
            CrossTestReport
        """
        report = CrossTestReport(
            result=CrossTestResult.ERROR,
            candidate=candidate,
        )
        
        if not self.session_manager.is_configured():
            report.result = CrossTestResult.NOT_CONFIGURED
            return report
        
        # EthicsGuardチェック
        is_allowed, _ = self._guard.check_action(ActionType.HTTP_REQUEST, candidate.endpoint)
        if is_allowed != ActionResult.ALLOWED:
            report.result = CrossTestResult.ERROR
            report.details["error"] = "Blocked by EthicsGuard"
            return report
        
        # 1. Victimセッションでアクセス（ベースライン）
        victim_response = self.session_manager.make_request_as(
            "victim", "GET", candidate.endpoint
        )
        
        if not victim_response:
            report.result = CrossTestResult.ERROR
            report.details["error"] = "Victim request failed"
            return report
        
        report.victim_response_status = victim_response.status_code
        report.victim_response_body = victim_response.text[:3000]  # M-2: 3000文字に拡大
        
        # Victimがアクセスできない場合は判定不能
        if victim_response.status_code not in (200, 201):
            report.result = CrossTestResult.INCONCLUSIVE
            report.details["reason"] = f"Victim cannot access (status: {victim_response.status_code})"
            return report
        
        # 2. Attackerセッションで同じリソースにアクセス
        attacker_response = self.session_manager.make_request_as(
            "attacker", "GET", candidate.endpoint
        )
        
        if not attacker_response:
            report.result = CrossTestResult.ERROR
            report.details["error"] = "Attacker request failed"
            return report
        
        report.attacker_response_status = attacker_response.status_code
        report.attacker_response_body = attacker_response.text[:3000]  # M-2: 3000文字に拡大
        
        # 3. IDOR判定
        report.result, report.details = self._determine_idor(
            victim_response.status_code,
            victim_response.text,
            attacker_response.status_code,
            attacker_response.text,
        )
        
        # IDORが確定した場合、Findingを生成
        if report.result == CrossTestResult.IDOR_CONFIRMED:
            report.finding = self._create_finding(candidate, report)
        
        self._test_history.append(report)
        return report
    
    def _determine_idor(
        self,
        _victim_status: int,
        victim_body: str,
        attacker_status: int,
        attacker_body: str,
    ) -> tuple[CrossTestResult, dict]:
        """
        レスポンス比較でIDOR判定
        
        Returns:
            (CrossTestResult, details dict)
        """
        details: dict = {}
        
        # Case 1: Attackerが401/403を受けた → 正常にブロック
        if attacker_status in (401, 403):
            return CrossTestResult.ACCESS_DENIED, {"reason": "Properly blocked"}
        
        # Case 2: Attackerが200でVictimと同じデータを取得 → IDOR確定
        if attacker_status == 200:
            # ボディの類似度を計算
            similarity = self._calculate_body_similarity(victim_body, attacker_body)
            details["body_similarity"] = f"{similarity:.1%}"
            
            # 80%以上の類似度 かつ 意味のあるデータがある場合
            if similarity > 0.8 and len(attacker_body) > 50:
                # PIIが含まれているか確認
                has_pii = any(
                    kw in attacker_body.lower() for kw in self.PII_KEYWORDS
                )
                details["contains_pii"] = has_pii
                
                return CrossTestResult.IDOR_CONFIRMED, details
            
            # 類似度が低いがデータは取得できている場合
            if len(attacker_body) > 50:
                details["reason"] = "Different data returned (partial IDOR possible)"
                return CrossTestResult.INCONCLUSIVE, details
        
        # Case 3: その他のステータスコード
        details["reason"] = f"Unexpected attacker status: {attacker_status}"
        return CrossTestResult.INCONCLUSIVE, details
    
    def _calculate_body_similarity(self, body1: str, body2: str) -> float:
        """
        2つのレスポンスボディの類似度を計算 (M-1: 改善版)
        
        SequenceMatcherとJSON正規化を使用し、
        タイムスタンプ等の動的値に影響されにくい比較を実現。
        
        Returns:
            0.0 - 1.0 の類似度
        """
        from difflib import SequenceMatcher
        import json as json_module
        
        if not body1 or not body2:
            return 0.0
        
        if body1 == body2:
            return 1.0
        
        # JSON正規化を試みる
        norm1 = self._normalize_response(body1)
        norm2 = self._normalize_response(body2)
        
        # SequenceMatcherで比較
        return SequenceMatcher(None, norm1, norm2).ratio()
    
    def _normalize_response(self, body: str) -> str:
        """
        動的値（タイムスタンプ、トークン等）を除去してJSON正規化
        
        Returns:
            正規化された文字列
        """
        import json as json_module
        
        try:
            data = json_module.loads(body)
            if isinstance(data, dict):
                # 動的値を除去
                for key in ["timestamp", "created_at", "updated_at", "token", "csrf", "nonce", "session", "_t", "time"]:
                    data.pop(key, None)
            return json_module.dumps(data, sort_keys=True)
        except json_module.JSONDecodeError:
            return body
    
    def _create_finding(
        self,
        candidate: IDORTestCandidate,
        report: CrossTestReport,
    ) -> Finding:
        """クロステスト結果からFindingを生成"""
        # ID情報を取得
        id_info = ""
        if candidate.id_param_type == "path":
            id_info = "path parameter"
        else:
            id_info = f"query parameter '{candidate.id_param_name}'"
        
        return Finding(
            vuln_type=VulnType.IDOR,
            severity=Severity.HIGH,
            title=f"IDOR: Cross-Account Access via {id_info}",
            description=(
                f"Cross-test confirmed that user 'attacker' can access resources "
                f"belonging to user 'victim' at {candidate.endpoint}. "
                f"The attacker received the same data as the victim "
                f"(similarity: {report.details.get('body_similarity', 'N/A')})."
            ),
            target_url=candidate.endpoint,
            target_program=self.program_name,
            evidence=Evidence(
                request_method="GET",
                request_url=candidate.endpoint,
                request_headers={},
                response_status=report.attacker_response_status,
                response_body=report.attacker_response_body[:500],
            ),
            reproduction_steps=[
                "1. Create two accounts: 'victim' and 'attacker'",
                f"2. As victim, access {candidate.endpoint} (baseline)",
                "3. Note the returned data",
                f"4. As attacker, access the same URL: {candidate.endpoint}",
                "5. Observe that attacker receives victim's data",
            ],
            impact=(
                "An attacker can access sensitive resources belonging to other users. "
                "This may lead to data breach, privacy violation, or further attacks."
            ),
            source_agent="idor_cross_tester",
            confidence=0.95,
            cwe_id="CWE-639",
        )
    
    def run_full_test(
        self,
        candidates: list[FindingCandidate],
    ) -> list[Finding]:
        """
        複数候補に対してクロステストを一括実行
        
        Args:
            candidates: ProxyLogAnalyzerからの候補リスト
        
        Returns:
            検出されたFindingのリスト
        """
        findings: list[Finding] = []
        
        if not self.session_manager.is_configured():
            logger.error("Session manager not configured. Cannot run cross-test.")
            return findings
        
        for candidate in candidates:
            if candidate.smell_type != SmellType.IDOR_CANDIDATE:
                continue
            
            # FindingCandidateからIDORTestCandidateに変換
            test_candidate = IDORTestCandidate(
                endpoint=candidate.target_url,
                id_param_type="path",  # デフォルトはpath
                original_candidate=candidate,
            )
            
            # クエリパラメータにIDがある場合
            parsed = urlparse(candidate.target_url)
            query_params = parse_qs(parsed.query)
            for param_name in query_params:
                if any(kw in param_name.lower() for kw in ["id", "uid", "user"]):
                    test_candidate.id_param_type = "query"
                    test_candidate.id_param_name = param_name
                    break
            
            # クロステスト実行
            report = self.execute_cross_test(test_candidate)
            
            if report.result == CrossTestResult.IDOR_CONFIRMED and report.finding:
                findings.append(report.finding)
                logger.info("IDOR confirmed: %s", candidate.target_url)
            elif report.result == CrossTestResult.ACCESS_DENIED:
                logger.info("Properly secured: %s", candidate.target_url)
            else:
                logger.debug("Inconclusive: %s (%s)", candidate.target_url, report.details)
        
        return findings
    
    def get_test_history(self) -> list[CrossTestReport]:
        """テスト履歴を取得"""
        return self._test_history.copy()
    
    def clear_history(self) -> None:
        """テスト履歴をクリア"""
        self._test_history.clear()


def create_idor_cross_tester(
    session_manager: MultiAccountSessionManager,
    program_name: str = "",
) -> IDORCrossTester:
    """IDORCrossTesterを作成"""
    return IDORCrossTester(session_manager, program_name)
