"""
IdorHunterSpecialist: API 認証・認可不備（IDOR/BOLA）の検証 Specialist
"""

import logging
import re
import uuid
import json
from typing import List, Dict, Optional, Any
from urllib.parse import urlparse, parse_qs, urlunparse, urlencode

from src.core.agents.swarm.base import Specialist, Task
from src.core.agents.swarm.logic.body_mutator import BodyMutator
from src.core.infra.network_client import AsyncNetworkClient
from src.core.models.finding import Finding, VulnType, Severity
from src.core.agents.swarm.logic.response_comparator import ResponseComparator, ComparisonInput
from src.core.session.multi_session_manager import get_multi_session_manager
from src.core.attack.openapi_tester import create_openapi_tester

logger = logging.getLogger(__name__)

class IdorHunterSpecialist(Specialist):
    """
    IDOR 検証 Specialist
    
    LogicManager から指示を受け、以下のテストを自動実行します：
    1. Unauthenticated Access (認証情報の削除)
    2. ID Manipulation (パラメータの操作)
    """
    
    name = "IdorHunterSpecialist"
    description = "Tests for IDOR and BOLA by manipulating auth context and real ID pools."
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.mode: str = self.config.get("mode", "bugbounty") # Default: safe mode for BB
    
    async def execute(self, task: Task, quick_mode: bool = False) -> List[Finding]:
        """タスクを実行"""
        findings = []
        url = task.target
        params = task.params
        
        # ワークスペースを取得（タスクから渡される可能性を考慮）
        if "workspace" in params:
            self._workspace_instance = params.get("workspace")
        self.mode = params.get("mode", self.mode).lower()
        
        method = params.get("method", "GET")
        headers = params.get("headers", {})
        body = params.get("body")
        use_proxy = params.get("use_proxy", True)
        safe_mode = params.get("safe_mode", True)
        user_approved = params.get("user_approved", False)
        
        # 人間が承認済みなら safe_mode を解除して破壊的テストを許可
        if user_approved:
            logger.info("[%s] User approved this task. Disabling safe_mode.", self.name)
            safe_mode = False
        
        # 1. 認証なしアクセステスト
        finding = await self._test_unauthenticated(url, method, headers, body, use_proxy, safe_mode)
        if finding:
            findings.append(finding)
            
        # 2. Mass Assignment テスト (POST/PUT/PATCH のみ)
        if method.upper() in ["POST", "PUT", "PATCH"]:
            mass_findings = await self._test_mass_assignment(url, method, headers, body, use_proxy, safe_mode)
            findings.extend(mass_findings)

        # 3. ID 操作テスト (実在IDプール連動)
        manipulation_findings = await self._test_id_manipulation(url, method, headers, body, use_proxy, safe_mode)
        findings.extend(manipulation_findings)
        
        # 4. クロスセッション操作テスト (BOLA/Multi-Session Matrix)
        # MultiSessionManager から代替セッションを自動取得
        msm = get_multi_session_manager()
        current_role = params.get("current_role", "default")
        alt_sessions = params.get("alternative_sessions", {})
        
        # 自動取得が有効な場合、MSM からマトリクスを構築
        auto_sessions = msm.get_all_alternative_sessions(exclude_role=current_role)
        if auto_sessions:
            logger.info("[%s] Found %d alternative sessions in MultiSessionManager", self.name, len(auto_sessions))
            alt_sessions.update(auto_sessions)

        if alt_sessions:
            cross_findings = await self._test_cross_session_access(url, method, headers, body, alt_sessions, use_proxy, safe_mode)
            findings.extend(cross_findings)

        # 5. HPP (HTTP Parameter Pollution) テスト
        hpp_findings = await self._test_hpp(url, method, headers, body, use_proxy, safe_mode)
        findings.extend(hpp_findings)

        # 6. GraphQL IDOR テスト
        graphql_endpoint = params.get("graphql_endpoint")
        if graphql_endpoint:
            gql_findings = await self._test_graphql_idor(graphql_endpoint, headers, body, use_proxy, safe_mode)
            findings.extend(gql_findings)

        return findings

    async def _test_mass_assignment(
        self, url: str, method: str, headers: Dict[str, str], body: Optional[str], use_proxy: bool = True, safe_mode: bool = True
    ) -> List[Finding]:
        """Mass Assignment (BOPLA) テストを実行"""
        if not body:
            return []
            
        if safe_mode:
            # 破壊的テストのため、safe_mode時はスキップ
            # (execute() 内で user_approved=True の場合に safe_mode は解除される)
            logger.warning("[%s] Skipping Mass Assignment test for %s (safe_mode=True)", self.name, url)
            return []

        ct = BodyMutator.detect_content_type(headers, body)
        if ct == "unknown":
            return []

        logger.info("[%s] Testing Mass Assignment for %s", self.name, url)
        
        # 1. 注入候補プロパティの選定
        # ハードコードリスト (キー: 注入する値)
        candidates = {
            "admin": True, "is_admin": True, "isAdmin": True, "role": "admin", "roles": ["admin"],
            "privilege": "root", "privileges": ["root"], "internal": True, "status": "active",
            "type": "admin", "access": "full", "permission": "all", "permissions": ["*"],
            "is_staff": True, "isStaff": True, "superuser": True, "is_verified": True, "verified": True,
            "plan": "premium", "tier": "gold", "quota": 99999, "limit": -1, "credits": 99999, "balance": 99999
        }
        
        # 文脈的な推測: URL からリソース名を抽出して ID を付与
        # e.g. /api/v1/organizations/123 -> org_id, organization_id
        path_parts = urlparse(url).path.strip("/").split("/")
        for part in path_parts:
            if part.isdigit() or len(part) > 20: continue # IDらしきものはスキップ
            base = part.rstrip("s")
            if len(base) > 2:
                candidates.update({f"{base}_id": 1, f"{base}Id": 1, f"{base}_status": "active"})

        # 動的抽出 (ベースラインGETおよびOpenAPI定義から)
        try:
            # OpenAPI 仕様がワークスペースにあればそこから特権キーを抽出
            if self.workspace and hasattr(self.workspace, "get_openapi_spec"):
                spec_data = self.workspace.get_openapi_spec()
                if spec_data:
                    tester = create_openapi_tester()
                    tester.spec = spec_data
                    tester._parse_endpoints() # エンドポイントもパースして精度向上
                    spec_candidates = tester.extract_privileged_properties()
                    if spec_candidates:
                        logger.info("[%s] Extracted %d privilege candidates from OpenAPI spec", self.name, len(spec_candidates))
                        candidates.update(spec_candidates)

            client = self.network_client or AsyncNetworkClient()
            # リソースのベースラインを取得
            get_resp = await client.request("GET", url, headers=headers, use_proxy=use_proxy)
            if get_resp.status == 200:
                baseline_data = BodyMutator.parse(get_resp.text, "json") if "application/json" in get_resp.headers.get("Content-Type", "") else {}
                current_body_data = BodyMutator.parse(body, ct)
                
                # GETにはあるがPOSTには含まれていないキーを抽出
                if isinstance(baseline_data, dict):
                    for k in baseline_data.keys():
                        if k not in current_body_data and k.lower() not in ["id", "created_at", "updated_at", "deleted_at"]:
                            # 型を推測して適当な特権値をセット
                            val = baseline_data[k]
                            if isinstance(val, bool):
                                candidates[k] = not val
                            elif isinstance(val, (int, float)):
                                candidates[k] = 999 if val == 0 else val * 2
                            elif isinstance(val, str):
                                candidates[k] = "admin"
                                if "role" in k.lower(): candidates[k] = "admin"
                                if "status" in k.lower(): candidates[k] = "active"
                
        except Exception as e:
            logger.debug("[%s] Dynamic prop extraction failed: %s", self.name, e)

        findings = []
        # 重複を排除しつつテスト実行 (多すぎる場合は制限)
        test_keys = list(candidates.keys())[:50]
        for prop_name in test_keys:
            prop_val = candidates[prop_name]
            test_body = BodyMutator.inject_properties(body, ct, {prop_name: prop_val})
            if test_body == body: continue

            try:
                client = self.network_client or AsyncNetworkClient()
                resp = await client.request(method, url, headers=headers, data=test_body, use_proxy=use_proxy)
                
                # Step 1: 応答のパースと値の確認
                if resp.status in [200, 201]:
                    # ヘッダーがなくても JSON パースを試行する
                    try:
                        resp_data = json.loads(resp.text)
                    except:
                        resp_data = BodyMutator.parse(resp.text, "json")
                        
                    # 注入した値がレスポンスに含まれているか（エコーバック）
                    if resp_data and str(resp_data.get(prop_name)) == str(prop_val):
                        # Step 2: Write-then-Read 検証 (GET で再取得)
                        get_url = url
                        if method == "POST":
                            rid = resp_data.get("id") or resp_data.get("uuid") or resp_data.get("user_id")
                            if rid:
                                if f"/{rid}" not in url:
                                    get_url = f"{url.rstrip('/')}/{rid}"
                                else:
                                    get_url = url
                        
                        logger.debug("[%s] Verifying persistence via GET %s", self.name, get_url)
                        final_check = await client.request("GET", get_url, headers=headers, use_proxy=use_proxy)
                        if final_check.status == 200:
                            final_data = BodyMutator.parse(final_check.text, "json")
                            if str(final_data.get(prop_name)) == str(prop_val):
                                findings.append(Finding(
                                    vuln_type=VulnType.IDOR,
                                    severity=Severity.HIGH,
                                    title="Mass Assignment: Privilege Escalation via Property Injection",
                                    description=f"Injected '{prop_name}': {prop_val} was successfully persisted in the resource.",
                                    evidence=f"Method: {method}\nPayload: {test_body}\nPersisted at: {get_url}",
                                    target_url=url,
                                    source_agent=self.name
                                ))
                            else:
                                # GET で確認できなかったがエコーバックはあった場合
                                findings.append(Finding(
                                    vuln_type=VulnType.IDOR,
                                    severity=Severity.LOW,
                                    title="Potential Mass Assignment (Echo Only)",
                                    description=f"Injected property '{prop_name}' was echoed in the response but could not be verified by GET.",
                                    evidence=f"Method: {method}\nPayload: {test_body}",
                                    target_url=url,
                                    source_agent=self.name
                                ))
                        else:
                            # GET が失敗した場合もエコーバックを報告
                            findings.append(Finding(
                                vuln_type=VulnType.IDOR,
                                severity=Severity.LOW,
                                title="Potential Mass Assignment (Echo Only)",
                                description=f"Injected property '{prop_name}' was echoed in the response. GET verification failed with status {final_check.status}.",
                                evidence=f"Method: {method}\nPayload: {test_body}",
                                target_url=url,
                                source_agent=self.name
                            ))
            except Exception as e:
                logger.error("[%s] Mass assignment test failed: %s", self.name, e)

        return findings

    async def _test_unauthenticated(
        self, url: str, method: str, headers: Dict[str, str], body: Optional[str], use_proxy: bool = True, safe_mode: bool = True
    ) -> Optional[Finding]:
        """認証情報を削除してアクセス可能か検証"""
        if safe_mode and method.upper() in ["POST", "PUT", "DELETE", "PATCH"]:
            logger.warning("[%s] Skipping destructive Unauth test for %s %s (safe_mode=True)", self.name, method, url)
            return None

        logger.info("[%s] Testing unauthenticated access for %s (proxy=%s)", self.name, url, use_proxy)
        
        auth_keys = ["authorization", "cookie", "x-api-key", "token", "session"]
        clean_headers = {k: v for k, v in headers.items() if k.lower() not in auth_keys}
        
        # 共有クライアントがない場合は新規作成
        client = self.network_client
        if client:
            return await self._run_unauth_check(client, url, method, headers, clean_headers, body, use_proxy)
        else:
            async with AsyncNetworkClient() as client:
                return await self._run_unauth_check(client, url, method, headers, clean_headers, body, use_proxy)

    async def _run_unauth_check(self, client, url, method, headers, clean_headers, body, use_proxy):
        try:
            baseline = await client.request(method, url, headers=headers, data=body, use_proxy=use_proxy)
            if baseline.status != 200:
                return None

            # 正常レスポンスから有効IDを収集
            await self._collect_ids_from_response(url, baseline.text)
            
            test_resp = await client.request(method, url, headers=clean_headers, data=body, use_proxy=use_proxy)
            
            # ResponseComparator で判定
            comparator = ResponseComparator(piimasker=getattr(self, "masker", None))
            comp_input = ComparisonInput(
                baseline_status=baseline.status,
                baseline_body=baseline.text,
                baseline_headers=baseline.headers,
                test_status=test_resp.status,
                test_body=test_resp.text,
                test_headers=test_resp.headers,
                original_id="baseline",
                test_id="unauth"
            )
            result = await comparator.compare(comp_input)

            if result.is_vulnerable:
                return Finding(
                    vuln_type=VulnType.IDOR,
                    severity=result.severity_hint,
                    title="Unauthenticated API Access Allowed",
                    description=f"The endpoint {url} is accessible without any authentication headers.",
                    evidence=result.report,
                    target_url=url,
                    source_agent=self.name,
                    additional_info={
                        "authz_differential": {
                            "scenario": "unauthenticated_access",
                            "confidence": round(float(result.confidence), 3),
                            "signals": list(result.signals),
                            "baseline_status": baseline.status,
                            "test_status": test_resp.status,
                            "original_id": "baseline",
                            "test_id": "unauth",
                        }
                    }
                )
        except Exception as e:  # pylint: disable=broad-except
            logger.error("[%s] Unauth request failed: %s", self.name, e)
        return None

    async def _collect_ids_from_response(self, url: str, text: str):
        """レスポンスボディから有効なIDを抽出してプールに蓄積 (Unified API への委譲)"""
        if not self.workspace or not text:
            return

        # 共有ワークスペースの統一APIを呼び出す (所有者ロールを付与)
        current_role = getattr(self, "current_role", None)
        mode = getattr(self, "config", {}).get("mode", "ctf")
        stage = (mode == "bugbounty")
        
        self.workspace.ingest_response(url, text, role=current_role, stage=stage)

    async def _test_cross_session_access(
        self, url: str, method: str, original_headers: Dict[str, str], body: Optional[str], 
        alt_sessions: Dict[str, Dict[str, Any]], use_proxy: bool = True, safe_mode: bool = True
    ) -> List[Finding]:
        """異なるユーザーセッションを用いてアクセス可能か検証 (Matrix Testing)"""
        findings = []
        
        if safe_mode and method.upper() in ["POST", "PUT", "DELETE", "PATCH"]:
            logger.warning("[%s] Skipping destructive Cross-Session test for %s %s", self.name, method, url)
            return []

        client = self.network_client
        should_close = False
        if not client:
            client = AsyncNetworkClient()
            should_close = True

        try:
            for role, session_data in alt_sessions.items():
                alt_headers = session_data.get("headers", {})
                
                # 自分自身のヘッダと同じならスキップ (実質的な重複)
                if alt_headers == original_headers:
                    continue
                
                logger.info("[%s] Testing access with alternative role: %s", self.name, role)
                
                # リクエスト実行
                resp = await client.request(method, url, headers=alt_headers, data=body, use_proxy=use_proxy)
                
                # Baseline 比較
                baseline = await client.request(method, url, headers=original_headers, data=body, use_proxy=use_proxy)
                
                comp_input = ComparisonInput(
                    baseline_status=baseline.status,
                    baseline_body=baseline.text,
                    baseline_headers=baseline.headers,
                    test_status=resp.status,
                    test_body=resp.text,
                    test_headers=resp.headers,
                    original_id="user-1" if "user-1" in baseline.text else "123",
                    test_id="user-1" if "user-1" in resp.text else "123"
                )
                
                from src.core.agents.swarm.logic.response_comparator import ResponseComparator
                comparator = ResponseComparator(piimasker=getattr(self, "masker", None))
                result = await comparator.compare(comp_input)
                
                logger.debug("[%s] BOLA comparison with role '%s': Score %.2f, Vuln: %s", self.name, role, result.confidence, result.is_vulnerable)

                if result.is_vulnerable:
                    findings.append(Finding(
                        vuln_type=VulnType.IDOR,
                        severity=result.severity_hint,
                        title=f"BOLA: Resource shared with unauthorized user (Role: {role})",
                        description=f"Resource {url} is accessible by user with role '{role}'.",
                        evidence=result.report,
                        target_url=url,
                        source_agent=self.name,
                        additional_info={
                            "authz_differential": {
                                "scenario": "cross_session_access",
                                "alternative_role": role,
                                "confidence": round(float(result.confidence), 3),
                                "signals": list(result.signals),
                                "baseline_status": baseline.status,
                                "test_status": resp.status,
                                "original_id": comp_input.original_id,
                                "test_id": comp_input.test_id,
                            }
                        }
                    ))
        except Exception as e:
            logger.error("[%s] Cross-session request failed: %s", self.name, e)
        finally:
            if should_close:
                await client.close()
                
        return findings

    async def _scan_for_secrets(self, text: str) -> List[Dict[str, Any]]:
        """SecretFinder を用いてレスポンスボディ内をインメモリでスキャン"""
        if not text or len(text) < 10:
            return []
            
        from src.tools.custom.secret_finder import SecretFinderTool
        tool = SecretFinderTool()
        try:
            # 高速なインメモリスキャンを実行
            findings = await tool.scan_text(text)
            return findings
        except Exception as e:
            logger.error("[%s] Error running in-memory SecretFinder: %s", self.name, e)
            return []

    async def _test_id_manipulation(
        self, url: str, method: str, headers: Dict[str, str], body: Optional[str], use_proxy: bool = True, safe_mode: bool = True
    ) -> List[Finding]:
        """ID パラメータ（数値、UUID）を URL および Body から抽出して操作・検証"""
        if safe_mode and method.upper() in ["POST", "PUT", "DELETE", "PATCH"]:
            logger.warning("[%s] Skipping destructive IDOR test for %s %s (safe_mode=True)", self.name, method, url)
            return []

        logger.info("[%s] Testing ID manipulation for %s (proxy=%s)", self.name, url, use_proxy)
        
        # UUID 抽出
        uuid_pattern = r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
        uuid_matches = set(re.findall(uuid_pattern, url))
        
        # 数値 ID 抽出 (パスの一部として存在する数値を対象にする)
        numeric_matches = set(re.findall(r'(?<=/)\d+(?=/|$|\?)', url))

        matches = []
        for m in uuid_matches:
            matches.append((m, "uuid", "url"))
        for m in numeric_matches:
            matches.append((m, "numeric", "url"))

        # Body 解析 (BodyMutator を使用)
        if body:
            ct = BodyMutator.detect_content_type(headers, body)
            if ct != "unknown":
                body_matches = BodyMutator.extract_ids(body, ct)
                matches.extend(body_matches)

        if not matches:
            return []
            
        client = self.network_client
        if client:
            return await self._run_id_manipulation_check(client, url, method, headers, body, matches, use_proxy)
        else:
            async with AsyncNetworkClient() as client:
                return await self._run_id_manipulation_check(client, url, method, headers, body, matches, use_proxy)

    async def _run_id_manipulation_check(self, client, url, method, headers, body, matches, use_proxy):
        findings = []
        # Baseline を最初に取得
        try:
            baseline = await client.request(method, url, headers=headers, data=body, use_proxy=use_proxy)
            if baseline.status != 200:
                logger.debug("[%s] Baseline failed (status %s), skipping manipulation check for %s", self.name, baseline.status, url)
                return []
        except Exception as e:
            logger.error("[%s] Baseline request error: %s", self.name, e)
            return []

        for match_value, match_type, target_loc in matches:
            new_ids = []
            
            # 1. 実在IDプールから取得を試みる
            if self.workspace:
                # エンドポイントの抽象化
                endpoint_pattern = re.sub(r'/\d+', '/{id}', url)
                endpoint_pattern = re.sub(r'/[0-9a-fA-F-]{36}', '/{uuid}', endpoint_pattern)
                endpoint_pattern = endpoint_pattern.split("?")[0]
                
                # 自分（現在のセッションで使用中のロール）以外の所有者IDを優先取得
                current_role = getattr(self, "current_role", None)
                pool_ids = self.workspace.get_pool_ids(endpoint_pattern, exclude=[match_value], exclude_owner=current_role)
                
                if pool_ids:
                    logger.info("[%s] Using real world IDs from pool for %s: %s", self.name, endpoint_pattern, pool_ids[:3])
                    new_ids.extend(pool_ids[:5]) # 最大5件程度に制限
            
            # 2. 予測ロジックでのID生成 (フォールバック、または追加テスト)
            if match_type == "numeric":
                preds = [str(int(match_value) - 1), str(int(match_value) + 1)]
                for p in preds:
                    if int(p) > 0 and p not in new_ids:
                        new_ids.append(p)
            elif match_type == "uuid":
                if not new_ids: # プールにIDがない場合のみ生成
                    new_ids.append(str(uuid.uuid4()))
                new_ids.append("00000000-0000-0000-0000-000000000000") # Null UUID は常に試す
            
            for new_id in new_ids:
                test_url = url
                test_body = body
                
                if target_loc == "url":
                    test_url = url.replace(match_value, new_id)
                elif target_loc == "body" and body:
                    ct = BodyMutator.detect_content_type(headers, body)
                    test_body = BodyMutator.replace_value(body, ct, str(match_value), str(new_id))
                
                try:
                    test_resp = await client.request(method, test_url, headers=headers, data=test_body, use_proxy=use_proxy)
                    
                    # ResponseComparator で判定
                    comparator = ResponseComparator(piimasker=getattr(self, "masker", None))
                    comp_input = ComparisonInput(
                        baseline_status=baseline.status,
                        baseline_body=baseline.text,
                        baseline_headers=baseline.headers,
                        test_status=test_resp.status,
                        test_body=test_resp.text,
                        test_headers=test_resp.headers,
                        original_id=str(match_value),
                        test_id=str(new_id)
                    )
                    result = await comparator.compare(comp_input)

                    if result.is_vulnerable:
                        findings.append(Finding(
                            vuln_type=VulnType.IDOR,
                            severity=result.severity_hint,
                            title=f"IDOR: {match_type.upper()} Manipulation Success ({target_loc.upper()})",
                            description=f"Accessed different resource ID {new_id} via {target_loc} parameters.",
                            evidence=result.report,
                            target_url=test_url,
                            source_agent=self.name,
                            additional_info={
                                "authz_differential": {
                                    "scenario": "id_manipulation",
                                    "match_type": match_type,
                                    "target_location": target_loc,
                                    "confidence": round(float(result.confidence), 3),
                                    "signals": list(result.signals),
                                    "baseline_status": baseline.status,
                                    "test_status": test_resp.status,
                                    "original_id": str(match_value),
                                    "test_id": str(new_id),
                                }
                            }
                        ))
                except Exception as e:  # pylint: disable=broad-except
                    logger.error("[%s] Manipulation request failed: %s", self.name, e)
        return findings

    async def _test_hpp(
        self, url: str, method: str, headers: Dict[str, str], body: Optional[str], use_proxy: bool = True, safe_mode: bool = True
    ) -> List[Finding]:
        """HPP (HTTP Parameter Pollution) テストを実行"""
        findings = []
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        if not query_params and not body:
            return []

        logger.info("[%s] Testing HPP for %s", self.name, url)
        client = self.network_client or AsyncNetworkClient()
        
        # テスト用 ID の選定
        test_ids = []
        if self.workspace:
            endpoint_pattern = re.sub(r'/\d+', '/{id}', url).split("?")[0]
            test_ids = self.workspace.get_pool_ids(endpoint_pattern, limit=1) or []
        
        if not test_ids:
            test_ids = ["999", "1"]

        # 1. URL Parameters HPP
        for k, v in query_params.items():
            # ID らしきパラメータを対象にする
            if any(id_keyword in k.lower() for id_keyword in ["id", "uuid", "uid", "user", "account"]):
                for tid in test_ids:
                    if str(tid) == str(v[0]): continue
                    
                    variations = [
                        # 標準的な重複 (e.g. id=1&id=2)
                        {k: [v[0], tid]},
                        {k: [tid, v[0]]},
                        # 配列形式 (e.g. id[]=1&id[]=2)
                        {f"{k}[]": [v[0], tid]},
                    ]
                    
                    for q_var in variations:
                        new_q = query_params.copy()
                        new_q.update(q_var)
                        test_url = urlunparse(parsed_url._replace(query=urlencode(new_q, doseq=True)))
                        
                        try:
                            resp = await client.request(method, test_url, headers=headers, data=body, use_proxy=use_proxy)
                            # レスポンスに攻撃パラメータの値が含まれているか、またはステータスが正常かを確認
                            # 簡易的な判定だが、BOLAの兆候として捉える
                            if resp.status == 200 and str(tid) in resp.text:
                                findings.append(Finding(
                                    vuln_type=VulnType.IDOR,
                                    severity=Severity.HIGH,
                                    title="HPP IDOR: Parameter Pollution in URL Query",
                                    description=f"Polluting query parameter '{k}' with an additional ID '{tid}' (variation: {list(q_var.keys())[0]}) allowed potential unauthorized access.",
                                    evidence=f"URL: {test_url}\nResponse snippet: {resp.text[:200]}",
                                    target_url=url,
                                    source_agent=self.name
                                ))
                                break # 1つのキーにつき1つ見つかれば十分
                        except Exception as e:
                            logger.debug("[%s] URL HPP failed: %s", self.name, e)

        # 2. Body Parameters HPP
        if body:
            ct = BodyMutator.detect_content_type(headers, body)
            if ct != "unknown":
                data = BodyMutator.parse(body, ct)
                if isinstance(data, dict):
                    for k in data.keys():
                        if any(id_keyword in k.lower() for id_keyword in ["id", "uuid", "uid", "user", "account"]):
                            for tid in test_ids:
                                # BodyMutator を使用して変異ボディを生成
                                variations = [
                                    BodyMutator.duplicate_param(body, ct, k, tid), # 標準重複
                                ]
                                
                                # JSON の場合は配列化も試みる
                                if ct == "json":
                                    try:
                                        json_data = json.loads(body)
                                        orig_val = json_data.get(k)
                                        json_data[k] = [orig_val, tid]
                                        variations.append(json.dumps(json_data))
                                    except: pass
                                
                                for test_body in variations:
                                    if test_body == body: continue
                                    try:
                                        resp = await client.request(method, url, headers=headers, data=test_body, use_proxy=use_proxy)
                                        if resp.status in [200, 201] and str(tid) in resp.text:
                                            findings.append(Finding(
                                                vuln_type=VulnType.IDOR,
                                                severity=Severity.HIGH,
                                                title="HPP IDOR: Parameter Pollution in Body",
                                                description=f"Duplicate or array parameter '{k}' in {ct} body reflected attacker-controlled ID '{tid}'.",
                                                evidence=f"Payload: {test_body}\nResponse snippet: {resp.text[:200]}",
                                                target_url=url,
                                                source_agent=self.name
                                            ))
                                            break
                                    except Exception as e:
                                        logger.debug("[%s] Body HPP failed: %s", self.name, e)
        return findings

    async def _test_graphql_idor(
        self, endpoint: str, headers: Dict[str, str], body: Optional[str], use_proxy: bool = True, safe_mode: bool = True
    ) -> List[Finding]:
        """GraphQL IDOR テストを実行"""
        findings = []
        client = self.network_client or AsyncNetworkClient()
        from src.core.attack.graphql_crafter import GraphQLCrafter
        crafter = GraphQLCrafter()

        logger.info("[%s] Testing GraphQL IDOR for %s", self.name, endpoint)

        # 1. Introspection で定義を取得
        introspection_query = crafter.get_introspection_query()
        try:
            intro_resp = await client.request("POST", endpoint, headers=headers, data=json.dumps({"query": introspection_query}), use_proxy=use_proxy)
            if intro_resp.status != 200:
                return []
            schema_json = json.loads(intro_resp.text)
        except Exception:
            return []

        # 2. テスト用 ID の選定
        test_id = "1"
        if self.workspace:
            ids = self.workspace.get_pool_ids("graphql", limit=1)
            if ids:
                test_id = ids[0]

        # 3. IDOR テスト用クエリ生成と実行
        test_queries = crafter.generate_idor_queries(schema_json, test_id)
        for gql_task in test_queries:
            try:
                resp = await client.request("POST", endpoint, headers=headers, data=json.dumps(gql_task), use_proxy=use_proxy)
                if resp.status == 200:
                    # 権限のないデータが返ってきているかチェック
                    # エラーがなく、かつレスポンス内にテスト用 ID が何らかの形で含まれているかを確認
                    # (JSON の引用符などを考慮し、より柔軟に判定)
                    resp_content = resp.text
                    if not "errors" in resp_content and (str(test_id) in resp_content or any(str(tid) in resp_content for tid in [test_id, f'"{test_id}"'])):
                        findings.append(Finding(
                            vuln_type=VulnType.IDOR,
                            severity=Severity.HIGH,
                            title=f"GraphQL IDOR: Unauthorized Access in {gql_task['operationName']}",
                            description=f"Accessed GraphQL operation '{gql_task['operationName']}' with unauthorized ID '{test_id}'.",
                            evidence=f"Query: {gql_task['query']}\nVariables: {gql_task['variables']}",
                            target_url=endpoint,
                            source_agent=self.name
                        ))
            except Exception as e:
                logger.debug("[%s] GraphQL IDOR task failed: %s", self.name, e)

        return findings
