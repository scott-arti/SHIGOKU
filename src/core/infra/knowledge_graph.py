"""
KnowledgeGraph: グラフデータベース連携モジュール

Neo4jを使用して、収集した資産情報（ドメイン、IP、エンドポイント、技術、脆弱性）を
グラフ構造として保存・管理する。
これにより、Attack Surface の可視化と動的な攻撃推論を可能にする。
"""

import json
import logging
from datetime import datetime
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse

from neo4j import GraphDatabase

from src.core.intel.cartographer import SiteMap, SiteNode
from src.core.intel.fingerprinter import TechInfo
from src.core.domain.model.target import TargetAsset
from src.config import settings

logger = logging.getLogger(__name__)


def _kg_safe_prop(value: Any) -> Any:
    """Neo4j ノードプロパティはプリミティブ/プリミティブ配列のみ許可される。

    Map(dict)や Map を含む配列はプロパティに設定できず
    Neo.ClientError.Statement.TypeError (gql_status 22G03) を引き起こすため、
    JSON 文字列へ直列化する。読み戻しは KG 側に無い (store 専用) ため文字列化で安全。
    """
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, default=str)
    if isinstance(value, list) and any(isinstance(v, (dict, list)) for v in value):
        return json.dumps(value, ensure_ascii=False, default=str)
    return value


class KnowledgeGraph:
    """Neo4j Knowledge Graph Wrapper"""

    def __init__(self, uri: Optional[str] = None, user: Optional[str] = None, password: Optional[str] = None):
        # 設定から値をロード（引数が優先）
        self.uri = uri or settings.neo4j_uri
        self.user = user or settings.neo4j_user
        self.password = password or settings.neo4j_password
        
        try:
            # SHIGOKU-MOD: informational notifications (like "index already exists") are noisy.
            # Suppress them by setting notifications_min_severity to "WARNING".
            for attempt in range(1, 4):
                try:
                    self.driver = GraphDatabase.driver(
                        self.uri, 
                        auth=(self.user, self.password),
                        notifications_min_severity="WARNING"
                    )
                    # Also explicitly set the logger level to avoid noise in the console
                    logging.getLogger("neo4j.notifications").setLevel(logging.WARNING)
                    
                    self.verify_connection()
                    self._ensure_indexes()
                    logger.info("✅ Connected to Neo4j Knowledge Graph")
                    break
                except Exception as e:
                    logger.warning(f"Neo4j connection attempt {attempt} failed: {e}")
                    import time
                    time.sleep(2)
                    self.driver = None
                    if attempt == 3:
                        raise e
                        
        except Exception as e:
            logger.error("❌ Failed to connect to Neo4j after 3 attempts: %s", e)
            self.driver = None

    def _ensure_indexes(self):
        """必要なインデックスが存在することを保証"""
        if not self.driver:
            return
        
        with self.driver.session() as session:
            try:
                # 3.x vs 4.x+ compatibility: 'IF NOT EXISTS' is 4.0+
                session.run("CREATE INDEX page_url_idx IF NOT EXISTS FOR (p:Page) ON (p.url)")
                session.run("CREATE INDEX domain_name_idx IF NOT EXISTS FOR (d:Domain) ON (d.name)")
                session.run("CREATE INDEX endpoint_url_idx IF NOT EXISTS FOR (e:Endpoint) ON (e.url)")
                session.run("CREATE INDEX ip_address_idx IF NOT EXISTS FOR (i:IP) ON (i.address)")
                logger.info("✅ Neo4j indexes ensured")
            except Exception as e:
                logger.warning(f"Failed to create indexes: {e}")

    def close(self):
        if self.driver:
            self.driver.close()

    def verify_connection(self):
        """接続確認"""
        self.driver.verify_connectivity()

    def store_sitemap(self, sitemap: SiteMap):
        """サイトマップ全体を保存"""
        if not self.driver:
            logger.warning("Neo4j driver not available. Skipping store_sitemap.")
            return

        with self.driver.session() as session:
            # 1. & 2. ドメインとページの登録（バッチ一括処理）
            domain = urlparse(sitemap.root_url).netloc
            pages = [(domain, node) for node in sitemap.nodes.values()]
            self.save_pages_batch(pages)

            # 3. リンク関係の構築
            for url, node in sitemap.nodes.items():
                for link in node.links:
                    # リンク先がサイトマップ内にある場合のみリレーションを作成（外部へのリンクは要検討）
                    if link in sitemap.nodes:
                        session.execute_write(self._create_link, url, link)

    def store_tech_stack(self, url: str, tech_list: List[TechInfo]):
        """URLに関連する技術スタックを保存"""
        if not self.driver or not tech_list:
            return

        with self.driver.session() as session:
            for tech in tech_list:
                session.execute_write(self._create_technology, url, tech)

    def save_pages_batch(self, pages: List[tuple[str, SiteNode]]) -> None:
        """
        ページを一括保存（UNWIND使用）
        
        Args:
            pages: (domain, SiteNode) のタプルリスト
        """
        if not self.driver or not pages:
            return
        
        # データを辞書形式に変換
        page_data = []
        for domain, node in pages:
            page_data.append({
                "url": node.url,
                "title": node.title,
                "status": node.status_code,
                "content_type": node.content_type,
                "domain": domain,
                "timestamp": datetime.now().isoformat()
            })
        
        with self.driver.session() as session:
            # UNWINDで一括処理
            query = """
            UNWIND $pages as page
            MERGE (d:Domain {name: page.domain})
            SET d.updated_at = page.timestamp
            WITH d, page
            MERGE (p:Page {url: page.url})
            SET p.title = page.title, 
                p.status = page.status, 
                p.content_type = page.content_type, 
                p.updated_at = page.timestamp
            MERGE (d)-[:CONTAINS]->(p)
            """
            session.execute_write(lambda tx: tx.run(query, pages=page_data))
        
        logger.info(f"[KnowledgeGraph] Batch saved {len(pages)} pages")

    def get_tech_stack(self, target_url: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        技術スタック情報を取得
        
        Args:
            target_url: 特定のURLに関連する技術のみを取得する場合に指定
            
        Returns:
            List[Dict[str, Any]]: 技術スタック情報のリスト
            [{"name": "Nginx", "category": "Web Server", "url": "..."}]
        """
        if not self.driver:
            return []
            
        with self.driver.session() as session:
            try:
                if target_url:
                    result = session.execute_read(self._get_tech_by_url, target_url)
                else:
                    result = session.execute_read(self._get_all_tech)
                return result
            except Exception as e:
                logger.error("Failed to get tech stack: %s", e)
                return []

    # --- Cypher Query Implementation ---

    @staticmethod
    def _create_domain(tx, domain: str):
        """Domainノード作成"""
        query = (
            "MERGE (d:Domain {name: $domain}) "
            "SET d.updated_at = $timestamp"
        )
        tx.run(query, domain=domain, timestamp=datetime.now().isoformat())

    @staticmethod
    def _create_page(tx, domain: str, node: SiteNode):
        """Pageノード作成とDomainとの接続"""
        # Pageノード作成
        query = (
            "MERGE (p:Page {url: $url}) "
            "SET p.title = $title, p.status = $status, p.content_type = $ctype, p.updated_at = $timestamp "
            "WITH p "
            "MATCH (d:Domain {name: $domain}) "
            "MERGE (d)-[:CONTAINS]->(p)"
        )
        tx.run(
            query,
            url=node.url,
            title=node.title,
            status=node.status_code,
            ctype=node.content_type,
            domain=domain,
            timestamp=datetime.now().isoformat()
        )

    @staticmethod
    def _create_link(tx, source_url: str, target_url: str):
        """Page間のLINKS_TOリレーション作成"""
        query = (
            "MATCH (s:Page {url: $source}) "
            "MATCH (t:Page {url: $target}) "
            "MERGE (s)-[:LINKS_TO]->(t)"
        )
        tx.run(query, source=source_url, target=target_url)

    @staticmethod
    def _create_technology(tx, url: str, tech: TechInfo):
        """Technologyノード作成とRUNS_ONリレーション"""
        query = (
            "MERGE (t:Technology {name: $name}) "
            "SET t.category = $category "
            "WITH t "
            "MATCH (p:Page {url: $url}) "
            "MERGE (p)-[:RUNS_ON]->(t)"
        )
        tx.run(query, name=tech.name, category=tech.category, url=url)

    @staticmethod
    def _get_tech_by_url(tx, target_url: str) -> List[Dict[str, Any]]:
        """指定URL/ドメインに関連するTechnologyを取得 (Page RUNS_ON / Domain CONTAINS 経由)

        SGK fix: get_tech_stack() から呼ばれていたが未実装だったため常に空を返していた。
        """
        query = (
            "MATCH (p:Page)-[:RUNS_ON]->(t:Technology) "
            "WHERE p.url = $url OR p.url STARTS WITH ($url + '/') "
            "RETURN t.name AS name, t.category AS category, p.url AS url "
            "UNION "
            "MATCH (d:Domain {name: $url})-[:CONTAINS]->(p:Page)-[:RUNS_ON]->(t:Technology) "
            "RETURN t.name AS name, t.category AS category, p.url AS url"
        )
        result = tx.run(query, url=target_url)
        return [record.data() for record in result]

    @staticmethod
    def _get_all_tech(tx) -> List[Dict[str, Any]]:
        """全Technologyを取得"""
        query = (
            "MATCH (t:Technology) "
            "RETURN t.name AS name, t.category AS category, '' AS url"
        )
        result = tx.run(query)
        return [record.data() for record in result]

    def store_recon_result(self, tool_name: str, target: str, result: Any) -> None:
        """
        Reconツールの実行結果を正規化して保存
        
        Args:
            tool_name: ツール名 (subfinder, httpx, naabu, katana, etc.)
            target: ターゲットURL/ドメイン
            result: ツールの出力データ(dict or list)
        """
        if not self.driver or not result:
            return

        try:
            if tool_name == "subfinder":
                # result はサブドメインのリストと想定
                if isinstance(result, list):
                    for sub in result:
                        self.save_pages_batch([(sub, SiteNode(url=f"http://{sub}"))])
                        # ドメインとIPの紐付けがあれば link_domain_to_ip を呼ぶ

            elif tool_name == "httpx":
                # result は詳細情報のリスト
                if isinstance(result, list):
                    for item in result:
                        url = item.get("url")
                        self.create_endpoint(
                            url=url,
                            status=item.get("status_code"),
                            content_type=item.get("content_type"),
                            web_server=item.get("web_server"),
                            tech=item.get("tech", [])
                        )
                        # 技術スタックの保存
                        tech_stack = item.get("tech", [])
                        for t in tech_stack:
                            self.create_technology(name=t, url=url)

            elif tool_name == "naabu":
                # ポートスキャン結果
                if isinstance(result, list):
                    for port in result:
                        # IPノードにポート情報を統合
                        pass # TODO: IPノードへのプロパティ追加

            elif "katana" in tool_name:
                # クローリング結果（URLリストや詳細）
                if isinstance(result, list):
                    for item in result:
                        if isinstance(item, str):
                            self.create_endpoint(url=item)
                        elif isinstance(item, dict):
                            url = item.get("request", {}).get("url") or item.get("url")
                            if url:
                                params = item.get("params", []) # クエリパラメータ等
                                self.create_endpoint(url=url, params=params)

            logger.info(f"Successfully stored {tool_name} results for {target} in KG")
        except Exception as e:
            logger.error(f"Failed to store recon result for {tool_name}: {e}")

    # ── SGK-2026-0261: Signal Bundle Persistence ──

    def store_signal_bundle(self, signal_bundle: dict) -> int:
        """
        Recon signal bundle を KG に永続化。

        既存 store_recon_result() は置き換えず、専用入口として追加。
        Endpoint ノードに signal プロパティを追記し、後続の dedupe/reference に利用可能にする。

        Args:
            signal_bundle: step8_return_to_mc の _signal_bundle dict
                           {_run_id, _host_surface_summary, _endpoint_signals}

        Returns:
            保存した signal 数
        """
        if not self.driver:
            return 0
        if not signal_bundle or not isinstance(signal_bundle, dict):
            return 0

        endpoint_signals = signal_bundle.get("_endpoint_signals", [])
        if not isinstance(endpoint_signals, list) or len(endpoint_signals) == 0:
            return 0

        run_id = signal_bundle.get("_run_id", "")
        stored_count = 0

        try:
            with self.driver.session() as session:
                for sig in endpoint_signals:
                    if not isinstance(sig, dict):
                        continue
                    url = sig.get("url", "")
                    method = sig.get("method", "GET")
                    if not url:
                        continue

                    session.run(
                        """
                        MERGE (s:AttackSurfaceSignal {signal_id: $signal_id})
                        SET s.entity_type = $entity_type,
                            s.url = $url,
                            s.method = $method,
                            s.primary_label = $primary_label,
                            s.candidate_labels = $candidate_labels,
                            s.confidence = $confidence,
                            s.why_suspicious = $why_suspicious,
                            s.source_observations = $source_observations,
                            s.auth_required = $auth_required,
                            s.auth_context = $auth_context,
                            s.interaction_kind = $interaction_kind,
                            s.lineage = $lineage,
                            s.signal_status = $status,
                            s.params = $params,
                            s.seen_count = $seen_count,
                            s.run_id = $run_id,
                            s.updated_at = $timestamp
                        WITH s
                        MERGE (e:Endpoint {url: $url, method: $method})
                        MERGE (s)-[:TARGETS_ENDPOINT]->(e)
                        """,
                        url=url,
                        method=method,
                        signal_id=sig.get("signal_id", ""),
                        entity_type=sig.get("entity_type", ""),
                        primary_label=sig.get("primary_label", ""),
                        candidate_labels=sig.get("candidate_labels", []),
                        confidence=sig.get("confidence", 0.5),
                        why_suspicious=sig.get("why_suspicious", ""),
                        source_observations=sig.get("source_observations", []),
                        auth_required=sig.get("auth_required", False),
                        auth_context=_kg_safe_prop(sig.get("auth_context", {})),
                        interaction_kind=sig.get("interaction_kind", "static"),
                        lineage=sig.get("lineage", ""),
                        params=_kg_safe_prop(sig.get("params", [])),
                        status=sig.get("status", "active"),
                        seen_count=sig.get("seen_count", 1),
                        run_id=run_id,
                        timestamp=datetime.now().isoformat(),
                    )
                    stored_count += 1

            logger.info(
                "[SGK-2026-0261] Stored %d endpoint signals in KG (run_id=%s)",
                stored_count,
                run_id,
            )
        except Exception as e:
            logger.error("Failed to store signal bundle in KG: %s", e)

        return stored_count

    # --- Rich Schema Operations (Ported from models/graph.py) ---

    def create_endpoint(self, url: str, method: str = "GET", **props) -> str:
        """Endpointノードを作成"""
        if not self.driver: return ""
        query = """
        MERGE (e:Endpoint {url: $url, method: $method})
        SET e += $props, e.updated_at = $timestamp
        RETURN elementId(e) as node_id
        """
        with self.driver.session() as session:
            result = session.run(query, url=url, method=method, props=props, timestamp=datetime.now().isoformat())
            return result.single()["node_id"]

    def create_parameter(self, name: str, endpoint_url: str, method: str = "GET", **props) -> str:
        """Parameterノードを作成しEndpointとリンク"""
        if not self.driver: return ""
        query = """
        MERGE (p:Parameter {name: $name, endpoint: $endpoint_key})
        SET p += $props, p.updated_at = $timestamp
        WITH p
        MATCH (e:Endpoint {url: $url, method: $method})
        MERGE (e)-[r:ACCEPTS_PARAM]->(p)
        RETURN elementId(p) as node_id
        """
        endpoint_key = f"{method}:{endpoint_url}"
        with self.driver.session() as session:
            result = session.run(
                query, 
                name=name, endpoint_key=endpoint_key, 
                url=endpoint_url, method=method, 
                props=props, timestamp=datetime.now().isoformat()
            )
            return result.single()["node_id"]

    def create_finding(self, title: str, vuln_type: str, url: str, severity: str = "medium", **props) -> str:
        """Findingノードを作成しEndpointとリンク"""
        if not self.driver: return ""
        query = """
        CREATE (f:Finding {
            title: $title,
            type: $vuln_type,
            severity: $severity,
            created_at: $timestamp
        })
        SET f += $props
        WITH f
        MATCH (e:Endpoint {url: $url})
        MERGE (e)-[:VULNERABLE_TO]->(f)
        RETURN elementId(f) as node_id
        """
        with self.driver.session() as session:
            result = session.run(
                query,
                title=title,
                vuln_type=vuln_type,
                url=url,
                severity=severity,
                timestamp=datetime.now().isoformat(),
                props=props
            )
            return result.single()["node_id"]

    def link_domain_to_ip(self, domain: str, ip: str) -> None:
        """Domain -> IP のリンクを作成"""
        if not self.driver: return
        query = """
        MATCH (d:Domain {name: $domain})
        MERGE (i:IP {address: $ip})
        SET i.updated_at = $timestamp
        MERGE (d)-[:RESOLVES_TO]->(i)
        """
        with self.driver.session() as session:
            session.run(query, domain=domain, ip=ip, timestamp=datetime.now().isoformat())

    # ── SGK-2026-0260: RecipeRun persistence ──────────────────────────────

    def store_recipe_run(
        self,
        recipe_name: str,
        target: str,
        success: bool,
        summary: Dict[str, Any],
        verdict: Optional[str] = None,
        verdict_reason_codes: Optional[list] = None,
        run_id: str = "",
        suppression_key_signal: str = "",
        suppression_key_endpoint: str = "",
    ) -> str:
        """Persist a recipe execution result as a :RecipeRun node.

        Links the run to the target :Endpoint node via :EXECUTED_AGAINST.
        Also stores suppression keys for cross-run dedup.
        Returns the elementId of the created node, or empty string on failure.
        """
        if not self.driver:
            return ""
        query = """
        MERGE (r:RecipeRun {key: $key})
        SET r.recipe_name = $recipe_name,
            r.target = $target,
            r.success = $success,
            r.summary = $summary,
            r.verdict = $verdict,
            r.verdict_reason_codes = $verdict_reason_codes,
            r.run_id = $run_id,
            r.suppression_key_signal = $suppression_key_signal,
            r.suppression_key_endpoint = $suppression_key_endpoint,
            r.executed_at = $timestamp
        WITH r
        MERGE (e:Endpoint {url: $target, method: $method})
        MERGE (r)-[:EXECUTED_AGAINST]->(e)
        RETURN elementId(r) as node_id
        """
        key = f"{recipe_name}:{target}"
        try:
            with self.driver.session() as session:
                result = session.run(
                    query,
                    key=key,
                    recipe_name=recipe_name,
                    target=target,
                    success=success,
                    summary=summary,
                    verdict=verdict or "",
                    verdict_reason_codes=verdict_reason_codes or [],
                    run_id=run_id,
                    suppression_key_signal=suppression_key_signal,
                    suppression_key_endpoint=suppression_key_endpoint,
                    method="GET",
                    timestamp=datetime.now().isoformat(),
                )
                record = result.single()
                return record["node_id"] if record else ""
        except Exception as e:
            logger.error("Failed to store recipe run in KG: %s", e)
            return ""

    def get_recipe_runs_for_domain(
        self,
        domain_name: str,
        limit: int = 20,
    ) -> Dict[str, Any]:
        """Query previous recipe runs for a domain.

        Returns dict with:
          - ``previous_recipe_runs``: List[str] of recipe names
          - ``previous_recipe_outcomes``: Dict[str, str] mapping recipe_name → outcome
          - ``suppression_keys``: List[str] of stored suppression keys
        """
        if not self.driver:
            return {"previous_recipe_runs": [], "previous_recipe_outcomes": {}, "suppression_keys": []}
        query = """
        MATCH (r:RecipeRun)-[:EXECUTED_AGAINST]->(e:Endpoint)
        WHERE e.url CONTAINS $domain
        RETURN r.recipe_name AS name, r.success AS success,
               r.suppression_key_signal AS sk_signal,
               r.suppression_key_endpoint AS sk_endpoint
        ORDER BY r.executed_at DESC LIMIT $limit
        """
        try:
            with self.driver.session() as session:
                result = session.run(query, domain=domain_name, limit=limit)
                previous_runs: List[str] = []
                outcomes: Dict[str, str] = {}
                suppression_keys: List[str] = []
                seen = set()
                for record in result:
                    name = record["name"]
                    if name and name not in seen:
                        seen.add(name)
                        previous_runs.append(name)
                        outcomes[name] = "success" if record["success"] else "failed"
                    # Collect suppression keys
                    for sk_key in ("sk_signal", "sk_endpoint"):
                        val = record.get(sk_key, "")
                        if val and val not in suppression_keys:
                            suppression_keys.append(val)
                return {
                    "previous_recipe_runs": previous_runs,
                    "previous_recipe_outcomes": outcomes,
                    "suppression_keys": suppression_keys,
                }
        except Exception as e:
            logger.warning("Failed to query recipe runs from KG: %s", e)
            return {"previous_recipe_runs": [], "previous_recipe_outcomes": {}, "suppression_keys": []}

    def get_nearby_findings(
        self,
        target_url: str,
        max_distance: int = 5,
    ) -> list:
        """Query findings on endpoints near *target_url*.

        Returns a list of dicts with ``status``, ``type``, ``severity``, ``title``.
        """
        if not self.driver:
            return []
        # Simple approximation: find all Findings on the same domain
        from urllib.parse import urlparse
        try:
            parsed = urlparse(target_url)
            domain = parsed.netloc or parsed.hostname or ""
        except Exception:
            domain = ""
        if not domain:
            return []
        query = """
        MATCH (f:Finding)-[:VULNERABLE_TO]-(e:Endpoint)
        WHERE e.url CONTAINS $domain
        RETURN f.type AS type, f.severity AS severity, f.title AS title
        LIMIT $max_distance
        """
        try:
            with self.driver.session() as session:
                result = session.run(query, domain=domain, max_distance=max_distance)
                findings = []
                for record in result:
                    finding_type = record.get("type", "")
                    status = "confirmed"  # KG findings are always confirmed
                    findings.append({
                        "status": status,
                        "type": finding_type,
                        "severity": record.get("severity", ""),
                        "title": record.get("title", ""),
                    })
                return findings
        except Exception as e:
            logger.warning("Failed to query nearby findings from KG: %s", e)
            return []

    # --- Advanced Queries ---

    def get_attack_surface(self, domain_name: str) -> Dict[str, Any]:
        """ドメインに関連する攻撃対象領域（Endpoint, Tech, Finding）を取得"""
        if not self.driver: return {}
        query = """
        MATCH (d:Domain {name: $domain})
        OPTIONAL MATCH (d)-[:CONTAINS]->(p:Page)
        OPTIONAL MATCH (p)-[:RUNS_ON]->(t:Technology)
        OPTIONAL MATCH (e:Endpoint) WHERE e.url CONTAINS $domain
        OPTIONAL MATCH (e)-[:VULNERABLE_TO]->(f:Finding)
        RETURN 
            collect(DISTINCT p.url) as pages,
            collect(DISTINCT t.name) as technologies,
            collect(DISTINCT e.url) as endpoints,
            count(DISTINCT f) as finding_count
        """
        with self.driver.session() as session:
            result = session.run(query, domain=domain_name)
            return result.single().data()

    def get_untested_endpoints(self, domain_name: str) -> List[Dict[str, Any]]:
        """まだ脆弱性スキャンが行われていないエンドポイントを取得"""
        if not self.driver: return []
        query = """
        MATCH (e:Endpoint)
        WHERE e.url CONTAINS $domain
        AND NOT (e)-[:VULNERABLE_TO]->(:Finding)
        AND (e.last_scanned IS NULL OR e.last_scanned < $threshold)
        RETURN e.url as url, e.method as method
        LIMIT 50
        """
        threshold = (datetime.now().timestamp() - 86400) # 24時間以内
        with self.driver.session() as session:
            result = session.run(query, domain=domain_name, threshold=threshold)
            return [record.data() for record in result]

    def get_contextual_flows(self, domain_name: str) -> List[Dict[str, Any]]:
        """
        ドメインに関連するコンテキストフロー（状態遷移）を抽出
        
        POST/PUT/PATCHエンドポイントを含むパスを「重要フロー」として識別する。
        """
        if not self.driver: return []
        query = """
        MATCH (s:Page)
        WHERE s.url CONTAINS $domain
        MATCH p=(s)-[:LINKS_TO*1..3]->(e:Endpoint)
        WHERE e.method IN ['POST', 'PUT', 'PATCH']
        WITH p, e
        MATCH (e)-[:LINKS_TO*1..2]->(f:Page)
        WHERE f.url CONTAINS $domain 
        AND (f.url CONTAINS 'success' OR f.url CONTAINS 'complete' OR f.url CONTAINS 'done' OR f.url CONTAINS 'thank')
        RETURN 
            [node IN nodes(p) | node.url] as initial_path,
            e.url as state_changing_endpoint,
            e.method as method,
            f.url as result_page
        LIMIT 10
        """
        with self.driver.session() as session:
            try:
                result = session.run(query, domain=domain_name)
                return [record.data() for record in result]
            except Exception as e:
                logger.error(f"Failed to get contextual flows: {e}")
                return []

    def store_state_transition(self, from_url: str, to_url: str, action: str = "POST", condition: Optional[str] = None) -> None:
        """
        明示的な状態遷移を保存（例: login -> dashboard via POST）
        """
        if not self.driver: return
        query = """
        MERGE (f:Page {url: $from_url})
        MERGE (t:Page {url: $to_url})
        MERGE (f)-[r:TRANSITIONS_TO {action: $action}]->(t)
        SET r.condition = $condition, 
            r.updated_at = $timestamp
        """
        with self.driver.session() as session:
            try:
                session.run(
                    query, 
                    from_url=from_url, to_url=to_url, action=action, 
                    condition=condition, timestamp=datetime.now().isoformat()
                )
                logger.info(f"Stored transition: {from_url} -> {to_url} ({action})")
            except Exception as e:
                logger.error(f"Failed to store state transition: {e}")

    # --- Pending Task Queue ---

    def save_pending_task(self, url: str, reason: str, category: str = "fuzzing"):
        """Pendingタスクを保存"""
        if not self.driver:
            return
        with self.driver.session() as session:
            session.execute_write(self._create_pending_task, url, reason, category)

    def get_pending_tasks(self, category: str = "fuzzing") -> List[str]:
        """PendingタスクのURLリストを取得"""
        if not self.driver:
            return []
        with self.driver.session() as session:
            return session.execute_read(self._get_pending_tasks_by_category, category)

    @staticmethod
    def _create_pending_task(tx, url: str, reason: str, category: str):
        # Pageノードがなければ作る（基本はあるはずだが）
        query = (
            "MERGE (p:Page {url: $url}) "
            "MERGE (t:PendingTask {url: $url, category: $category}) "
            "SET t.reason = $reason, t.created_at = $timestamp, t.status = 'PENDING' "
            "MERGE (p)-[:HAS_PENDING_TASK]->(t)"
        )
        tx.run(query, url=url, reason=reason, category=category, timestamp=datetime.now().isoformat())

    @staticmethod
    def _get_pending_tasks_by_category(tx, category: str):
        query = (
            "MATCH (t:PendingTask {category: $category, status: 'PENDING'}) "
            "RETURN t.url as url"
        )
        result = tx.run(query, category=category)
        return [record["url"] for record in result]

# テスト用
if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    
    # 接続テストのみ
    kg = KnowledgeGraph(password="shigoku2024") # docker-compose.ymlの定義値
    if kg.driver:
        print("Driver initialized.")
        kg.close()
    else:
        print("Driver init failed.")
