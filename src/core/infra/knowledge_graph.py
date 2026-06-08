"""
KnowledgeGraph: グラフデータベース連携モジュール

Neo4jを使用して、収集した資産情報（ドメイン、IP、エンドポイント、技術、脆弱性）を
グラフ構造として保存・管理する。
これにより、Attack Surface の可視化と動的な攻撃推論を可能にする。
"""

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
