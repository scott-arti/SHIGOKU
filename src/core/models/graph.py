"""
Knowledge Graph: Neo4j Wrapper for SHIGOKU

資産間の関係性（Domain → IP → Endpoint → Parameter → Finding）を
グラフ構造で保持し、Attack Surface の可視化と横展開を可能にする。
"""

from typing import Optional, Any
from dataclasses import dataclass
import os
import logging


@dataclass
class NodeInfo:
    """ノード情報"""
    node_id: str
    labels: list[str]
    properties: dict[str, Any]


class KnowledgeGraph:
    """
    Neo4j Knowledge Graph for asset relationships.
    
    ノード種別:
    - Program: バグバウンティプログラム
    - Domain: ドメイン
    - IP: IPアドレス
    - Endpoint: APIエンドポイント
    - Parameter: パラメータ
    - Technology: 技術スタック（Framework, Server, etc.）
    - Finding: 発見された脆弱性
    - Company: 企業（Parent-Child関係用）
    
    エッジ種別:
    - RESOLVES_TO: Domain → IP
    - HOSTS: IP → Endpoint
    - ACCEPTS_PARAM: Endpoint → Parameter
    - USES_TECH: Domain/Endpoint → Technology
    - VULNERABLE_TO: Endpoint/Parameter → Finding
    - BELONGS_TO: Domain → Program
    - OWNED_BY: Program → Company
    - PARENT_OF: Company → Company (Cross-Program Intelligence用)
    """
    
    def __init__(
        self,
        uri: Optional[str] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
    ):
        self.uri = uri or os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.user = user or os.getenv("NEO4J_USER", "neo4j")
        self.password = password or os.getenv("NEO4J_PASSWORD", "shigoku2024")
        self._driver = None
    
    def connect(self) -> bool:
        """Neo4jに接続"""
        try:
            from neo4j import GraphDatabase
            self._driver = GraphDatabase.driver(
                self.uri,
                auth=(self.user, self.password),
                notifications_min_severity="WARNING"
            )
            # Suppress noisy driver-internal notifications
            logging.getLogger("neo4j.notifications").setLevel(logging.WARNING)
            # 接続テスト
            with self._driver.session() as session:
                session.run("RETURN 1")
            return True
        except Exception as e:
            print(f"Neo4j connection failed: {e}")
            return False
    
    def close(self) -> None:
        """接続を閉じる"""
        if self._driver:
            self._driver.close()
    
    def _ensure_connected(self) -> None:
        """接続を確保"""
        if not self._driver:
            self.connect()
    
    # ===== ノード作成 =====
    
    def create_program(self, name: str, platform: str = "hackerone", **props) -> str:
        """プログラムノードを作成"""
        self._ensure_connected()
        query = """
        MERGE (p:Program {name: $name})
        SET p.platform = $platform
        SET p += $props
        RETURN elementId(p) as node_id
        """
        with self._driver.session() as session:
            result = session.run(query, name=name, platform=platform, props=props)
            return result.single()["node_id"]
    
    def create_domain(self, domain: str, program: Optional[str] = None, **props) -> str:
        """ドメインノードを作成"""
        self._ensure_connected()
        query = """
        MERGE (d:Domain {name: $domain})
        SET d += $props
        RETURN elementId(d) as node_id
        """
        with self._driver.session() as session:
            result = session.run(query, domain=domain, props=props)
            node_id = result.single()["node_id"]
        
        if program:
            self.link_domain_to_program(domain, program)
        
        return node_id
    
    def create_endpoint(
        self,
        url: str,
        method: str = "GET",
        params: Optional[list[str]] = None,
        **props
    ) -> str:
        """エンドポイントノードを作成"""
        self._ensure_connected()
        query = """
        MERGE (e:Endpoint {url: $url, method: $method})
        SET e += $props
        RETURN elementId(e) as node_id
        """
        with self._driver.session() as session:
            result = session.run(query, url=url, method=method, props=props)
            node_id = result.single()["node_id"]
        
        # パラメータノードも作成
        if params:
            for param in params:
                self.create_parameter(param, url, method)
        
        return node_id
    
    def create_parameter(self, name: str, endpoint_url: str, method: str = "GET", **props) -> str:
        """パラメータノードを作成"""
        self._ensure_connected()
        query = """
        MERGE (p:Parameter {name: $name, endpoint: $endpoint})
        SET p += $props
        RETURN elementId(p) as node_id
        """
        with self._driver.session() as session:
            result = session.run(query, name=name, endpoint=f"{method}:{endpoint_url}", props=props)
            node_id = result.single()["node_id"]
        
        # エンドポイントとリンク
        self._link_endpoint_to_param(endpoint_url, method, name)
        return node_id
    
    def create_technology(self, name: str, version: Optional[str] = None, **props) -> str:
        """技術スタックノードを作成"""
        self._ensure_connected()
        query = """
        MERGE (t:Technology {name: $name})
        SET t.version = $version
        SET t += $props
        RETURN elementId(t) as node_id
        """
        with self._driver.session() as session:
            result = session.run(query, name=name, version=version, props=props)
            return result.single()["node_id"]
    
    def create_finding(
        self,
        title: str,
        vuln_type: str,
        severity: str = "medium",
        **props
    ) -> str:
        """脆弱性Findingノードを作成"""
        self._ensure_connected()
        import time
        query = """
        CREATE (f:Finding {
            title: $title,
            type: $vuln_type,
            severity: $severity,
            created_at: $timestamp
        })
        SET f += $props
        RETURN elementId(f) as node_id
        """
        with self._driver.session() as session:
            result = session.run(
                query,
                title=title,
                vuln_type=vuln_type,
                severity=severity,
                timestamp=time.time(),
                props=props
            )
            return result.single()["node_id"]
    
    def create_company(self, name: str, parent: Optional[str] = None, **props) -> str:
        """企業ノードを作成（Cross-Program Intelligence用）"""
        self._ensure_connected()
        query = """
        MERGE (c:Company {name: $name})
        SET c += $props
        RETURN elementId(c) as node_id
        """
        with self._driver.session() as session:
            result = session.run(query, name=name, props=props)
            node_id = result.single()["node_id"]
        
        if parent:
            self.link_company_parent(name, parent)
        
        return node_id
    
    # ===== リンク作成 =====
    
    def link_domain_to_ip(self, domain: str, ip: str) -> None:
        """ドメイン → IP のリンクを作成"""
        self._ensure_connected()
        query = """
        MATCH (d:Domain {name: $domain})
        MERGE (i:IP {address: $ip})
        MERGE (d)-[:RESOLVES_TO]->(i)
        """
        with self._driver.session() as session:
            session.run(query, domain=domain, ip=ip)
    
    def link_domain_to_program(self, domain: str, program: str) -> None:
        """ドメイン → プログラム のリンクを作成"""
        self._ensure_connected()
        query = """
        MATCH (d:Domain {name: $domain})
        MATCH (p:Program {name: $program})
        MERGE (d)-[:BELONGS_TO]->(p)
        """
        with self._driver.session() as session:
            session.run(query, domain=domain, program=program)
    
    def link_domain_to_tech(self, domain: str, tech: str) -> None:
        """ドメイン → 技術スタック のリンクを作成"""
        self._ensure_connected()
        query = """
        MATCH (d:Domain {name: $domain})
        MERGE (t:Technology {name: $tech})
        MERGE (d)-[:USES_TECH]->(t)
        """
        with self._driver.session() as session:
            session.run(query, domain=domain, tech=tech)
    
    def link_endpoint_to_finding(self, endpoint_url: str, finding_title: str) -> None:
        """エンドポイント → Finding のリンクを作成"""
        self._ensure_connected()
        query = """
        MATCH (e:Endpoint {url: $url})
        MATCH (f:Finding {title: $title})
        MERGE (e)-[:VULNERABLE_TO]->(f)
        """
        with self._driver.session() as session:
            session.run(query, url=endpoint_url, title=finding_title)
    
    def link_company_parent(self, child: str, parent: str) -> None:
        """子会社 → 親会社 のリンク（Cross-Program Intelligence用）"""
        self._ensure_connected()
        query = """
        MATCH (c:Company {name: $child})
        MERGE (p:Company {name: $parent})
        MERGE (p)-[:PARENT_OF]->(c)
        """
        with self._driver.session() as session:
            session.run(query, child=child, parent=parent)
    
    def _link_endpoint_to_param(self, url: str, method: str, param: str) -> None:
        """内部: エンドポイント → パラメータ のリンク"""
        query = """
        MATCH (e:Endpoint {url: $url, method: $method})
        MATCH (p:Parameter {name: $param, endpoint: $endpoint_key})
        MERGE (e)-[:ACCEPTS_PARAM]->(p)
        """
        with self._driver.session() as session:
            session.run(query, url=url, method=method, param=param, endpoint_key=f"{method}:{url}")
    
    # ===== 検索 =====
    
    def find_related_assets(self, node_id: str, depth: int = 2) -> list[dict]:
        """関連資産を検索"""
        self._ensure_connected()
        query = f"""
        MATCH (n)-[r*1..{depth}]-(related)
        WHERE elementId(n) = $node_id
        RETURN DISTINCT labels(related) as labels, properties(related) as props
        LIMIT 100
        """
        with self._driver.session() as session:
            result = session.run(query, node_id=node_id)
            return [{"labels": r["labels"], "properties": r["props"]} for r in result]
    
    def get_attack_surface(self, program: str) -> dict:
        """プログラムの攻撃対象領域を取得"""
        self._ensure_connected()
        query = """
        MATCH (p:Program {name: $program})<-[:BELONGS_TO]-(d:Domain)
        OPTIONAL MATCH (d)-[:RESOLVES_TO]->(i:IP)
        OPTIONAL MATCH (d)-[:USES_TECH]->(t:Technology)
        RETURN 
            collect(DISTINCT d.name) as domains,
            collect(DISTINCT i.address) as ips,
            collect(DISTINCT t.name) as technologies
        """
        with self._driver.session() as session:
            result = session.run(query, program=program)
            record = result.single()
            return {
                "domains": record["domains"] or [],
                "ips": record["ips"] or [],
                "technologies": record["technologies"] or [],
            }
    
    def find_related_companies(self, company: str) -> list[str]:
        """関連企業（親子関係）を検索（Cross-Program Intelligence用）"""
        self._ensure_connected()
        query = """
        MATCH (c:Company {name: $company})-[:PARENT_OF*0..3]-(related:Company)
        WHERE related.name <> $company
        RETURN DISTINCT related.name as name
        """
        with self._driver.session() as session:
            result = session.run(query, company=company)
            return [r["name"] for r in result]
    
    def find_domains_by_tech(self, tech: str, program: Optional[str] = None) -> list[str]:
        """特定技術スタックを使用するドメインを検索"""
        self._ensure_connected()
        if program:
            query = """
            MATCH (d:Domain)-[:USES_TECH]->(t:Technology {name: $tech})
            MATCH (d)-[:BELONGS_TO]->(p:Program {name: $program})
            RETURN d.name as domain
            """
            params = {"tech": tech, "program": program}
        else:
            query = """
            MATCH (d:Domain)-[:USES_TECH]->(t:Technology {name: $tech})
            RETURN d.name as domain
            """
            params = {"tech": tech}
        
        with self._driver.session() as session:
            result = session.run(query, **params)
            return [r["domain"] for r in result]
    
    def get_findings_by_program(self, program: str) -> list[dict]:
        """プログラムの全Findingを取得"""
        self._ensure_connected()
        query = """
        MATCH (p:Program {name: $program})<-[:BELONGS_TO]-(d:Domain)
        MATCH (e:Endpoint)-[:VULNERABLE_TO]->(f:Finding)
        WHERE e.url CONTAINS d.name
        RETURN f.title as title, f.type as type, f.severity as severity
        """
        with self._driver.session() as session:
            result = session.run(query, program=program)
            return [dict(r) for r in result]
