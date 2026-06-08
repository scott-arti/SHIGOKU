import logging
from typing import List, Any, Optional
from urllib.parse import urlparse
from src.core.domain.model.task import Task
from src.core.infra.knowledge_graph import KnowledgeGraph

logger = logging.getLogger(__name__)

class AttackPlanner:
    """
    Neo4j 知識グラフを基にした動的攻撃プランナー
    Recon フェーズで得られた技術スタックやエンドポイント情報を解析し、
    最適な Attack タスクを推論して MasterConductor に提案する。
    """

    def __init__(self, kg: Optional[KnowledgeGraph] = None):
        self.kg = kg

    def infer_tasks(self, kg: KnowledgeGraph, context: Any, insights: Optional[list] = None) -> List[Task]:
        """
        知識グラフを解析し、推奨される攻撃タスクを生成する
        
        Args:
            kg: 知識グラフ(Neo4j)
            context: 実行コンテキスト
            insights: SelfReflectionからの洞察リスト
        """
        if not kg:
            return []

        tasks = []
        scope_hosts = self._resolve_scope_hosts(context)
        if not scope_hosts:
            logger.warning("[*] AttackPlanner scope is empty. Skipping KG task inference to avoid out-of-scope tasks.")
            return []
        domain = scope_hosts[0]
        
        logger.info("[*] Inferring attack tasks for domain: %s (Insights: %d)", domain, len(insights or []))

        # 1. 技術スタックに基づく推論
        tasks.extend(self._infer_by_technology(kg, domain))

        # 2. 未テストのエンドポイントに基づく推論
        tasks.extend(self._infer_by_untested_endpoints(kg, domain, scope_hosts))

        # 3. Insights に基づく調整
        if insights:
            tasks = self._apply_insights(tasks, insights)

        logger.info("[*] Inferred %d additional tasks from KG", len(tasks))
        return tasks

    def _normalize_host_candidate(self, raw: Any) -> str:
        candidate = str(raw or "").strip()
        if not candidate:
            return ""
        if candidate.startswith(("http://", "https://")):
            parsed = urlparse(candidate)
        else:
            parsed = urlparse(f"//{candidate}")
        host = (parsed.hostname or parsed.netloc or "").strip().lower()
        if not host:
            # bare host fallback
            host = candidate.split("/")[0].split("?")[0].strip().lower()
        if ":" in host:
            host = host.split(":", 1)[0].strip()
        return host

    def _resolve_scope_hosts(self, context: Any) -> list[str]:
        hosts: list[str] = []
        seen: set[str] = set()

        def _push(raw: Any) -> None:
            host = self._normalize_host_candidate(raw)
            if not host or host in seen:
                return
            seen.add(host)
            hosts.append(host)

        _push(getattr(context, "target_domain", ""))

        target_info = getattr(context, "target_info", {})
        if isinstance(target_info, dict):
            _push(target_info.get("target", ""))
            _push(target_info.get("host", ""))
            for raw in target_info.get("in_scope_domains", []) or []:
                _push(raw)

        for raw in (getattr(context, "discovered_assets", []) or [])[:20]:
            _push(raw)

        return hosts

    def _is_url_in_scope(self, url: str, scope_hosts: list[str]) -> bool:
        if not scope_hosts:
            return False
        host = self._normalize_host_candidate(url)
        if not host:
            return False
        return any(host == scope_host or host.endswith(f".{scope_host}") for scope_host in scope_hosts)

    def _apply_insights(self, tasks: List[Task], insights: list) -> List[Task]:
        """Insightsに基づきタスクの優先度調整やフィルタリングを行う"""
        from src.core.intelligence.self_reflection import ReflectionInsight
        
        filtered_tasks = []
        for task in tasks:
            skipped = False
            for insight in insights:
                if not isinstance(insight, ReflectionInsight):
                    continue
                
                # 失敗パターンに基づくフィルタリング
                if insight.category == "failure_pattern":
                    # エージェントタイプが頻繁に失敗/ブロックされている場合、優先度を下げるかスキップ
                    if task.agent_type in insight.insight.lower():
                        if insight.confidence > 0.8:
                            logger.info("Insight-driven skip: %s (Reason: %s)", task.name, insight.insight)
                            skipped = True
                            break
                        else:
                            task.priority = max(10, task.priority - 30)
                            logger.info("Insight-driven priority reduction: %s", task.name)

                # 成功パターンに基づくブースト
                if insight.category == "success_pattern":
                    if task.agent_type in insight.insight.lower():
                        task.priority = min(100, task.priority + 20)
                        logger.info("Insight-driven priority boost: %s", task.name)

            if not skipped:
                filtered_tasks.append(task)
        
        return filtered_tasks

    def _infer_by_technology(self, kg: KnowledgeGraph, domain: str) -> List[Task]:
        """技術スタックから脆弱性を推論"""
        tasks = []
        # KG からドメインに紐づく技術を取得
        surface = kg.get_attack_surface(domain)
        techs = surface.get("technologies", [])

        # 推論マッピング
        tech_rules = {
            "Nginx": ["cve_scan", "config_audit"],
            "Apache": ["cve_scan", "config_audit"],
            "PHP": ["rce_test", "lfi_test"],
            "WordPress": ["wp_scan", "plugin_exploit"],
            "Spring Boot": ["actuator_check", "java_deserialization"],
            "Django": ["template_injection", "config_check"],
            "Laravel": ["debug_mode_check", "ignition_exploit"],
            "Firebase": ["security_rule_audit"],
            "Git": ["git_config_exposure"]
        }

        import uuid
        for tech in techs:
            actions = tech_rules.get(tech, [])
            for action in actions:
                tasks.append(Task(
                    id=f"kg-tech-{uuid.uuid4().hex[:6]}",
                    name=f"Tech-based: {action} on {tech}",
                    agent_type=self._map_action_to_agent(action),
                    action="execute",
                    priority=70,
                    params={"target": domain, "reason": f"Detected tech: {tech}", "tags": ["kg_inferred", "tech_match"]}
                ))
        
        return tasks

    def _infer_by_untested_endpoints(self, kg: KnowledgeGraph, domain: str, scope_hosts: list[str]) -> List[Task]:
        """未テストのエンドポイントを Attack 対象として抽出"""
        tasks = []
        untested = kg.get_untested_endpoints(domain)
        
        import uuid
        for endpoint in untested:
            url = str(endpoint.get("url", "") or "").strip()
            if not url:
                continue
            if not self._is_url_in_scope(url, scope_hosts):
                logger.debug("Skipping out-of-scope KG endpoint inference: %s", url)
                continue
            method = endpoint.get("method", "GET")
            
            # 重要そうなエンドポイント(API, Admin等)には高い優先度
            priority = 50
            if any(k in url.lower() for k in ["api", "v1", "v2", "admin", "user", "auth", "login"]):
                priority = 80

            tasks.append(Task(
                id=f"kg-end-{uuid.uuid4().hex[:6]}",
                name=f"Fuzzing endpoint: {url}",
                agent_type="fuzzing",
                action="execute",
                priority=priority,
                target=url,
                params={"target": url, "method": method, "tags": ["kg_inferred", "untested_endpoint"]}
            ))
        
        return tasks

    def _map_action_to_agent(self, action: str) -> str:
        """アクション名からエージェントタイプへの簡易マッピング"""
        mapping = {
            "cve_scan": "vuln_scanner",
            "config_audit": "config_auditor",
            "rce_test": "injection_hunter",
            "lfi_test": "injection_hunter",
            "wp_scan": "vuln_scanner",
            "actuator_check": "config_auditor",
            "java_deserialization": "injection_hunter",
            "template_injection": "injection_hunter",
            "debug_mode_check": "config_auditor",
            "security_rule_audit": "config_auditor",
            "git_config_exposure": "discovery"
        }
        return mapping.get(action, "generic_agent")
