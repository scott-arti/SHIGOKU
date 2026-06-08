from typing import Optional, Dict, List, Any
import re
import json
import asyncio
import subprocess
import logging
from pathlib import Path
from src.core.agent import Agent as GeneralAgent
from src.prompts import get_agent_prompt

logger = logging.getLogger(__name__)
from src.core.intel.fingerprinter import Fingerprinter

from src.core.engine.agent_registry import register_agent

@register_agent(
    names=["scopeparser", "scope_parser", "scope", "fingerprinter", "tech_detect", "wappalyzer"],
    tags=["recon", "scope", "utils"]
)
class ScopeParserAgent(GeneralAgent):
    """
    Scope Parser Agent (統合版)
    ターゲット情報のスコープ解析、除外設定、IPレンジ計算、
    および技術スタック特定（Wappalyzer的な機能）を行うエージェント。
    
    統合: 旧FingerprinterAgentの機能を含む
    """
    def __init__(self, config: 'AgentConfig' = None, workspace_root: Optional[str] = None, project_manager: Any = None, master_conductor: Any = None, **kwargs):
        # AgentFactory (Unified Interface Phase 2) 対応
        if config:
            # configが渡された場合 (AgentFactory経由)
            super().__init__(
                name=config.name,
                instructions=config.instructions,
                model=config.model,
                mode="security",
                tools=getattr(config, 'tools', None),
                workspace_root=workspace_root,
                project_manager=project_manager,
                master_conductor=master_conductor,
                **kwargs
            )
        else:
            # レガシー呼び出し用フォールバック
            from src.config import settings
            super().__init__(
                name="ScopeParser",
                instructions=get_agent_prompt("scope_parser"),
                model=getattr(settings, "model", None) or getattr(settings, "model_output", "deepseek/deepseek-chat"),
                mode="security",
                workspace_root=workspace_root,
                project_manager=project_manager,
                master_conductor=master_conductor,
                **kwargs
            )
    
    async def process(self, scope_input: str, workspace_root: Optional[str] = None) -> Dict[str, Any]:
        """
        スコープ解析を実行
        
        Args:
            scope_input: スコープ定義文字列またはYAMLファイルパス
            workspace_root: 出力先ワークスペースルート
        
        Returns:
            {
                "targets": [ドメイン/IP/URLのリスト],
                "exclusions": [除外対象のリスト],
                "wildcards": [ワイルドカード展開結果],
                "scope_file_path": "保存先パス (あれば)"
            }
        """
        targets = []
        exclusions = []
        
        # ファイルパスかどうか判定
        if Path(scope_input).exists():
            targets, exclusions = self._parse_yaml_file(scope_input)
        else:
            # 直接テキストとして解析
            targets = self._extract_targets_from_text(scope_input)
        
        result = {
            "targets": targets,
            "exclusions": exclusions,
            "wildcards": self._expand_wildcards(targets),
        }
        
        # Workspace に保存
        if workspace_root:
            scope_file_path = Path(workspace_root) / "scope.json"
            scope_file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(scope_file_path, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            result["scope_file_path"] = str(scope_file_path)
        
        return result
    
    def _parse_yaml_file(self, file_path: str) -> tuple[list[str], list[str]]:
        """YAMLファイルからスコープを抽出"""
        try:
            import yaml
            with open(file_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            
            targets = data.get("targets", []) or data.get("in_scope", [])
            exclusions = data.get("exclusions", []) or data.get("out_of_scope", [])
            
            return targets, exclusions
        except Exception:
            # YAMLパースに失敗した場合はテキストとして処理
            return self._extract_targets_from_file(file_path), []
    
    def _extract_targets_from_file(self, file_path: str) -> list[str]:
        """テキストファイルからターゲットを抽出"""
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        return self._extract_targets_from_text(content)
    
    def _extract_targets_from_text(self, text: str) -> list[str]:
        """テキストからドメイン/IP/URLを抽出"""
        targets = []
        
        # URLパターン
        url_pattern = r'https?://[^\s<>"]+' 
        urls = re.findall(url_pattern, text)
        targets.extend(urls)
        
        # ドメインパターン（ワイルドカード含む）
        domain_pattern = r'(?:\*\.)?[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*'
        domains = re.findall(domain_pattern, text)
        targets.extend([d for d in domains if d not in targets and '.' in d])
        
        # IPv4パターン
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?\b'
        ips = re.findall(ip_pattern, text)
        targets.extend([ip for ip in ips if ip not in targets])
        
        return list(set(targets))  # 重複除去
            
    def _expand_wildcards(self, targets: list[str]) -> Dict[str, str]:
        """
        ワイルドカード (*.example.com) の説明を返す
        
        実際のサブドメイン列挙はReconBotの仕事なので、ここでは解釈のみ
        """
        wildcards = {}
        for target in targets:
            if target.startswith("*."):
                wildcards[target] = f"All subdomains of {target[2:]}"
        return wildcards
    
    # ===========================================
    # Fingerprinting機能 (旧FingerprinterAgentから統合)
    # ===========================================
    
    async def fingerprint(self, target_url: str, context: Optional[Dict] = None) -> Dict[str, Any]:
        """
        技術スタック検出を実行 (Async)
        
        Args:
            target_url: 対象URL
            context: ExecutionContextへの参照（tech_stack更新用）
        
        Returns:
            {
                "technologies": [検出された技術のリスト],
                "confidence": "検出の確信度 (high/medium/low)",
                "method": "検出方法"
            }
        """
        technologies = []
        method = "passive_analysis"
        
        # Method 1: whatweb (コマンドが利用可能なら)
        try:
            whatweb_result = await self._run_whatweb(target_url)
            if whatweb_result:
                technologies.extend(whatweb_result)
                method = "whatweb_cli"
        except Exception as e:
            logger.debug("whatweb execution failed: %s", e)
        
        # Method 2: Fingerprinter Module (Header + HTML analysis)
        # whatwebが失敗した場合や、詳細なHTML解析が必要な場合に使用
        if not technologies or method == "whatweb_cli":  # 補完として使う
            logger.info(f"🔍 Starting passive fingerprinting for {target_url}...")
            try:
                from src.core.infra.network_client import AsyncNetworkClient
                async with AsyncNetworkClient() as client:
                    response = await client.request("GET", target_url, timeout=10, follow_redirects=True)
                
                # Fingerprinterモジュールを使用
                fp = Fingerprinter()
                detected_info = fp.identify(response.text, response.headers)
                
                detected_names = [info.name for info in detected_info]
                
                # Only extend if new technologies are found or if whatweb didn't find anything
                if detected_names and (not technologies or method == "whatweb_cli"):
                    technologies.extend(detected_names)
                    if not method == "whatweb_cli": # Only change method if whatweb wasn't the primary source
                        method = "passive_fingerprint"
                    logger.info(f"✅ Passive fingerprinting found technologies: {detected_names}")
                elif not detected_names:
                    logger.info(f"ℹ️ Passive fingerprinting found no new technologies for {target_url}.")
            except Exception as e:
                logger.debug(f"Passive fingerprinting failed for {target_url}: {e}")
                logger.warning(f"⚠️ Passive fingerprinting failed for {target_url}: {e}")
        
        # 重複除去
        technologies = list(set(technologies))
        
        # Context の tech_stack を更新
        if context and technologies:
            if "tech_stack" not in context:
                context["tech_stack"] = []
            context["tech_stack"].extend(technologies)
            # context["tech_stack"] はリストであるべき
            context["tech_stack"] = list(set(context["tech_stack"]))
        
        return {
            "technologies": technologies,
            "confidence": "high" if "whatweb_cli" in method else "medium",
            "method": method
        }
    
    async def _run_whatweb(self, url: str) -> List[str]:
        """whatweb コマンドを実行して技術を検出 (Async)"""
        try:
            proc = await asyncio.create_subprocess_exec(
                "whatweb", "-a", "3", "--colour=never", url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
            
            if proc.returncode == 0:
                output = stdout.decode()
                techs = []
                for match in re.findall(r'(\w+)(?:[\d\.]+])?', output):
                    if match and len(match) > 2:
                        techs.append(match)
                return list(set(techs))[:10]
        except Exception:
            pass
        return []
    



# 後方互換性のためのエイリアス（非推奨）
FingerprinterAgent = ScopeParserAgent
