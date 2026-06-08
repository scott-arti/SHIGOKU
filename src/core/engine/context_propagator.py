"""
ContextPropagator - タスク実行結果からコンテキストを抽出

タスク実行結果やFindingからJWT、Admin panel、新エンドポイント等を抽出し、
TaskContext として返す。

用途:
- execute_with_replan() 内でタスク結果を分析
- 発見した情報をキュー内タスクに伝播
"""

import logging
import re
from typing import Dict, Any, List, Optional, Tuple, Pattern

from src.core.engine.task_queue import TaskContext

logger = logging.getLogger(__name__)


class ContextPropagator:
    """
    タスク実行結果からコンテキストを抽出
    
    JWT、Bearer Token、Admin panel等を正規表現で検出し、
    TaskContext として返す。
    """
    
    # トークン検出パターン
    TOKEN_PATTERNS: Dict[str, Pattern[str]] = {
        "jwt": re.compile(
            r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*",
            re.IGNORECASE
        ),
        "bearer": re.compile(
            r"Bearer\s+([A-Za-z0-9-_.]+)",
            re.IGNORECASE
        ),
        "api_key": re.compile(
            r"(?:api[_-]?key|apikey|x-api-key)[=:\s]+['\"]?([A-Za-z0-9-_]{20,})['\"]?",
            re.IGNORECASE
        ),
        "session": re.compile(
            r"(?:session[_-]?id|sessionid|PHPSESSID|JSESSIONID)[=:\s]+['\"]?([A-Za-z0-9-_]{16,})['\"]?",
            re.IGNORECASE
        ),
    }
    
    # 重要パス検出パターン: (pattern, finding_name)
    CRITICAL_PATH_PATTERNS: List[Tuple[Pattern[str], str]] = [
        (re.compile(r"/admin(?:/|$)", re.IGNORECASE), "admin_panel"),
        (re.compile(r"/dashboard(?:/|$)", re.IGNORECASE), "dashboard"),
        (re.compile(r"/api/v[0-9]+", re.IGNORECASE), "api_versioned"),
        (re.compile(r"/graphql(?:/|$)", re.IGNORECASE), "graphql"),
        (re.compile(r"/swagger(?:/|$)", re.IGNORECASE), "swagger"),
        (re.compile(r"/debug(?:/|$)", re.IGNORECASE), "debug_endpoint"),
        (re.compile(r"/actuator(?:/|$)", re.IGNORECASE), "actuator"),
        (re.compile(r"\.git(?:/|$)", re.IGNORECASE), "git_exposed"),
        (re.compile(r"/\.env(?:$|\.)", re.IGNORECASE), "env_file"),
        (re.compile(r"/wp-admin(?:/|$)", re.IGNORECASE), "wordpress_admin"),
    ]
    
    # URL検出パターン
    URL_PATTERN: Pattern[str] = re.compile(
        r"https?://[^\s\"'<>`]+",
        re.IGNORECASE
    )
    
    # パラメータ検出パターン（クエリパラメータ）
    PARAM_PATTERN: Pattern[str] = re.compile(
        r"[?&]([a-zA-Z_][a-zA-Z0-9_]*)=",
        re.IGNORECASE
    )
    
    # 技術スタック検出パターン
    TECH_PATTERNS: Dict[str, Pattern[str]] = {
        "php": re.compile(r"\.php(?:\?|$)|X-Powered-By:\s*PHP", re.IGNORECASE),
        "java": re.compile(r"\.jsp|JSESSIONID|X-Powered-By:\s*Servlet", re.IGNORECASE),
        "aspnet": re.compile(r"\.aspx?|ASP\.NET|__VIEWSTATE", re.IGNORECASE),
        "nodejs": re.compile(r"X-Powered-By:\s*Express", re.IGNORECASE),
        "python": re.compile(r"X-Powered-By:\s*(?:Flask|Django|gunicorn)", re.IGNORECASE),
        "ruby": re.compile(r"X-Powered-By:\s*(?:Phusion|Rails)", re.IGNORECASE),
        "wordpress": re.compile(r"/wp-content/|/wp-includes/", re.IGNORECASE),
        "drupal": re.compile(r"/sites/default/|Drupal", re.IGNORECASE),
        "laravel": re.compile(r"laravel_session|XSRF-TOKEN", re.IGNORECASE),
        "spring": re.compile(r"X-Application-Context|/actuator/", re.IGNORECASE),
    }
    
    def __init__(self, base_domain: Optional[str] = None):
        """
        Args:
            base_domain: ベースドメイン（スコープ外URLを除外する場合）
        """
        self.base_domain = base_domain
    
    def extract(self, result: Dict[str, Any]) -> TaskContext:
        """
        タスク実行結果からコンテキストを抽出
        
        Args:
            result: タスク実行結果（_dispatch() の戻り値）
        
        Returns:
            抽出されたコンテキスト
        """
        context = TaskContext()
        
        # 結果全体をテキスト化して検索
        text = self._result_to_text(result)
        
        # 1. トークン抽出
        context.auth_tokens = self._extract_tokens(text)
        
        # 2. URL/エンドポイント抽出
        context.discovered_endpoints = self._extract_endpoints(text)
        
        # 3. 重要パス検出
        context.critical_findings = self._detect_critical_paths(text)
        
        # 4. パラメータ抽出
        context.discovered_params = self._extract_params(text)
        
        # 5. 技術スタック検出
        context.tech_stack = self._detect_tech_stack(text)
        
        # 6. 結果内の構造化データから追加抽出
        self._extract_from_structured(result, context)
        
        if not context.is_empty():
            logger.debug(
                "Extracted context: tokens=%d, endpoints=%d, critical=%d",
                len(context.auth_tokens),
                len(context.discovered_endpoints),
                len(context.critical_findings)
            )
        
        return context
    
    def extract_from_finding(self, finding: Any) -> TaskContext:
        """
        Finding オブジェクトからコンテキストを抽出
        
        Args:
            finding: Finding オブジェクト
        
        Returns:
            抽出されたコンテキスト
        """
        context = TaskContext()
        
        # Finding の各フィールドを検索
        texts = []
        
        if hasattr(finding, 'evidence') and finding.evidence:
            if isinstance(finding.evidence, dict):
                texts.append(str(finding.evidence))
            else:
                texts.append(str(finding.evidence))
        
        if hasattr(finding, 'description'):
            texts.append(str(finding.description))
        
        if hasattr(finding, 'raw_request'):
            texts.append(str(finding.raw_request))
        
        if hasattr(finding, 'raw_response'):
            texts.append(str(finding.raw_response))
        
        combined_text = "\n".join(texts)
        
        # 抽出
        context.auth_tokens = self._extract_tokens(combined_text)
        context.discovered_endpoints = self._extract_endpoints(combined_text)
        context.critical_findings = self._detect_critical_paths(combined_text)
        context.discovered_params = self._extract_params(combined_text)
        context.tech_stack = self._detect_tech_stack(combined_text)
        
        return context
    
    def _result_to_text(self, result: Dict[str, Any]) -> str:
        """結果を検索可能なテキストに変換"""
        parts = []
        
        def flatten(obj: Any, depth: int = 0) -> None:
            if depth > 10:  # 深さ制限
                return
            
            if isinstance(obj, str):
                parts.append(obj)
            elif isinstance(obj, dict):
                for v in obj.values():
                    flatten(v, depth + 1)
            elif isinstance(obj, (list, tuple)):
                for item in obj:
                    flatten(item, depth + 1)
        
        flatten(result)
        return "\n".join(parts)
    
    def _extract_tokens(self, text: str) -> Dict[str, str]:
        """認証トークンを抽出"""
        tokens: Dict[str, str] = {}
        
        for token_type, pattern in self.TOKEN_PATTERNS.items():
            match = pattern.search(text)
            if match:
                # グループがあればグループを使用、なければ全体マッチ
                token_value = match.group(1) if match.lastindex else match.group(0)
                tokens[token_type] = token_value
                logger.debug("Found %s token: %s...", token_type, token_value[:20])
        
        return tokens
    
    def _extract_endpoints(self, text: str) -> List[str]:
        """エンドポイント/URLを抽出"""
        endpoints: List[str] = []
        
        for match in self.URL_PATTERN.finditer(text):
            url = str(match.group(0) or "").strip()
            if not url:
                continue
            url = url.strip("`'\"")
            url = url.rstrip("`'\"),.;:]}>")
            if not url:
                continue
            
            # スコープチェック（設定されている場合）
            if self.base_domain:
                if self.base_domain not in url:
                    continue
            
            # 重複排除
            if url not in endpoints:
                endpoints.append(url)
        
        # 最大100件に制限
        return endpoints[:100]
    
    def _detect_critical_paths(self, text: str) -> List[str]:
        """重要パスを検出"""
        findings: List[str] = []
        
        for pattern, finding_name in self.CRITICAL_PATH_PATTERNS:
            if pattern.search(text):
                if finding_name not in findings:
                    findings.append(finding_name)
                    logger.debug("Detected critical path: %s", finding_name)
        
        return findings
    
    def _extract_params(self, text: str) -> List[str]:
        """クエリパラメータを抽出"""
        params: List[str] = []
        
        for match in self.PARAM_PATTERN.finditer(text):
            param = match.group(1)
            if param not in params:
                params.append(param)
        
        # 最大50件に制限
        return params[:50]
    
    def _detect_tech_stack(self, text: str) -> List[str]:
        """技術スタックを検出"""
        detected: List[str] = []
        
        for tech_name, pattern in self.TECH_PATTERNS.items():
            if pattern.search(text):
                if tech_name not in detected:
                    detected.append(tech_name)
        
        return detected
    
    def _extract_from_structured(
        self,
        result: Dict[str, Any],
        context: TaskContext,
    ) -> None:
        """構造化データから追加情報を抽出"""
        
        # new_assets フィールド
        new_assets = result.get("new_assets", [])
        for asset in new_assets:
            if isinstance(asset, str) and asset not in context.discovered_endpoints:
                context.discovered_endpoints.append(asset)
        
        # findings フィールド
        findings = result.get("findings", [])
        for finding in findings:
            if isinstance(finding, dict):
                # 脆弱性タイプに基づく critical_findings 追加
                vuln_type = finding.get("type", "").lower()
                if "admin" in vuln_type and "admin_panel" not in context.critical_findings:
                    context.critical_findings.append("admin_panel")
                if "graphql" in vuln_type and "graphql" not in context.critical_findings:
                    context.critical_findings.append("graphql")
        
        # tokens フィールド（直接渡される場合）
        tokens = result.get("tokens", {})
        if isinstance(tokens, dict):
            context.auth_tokens.update(tokens)
        
        # WAF情報
        waf_info = result.get("waf_info", {})
        if isinstance(waf_info, dict):
            context.waf_info.update(waf_info)

        # 7. Tagged Files Processing (Phase 3b Recon Integration)
        # ReconPipeline step8 で返される tagged_* キーを処理
        for key, value in result.items():
            if key.startswith("tagged_") and isinstance(value, dict):
                file_path = value.get("file")
                tags = value.get("tags", [])
                
                if file_path:
                    try:
                        import json
                        from pathlib import Path
                        path = Path(file_path)
                        if path.exists():
                            with open(path, "r") as f:
                                count = 0
                                for line in f:
                                    if not line.strip(): continue
                                    item = json.loads(line)
                                    url = item.get("url")
                                    if url and url not in context.discovered_endpoints:
                                        context.discovered_endpoints.append(url)
                                        count += 1
                                    
                                    # パラメータ抽出
                                    if "params" in item:
                                        for p in item["params"]:
                                            if p not in context.discovered_params:
                                                context.discovered_params.append(p)
                                
                                logger.debug(f" extracted {count} items from {key}")
                                
                        # タグに基づいて critical_findings に追加
                        for tag in tags:
                            if tag not in context.critical_findings:
                                context.critical_findings.append(tag)
                                logger.info(f"Context trigger: {tag} (from {key})")

                    except Exception as e:
                        logger.warning(f"Failed to process tagged file {key}: {e}")


def create_context_propagator(
    base_domain: Optional[str] = None,
) -> ContextPropagator:
    """ContextPropagator 作成ヘルパー"""
    return ContextPropagator(base_domain=base_domain)
