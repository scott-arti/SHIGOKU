import logging
import asyncio
import ipaddress
from typing import List, Dict, Any, Optional
from datetime import datetime
from urllib.parse import urlparse, urlunparse

from src.core.agents.base import BaseAgent
from src.core.config.settings import get_settings
from src.core.infra.network_client import AsyncNetworkClient
from src.core.models.url_context import RichUrlContext, TagMatch
from src.core.agents.specialized.caido_auth import CaidoAuthResolver, CaidoAuthError

logger = logging.getLogger(__name__)

class CaidoSitemapAgent(BaseAgent):
    """CaidoのGraphQL APIを使用し、Sitemapやリクエスト履歴からエンドポイントを抽出する専門エージェント"""

    def __init__(self, **kwargs):
        cfg = get_settings()
        default_model = cfg.model if getattr(cfg, "model", "") else "deepseek/deepseek-chat"
        super().__init__(
            config={
                "name": "CaidoSitemapAgent",
                "description": "Extracts endpoints and context from Caido via GraphQL API",
                "model": kwargs.get("model", default_model),
                "instructions": "CaidoのSitemapデータを解析し、SHIGOKUが攻撃可能なエンドポイントを抽出してください。"
            },
            **kwargs
        )
        self.settings = cfg
        # 末尾の / を取り除いて正規化
        self.caido_url = self.settings.caido.url.rstrip("/")
        self.caido_token = self.settings.caido.token
        self.caido_auth = CaidoAuthResolver(self.caido_url, self.caido_token, timeout_seconds=30)

    @staticmethod
    def _normalize_host_token(host: Optional[str]) -> str:
        token = str(host or "").strip().lower()
        if not token:
            return ""

        # Accept host-like tokens, netloc strings (host:port / [::1]:port), and full URLs.
        try:
            parsed = urlparse(token if "://" in token else f"//{token}")
            hostname = str(parsed.hostname or "").strip().lower()
            if hostname:
                return hostname
        except Exception:
            pass

        if token.startswith("[") and token.endswith("]"):
            token = token[1:-1]

        if ":" in token and token.count(":") == 1:
            maybe_host, maybe_port = token.rsplit(":", 1)
            if maybe_port.isdigit():
                token = maybe_host

        return token

    @classmethod
    def _is_loopback_host(cls, host: Optional[str]) -> bool:
        token = cls._normalize_host_token(host)
        if not token:
            return False
        if token == "localhost":
            return True
        try:
            return ipaddress.ip_address(token).is_loopback
        except ValueError:
            return False

    @classmethod
    def _host_matches_domain(cls, host: Optional[str], normalized_domain: str) -> bool:
        if not normalized_domain:
            return True

        normalized_host = cls._normalize_host_token(host)
        if not normalized_host:
            return False

        if (
            normalized_host == normalized_domain
            or normalized_host.endswith(f".{normalized_domain}")
        ):
            return True

        if cls._is_loopback_host(normalized_host) and cls._is_loopback_host(normalized_domain):
            return True

        return False

    @staticmethod
    def _normalize_domain_filter(domain: Optional[str]) -> str:
        """Normalize domain filter input.

        Accepts inputs like:
        - example.com
        - *.example.com
        - example.com:8080
        - http://example.com:8080/path
        """
        token = str(domain or "").strip().lower()
        if not token:
            return ""

        if token.startswith("*."):
            token = token[2:]

        host = ""
        if "://" in token:
            try:
                parsed = urlparse(token)
                host = str(parsed.hostname or "").strip().lower()
            except Exception:
                host = ""
        else:
            host = token.split("/", 1)[0]

        if host.startswith("*."):
            host = host[2:]
        return CaidoSitemapAgent._normalize_host_token(host)

    async def _query_graphql(self, query: str, variables: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Caido GraphQL API にクエリを投げる"""
        if not self.caido_token:
            logger.error("Caido API Token is not set. Please set SHIGOKU_CAIDO__TOKEN (e.g., in ~/.zshenv).")
            return {}

        try:
            access_token = await self.caido_auth.get_access_token()
        except CaidoAuthError as exc:
            logger.error("Caido authentication flow failed: %s", exc)
            return {}

        if not access_token:
            logger.error("Could not resolve a usable Caido access token.")
            return {}

        payload = await self._query_graphql_payload(
            query=query,
            variables=variables,
            access_token=access_token,
        )
        if not payload:
            return {}

        errors = payload.get("errors", [])
        if errors and self._has_invalid_token_error(errors):
            # PAT経由のトークンは失効しやすいため1回だけ再取得してリトライ
            if self.caido_auth.is_pat:
                logger.warning("Caido access token rejected. Retrying once after refresh/exchange.")
                try:
                    refreshed_token = await self.caido_auth.get_access_token(force_refresh=True)
                except CaidoAuthError as exc:
                    logger.error("Caido token refresh/exchange failed: %s", exc)
                    return {}
                if not refreshed_token:
                    logger.error("Caido token refresh/exchange returned no access token.")
                    return {}
                payload = await self._query_graphql_payload(
                    query=query,
                    variables=variables,
                    access_token=refreshed_token,
                )
                if not payload:
                    return {}
                errors = payload.get("errors", [])

        if errors:
            logger.error("Caido GraphQL Error: %s", errors)

        return payload.get("data") or {}

    async def _query_graphql_payload(
        self,
        *,
        query: str,
        variables: Optional[Dict[str, Any]],
        access_token: str,
    ) -> Dict[str, Any]:
        """Caido GraphQL API の生レスポンス(payload)を取得する"""
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        
        # ネットワーククライアントの生成 (API自体はプロキシを通さないため proxy_manager を回避するか利用しない)
        async with AsyncNetworkClient() as client:
            try:
                resp = await client.request(
                    "POST",
                    f"{self.caido_url}/graphql",
                    json={"query": query, "variables": variables or {}},
                    headers=headers,
                    use_proxy=False,
                    timeout=30 # 念のため長めに設定
                )
                
                # Caido が動作していない場合は例外になるかここに来ない
                if resp.status_code >= 400:
                    logger.error("Caido API returned HTTP %d", resp.status_code)
                    return {}
                    
                data = resp.json()
                return data if isinstance(data, dict) else {}
                
            except Exception as e:
                logger.error("Failed to connect to Caido API: %s (Is Caido running?)", e)
                return {}

    @staticmethod
    def _has_invalid_token_error(errors: Any) -> bool:
        if not isinstance(errors, list):
            return False
        for error in errors:
            if not isinstance(error, dict):
                continue
            ext = error.get("extensions")
            if isinstance(ext, dict):
                caido_ext = ext.get("CAIDO")
                if isinstance(caido_ext, dict):
                    reason = str(caido_ext.get("reason", "") or "").upper()
                    code = str(caido_ext.get("code", "") or "").upper()
                    if reason == "INVALID_TOKEN" or code == "AUTHORIZATION":
                        return True
            message = str(error.get("message", "") or "").upper()
            if "INVALID_TOKEN" in message:
                return True
        return False

    async def fetch_recent_requests(self, domain: Optional[str] = None, limit: int = 100) -> List[RichUrlContext]:
        """直近のリクエスト履歴からURLコンテキストを抽出 (Sitemap同等)"""
        # 最新のリクエストを取得し、ホストとパスを取り出す
        # CaidoのRequestタイプに基づいたGraphQLクエリを構築
        query = """
        query GetRecentRequests($last: Int!, $before: String) {
            requests(last: $last, before: $before) {
                pageInfo {
                    hasPreviousPage
                    startCursor
                }
                edges {
                    node {
                        id
                        host
                        port
                        isTls
                        method
                        path
                        query
                        raw
                        response {
                            statusCode
                        }
                    }
                }
            }
        }
        """
        normalized_domain = self._normalize_domain_filter(domain)
        page_size = max(50, min(limit, 500))
        data = await self._query_graphql(query, {"last": page_size, "before": None})

        requests_conn = data.get("requests", {}) if isinstance(data, dict) else {}
        edges = list(requests_conn.get("edges", []) or [])
        page_info = requests_conn.get("pageInfo", {}) if isinstance(requests_conn, dict) else {}
        has_prev = bool(page_info.get("hasPreviousPage"))
        start_cursor = page_info.get("startCursor")

        if not edges:
            logger.warning("No requests returned from Caido API or token invalid.")
            return []

        contexts = []
        seen_urls = set()
        scanned_pages = 1
        scanned_edges = len(edges)

        # When domain is specified, scan deeper if first page did not include matching hosts.
        if normalized_domain:
            search_budget = max(limit * 10, 1000)
            max_pages = max(1, min(50, (search_budget + page_size - 1) // page_size))

            # Fast pre-check: does first page contain any candidate host?
            first_page_has_candidate = any(
                self._host_matches_domain(
                    self._normalize_host_token((edge.get("node") or {}).get("host", "")),
                    normalized_domain,
                )
                for edge in edges
                if isinstance(edge, dict)
            )

            while not first_page_has_candidate and has_prev and start_cursor and scanned_pages < max_pages:
                next_data = await self._query_graphql(query, {"last": page_size, "before": start_cursor})
                next_conn = next_data.get("requests", {}) if isinstance(next_data, dict) else {}
                next_edges = list(next_conn.get("edges", []) or [])
                next_info = next_conn.get("pageInfo", {}) if isinstance(next_conn, dict) else {}
                has_prev = bool(next_info.get("hasPreviousPage"))
                start_cursor = next_info.get("startCursor")
                scanned_pages += 1
                scanned_edges += len(next_edges)
                if not next_edges:
                    break
                edges.extend(next_edges)

                if any(
                    self._host_matches_domain(
                        self._normalize_host_token((edge.get("node") or {}).get("host", "")),
                        normalized_domain,
                    )
                    for edge in next_edges
                    if isinstance(edge, dict)
                ):
                    first_page_has_candidate = True
                    break

            if scanned_pages > 1:
                logger.info(
                    "Caido domain search expanded backward to %d pages (%d requests scanned) for domain '%s'.",
                    scanned_pages,
                    scanned_edges,
                    normalized_domain,
                )

        for edge in edges:
            node = edge.get("node", {})
            if not node:
                continue
                
            host = self._normalize_host_token(node.get("host", ""))
            
            # ドメインでのフィルタリング
            if not self._host_matches_domain(host, normalized_domain):
                continue

            method = node.get("method", "GET")
            path = node.get("path", "/")
            q = node.get("query", "")
            is_tls = node.get("isTls", False)
            port = node.get("port", 443 if is_tls else 80)
            
            # URLの組み立て
            scheme = "https" if is_tls else "http"
            port_str = "" if (scheme == "https" and port == 443) or (scheme == "http" and port == 80) else f":{port}"
            full_path = f"{path}?{q}" if q else path
            full_url = f"{scheme}://{host}{port_str}{full_path}"

            # 重複パターンの簡易排除
            url_key = f"{method}:{full_url}"
            if url_key in seen_urls:
                continue
            seen_urls.add(url_key)
            
            response_status = 0
            if node.get("response"):
                response_status = node.get("response", {}).get("statusCode", 0)
            
            # raw (Base64) からヘッダー情報を抽出
            headers = {}
            auth_context = {}
            raw_b64 = node.get("raw", "")
            if raw_b64:
                import base64
                try:
                    raw_bytes = base64.b64decode(raw_b64)
                    raw_str = raw_bytes.decode('utf-8', errors='ignore')
                    lines = raw_str.split('\r\n')
                    if len(lines) > 1:
                        for line in lines[1:]:
                            if not line.strip():
                                break
                            if ':' in line:
                                k, v = line.split(':', 1)
                                k_strip, v_strip = k.strip(), v.strip()
                                headers[k_strip] = v_strip
                                if k_strip.lower() == "authorization":
                                    auth_context["Authorization"] = v_strip
                                elif k_strip.lower() == "cookie":
                                    auth_context["Cookie"] = v_strip
                except Exception as e:
                    logger.debug("Failed to parse raw request for %s: %s", url_key, e)

            context = RichUrlContext(
                url=full_url,
                method=method,
                headers=headers,
                auth_context=auth_context,
                response_status=response_status,
                source="caido_requests"
            )
            contexts.append(context)
            
            # ID プールへの蓄積を試行 (URLから)
            await self._ingest_if_available(full_url)

        if normalized_domain and not contexts and edges:
            try:
                from collections import Counter

                host_counter: Counter[str] = Counter()
                for edge in edges:
                    node = edge.get("node", {}) if isinstance(edge, dict) else {}
                    raw_host = str(node.get("host", "") or "").strip().lower()
                    host_no_port = raw_host.split(":", 1)[0]
                    if host_no_port:
                        host_counter[host_no_port] += 1

                top_hosts = ", ".join(
                    f"{host}({count})" for host, count in host_counter.most_common(8)
                )
                logger.warning(
                    "Caido returned requests but none matched domain filter '%s'. Top hosts in buffer: %s",
                    normalized_domain,
                    top_hosts or "-",
                )
            except Exception:
                pass

        logger.info("Extracted %d unique endpoints from Caido.", len(contexts))
        return contexts

    async def process(self, input_message: str) -> str:
        """エージェントのメイン処理"""
        # MasterConductor からこのエージェントを直接呼び出した場合のハンドラ
        logger.info("CaidoSitemapAgent processing input: %s", input_message)
        
        # input_message にドメイン名が含まれていると想定
        domain = input_message.strip() if "." in input_message else None
        
        contexts = await self.fetch_recent_requests(domain=domain, limit=100)
        
        if not contexts:
            return "Caidoからエンドポイントを取得できませんでした。Caidoが実行中か、APIトークンが正しく設定されているか確認してください。"
            
        result = [f"Found {len(contexts)} endpoints in Caido:"]
        for ctx in contexts:
            result.append(f" - [{ctx.method}] {ctx.url} (Status: {ctx.response_status})")
            
        return "\n".join(result)
