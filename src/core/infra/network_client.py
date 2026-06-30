"""
AsyncNetworkClient - 高速非同期ネットワーククライアント

aiohttp をベースに、プロキシローテーション、自動リトライ、
詳細なロギングを提供する。

用途:
- Swarm Agent からの高速スキャン
- WAF 回避（IP分散）
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, Union

import aiohttp
from aiohttp import ClientTimeout

from src.core.infra.proxy_manager import ProxyChainManager
from src.core.infra.cache_manager import get_cache
 
logger = logging.getLogger(__name__)


class NetworkClientError(Exception):
    """Network Client specific error"""
    pass


@dataclass
class NetworkResponse:
    """統一ネットワークレスポンス"""
    status: int
    headers: Dict[str, str]
    body: str  # テキスト本文
    elapsed: float  # 秒
    url: str
    proxy_used: Optional[str] = None
    
    cookies: Dict[str, str] = field(default_factory=dict)
    
    @property
    def is_success(self) -> bool:
        return 200 <= self.status < 300

    @property
    def status_code(self) -> int:
        """Alias for status for compatibility with requests/httpx"""
        return self.status

    @property
    def text(self) -> str:
        """Alias for body for compatibility with requests/httpx"""
        return self.body

    def json(self) -> Any:
        """Parse body as JSON"""
        import json
        return json.loads(self.body)



# Global Context for Cookies (to avoid passing it through every agent)
import contextvars
current_scan_cookies: contextvars.ContextVar[Optional[Dict[str, str]]] = contextvars.ContextVar("current_scan_cookies", default=None)

# Reauth context for 401 detection — set by MasterConductor before task execution
current_reauth_context: contextvars.ContextVar[Optional[dict[str, Any]]] = contextvars.ContextVar(
    "current_reauth_context", default=None
)

class AsyncNetworkClient:
    """
    非同期ネットワーククライアント
    
    機能:
    - プロキシローテーション (ProxyChainManager連携)
    - 自動リトライ (接続エラー, タイムアウト, 5xx)
    - カスタムUser-Agent
    - ContextVarによるCookie自動注入
    """
    
    _docker_cache: Optional[bool] = None  # Docker環境判定のキャッシュ
    
    
    def __init__(
        self,
        proxy_manager: Optional[ProxyChainManager] = None,
        default_timeout: int = 30,
        user_agent: str = "Shigoku-SwarmBot/1.0",
        mode: str = "bugbounty",  # bugbounty, ctf, vulntest
        cookies: Optional[Dict[str, str]] = None,  # Explicit override
        event_bus: Optional[Any] = None
    ):
        self.proxy_manager = proxy_manager
        self.default_timeout = default_timeout
        self.user_agent = user_agent
        self.mode = mode
        self.event_bus = event_bus
        
        # Auto-initialize event bus if not provided
        if self.event_bus is None:
            try:
                from src.core.infra.event_bus import get_event_bus
                self.event_bus = get_event_bus()
            except ImportError:
                pass

        # Priority: Explicit Arg > ContextVar > Empty
        ctx_cookies = current_scan_cookies.get()
        self.initial_cookies = cookies or ctx_cookies or {}
        
        self._session: Optional[aiohttp.ClientSession] = None
        self._lock: Optional[asyncio.Lock] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._cache = get_cache()
        
        # Auto-initialize proxy manager if not provided
        if self.proxy_manager is None:
            try:
                from src.core.config.settings import get_settings
                self.proxy_manager = get_proxy_manager()
            except Exception:
                pass

    def _is_docker(self) -> bool:
        """Docker環境かどうかを判定（キャッシュ付き）"""
        if AsyncNetworkClient._docker_cache is None:
            from pathlib import Path
            result = False
            if Path('/.dockerenv').exists():
                result = True
            else:
                try:
                    # cgroupをチェック (v1/v2対応)
                    cgroup = Path('/proc/self/cgroup')
                    if cgroup.exists() and 'docker' in cgroup.read_text():
                        result = True
                except Exception:
                    pass
            AsyncNetworkClient._docker_cache = result
        return AsyncNetworkClient._docker_cache

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    async def start(self):
        """セッション開始（接続プーリング最適化・ループ整合性チェック）"""
        # ロックの初期化と検証（ループ変更対応）
        try:
            current_loop = asyncio.get_running_loop()
        except RuntimeError:
            return  # No loop running

        # ループが変わった場合、ロックを作り直す
        # (以前のロックは古いループに属しており、使おうとするとエラーになる)
        if self._lock is None or self._loop is not current_loop:
            self._lock = asyncio.Lock()
            self._loop = current_loop
            # ループが変わった＝以前のセッションも無効なので破棄
            self._session = None

        try:
            async with self._lock:
                # 二重チェック
                if self._session and not self._session.closed:
                    if self._session.loop is current_loop:
                        return

                # 1. ループ不一致・Closedチェック
                if self._session:
                    logger.warning(
                        "NetworkClient session loop mismatch or closed (old_loop=%s id=%s, current=%s id=%s). Recreating session...",
                        getattr(self._session, "loop", "unknown"),
                        id(getattr(self._session, "loop", None)),
                        current_loop,
                        id(current_loop)
                    )
                    try:
                        if not self._session.closed:
                            await self._session.close()
                    except Exception as e:
                        logger.warning(f"Error closing old session: {e}")
                    self._session = None

                # 2. セッション作成
                if not self._session:
                    connector = aiohttp.TCPConnector(
                        limit=500,              # 同時接続上限 (100->500)
                        limit_per_host=50,      # ホストあたりの接続上限 (30->50)
                        ttl_dns_cache=300,      # DNSキャッシュ5分
                        use_dns_cache=True,
                        enable_cleanup_closed=True, # クローズ済み接続の自動クリーンアップ
                        force_close=False,      # 接続再利用を有効化
                    )
                    self._session = aiohttp.ClientSession(
                        connector=connector,
                        headers={"User-Agent": self.user_agent},
                        cookies=self.initial_cookies
                    )
        except (RuntimeError, ValueError) as e:
             # "Future attached to a different loop" などのエラー時のリカバリ
             logger.warning(f"Lock/Loop error in start(): {e}. Resetting lock.")
             self._lock = asyncio.Lock()
             # 再帰呼び出し (無限ループ防止のため1回のみなどの制御が望ましいが、簡易的に)
             async with self._lock:
                 if not self._session or self._session.closed or self._session.loop is not current_loop:
                     # Force recreate logic duplicated (simplified)
                     self._session = aiohttp.ClientSession(
                        headers={"User-Agent": self.user_agent},
                        cookies=self.initial_cookies
                     )


    async def close(self):
        """セッション終了"""
        if self._session:
            await self._session.close()
            self._session = None
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """セッション終了（コンテキストマネージャーとして使用される場合）"""
        await self.close()
    
    def __del__(self):
        """オブジェクト破棄時にセッションをクローズ（最終手段）"""
        if self._session and not self._session.closed:
            import warnings
            warnings.warn("AsyncNetworkClient was not properly closed. Please use 'async with' or call 'await close()' explicitly.", ResourceWarning)

    def get_cookies(self) -> Dict[str, str]:
        """現在のセッションの全Cookieを取得"""
        if not self._session:
            return self.initial_cookies
        return {cookie.key: cookie.value for cookie in self._session.cookie_jar}

    @staticmethod
    def _check_proxy_reachable(proxy_url: str) -> bool:
        """指定されたプロキシが到達可能かTCPチェックを行う"""
        import socket
        from urllib.parse import urlparse
        
        try:
            parsed = urlparse(proxy_url)
            host = parsed.hostname
            # Caido/Burpのデフォルト8080を意識
            port = parsed.port or (8080 if any(k in proxy_url.lower() for k in ["caido", "burp", "8080"]) else 80)
            
            if not host:
                return False
                
            # 2秒タイムアウトで接続テスト
            with socket.create_connection((host, port), timeout=2):
                return True
        except (socket.timeout, ConnectionRefusedError, socket.gaierror):
            return False
        except Exception as e:
            logger.debug(f"Proxy connection check failed: {e}")
            return False

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Any = None,
        json: Any = None,
        timeout: Optional[int] = None,
        use_proxy: bool = True,  # 全通信プロキシ化のためデフォルト True に変更
        retries: int = 1,  # リトライ回数を 1 に削減（タイムアウト防止）
        use_cache: bool = True,
        cache_ttl: int = 300,
        auto_waf_bypass: bool = True,
        **kwargs
    ) -> NetworkResponse:
        """
        リクエストを実行（リトライ・プロキシ回転付き）

        Note: use_proxy is False by default (Opt-in).

        Returns:
            NetworkResponse: レスポンスオブジェクト

        Raises:
            Exception: リトライ上限到達時
        """
        # ループが変わっていないかチェックするために常に start() を呼ぶ
        # start() 内部で軽量なチェックを行っているためパフォーマンスへの影響は軽微
        await self.start()

        # 0. プロキシ死活監視 (絶対プロキシ主義)
        if use_proxy:
            proxy_config_url = None
            try:
                from src.core.config.settings import get_settings
                proxy_config_url = get_settings().get_proxy_url()
            except ImportError:
                pass

            if proxy_config_url and not self._check_proxy_reachable(proxy_config_url):
                logger.critical("🚨 Mandatory Proxy (Caido/Burp) is NOT reachable: %s", proxy_config_url)
                raise NetworkClientError(
                    f"Proxy is required but unreachable at {proxy_config_url}. "
                    "Please start Caido or check your settings."
                )



        # 1. キャッシュチェック (GETのみ)
        cache_key = None
        if use_cache and method.upper() == "GET":
            import hashlib
            # URLとパラムからキー生成
            param_str = str(sorted(params.items())) if params else ""
            key_base = f"{method}:{url}:{param_str}"
            cache_key = f"http:res:{hashlib.md5(key_base.encode()).hexdigest()}"
            
            cached_res = await self._cache.get(cache_key)
            if cached_res:
                logger.debug("Cache hit for %s", url)
                return NetworkResponse(**cached_res)

        timeout_val = timeout if timeout is not None else self.default_timeout
        client_timeout = ClientTimeout(total=timeout_val)
        last_exception = None

        # Compatibility: convert httpx's follow_redirects to aiohttp's allow_redirects
        if "follow_redirects" in kwargs:
            allow_redirects = kwargs.pop("follow_redirects")
            if "allow_redirects" not in kwargs:
                kwargs["allow_redirects"] = allow_redirects

        for attempt in range(retries + 1):
            proxy_url = None
            should_use_proxy = use_proxy and self.mode != "ctf"
            if should_use_proxy and self.proxy_manager:
                proxy_url = self.proxy_manager.get_proxy()

            logger.debug(f"Requesting {method} {url} (proxy={proxy_url})")
            
            # Sanitize parameters and headers to avoid type errors in aiohttp/yarl
            params = self._sanitize_request_parameters(params)
            headers = self._sanitize_request_parameters(headers)

            start_time = time.time()
            try:
                async with self._session.request(
                    method,
                    url,
                    headers=headers,
                    params=params,
                    data=data,
                    json=json,
                    timeout=client_timeout,
                    proxy=proxy_url,
                    **kwargs
                ) as response:
                    body = await response.text(errors='replace')
                    elapsed = time.time() - start_time

                    if use_proxy and self.proxy_manager and proxy_url:
                        await self.proxy_manager.report_success(proxy_url, latency_ms=elapsed * 1000)

                    # Phase 4: FlagWatcher Hook
                    from src.core.engine.flag_watcher import FlagWatcher
                    FlagWatcher.get_instance().check(body, source=f"HTTP:{url}")

                    net_res = NetworkResponse(
                        status=response.status,
                        headers=dict(response.headers),
                        body=body,
                        elapsed=elapsed,
                        url=str(response.url),
                        proxy_used=proxy_url,
                        cookies={k: v.value for k, v in response.cookies.items()}
                    )
                    
                    if cache_key and net_res.is_success:
                        res_dict = {
                            "status": net_res.status,
                            "headers": net_res.headers,
                            "body": net_res.body,
                            "elapsed": net_res.elapsed,
                            "url": net_res.url,
                            "proxy_used": net_res.proxy_used,
                            "cookies": net_res.cookies
                        }
                        await self._cache.set(cache_key, res_dict, ttl=cache_ttl)
                    
                    # 5xx エラーはリトライ対象
                    if 500 <= response.status < 600 and attempt < retries:
                        logger.warning("Request failed (%d) on attempt %d/%d for %s. Retrying...", response.status, attempt + 1, retries + 1, url)
                        await asyncio.sleep(0.5 * (attempt + 1))
                        continue

                    # 403/406 WAF Block (Tier 7 WAF Bypass)
                    if response.status in (403, 406) and auto_waf_bypass and attempt < retries:
                        logger.warning("WAF Block detected (%d) on attempt %d/%d for %s. Attempting bypass...", response.status, attempt + 1, retries + 1, url)
                        waf_name = "unknown"
                        waf_confidence = 0.0
                        mutation_types = None
                        try:
                            # Phase 4 entry: Signature-based WAF modeling.
                            try:
                                from src.core.waf.detector import WAFDetector
                                if getattr(self, "_waf_detector", None) is None:
                                    self._waf_detector = WAFDetector()
                                detection = self._waf_detector.detect(
                                    status_code=response.status,
                                    headers=dict(response.headers),
                                    body=body,
                                )
                                if detection.waf_name:
                                    waf_name = detection.waf_name
                                    waf_confidence = detection.confidence
                            except Exception as det_exc:
                                logger.debug("WAFDetector unavailable/failure: %s", det_exc)

                            # Bypass profile selection (headers + mutation focus)
                            try:
                                from src.core.waf.bypasser import WAFBypasser
                                if getattr(self, "_waf_bypasser", None) is None:
                                    self._waf_bypasser = WAFBypasser()
                                bypass_headers = self._waf_bypasser.build_bypass_headers(
                                    waf_name=None if waf_name == "unknown" else waf_name,
                                    attempt=attempt,
                                )
                                mutation_types = self._waf_bypasser.choose_mutation_types(
                                    waf_name=None if waf_name == "unknown" else waf_name
                                )
                                if bypass_headers:
                                    headers = {**(headers or {}), **bypass_headers}
                            except Exception as bypass_exc:
                                logger.debug("WAFBypasser unavailable/failure: %s", bypass_exc)

                            from src.core.attack.waf_mutator import WAFPayloadMutator
                            if getattr(self, '_waf_mutator', None) is None:
                                self._waf_mutator = WAFPayloadMutator()
                                
                            # EventBus通知
                            if self.event_bus:
                                from src.core.infra.event_bus import Event, EventType
                                self.event_bus.emit_sync(Event(
                                    type=EventType.LOG_MESSAGE,
                                    payload={
                                        "level": "warning",
                                        "message": (
                                            f"WAF Block {response.status} at {url}. "
                                            f"detected={waf_name} confidence={waf_confidence:.2f}. "
                                            "Initiating payload mutation."
                                        ),
                                        "target": "WAFBypass",
                                    },
                                    source="AsyncNetworkClient"
                                ))
                                
                            # Mutate payloads
                            if params:
                                params = self._mutate_payloads(self._waf_mutator, params, mutation_types=mutation_types)
                            if data:
                                data = self._mutate_payloads(self._waf_mutator, data, mutation_types=mutation_types)
                            if json_data := json: # rename slightly to avoid hiding json module in block
                                json = self._mutate_payloads(self._waf_mutator, json_data, mutation_types=mutation_types)
                                
                        except Exception as e:
                            logger.error(f"Error during WAF mutation: {e}")
                        
                        await asyncio.sleep(0.5 * (attempt + 1))
                        continue

                    # 401 Unauthorized 検知 -> EventBusに通知
                    if response.status == 401 and self.event_bus:
                        from src.core.infra.event_bus import Event, EventType
                        from src.core.agents.swarm.auth.reauth_contracts import (
                            generate_reauth_attempt_id,
                        )
                        reauth_ctx = current_reauth_context.get() or {}
                        reauth_attempt_id = generate_reauth_attempt_id()
                        origin_task_id = reauth_ctx.get("origin_task_id", "unknown")
                        auth_context_version = reauth_ctx.get("auth_context_version", 0)

                        self.event_bus.emit_sync(Event(
                            type=EventType.SESSION_EXPIRED,
                            payload={
                                "url": url,
                                "method": method,
                                "request_headers": headers or {},
                                "origin_task_id": origin_task_id,
                                "reauth_attempt_id": reauth_attempt_id,
                                "auth_context_version": auth_context_version,
                            },
                            source="AsyncNetworkClient"
                        ))

                    return net_res

            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                # 接続エラー関連
                last_exception = e
                elapsed = time.time() - start_time

                # プロキシ失敗報告
                if use_proxy and self.proxy_manager and proxy_url:
                    self.proxy_manager.report_failure(proxy_url)

                # Docker環境かつlocalhostへの接続エラーの場合、自動フォールバックを試みる
                is_localhost = any(x in url for x in ["localhost", "127.0.0.1", "0.0.0.0"])
                
                # Linux環境ではhost.docker.internalが解決できないため、フォールバックしない
                import platform
                is_linux = platform.system().lower() == "linux"
                
                if self._is_docker() and is_localhost and not is_linux:
                    if "host.docker.internal" not in url:
                        logger.warning(
                            "Connection to %s failed in Docker. "
                            "Retrying with 'host.docker.internal' as fallback...",
                            url
                        )
                        url = url.replace("localhost", "host.docker.internal") \
                                 .replace("127.0.0.1", "host.docker.internal") \
                                 .replace("0.0.0.0", "host.docker.internal")
                    else:
                        logger.warning(
                            "Connection to %s failed even with 'host.docker.internal'. "
                            "Please check your Docker networking or host firewall.",
                            url
                        )
                elif is_localhost:
                    # 全環境共通: localhostへのHTTPS接続が失敗した場合にHTTPにフォールバック
                    if url.startswith("https://"):
                        logger.warning(
                            "HTTPS connection to %s failed. "
                            "Falling back to HTTP for localhost...",
                            url
                        )
                        url = url.replace("https://", "http://", 1)
                    else:
                        logger.warning(
                            "Connection to %s failed. "
                            "If you are using Docker, ensure the target port is exposed and reachable.",
                            url
                        )

                logger.warning(
                    "Connection error on attempt %d/%d for %s: %s",
                    attempt + 1, retries + 1, url, str(e)
                )

                if attempt < retries:
                    await asyncio.sleep(1.0 * (attempt + 1))
                    continue

            except Exception as e:
                # 予期せぬエラー
                logger.error("Unexpected error for %s: %s", url, e)
                raise NetworkClientError(f"Unexpected error: {e}") from e

        # リトライアウト
        if last_exception:
            raise NetworkClientError(f"Request failed after {retries} retries") from last_exception

        # ここには到達しないはずだが念のため
        raise Exception(f"Request failed for {url}")


    async def save_session_async(self, filepath: str) -> None:
        """
        セッション情報を完全非同期で保存
        """
        import aiofiles
        import aiofiles.os
        import json
        from pathlib import Path
        from datetime import datetime
        
        data = {
            'version': '1.0',
            'saved_at': datetime.now().astimezone().isoformat(),
            'cookies': self.get_cookies(),
            'user_agent': self.user_agent,
            'mode': self.mode,
            'metadata': {}
        }
        
        try:
            import orjson
            json_bytes = orjson.dumps(
                data,
                option=orjson.OPT_INDENT_2 | orjson.OPT_NON_STR_KEYS
            )
            # Use temp file and move for atomic write
            tmp_path = Path(filepath).with_suffix('.tmp')
            async with aiofiles.open(tmp_path, 'wb') as f:
                await f.write(json_bytes)
            await aiofiles.os.replace(str(tmp_path), filepath)
            return
        except ImportError:
            pass
        
        # Fallback to standard json
        tmp_path = Path(filepath).with_suffix('.tmp')
        async with aiofiles.open(tmp_path, 'w', encoding='utf-8') as f:
            await f.write(json.dumps(data, indent=2, ensure_ascii=False))
        await aiofiles.os.replace(str(tmp_path), filepath)

    async def load_session_async(self, filepath: str) -> None:
        """
        セッション情報を完全非同期で読み込み
        """
        import aiofiles
        import json
        from pathlib import Path
        
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Session file not found: {filepath}")
            
        try:
            import orjson
            async with aiofiles.open(path, 'rb') as f:
                content = await f.read()
            data = orjson.loads(content)
        except ImportError:
            async with aiofiles.open(path, 'r', encoding='utf-8') as f:
                content = await f.read()
            data = json.loads(content)
            
        version = data.get('version', '1.0')
        if version != '1.0':
            logger.warning(
                "Session file version mismatch: expected 1.0, got %s",
                version
            )

        self.user_agent = data.get('user_agent', self.user_agent)
        self.mode = data.get('mode', self.mode)
        
        loaded_cookies = data.get('cookies', {})
        self.initial_cookies.update(loaded_cookies)
        
        if self._session:
            for key, value in loaded_cookies.items():
                self._session.cookie_jar.update_cookies({key: value})
        
        logger.info(
            "Session loaded from %s (saved_at: %s, cookies: %d)",
            filepath,
            data.get('saved_at', 'unknown'),
            len(loaded_cookies)
        )

    def _mutate_payloads(self, mutator: Any, payloads: Any, mutation_types: Optional[list[Any]] = None) -> Any:
        """WAF回避のためのペイロード再帰変異用ヘルパー"""
        import random
        if isinstance(payloads, dict):
            new_payloads = {}
            for k, v in payloads.items():
                if isinstance(v, str) and v:
                    try:
                        mutated_opts = mutator.mutate(v, mutations=mutation_types)
                    except TypeError:
                        mutated_opts = mutator.mutate(v)
                    if mutated_opts:
                        new_payloads[k] = random.choice(mutated_opts).mutated
                    else:
                        new_payloads[k] = v
                elif isinstance(v, dict):
                    new_payloads[k] = self._mutate_payloads(mutator, v, mutation_types=mutation_types)
                elif isinstance(v, list):
                    new_payloads[k] = [self._mutate_payloads(mutator, item, mutation_types=mutation_types) for item in v]
                else:
                    new_payloads[k] = v
            return new_payloads
        elif isinstance(payloads, str) and payloads:
            try:
                mutated_opts = mutator.mutate(payloads, mutations=mutation_types)
            except TypeError:
                mutated_opts = mutator.mutate(payloads)
            return random.choice(mutated_opts).mutated if mutated_opts else payloads
        return payloads


    def _sanitize_request_parameters(self, params: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        リクエストパラメータやヘッダー内の非スカラー値をサニタイズし、
        aiohttp (yarl) での 'Invalid variable type' エラーを防止します。
        """
        if params is None:
            return None
        if not isinstance(params, dict):
            return params

        sanitized = {}
        for k, v in params.items():
            if v is None:
                continue
            
            # aiohttp/yarl が許容する基本型: str, int, float
            if isinstance(v, (str, int, float, bool)):
                sanitized[str(k)] = v
            elif isinstance(v, dict):
                # 辞書が値として渡された場合（エラーの直接原因）
                # 'Cookie' キーのみの辞書などの特殊ケースを考慮しつつ文字列化
                if len(v) == 1 and ("Cookie" in v or "cookie" in v):
                     sanitized[str(k)] = str(list(v.values())[0])
                else:
                    import json
                    try:
                        sanitized[str(k)] = json.dumps(v)
                    except:
                        sanitized[str(k)] = str(v)
            elif isinstance(v, (list, tuple)):
                # リストの場合は、中身もサニタイズ（aiohttp はマルチバリューをサポート）
                sanitized[str(k)] = [
                    str(i) if not isinstance(i, (str, int, float, bool)) else i 
                    for i in v
                ]
            else:
                sanitized[str(k)] = str(v)
        
        return sanitized


def create_network_client(
    proxy_manager: Optional[ProxyChainManager] = None
) -> AsyncNetworkClient:
    """AsyncNetworkClient 作成ヘルパー"""
    return AsyncNetworkClient(proxy_manager=proxy_manager)


async def create_network_client_with_session(
    proxy_manager: Optional[ProxyChainManager] = None
) -> AsyncNetworkClient:
    """AsyncNetworkClient 作成とセッション開始を同時に行うヘルパー"""
    client = AsyncNetworkClient(proxy_manager=proxy_manager)
    await client.start()
    return client
