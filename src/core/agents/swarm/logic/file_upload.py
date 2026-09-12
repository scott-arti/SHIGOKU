"""
File Upload Specialist
LogicSwarmの一部として動作し、ファイルアップロード脆弱性検査を担当する。
Core Attack Module (FileUploadTester) を利用して攻撃を実行し、
結果をFinding形式で報告する。
"""

import logging
import secrets
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

from src.core.agents.swarm.base import Specialist, Task
from src.core.models.finding import Finding, VulnType, Severity, Evidence
from src.core.attack.file_upload_tester import FileUploadTester, normalize_upload_extra_params
from src.core.infra.network_client import AsyncNetworkClient

# ProxyManager連携のため
from src.core.infra.proxy_manager import get_proxy_manager

logger = logging.getLogger(__name__)


class FileUploadSpecialist(Specialist):
    """
    Unrestricted File Upload Vulnerability Specialist
    ファイルアップロード機能に対する攻撃（RCE狙い）を実行する
    """
    name = "FileUploadSpecialist"
    description = "Detects Unrestricted File Upload vulnerabilities leading to RCE"
    timeout_seconds = 300 # アップロードは時間がかかる場合がある
    is_aggressive = True  # 書き込みを伴うため
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        
        # クライアント初期化 (ProxyManager連携)
        proxy_manager = None
        try:
            proxy_manager = get_proxy_manager()
        except (ImportError, AttributeError, ValueError):
            pass
        except Exception:
            logger.debug("Failed to initialize proxy manager for FileUploadSpecialist")

        self._client = AsyncNetworkClient(proxy_manager=proxy_manager)
        self._tester = FileUploadTester(client=self._client)

    async def close(self):
        """リソースを解放する"""
        if self._client:
            await self._client.close()
        await super().close()

    async def execute(self, task: Task, quick_mode: bool = False) -> List[Finding]:
        """
        タスクを実行し、脆弱性を検出する
        
        Args:
            task: ターゲット情報を含むタスク
            
        Returns:
            List[Finding]: 検出された脆弱性リスト
        """
        findings = []
        
        # 1. Katana URL の収集 (コンテキスト)
        katana_urls = []
        try:
            from src.core.project.project_manager import get_project_manager
            # プロジェクト名を取得（タスクパラメータ、またはターゲットURLから）
            project_name = task.params.get("project_name")
            if not project_name:
                from urllib.parse import urlparse
                project_name = urlparse(task.target).netloc
            
            pm = get_project_manager(project_name)
            tagged_dir = pm.project_dir / "tagged_urls"
            
            if tagged_dir.exists():
                import json
                # .jsonl ファイル（Katana等の出力）を読み込む
                for jsonl_file in tagged_dir.glob("*.jsonl"):
                    try:
                        with open(jsonl_file, "r", encoding="utf-8") as f:
                            for line in f:
                                if not line.strip(): continue
                                entry = json.loads(line)
                                if "url" in entry:
                                    katana_urls.append(entry["url"])
                    except Exception as e:
                        logger.debug("Failed to read %s: %s", jsonl_file, e)
                
                logger.info("Loaded %d contextual URLs from project %s", len(katana_urls), project_name)
        except (ImportError, ValueError) as e:
            logger.debug("Project context loading aborted: %s", e)
        except Exception as e:
            logger.debug("Project context loading failed: %s", e)

        # 2. Tester の初期化と実行
        # タスクごとに Katana URL を反映させるため、ここで作成
        tester = FileUploadTester(client=self._client, katana_urls=katana_urls)
        
        # パラメータの抽出
        param_name = task.params.get("param_name", "file")
        extra_params = normalize_upload_extra_params(task.params.get("extra_params", {}))

        # SGK-2026-0481: アップロード経由の保存型XSS専用経路（opt-in）。
        # xss_via_upload が真のときだけ分岐する。従来の file_upload 経路
        # （0480 の uploaded_file_retrieved）は非回帰のまま。
        if task.params.get("xss_via_upload"):
            return await self._execute_xss_via_upload(
                task, tester, param_name, extra_params
            )

        # 実行 (Aggressive=True 必須)
        results = await tester.test_upload(
            target_url=task.target,
            param_name=param_name,
            extra_params=extra_params,
            auth_headers=task.params.get("headers"),
            aggressive=self.is_aggressive,
            safe_only=bool(task.params.get("safe_only", False)),
        )
        
        # 3. 結果の Finding 化
        for res in results:
            if res.success:
                # 脆弱性情報の構築
                path_summary = "\n".join([f"- {p.url} (Score: {p.score})" for p in res.suggested_paths[:5]])
                
                title = f"Unrestricted File Upload: {res.technique}"
                description = (
                    f"Successfully uploaded '{res.filename}' using {res.technique} technique.\n\n"
                    f"Predicted storage locations:\n{path_summary}"
                )
                request_body = (
                    "multipart/form-data upload\n"
                    f"{param_name}=@{res.filename}; filename={res.filename}; content_type={res.mime_type}"
                )
                if extra_params:
                    for key, value in extra_params.items():
                        request_body += f"\n{key}={value}"
                response_body = (
                    f"Status: {res.status_code}\n"
                    f"Evidence: {res.evidence}\n\n"
                    f"Top Suggested Path: {res.suggested_paths[0].url if res.suggested_paths else 'Unknown'}"
                )
                response_headers = {}
                content_type = res.delivery_telemetry.get("content_type") if isinstance(res.delivery_telemetry, dict) else None
                if content_type:
                    response_headers["Content-Type"] = content_type
                confidence = 0.9 if res.retrieved else 0.7

                file_upload_evidence: Dict[str, Any] = {
                    "upload_allowed": True,
                    "retrieved": bool(res.retrieved),
                    "retrieval_url": res.retrieval_url,
                    "retrieval_status": res.retrieval_status,
                    "execution_observed": False,
                    "safe_canary": bool(task.params.get("safe_only", False)),
                    "mime_type": res.mime_type,
                    "technique": res.technique,
                }
                impact = ""
                reproduction_steps: List[str] = []
                if res.retrieved and res.retrieval_marker:
                    # SGK-2026-0480: 設置＋Web 取得の本物証跡（一意マーカー往復）。
                    # retrieved でない/marker 無しは impact/repro/retrieval_marker を
                    # 付けない（fail-closed・従来の非確定 finding のまま byte-identical）。
                    file_upload_evidence["retrieval_marker"] = res.retrieval_marker
                    retrieval_excerpt = ""
                    if isinstance(res.delivery_telemetry, dict):
                        retrieval_excerpt = str(res.delivery_telemetry.get("retrieval_body_excerpt") or "")
                    response_body += (
                        f"\n\nRetrieval URL: {res.retrieval_url}\n"
                        f"Retrieval Status: {res.retrieval_status}\n"
                        f"Retrieval Marker: {res.retrieval_marker}"
                    )
                    if retrieval_excerpt:
                        response_body += f"\nRetrieval Body Excerpt: {retrieval_excerpt}"
                    impact = (
                        "認証境界内で任意の非実行ファイルをサーバへ設置し、"
                        "Web から取得できる。悪性ファイル設置・保存型攻撃・"
                        "情報設置の起点になり得る。"
                    )
                    reproduction_steps = [
                        "アップロード対象エンドポイントへ、実行毎に一意なマーカー"
                        "（SHIGOKU_PROBE_<random>）を含む良性・非実行ファイルを"
                        "multipart/form-data で送信する。",
                        "アップロード応答から保存先 URL を特定する。",
                        "保存先 URL を GET し、応答本文に同一の一意マーカーが"
                        "出現することを確認する。",
                    ]

                findings.append(Finding(
                    vuln_type=VulnType.FILE_UPLOAD,
                    severity=Severity.HIGH,
                    title=title,
                    description=description,
                    evidence=Evidence(
                        request_method="POST",
                        request_url=task.target,
                        request_body=request_body,
                        response_status=res.status_code,
                        response_headers=response_headers,
                        response_body=response_body,
                    ),
                    target_url=task.target,
                    source_agent=self.name,
                    confidence=confidence,
                    impact=impact,
                    reproduction_steps=reproduction_steps,
                    additional_info={
                        "payload": res.filename,
                        "file_upload_evidence": file_upload_evidence,
                        "payload_delivery": res.delivery_telemetry,
                    },
                ))
                
        return findings

    async def _execute_xss_via_upload(
        self,
        task: Task,
        tester: FileUploadTester,
        param_name: str,
        extra_params: Dict[str, str],
    ) -> List[Finding]:
        """アップロードした HTML がブラウザで実行される保存型XSSを実証する。

        - 実行毎の nonce を埋め込んだ良性 HTML を1つアップロードし、取得URLを
          マーカー（nonce）往復で確定する。
        - 取得URLを実ブラウザで開き、dialog message == nonce を観測したときだけ
          vuln_type=XSS の Finding を発行する。
        - 取得不可・非発火・nonce 不一致・ブラウザ利用不可は Finding を出さない
          （fail-closed・偽◎なし）。
        """
        nonce = "sgk" + secrets.token_hex(6)
        payload = tester.payload_manager.get_xss_probe_payload(nonce)

        retrieval_url, _marker = await tester.locate_uploaded(
            target_url=task.target,
            param_name=param_name,
            payload=payload,
            extra_params=extra_params,
            auth_headers=task.params.get("headers"),
        )
        if not retrieval_url:
            return []

        cookies = self._cookies_from_headers(task.params.get("headers"), task.target)
        try:
            from src.tools.browser.playwright_validator import PlaywrightValidator

            validator = PlaywrightValidator()
            fired = await validator.validate_xss(
                retrieval_url, timeout=8.0, cookies=cookies
            )
        except Exception as exc:  # noqa: BLE001 — browser tool boundary, fail closed
            logger.debug("Stored-XSS browser validation unavailable: %s", exc)
            return []
        if not fired:
            return []

        observed = self._first_dialog_message(validator)
        if observed != nonce:
            return []

        # SGK-2026-0481 追補: 取得URLの生の応答本文（実際に配信された HTML バイト列＝
        # nonce ペイロードを含む）を証拠に併記する。SGK-2026-0479 と同型で、要約では
        # なく独立検証可能な生証拠を審査へ渡す。取得失敗でも Finding は止めない（best-effort）。
        served_body = ""
        try:
            served = await self._client.request(
                "GET", retrieval_url, headers=task.params.get("headers")
            )
            served_body = getattr(served, "text", "") or ""
        except Exception as exc:  # noqa: BLE001 — network boundary, evidence is best-effort
            logger.debug("Failed to fetch served body for evidence: %s", exc)

        roundtrip_body = (
            "[Stored XSS via upload runtime execution]\n"
            f"test_url={retrieval_url}\n"
            f"injected_nonce={nonce}\n"
            f"observed_dialog_message={observed}\n"
            f"nonce_match=True\n"
            f"nonce_present_in_served_body={nonce in served_body}\n"
            "--- raw served response body (GET retrieval_url) ---\n"
            f"{served_body[:4000]}"
        )
        return [Finding(
            vuln_type=VulnType.XSS,
            severity=Severity.HIGH,
            title="Stored XSS via File Upload",
            description=(
                f"An uploaded file ('{payload.filename}') is served by the target "
                "and executed by the browser, running attacker-supplied script in "
                "the target's origin."
            ),
            evidence=Evidence(
                request_method="GET",
                request_url=retrieval_url,
                response_status=200,
                response_body=roundtrip_body,
            ),
            target_url=task.target,
            source_agent=self.name,
            confidence=0.9,
            impact=(
                "アップロードしたファイルがブラウザで実行される保存型XSS。"
                "任意スクリプト実行の起点。"
            ),
            reproduction_steps=[
                "HTMLをアップロード",
                "取得URLをブラウザで開く",
                "alert発火を確認",
            ],
            additional_info={
                "browser_execution": {
                    "dialog_observed": True,
                    "executor": "playwright",
                    "event": "stored_upload_browser_execution",
                    "variant": "stored",
                    "parameter": param_name,
                    "payload": payload.content.decode(),
                    "test_url": retrieval_url,
                    "nonce": nonce,
                    "observed_dialog_message": observed,
                    "nonce_match": True,
                },
            },
            tags=["xss", "file_upload", "stored"],
        )]

    @staticmethod
    def _first_dialog_message(validator: Any) -> str:
        """validate_xss 後に記録された最初の dialog ログの message を返す。"""
        logs = getattr(validator, "_last_observation_logs", None) or []
        for entry in logs:
            if isinstance(entry, dict) and entry.get("type") == "dialog":
                return str(entry.get("message") or "")
        return ""

    @staticmethod
    def _cookies_from_headers(
        headers: Optional[Dict[str, str]], target_url: str
    ) -> List[Dict[str, Any]]:
        """'Cookie' ヘッダ文字列を Playwright の cookies 形式へ変換する。"""
        if not isinstance(headers, dict):
            return []
        cookie_header = ""
        for key, value in headers.items():
            if str(key).lower() == "cookie":
                cookie_header = str(value or "")
                break
        if not cookie_header:
            return []
        domain = urlparse(target_url).hostname or ""
        cookies: List[Dict[str, Any]] = []
        for part in cookie_header.split(";"):
            name, separator, value = part.partition("=")
            name = name.strip()
            if not separator or not name:
                continue
            cookies.append({
                "name": name,
                "value": value.strip(),
                "domain": domain,
                "path": "/",
            })
        return cookies
