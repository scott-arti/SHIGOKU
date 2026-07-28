"""
File Upload Tester v2
Katanaデータとコンテキストを活用してファイルアップロード脆弱性を検証する。
"""

import logging
import re
import ast
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from urllib.parse import parse_qsl, urljoin
from src.core.infra.network_client import AsyncNetworkClient
from src.core.attack.path_predictor import PathPredictor, SuggestedPath
from src.core.attack.payload_manager import PayloadManager, UploadPayload

logger = logging.getLogger(__name__)


def normalize_upload_extra_params(value: Any) -> Dict[str, str]:
    """Normalize upload form extra params at the attack boundary.

    LLM/ReAct tool calls can carry form parameters as a dict, a JSON string, a
    Python-literal dict string, or occasionally a query-string-like value. The
    multipart sender needs a mapping, so normalize all accepted forms here and
    fail closed to an empty mapping for unsupported input shapes.
    """
    if value is None:
        return {}

    if isinstance(value, Mapping):
        return {str(key): str(param_value) for key, param_value in value.items()}

    if isinstance(value, (list, tuple)):
        try:
            return {
                str(key): str(param_value)
                for key, param_value in dict(value).items()
            }
        except (TypeError, ValueError):
            logger.debug("Ignoring unsupported upload extra_params sequence")
            return {}

    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return {}

        for parser in (json.loads, ast.literal_eval):
            try:
                decoded = parser(stripped)
            except (ValueError, SyntaxError, TypeError):
                continue
            if isinstance(decoded, Mapping):
                return {
                    str(key): str(param_value)
                    for key, param_value in decoded.items()
                }

        if "=" in stripped:
            pairs = parse_qsl(stripped, keep_blank_values=True)
            if pairs:
                return {str(key): str(param_value) for key, param_value in pairs}

        logger.debug("Ignoring unsupported upload extra_params string format")
        return {}

    logger.debug("Ignoring unsupported upload extra_params type: %s", type(value).__name__)
    return {}


@dataclass
class UploadResult:
    """アップロード試行結果（内部用）"""
    success: bool
    technique: str
    filename: str
    mime_type: str
    status_code: int
    response_body: str
    suggested_paths: List[SuggestedPath] = field(default_factory=list)
    evidence: str = ""
    retrieved: bool = False
    retrieval_url: str = ""
    retrieval_status: int = 0
    delivery_telemetry: Dict[str, Any] = field(default_factory=dict)

class FileUploadTester:
    """
    ファイルアップロード脆弱性診断クラス（リファクタリング版）
    """

    def __init__(self, client: AsyncNetworkClient, katana_urls: Optional[List[str]] = None):
        self.client = client
        self.payload_manager = PayloadManager()
        self.path_predictor = PathPredictor(katana_urls)

    async def test_upload(
        self,
        target_url: str,
        param_name: str = "file",
        extra_params: Optional[Any] = None,
        auth_headers: Optional[Dict[str, str]] = None,
        aggressive: bool = False,
        safe_only: bool = False,
        verify_retrieval: bool = True,
    ) -> List[UploadResult]:
        """
        ファイルアップロード脆弱性テストを実行する
        """
        if not aggressive:
            logger.warning("FileUploadTester requires aggressive=True (write operation inevitable)")
            return []

        extra_params = normalize_upload_extra_params(extra_params)

        logger.info(f"Starting File Upload Scanning on {target_url}")

        # 0. ベースライン取得 (成否判定用)
        baseline_body = ""
        try:
            resp = await self.client.request("GET", target_url, headers=auth_headers)
            baseline_body = resp.text
        except Exception as e:
            logger.debug(f"Failed to fetch baseline: {e}")

        results = []

        # 1. ペイロードの試行
        # safe_only=True は、実アプリでも安全に扱える canary ファイルの
        # アップロード・取得確認だけを行う。PHP/.htaccess/RCE 寄りの検証は
        # 明示的な aggressive 経路に残す。
        if safe_only:
            payloads = [self.payload_manager.get_probe_payload()]
        else:
            payloads = self.payload_manager.get_all_payloads()
            # .htaccess も試行
            payloads.insert(0, self.payload_manager.get_htaccess_payload())

        for payload in payloads:
            try:
                res = await self._execute_upload(
                    target_url, param_name, payload, extra_params, auth_headers, baseline_body
                )
                if res.success:
                    # 成功した場合は保存先を推測
                    response_paths = self._extract_response_suggested_paths(
                        target_url,
                        payload.filename,
                        res.response_body,
                    )
                    predicted_paths = self.path_predictor.predict(target_url, payload.filename)
                    res.suggested_paths = self._merge_suggested_paths(response_paths, predicted_paths)
                    if verify_retrieval:
                        await self._verify_retrieval(res, payload, auth_headers)
                    res.evidence = (
                        f"Server accepted '{payload.filename}' using {payload.technique}"
                        + (f"; retrieved at {res.retrieval_url}" if res.retrieved else "")
                    )
                    logger.info(f"Potential Upload Vulnerability found: {payload.technique}")
                    results.append(res)
                    # 最初の1つが見つかったら止めるか？（欲張るなら続行）
                    # ひとまず全て試す。
            except Exception as e:
                logger.error(f"Error during upload test ({payload.technique}): {e}")

        return results

    def _extract_response_suggested_paths(
        self,
        target_url: str,
        filename: str,
        response_body: str,
    ) -> List[SuggestedPath]:
        """アップロード応答本文から、保存先らしいファイルパスを抽出する。

        DVWA 専用の固定パスではなく、実アプリでもよくある
        "uploaded to ../path/file.ext" 形式の本文を利用する。
        """
        if not filename or not response_body or filename not in response_body:
            return []

        escaped_filename = re.escape(filename)
        pattern = re.compile(rf"((?:\.\./|/|[A-Za-z0-9_.~-]+/)[^\s<>'\"]*{escaped_filename})")
        suggestions: List[SuggestedPath] = []
        seen: set[str] = set()
        for match in pattern.finditer(response_body):
            raw_path = match.group(1).strip().strip("'\"<>")
            if not raw_path or filename not in raw_path:
                continue
            full_url = urljoin(target_url, raw_path)
            if full_url in seen:
                continue
            seen.add(full_url)
            suggestions.append(SuggestedPath(
                url=full_url,
                tier=0,
                reason="Upload response referenced the stored file path",
                score=95,
            ))
        return suggestions

    @staticmethod
    def _merge_suggested_paths(
        primary: List[SuggestedPath],
        fallback: List[SuggestedPath],
    ) -> List[SuggestedPath]:
        merged: List[SuggestedPath] = []
        seen: set[str] = set()
        for suggestion in [*primary, *fallback]:
            if suggestion.url in seen:
                continue
            seen.add(suggestion.url)
            merged.append(suggestion)
        return sorted(merged, key=lambda item: item.score, reverse=True)

    async def _execute_upload(
        self,
        url: str,
        param_name: str,
        payload: UploadPayload,
        extra_params: Optional[Dict[str, str]],
        headers: Optional[Dict[str, str]],
        baseline_body: str
    ) -> UploadResult:
        """実際にファイルをマルチパートリクエストで送信する"""
        import aiohttp
        
        data = aiohttp.FormData()
        data.add_field(param_name, payload.content, filename=payload.filename, content_type=payload.mime_type)
        
        if extra_params:
            for k, v in extra_params.items():
                data.add_field(k, str(v))

        # Content-Type は aiohttp が boundary 付きで設定するため、既存のものは削除
        req_headers = headers.copy() if headers else {}
        if "Content-Type" in req_headers:
            del req_headers["Content-Type"]

        response = await self.client.request("POST", url, headers=req_headers, data=data, timeout=30)
        
        success = self._is_success(response.status, response.text, baseline_body)

        return UploadResult(
            success=success,
            technique=payload.technique,
            filename=payload.filename,
            mime_type=payload.mime_type,
            status_code=response.status,
            response_body=response.text,
            delivery_telemetry={
                "upload_status": response.status,
                "body_length": len(response.text or ""),
                "content_type": getattr(response, "headers", {}).get("content-type", "")
                if isinstance(getattr(response, "headers", {}), dict)
                else "",
                "delivered": success,
            },
        )

    async def _verify_retrieval(
        self,
        result: UploadResult,
        payload: UploadPayload,
        auth_headers: Optional[Dict[str, str]],
    ) -> None:
        """推測された保存先に canary が取得可能かを確認する。

        取得確認は安全な読み取りだけで、PHP 実行や .htaccess 効果確認は行わない。
        """
        marker = payload.content.decode(errors="ignore")
        for suggested in result.suggested_paths[:8]:
            try:
                resp = await self.client.request("GET", suggested.url, headers=auth_headers, timeout=15)
            except Exception as exc:
                result.delivery_telemetry.setdefault("retrieval_errors", []).append(str(exc))
                continue

            status = getattr(resp, "status", 0)
            body = getattr(resp, "text", "") or ""
            result.delivery_telemetry.setdefault("retrieval_attempts", []).append({
                "url": suggested.url,
                "status": status,
                "body_length": len(body),
            })
            if status in {200, 201} and marker and marker in body:
                result.retrieved = True
                result.retrieval_url = suggested.url
                result.retrieval_status = status
                return

    def _is_success(self, status: int, body: str, baseline: str) -> bool:
        """アップロードが成功したかどうかの判定（Ver.1: 緩め）"""
        if status >= 500:
            return False
            
        body_lower = body.lower()
        baseline_lower = baseline.lower()

        # 1. 成功キーワード（ベースラインにないもの）
        SUCCESS_KEYWORDS = ["stored in", "successfully uploaded", "upload success", "file created"]
        for kw in SUCCESS_KEYWORDS:
            if kw in body_lower and kw not in baseline_lower:
                return True

        # 2. 状態コードが 200/201 かつ、何らかの変化がある
        if status in [200, 201]:
            # ベースラインと明らかに長さが違う、または明示的なエラーキーワードがない
            ERROR_KEYWORDS = ["invalid", "forbidden", "denied", "not allowed", "error", "failed"]
            if not any(ek in body_lower for ek in ERROR_KEYWORDS):
                # かつ、何らかの変化があったとみなす
                if len(body) != len(baseline):
                    return True

        return False
