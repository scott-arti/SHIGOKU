"""
File Upload Tester v2
Katanaデータとコンテキストを活用してファイルアップロード脆弱性を検証する。
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from src.core.infra.network_client import AsyncNetworkClient
from src.core.attack.path_predictor import PathPredictor, SuggestedPath
from src.core.attack.payload_manager import PayloadManager, UploadPayload

logger = logging.getLogger(__name__)

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
        extra_params: Optional[Dict[str, str]] = None,
        auth_headers: Optional[Dict[str, str]] = None,
        aggressive: bool = False
    ) -> List[UploadResult]:
        """
        ファイルアップロード脆弱性テストを実行する
        """
        if not aggressive:
            logger.warning("FileUploadTester requires aggressive=True (write operation inevitable)")
            return []

        logger.info(f"Starting File Upload Scanning on {target_url}")

        # 0. ベースライン取得 (成否判定用)
        baseline_body = ""
        try:
            resp = await self.client.request("GET", target_url, headers=auth_headers)
            baseline_body = resp.text
        except Exception as e:
            logger.debug(f"Failed to fetch baseline: {e}")

        results = []

        # 1. 攻撃ペイロードの試行
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
                    res.suggested_paths = self.path_predictor.predict(target_url, payload.filename)
                    res.evidence = f"Server accepted '{payload.filename}' using {payload.technique}"
                    logger.info(f"Potential Upload Vulnerability found: {payload.technique}")
                    results.append(res)
                    # 最初の1つが見つかったら止めるか？（欲張るなら続行）
                    # ひとまず全て試す。
            except Exception as e:
                logger.error(f"Error during upload test ({payload.technique}): {e}")

        return results

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
            response_body=response.text
        )

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
