#!/usr/bin/env python3
"""Shared form parsing helper extracted from SmartXSSHunter / SmartSQLiHunter.

This module provides the canonical `fetch_and_parse_form` implementation.
Each hunter facade imports and re-exports it as `_fetch_and_parse_form` to
preserve the existing monkeypatch surface.
"""

import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


async def fetch_and_parse_form(url: str, auth_headers: Dict[str, str]) -> List[Dict[str, Any]]:
    """
    HTML を取得して BeautifulSoup でフォームを解析（高速・第一選択）

    Args:
        url: 対象 URL
        auth_headers: 認証ヘッダー

    Returns:
        フォーム情報のリスト
    """
    from bs4 import BeautifulSoup

    from src.core.infra.network_client import AsyncNetworkClient

    forms: List[Dict[str, Any]] = []
    try:
        client = AsyncNetworkClient()
        resp = await client.request("GET", url, headers=auth_headers)
        # resp は辞書：{"status": 200, "body": "...", "headers": {...}}
        body = resp.get("body", "") if isinstance(resp, dict) else getattr(resp, "text", "")
        soup = BeautifulSoup(body, "html.parser")

        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()

            inputs: List[Dict[str, Any]] = []
            for input_elem in form.find_all(["input", "select", "textarea"]):
                name = input_elem.get("name")
                if name:
                    input_type = input_elem.get("type", "text")
                    value = input_elem.get("value", "1")
                    inputs.append({"name": name, "type": input_type, "value": value})

            forms.append({
                "action": action,
                "method": method,
                "inputs": inputs
            })

        await client.close()
    except Exception as e:
        logger.debug("[form_parsing] HTML form parsing failed for %s: %s", url, e)

    return forms
