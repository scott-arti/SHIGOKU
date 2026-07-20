"""Shared form harvesting utility for injection specialists.

Provides a robust `fetch_and_parse_form()` that extracts HTML form parameters
from both authenticated and unauthenticated pages. Uses AsyncNetworkClient as
the primary path with a synchronous urllib fallback when the primary path
returns an empty body or raises.
"""

import asyncio
import logging
import urllib.request
from typing import Any, Dict, List

from src.core.infra.network_client import AsyncNetworkClient

logger = logging.getLogger(__name__)


def _parse_forms_from_html(html_body: str) -> List[Dict[str, Any]]:
    """Parse all <form> elements from an HTML string.

    Extracts action, method, and named inputs (input/select/textarea).
    """
    from bs4 import BeautifulSoup

    forms: List[Dict[str, Any]] = []
    if not html_body:
        return forms

    soup = BeautifulSoup(html_body, "html.parser")
    for form in soup.find_all("form"):
        action = str(form.get("action", ""))
        method = str(form.get("method", "GET")).upper()

        inputs: List[Dict[str, str]] = []
        for elem in form.find_all(["input", "select", "textarea"]):
            name = str(elem.get("name", ""))
            if name:
                input_type = str(elem.get("type", "text"))
                value = str(elem.get("value", "1"))
                inputs.append({"name": name, "type": input_type, "value": value})

        forms.append({"action": action, "method": method, "inputs": inputs})
    return forms


def _urllib_fetch(url: str, auth_headers: Dict[str, str]) -> str:
    """Synchronous fallback: fetch a URL via stdlib urllib.

    Intended to be called via ``run_in_executor``. Auth headers are passed
    through but never logged.
    """
    req = urllib.request.Request(url, headers=auth_headers)
    with urllib.request.urlopen(req, timeout=20) as resp:
        return resp.read().decode("utf-8", errors="replace")


async def fetch_and_parse_form(
    url: str, auth_headers: Dict[str, str]
) -> List[Dict[str, Any]]:
    """Fetch *url* and extract HTML form parameters.

    Uses ``AsyncNetworkClient`` as the primary path (cache disabled, timeout
    20s).  Falls back to ``urllib`` in a thread executor when the primary
    response body is empty or when the primary path raises.

    Returns:
        A list of form dicts with keys ``action``, ``method``, and ``inputs``.
        Returns ``[]`` when both paths fail or no forms are found.
    """
    forms: List[Dict[str, Any]] = []
    body: str = ""

    # -- Primary path: AsyncNetworkClient -----------------------------------
    client = AsyncNetworkClient()
    try:
        resp = await client.request(
            "GET", url, headers=auth_headers, use_cache=False, timeout=20
        )
        # resp is a NetworkResponse (dataclass) but some paths may return dict
        if isinstance(resp, dict):
            body = str(resp.get("body", "") or "")
        else:
            body = str(getattr(resp, "body", "") or "")
    except Exception as exc:
        logger.warning(
            "Primary fetch failed for %s (%s), trying urllib fallback",
            url,
            type(exc).__name__,
        )
    finally:
        await client.close()

    # -- Fallback path: urllib in thread executor ---------------------------
    if not body:
        try:
            loop = asyncio.get_running_loop()
            body = await loop.run_in_executor(
                None, _urllib_fetch, url, auth_headers
            )
        except Exception as exc:
            logger.warning(
                "Urllib fallback also failed for %s (%s)",
                url,
                type(exc).__name__,
            )

    # -- Parse ----------------------------------------------------------------
    if body:
        forms = _parse_forms_from_html(body)
        if not forms:
            logger.info("Page fetched for %s (%d bytes) but no <form> elements found", url, len(body))

    return forms
