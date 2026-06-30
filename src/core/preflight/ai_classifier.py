"""
Lightweight AI-based classifier for ambiguous HTTP responses.

Used as a supplementary fallback when the deterministic auth_probe
cannot classify a response with certainty.

Design constraints (from plan):
- Max 1 call per probe
- Max 5 calls per run (configurable)
- Model failure => UNKNOWN
- Unknown => strict fail (handled by caller)
- AI is supplementary only, not decision-making
- Never raises exceptions from classify()
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import TYPE_CHECKING, Any, Optional

from src.core.preflight.models import (
    ResponseClassificationInput,
    ResponseClassificationResult,
)

if TYPE_CHECKING:
    from src.core.models.llm import LLMClient

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Fixed label set (must match AuthClassification enum values)
# ---------------------------------------------------------------------------

_ALLOWED_LABELS: frozenset[str] = frozenset({
    "authenticated",
    "login_page",
    "session_expired",
    "waf_challenge",
    "rate_limited",
    "unknown",
})

# ---------------------------------------------------------------------------
# Prompt templates
# ---------------------------------------------------------------------------

_USER_PROMPT_TEMPLATE = (
    "Status: {status_code}\n"
    "Title: {title}\n"
    "Markers found: {markers}\n"
    "Response fragment: {fragment}\n\n"
    "Classify as one of: authenticated, login_page, session_expired, "
    "waf_challenge, rate_limited, unknown"
)

# ---------------------------------------------------------------------------
# Label descriptions (referenced in error logging, not sent in prompt)
# ---------------------------------------------------------------------------

_LABEL_DESCRIPTIONS: dict[str, str] = {
    "authenticated": "Response indicates successful authentication session.",
    "login_page": "Response is a login/challenge page requiring credentials.",
    "session_expired": "Response indicates the session has expired or is invalid.",
    "waf_challenge": "Response contains a WAF/bot-detection challenge (e.g. Cloudflare).",
    "rate_limited": "Response indicates rate limiting or throttling (HTTP 429 or similar).",
    "unknown": "Cannot determine the response classification.",
}


# ---------------------------------------------------------------------------
# AIClassifier
# ---------------------------------------------------------------------------

class AIClassifier:
    """Lightweight AI-based classifier for ambiguous HTTP responses.

    Used as a supplementary fallback when the deterministic auth_probe
    cannot classify a response with certainty.

    Attributes:
        timeout: Per-call timeout in seconds.
        max_calls_per_run: Maximum AI calls per preflight run.
    """

    def __init__(
        self,
        llm_client: Optional["LLMClient"] = None,
        timeout: float = 3.0,
        max_calls_per_run: int = 5,
    ) -> None:
        """Initialise the AI classifier.

        Args:
            llm_client: Optional LLMClient from src.core.models.llm.
                        If None, AI classification is disabled.
            timeout: Per-call timeout in seconds.
            max_calls_per_run: Maximum AI calls per preflight run.
        """
        self._llm_client = llm_client
        self._timeout = timeout
        self._max_calls_per_run = max_calls_per_run
        self._call_count: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def can_classify(self) -> bool:
        """Return True if AI classification is available and within call budget."""
        return self._llm_client is not None and self._call_count < self._max_calls_per_run

    async def classify(
        self,
        input_data: ResponseClassificationInput,
    ) -> ResponseClassificationResult:
        """Classify an ambiguous HTTP response using a lightweight LLM.

        Builds a compact deterministic prompt, sends it to the LLM, and
        parses the structured JSON response.

        Args:
            input_data: Stripped-down response characteristics from auth_probe.

        Returns:
            ResponseClassificationResult with label (one of the fixed label set)
            and confidence (0.0–1.0).  On any failure the result is ``unknown``
            with confidence 0.0.

        Never raises – all failures are caught and logged.
        """
        # --- guard: classifier disabled / budget exhausted ---
        if not self.can_classify():
            logger.debug(
                "AI classify skipped: client=%s, calls=%d/%d",
                self._llm_client is not None,
                self._call_count,
                self._max_calls_per_run,
            )
            return self._unknown_result(0.0)

        self._call_count += 1
        start = time.monotonic()

        # --- build prompt ---
        messages = self._build_messages(input_data)

        # --- call LLM ---
        from src.core.models.llm import LLMClient
        response_client = LLMClient(role="response_classifier")

        try:
            response = await asyncio.wait_for(
                response_client.agenerate(
                    messages,
                    tools=None,
                    force_cloud=False,
                    mask_pii=False,
                ),
                timeout=self._timeout,
            )
        except asyncio.TimeoutError:
            elapsed = (time.monotonic() - start) * 1000.0
            logger.warning("AI classifier timed out after %.0fms", elapsed)
            return self._unknown_result(elapsed)
        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000.0
            logger.warning("AI classifier LLM call failed: %s", exc)
            return self._unknown_result(elapsed)

        # --- extract and validate ---
        return self._parse_response(response, start)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_messages(
        self,
        input_data: ResponseClassificationInput,
    ) -> list[dict[str, str]]:
        """Build the compact prompt messages for the LLM."""
        markers = ", ".join(input_data.top_markers) if input_data.top_markers else "none"
        title = input_data.title or "none"
        fragment = input_data.response_fragment or "none"

        user_prompt = _USER_PROMPT_TEMPLATE.format(
            status_code=input_data.status_code,
            title=title,
            markers=markers,
            fragment=fragment,
        )

        return [
            {"role": "user", "content": user_prompt},
        ]

    def _parse_response(
        self,
        response: Any,
        start: float,
    ) -> ResponseClassificationResult:
        """Parse the LLM response JSON and validate the result."""
        elapsed = (time.monotonic() - start) * 1000.0

        try:
            raw_content = response.choices[0].message.content
        except (AttributeError, IndexError, TypeError) as exc:
            logger.warning("AI classifier unexpected response structure: %s", exc)
            return self._unknown_result(elapsed)

        # Parse JSON
        try:
            parsed = json.loads(raw_content)
        except json.JSONDecodeError as exc:
            logger.warning("AI classifier JSON parse failed: %s", exc)
            return self._unknown_result(elapsed)

        # Extract fields
        label = str(parsed.get("label", "unknown")).strip().lower()
        try:
            confidence = float(parsed.get("confidence", 0.0))
        except (ValueError, TypeError):
            confidence = 0.0

        # Clamp confidence
        confidence = max(0.0, min(1.0, confidence))

        # Validate label
        if label not in _ALLOWED_LABELS:
            logger.warning(
                "AI classifier returned invalid label %r (allowed: %s), "
                "falling back to unknown",
                label,
                sorted(_ALLOWED_LABELS),
            )
            label = "unknown"
            confidence = 0.0

        model_used = getattr(self._llm_client, "model", "")

        logger.debug(
            "AI classify result: label=%s confidence=%.2f elapsed=%.0fms",
            label,
            confidence,
            elapsed,
        )

        return ResponseClassificationResult(
            label=label,
            confidence=confidence,
            model_used=model_used,
            elapsed_ms=elapsed,
        )

    @staticmethod
    def _unknown_result(elapsed_ms: float) -> ResponseClassificationResult:
        """Return a safe UNKNOWN result with zero confidence."""
        return ResponseClassificationResult(
            label="unknown",
            confidence=0.0,
            model_used="",
            elapsed_ms=elapsed_ms,
        )
