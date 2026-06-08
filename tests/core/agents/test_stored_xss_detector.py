"""
Phase X-2: StoredXSSDetector ユニットテスト
受け入れ基準検証:
- フォーム検出→マーカー注入→保存→表示確認のフローが動作する
- 表示画面URLが複数の戦略で特定される
- HITL統合フローが実装される
- レートリミット・データ破壊回避のガードレールが機能する
"""
import asyncio
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from src.core.agents.swarm.injection.stored_xss_detector import (
    DisplayURLResolver,
    FormDetector,
    FormRiskLevel,
    HITLGate,
    MarkerReflection,
    ParsedForm,
    StoredXSSDetector,
    StoredXSSFinding,
    XSSPayloadGenerator,
    _classify_reflection_context,
    _extract_snippet,
)


# ---------------------------------------------------------------------------
# HITLGate
# ---------------------------------------------------------------------------

class TestHITLGate:
    @pytest.mark.asyncio
    async def test_auto_approve_low_risk(self):
        gate = HITLGate(auto_approve_low_risk=True)
        form = ParsedForm("/search", "GET", {"q": ""}, FormRiskLevel.LOW)
        approved = await gate.request_approval(form, {"q": "test"}, "test")
        assert approved is True

    @pytest.mark.asyncio
    async def test_deny_medium_risk_by_default(self):
        gate = HITLGate(auto_approve_low_risk=True)
        form = ParsedForm("/create", "POST", {"name": ""}, FormRiskLevel.MEDIUM)
        approved = await gate.request_approval(form, {"name": "x"}, "payload injection")
        assert approved is False

    @pytest.mark.asyncio
    async def test_pending_list_populated(self):
        gate = HITLGate(auto_approve_low_risk=True)
        form = ParsedForm("/create", "POST", {"name": ""}, FormRiskLevel.MEDIUM)
        await gate.request_approval(form, {"name": "x"}, "reason")
        assert len(gate.get_pending_requests()) == 1
        assert gate.get_pending_requests()[0].form_action == "/create"


# ---------------------------------------------------------------------------
# FormDetector
# ---------------------------------------------------------------------------

class TestFormDetector:
    def test_risk_classification_high(self):
        detector = FormDetector()
        risk = detector.classify_risk("http://example.com/admin/delete", "POST")
        assert risk == FormRiskLevel.HIGH

    def test_risk_classification_medium(self):
        detector = FormDetector()
        risk = detector.classify_risk("http://example.com/posts/create", "POST")
        assert risk == FormRiskLevel.MEDIUM

    def test_risk_classification_low(self):
        detector = FormDetector()
        risk = detector.classify_risk("http://example.com/search", "GET")
        assert risk == FormRiskLevel.LOW


# ---------------------------------------------------------------------------
# DisplayURLResolver
# ---------------------------------------------------------------------------

class TestDisplayURLResolver:
    def test_resolve_create_path(self):
        resolver = DisplayURLResolver()
        form = ParsedForm("http://example.com/posts/create", "POST", {})
        urls = resolver.resolve(form)
        assert any("/list" in u or "/index" in u for u in urls), f"Got: {urls}"

    def test_resolve_add_path(self):
        resolver = DisplayURLResolver()
        form = ParsedForm("http://example.com/comments/add", "POST", {})
        urls = resolver.resolve(form)
        assert len(urls) >= 1

    def test_no_duplicates(self):
        resolver = DisplayURLResolver()
        form = ParsedForm("http://example.com/posts/create", "POST", {})
        urls = resolver.resolve(form)
        assert len(urls) == len(set(urls))

    @pytest.mark.asyncio
    async def test_extract_links_from_html(self):
        resolver = DisplayURLResolver()
        html = '<html><a href="/posts/list">List</a><a href="/posts/42">View</a></html>'
        links = await resolver.extract_from_response_links(html, "http://example.com")
        assert "http://example.com/posts/list" in links
        assert "http://example.com/posts/42" in links


# ---------------------------------------------------------------------------
# Reflection context classifier
# ---------------------------------------------------------------------------

class TestReflectionClassifier:
    def test_html_text_context(self):
        html = "<p>Hello shigoku_probe_abc123</p>"
        ctx = _classify_reflection_context(html, "shigoku_probe_abc123")
        assert ctx == "html_text"

    def test_script_block_context(self):
        html = "<script>var x = 'shigoku_probe_abc123';</script>"
        ctx = _classify_reflection_context(html, "shigoku_probe_abc123")
        assert ctx == "script_block"

    def test_tag_attribute_context(self):
        html = '<input value="shigoku_probe_abc123">'
        ctx = _classify_reflection_context(html, "shigoku_probe_abc123")
        assert ctx in ("tag_attribute", "html_text")

    def test_snippet_extraction(self):
        html = "abcdefg MARKER hijklmn"
        snippet = _extract_snippet(html, "MARKER", window=5)
        assert "MARKER" in snippet
        assert len(snippet) <= 5 + len("MARKER") + 5 + 2  # rough check


# ---------------------------------------------------------------------------
# XSSPayloadGenerator
# ---------------------------------------------------------------------------

class TestXSSPayloadGenerator:
    def test_returns_payloads_for_html_text(self):
        gen = XSSPayloadGenerator()
        payloads = gen.generate("html_text")
        assert len(payloads) > 0
        assert any("<script>" in p for p in payloads)

    def test_returns_payloads_for_script_block(self):
        gen = XSSPayloadGenerator()
        payloads = gen.generate("script_block")
        assert len(payloads) > 0
        assert any("alert" in p for p in payloads)

    def test_fallback_for_unknown_context(self):
        gen = XSSPayloadGenerator()
        payloads = gen.generate("unknown")
        assert len(payloads) > 0


# ---------------------------------------------------------------------------
# StoredXSSDetector integration (mocked network)
# ---------------------------------------------------------------------------

class TestStoredXSSDetector:

    def _make_mock_response(self, body: str):
        return {"status": 200, "body": body, "headers": {}}

    @pytest.mark.asyncio
    async def test_marker_generated_with_prefix(self):
        detector = StoredXSSDetector()
        marker = detector._generate_marker()
        assert marker.startswith("shigoku_probe_")
        assert len(marker) > len("shigoku_probe_")

    @pytest.mark.asyncio
    async def test_csrf_params_excluded_from_injection(self):
        detector = StoredXSSDetector()
        form = ParsedForm(
            "/post", "POST",
            {"title": "", "body": "", "csrf_token": "abc", "submit": "Send"},
        )
        injectable = detector._get_injectable_params(form)
        assert "csrf_token" not in injectable
        assert "submit" not in injectable
        assert "title" in injectable
        assert "body" in injectable

    @pytest.mark.asyncio
    async def test_hitl_gate_blocks_medium_risk_payload(self):
        """Medium-riskフォームへのペイロード注入はHITLでブロックされる"""
        gate = HITLGate(auto_approve_low_risk=True)
        detector = StoredXSSDetector(hitl_gate=gate)

        form = ParsedForm(
            "http://example.com/comment/create", "POST",
            {"comment": ""}, FormRiskLevel.MEDIUM,
        )

        # HITL will auto-deny medium risk → no findings
        with patch.object(
            detector._form_detector, "detect_forms",
            return_value=[form]
        ), patch.object(
            detector, "_submit_form",
            return_value=(True, "")
        ), patch.object(
            detector, "_check_reflections",
            return_value=[MarkerReflection(found=True, url="http://example.com/comments", context="html_text")]
        ):
            findings = await detector.scan("http://example.com")

        # Payload injection should be blocked by HITL
        assert len(findings) == 0
        assert len(gate.get_pending_requests()) >= 1

    @pytest.mark.asyncio
    async def test_static_verification_detects_reflection(self):
        """静的確認: 未エスケープのペイロード反射を検出"""
        detector = StoredXSSDetector()
        payload = "<script>alert(1)</script>"

        mock_resp = self._make_mock_response(
            f"<html><div>{payload}</div></html>"
        )

        with patch(
            "src.core.agents.swarm.injection.stored_xss_detector.AsyncNetworkClient"
        ) as MockClient:
            mock_instance = AsyncMock()
            mock_instance.request = AsyncMock(return_value=mock_resp)
            mock_instance.close = AsyncMock()
            MockClient.return_value = mock_instance

            executed, evidence = await detector._verify_with_static_check(
                "http://example.com/posts", payload
            )

        assert executed is True
        assert "url" in evidence

    @pytest.mark.asyncio
    async def test_display_url_multiple_strategies(self):
        """表示画面URLが複数の戦略で特定されることを確認"""
        detector = StoredXSSDetector()
        form = ParsedForm(
            "http://example.com/posts/create", "POST",
            {"title": "", "body": ""}
        )

        # Submit returns body with links
        submit_body = '<a href="/posts/list">All Posts</a>'
        with patch.object(detector, "_submit_form", return_value=(True, submit_body)):
            # Manually test URL resolver strategies
            from_pattern = detector._url_resolver.resolve(form)
            from_links = await detector._url_resolver.extract_from_response_links(
                submit_body, "http://example.com"
            )

        assert len(from_pattern) >= 1, "Pattern-based strategy must return URLs"
        assert "http://example.com/posts/list" in from_links, "Link extraction must work"


# ---------------------------------------------------------------------------
# End-to-end flow (fully mocked)
# ---------------------------------------------------------------------------

class TestStoredXSSE2EFlow:

    @pytest.mark.asyncio
    async def test_full_flow_low_risk_form(self):
        """
        低リスクフォームでの完全フロー:
        フォーム検出 → HITL承認（自動） → マーカー注入 → 反射確認 → ペイロード注入
        ※低リスクフォームはマーカー注入のみ自動承認（ペイロード注入は中リスク扱い）
        """
        gate = HITLGate(auto_approve_low_risk=True)
        detector = StoredXSSDetector(hitl_gate=gate)

        low_risk_form = ParsedForm(
            "http://example.com/search", "GET",
            {"q": ""}, FormRiskLevel.LOW,
        )

        with patch.object(
            detector._form_detector, "detect_forms",
            return_value=[low_risk_form]
        ), patch.object(
            detector, "_submit_form",
            return_value=(True, "")
        ), patch.object(
            detector, "_check_reflections",
            return_value=[]  # マーカー未反射
        ):
            findings = await detector.scan("http://example.com")

        # 反射なしなので findings は空
        assert findings == []

    @pytest.mark.asyncio
    async def test_marker_uniqueness(self):
        """マーカーが毎回ユニークであることを確認"""
        detector = StoredXSSDetector()
        markers = {detector._generate_marker() for _ in range(100)}
        assert len(markers) == 100, "Markers must be unique"
