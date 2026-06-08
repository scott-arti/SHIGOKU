"""
CRLF 分類テスト

classify_target_url と build_unknown_hypotheses が crlf_candidate タグと
CRLF 関連 URL / パラメータを正しく "crlf" に分類することを検証する。
"""

import pytest
from unittest.mock import MagicMock

from src.core.agents.swarm.injection.manager import InjectionManagerAgent
from src.core.agents.swarm.injection.manager_internal.unknown_hypotheses import (
    build_unknown_hypotheses,
)
from src.core.agents.swarm.injection.manager_internal.target_classifier import (
    classify_target_url,
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _agent() -> InjectionManagerAgent:
    config = MagicMock()
    config.get.return_value = 1
    agent = InjectionManagerAgent(config=config)
    return agent


def _hypotheses(agent: InjectionManagerAgent, url: str, base_params: dict = None) -> list:
    """build_unknown_hypotheses の返値から specialists リストを取り出す。"""
    result = build_unknown_hypotheses(url, base_params or {}, available_specialists=set(agent.specialists.keys()))
    return result.get("selected_specialists", [])


def _signals(agent: InjectionManagerAgent, url: str, base_params: dict = None) -> list:
    result = build_unknown_hypotheses(url, base_params or {}, available_specialists=set(agent.specialists.keys()))
    return result.get("signals", [])


# ---------------------------------------------------------------------------
# classify_target_url: crlf_candidate タグ → "crlf"
# ---------------------------------------------------------------------------

class TestClassifyUrlCRLF:

    def test_crlf_candidate_tag_returns_crlf(self):
        result = classify_target_url(
            "http://target.test/redirect?url=x", "crlf_candidate"
        )
        assert result == "crlf"

    def test_crlf_candidate_beats_redirect_param(self):
        """B6: crlf_candidate が redirect_param より先に評価される（誤分類防止）"""
        result = classify_target_url(
            "http://target.test/redirect?url=x", "crlf_candidate"
        )
        assert result == "crlf"
        # redirect_param が来ても crlf_candidate は上書きされない
        result2 = classify_target_url(
            "http://target.test/redirect?url=x", "redirect_param"
        )
        assert result2 == "redirect"

    def test_cors_candidate_unaffected(self):
        """CORS 分類が crlf 追加で壊れていない"""
        result = classify_target_url(
            "http://target.test/api/data", "cors_candidate"
        )
        assert result == "cors"

    def test_unknown_category_with_crlf_path_does_not_return_crlf_directly(self):
        """カテゴリなし + /redirect パスは classify_target_url では "redirect" を返す（パス判定より前にクエリ評価）"""
        result = classify_target_url(
            "http://target.test/redirect?url=x", ""
        )
        # url= クエリパラメータがあるので redirect が先に取る
        assert result == "redirect"


# ---------------------------------------------------------------------------
# _build_unknown_hypotheses: crlf 仮説の生成
# ---------------------------------------------------------------------------

class TestBuildUnknownHypothesesCRLF:

    def setup_method(self):
        self.agent = _agent()
        # crlf specialist が存在しないと selected_specialists から除外されるため追加
        self.agent.specialists["crlf"] = MagicMock()

    def test_crlf_signal_from_redirect_path(self):
        """/redirect パスで crlf_signal が生成される"""
        signals = _signals(self.agent, "http://target.test/redirect")
        assert "crlf_signal" in signals

    def test_crlf_specialist_selected_from_redirect_path(self):
        """/redirect パスで crlf specialist が選ばれる"""
        specialists = _hypotheses(self.agent, "http://target.test/redirect")
        assert "crlf" in specialists

    def test_crlf_signal_from_location_path(self):
        """/location パスで crlf_signal が生成される"""
        signals = _signals(self.agent, "http://target.test/location?next=/home")
        assert "crlf_signal" in signals

    def test_crlf_signal_from_forward_path(self):
        """/forward パスで crlf_signal が生成される"""
        signals = _signals(self.agent, "http://target.test/forward")
        assert "crlf_signal" in signals

    def test_crlf_signal_from_redir_path(self):
        """/redir パスで crlf_signal が生成される"""
        signals = _signals(self.agent, "http://target.test/redir?url=x")
        assert "crlf_signal" in signals

    def test_crlf_signal_from_url_param(self):
        """url= クエリパラメータで crlf_signal が生成される"""
        signals = _signals(self.agent, "http://target.test/go?url=https://example.com")
        assert "crlf_signal" in signals

    def test_crlf_signal_from_lang_param(self):
        """lang= クエリパラメータで crlf_signal が生成される"""
        signals = _signals(self.agent, "http://target.test/page?lang=ja")
        assert "crlf_signal" in signals

    def test_crlf_signal_from_charset_param(self):
        """charset= クエリパラメータで crlf_signal が生成される"""
        signals = _signals(self.agent, "http://target.test/doc?charset=utf-8")
        assert "crlf_signal" in signals

    def test_crlf_signal_from_next_param(self):
        """next= クエリパラメータで crlf_signal が生成される"""
        signals = _signals(self.agent, "http://target.test/login?next=/dashboard")
        assert "crlf_signal" in signals

    def test_crlf_signal_from_header_param(self):
        """header= クエリパラメータで crlf_signal が生成される"""
        signals = _signals(self.agent, "http://target.test/api?header=X-Custom")
        assert "crlf_signal" in signals

    def test_crlf_specialist_not_selected_when_not_registered(self):
        """crlf specialist が未登録なら selected_specialists に含まれない"""
        agent = _agent()
        # __init__ で登録される crlf を削除して未登録状態にする
        agent.specialists.pop("crlf", None)
        specialists = _hypotheses(agent, "http://target.test/redirect")
        assert "crlf" not in specialists

    def test_no_crlf_signal_for_unrelated_path(self):
        """CRLF と無関係なパス・パラメータでは crlf_signal が出ない"""
        signals = _signals(
            self.agent,
            "http://target.test/profile?id=1&name=alice",
        )
        assert "crlf_signal" not in signals

    def test_crlf_does_not_suppress_other_hypotheses(self):
        """crlf が追加されても sqli などの他仮説が残る"""
        signals = _signals(
            self.agent,
            "http://target.test/search?q=test&redirect=/home",
        )
        assert "crlf_signal" in signals
        assert "xss_signal" in signals


# ---------------------------------------------------------------------------
# specialist 登録確認
# ---------------------------------------------------------------------------

class TestCRLFSpecialistRegistration:

    def test_crlf_specialist_registered_on_init(self):
        """初期化時に crlf specialist が登録される"""
        agent = _agent()
        assert "crlf" in agent.specialists

    def test_crlf_tool_registered(self):
        """crlf_scan ツールが登録される"""
        agent = _agent()
        assert "crlf_scan" in agent.available_tools

    def test_per_url_timeout_has_crlf(self):
        """PER_URL_TIMEOUT_BY_TYPE に crlf エントリが存在する"""
        assert "crlf" in InjectionManagerAgent.PER_URL_TIMEOUT_BY_TYPE
        assert InjectionManagerAgent.PER_URL_TIMEOUT_BY_TYPE["crlf"] == 90
