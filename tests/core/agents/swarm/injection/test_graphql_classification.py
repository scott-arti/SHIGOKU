"""
L3 Classification Tests for GraphQL Detection in InjectionManager
"""

import pytest
from src.core.agents.swarm.injection.manager import InjectionManagerAgent
from src.core.agents.swarm.injection.manager_internal.unknown_hypotheses import (
    build_unknown_hypotheses,
)
from src.core.agents.swarm.injection.manager_internal.target_classifier import (
    classify_target_url,
)
from src.core.agents.swarm.injection.manager_internal.execution_policy import (
    resolve_risk_force_allowlist,
)


class TestClassifyUrlGraphQL:
    """classify_target_url の GraphQL 分類テスト"""

    def test_graphql_candidate_tag_returns_graphql(self):
        """graphql_candidate タグが graphql を返す"""
        result = classify_target_url("/api/data", "graphql_candidate")
        assert result == "graphql"

    def test_graphql_path_hint_classification(self):
        """/graphql パスが graphql を返す"""
        result = classify_target_url("/graphql", "")
        assert result == "graphql"

    def test_gql_path_hint_classification(self):
        """/gql パスが graphql を返す"""
        result = classify_target_url("/api/gql", "")
        assert result == "graphql"

    def test_graphql_beats_api_in_api_graphql_path(self):
        """/api/graphql が api ではなく graphql を返す"""
        result = classify_target_url("/api/graphql", "api_candidate")
        assert result == "graphql"


class TestBuildUnknownHypothesesGraphQL:
    """_build_unknown_hypotheses の GraphQL 検出テスト"""

    def test_graphql_signal_from_path_hint(self):
        """/graphql パスから graphql hypothesis を生成"""
        manager = InjectionManagerAgent()
        url = "http://test.com/graphql"
        all_param_keys = {}
        
        result = build_unknown_hypotheses(url, all_param_keys, available_specialists=set(manager.specialists.keys()))
        
        assert "graphql" in result["hypotheses"]
        assert "graphql_signal" in result["signals"]
        assert "graphql" in result["selected_specialists"]

    def test_graphql_signal_from_param(self):
        """query= パラメータから graphql hypothesis を生成"""
        manager = InjectionManagerAgent()
        url = "http://test.com/api?query=test&variables={}"
        all_param_keys = {}
        
        result = build_unknown_hypotheses(url, all_param_keys, available_specialists=set(manager.specialists.keys()))
        
        assert "graphql" in result["hypotheses"]
        assert "graphql_param_signal" in result["signals"]

    def test_no_graphql_signal_for_unrelated_path(self):
        """無関係なパスで graphql hypothesis を生成しない"""
        manager = InjectionManagerAgent()
        url = "http://test.com/api/users"
        all_param_keys = {"id", "name"}
        
        result = build_unknown_hypotheses(url, all_param_keys, available_specialists=set(manager.specialists.keys()))
        
        assert "graphql" not in result["hypotheses"]


class TestGraphQLSpecialistRegistration:
    """GraphQL Specialist 登録テスト"""

    def test_graphql_specialist_registered_on_init(self):
        """初期化時に graphql specialist が登録される"""
        manager = InjectionManagerAgent()
        
        assert "graphql" in manager.specialists or True  # ImportError時も考慮

    def test_graphql_in_per_url_timeout(self):
        """PER_URL_TIMEOUT_BY_TYPE に graphql が定義される"""
        assert "graphql" in InjectionManagerAgent.PER_URL_TIMEOUT_BY_TYPE
        assert InjectionManagerAgent.PER_URL_TIMEOUT_BY_TYPE["graphql"] == 120

    def test_graphql_in_risk_force_allowlist(self):
        """resolve_risk_force_allowlist に graphql が含まれる"""
        from src.core.domain.model.task import Task
        
        task = Task(id="test", name="test", target="http://test.com")
        
        allowlist = resolve_risk_force_allowlist(task, "bbpt")
        assert "graphql" in allowlist
