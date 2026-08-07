"""
VDP M3a read-only guard tests — SGK-2026-0421 Step 5.

Method alone never decides read-only: GET with state-changing semantics and
GraphQL mutations are rejected; POST carrying a GraphQL query is allowed.
"""
from __future__ import annotations

import pytest

from src.core.engine.vdp_readonly_guard import (
    evaluate_readonly_request,
    is_state_changing_method,
)


class TestMethodOnlyIsNeverEnough:
    @pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE"])
    def test_state_changing_methods_rejected(self, method):
        v = evaluate_readonly_request(method)
        assert v.allowed is False
        assert v.risk_class == "state_changing"

    def test_get_with_state_changing_semantics_rejected(self):
        for semantics in (
            "form_submit",
            "workflow_transition",
            "upload",
            "update",
            "delete",
            "state_change",
            "approval",
            "invite",
            "refund",
        ):
            v = evaluate_readonly_request("GET", action_semantics=semantics)
            assert v.allowed is False, semantics
            assert v.risk_class == "state_changing"

    def test_get_normal_read_allowed(self):
        v = evaluate_readonly_request("GET")
        assert v.allowed is True
        assert v.risk_class == "read_only"

    def test_head_and_options_allowed(self):
        assert evaluate_readonly_request("HEAD").allowed is True
        assert evaluate_readonly_request("OPTIONS").allowed is True

    def test_unknown_method_rejected(self):
        v = evaluate_readonly_request("TRACE")
        assert v.allowed is False
        v2 = evaluate_readonly_request("BREW")
        assert v2.allowed is False
        assert v2.risk_class == "unknown"

    def test_empty_method_rejected(self):
        assert evaluate_readonly_request("").allowed is False


class TestGraphQL:
    def test_graphql_mutation_on_post_rejected(self):
        v = evaluate_readonly_request(
            "POST", graphql_operation="mutation"
        )
        assert v.allowed is False
        assert v.operation == "graphql_mutation"

    def test_graphql_query_on_post_allowed(self):
        v = evaluate_readonly_request("POST", graphql_operation="query")
        assert v.allowed is True
        assert v.operation == "graphql_query"

    def test_graphql_mutation_detected_from_body(self):
        body = '{"query": "mutation { deleteUser(id: 1) { id } }"}'
        v = evaluate_readonly_request("POST", body=body)
        assert v.allowed is False
        assert v.operation == "graphql_mutation"

    def test_graphql_query_detected_from_body(self):
        body = '{"query": "query { user(id: 1) { name } }"}'
        v = evaluate_readonly_request("POST", body=body)
        assert v.allowed is True

    def test_mutation_keyword_within_query_text_is_mutation(self):
        # JSON "query" field whose body text contains mutation → mutation.
        body = '{"query": "mutation { updateProfile(input: 1) }"}'
        assert evaluate_readonly_request("POST", body=body).allowed is False

    def test_mutation_on_get_rejected_via_body_sniff(self):
        v = evaluate_readonly_request("GET", body="mutation { x }")
        assert v.allowed is False

    def test_body_never_leaks_into_verdict(self):
        secret = "SUPER-SECRET-BODY-TOKEN-12345"
        v = evaluate_readonly_request(
            "POST", body=f'{{"query": "mutation {{ delete }}", "pw": "{secret}"}}'
        )
        assert secret not in v.reason
        assert secret not in str(v)


class TestDeterminism:
    def test_same_input_same_verdict(self):
        a = evaluate_readonly_request("POST", body='{"query": "mutation {x}"}')
        b = evaluate_readonly_request("POST", body='{"query": "mutation {x}"}')
        assert (a.allowed, a.operation, a.reason) == (b.allowed, b.operation, b.reason)

    def test_is_state_changing_method(self):
        assert is_state_changing_method("POST")
        assert is_state_changing_method("delete")
        assert not is_state_changing_method("GET")
        assert not is_state_changing_method("")
