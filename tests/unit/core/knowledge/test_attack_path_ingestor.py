from __future__ import annotations

from pathlib import Path


def _sample_attack_path_payload() -> dict:
    return {
        "nodes": [
            {
                "node_id": "target:example.test",
                "display_label": "example.test",
                "node_type": "Target",
                "evidence_state": "confirmed",
                "why_in_path": "Root target of the assessment",
                "source_refs": ["sess-001"],
                "blocked_reason": "",
                "next_validation_hint": "",
                "observed_at": "2026-07-21T00:00:00+00:00",
                "inferred_after": "2026-07-21T00:05:00+00:00",
                "extra": {"url": "https://example.test", "domain": "example.test"},
            },
            {
                "node_id": "attack_path:CHAIN-001",
                "display_label": "Account takeover chain",
                "node_type": "AttackPath",
                "evidence_state": "confirmed",
                "why_in_path": "Stored XSS leads to account takeover",
                "source_refs": ["CHAIN-001", "account_takeover_xss_csrf"],
                "blocked_reason": "",
                "next_validation_hint": "Path confirmed — escalate to program owner",
                "observed_at": "2026-07-21T00:01:00+00:00",
                "inferred_after": "2026-07-21T00:05:00+00:00",
                "extra": {"severity": "critical", "confidence": 0.95},
            },
            {
                "node_id": "endpoint:https_example_test_account",
                "display_label": "https://example.test/account",
                "node_type": "Endpoint",
                "evidence_state": "confirmed",
                "why_in_path": "Affected endpoint",
                "source_refs": ["CHAIN-001"],
                "blocked_reason": "",
                "next_validation_hint": "",
                "observed_at": None,
                "inferred_after": None,
                "extra": {"url": "https://example.test/account"},
            },
        ],
        "edges": [
            {
                "edge_id": "edge:target_to_path:CHAIN-001",
                "source_node_id": "target:example.test",
                "target_node_id": "attack_path:CHAIN-001",
                "edge_type": "SUPPORTS_PATH",
                "display_label": "target hosts attack path",
                "evidence_state": "confirmed",
                "why_in_path": "Target is in scope",
                "source_refs": ["sess-001", "CHAIN-001"],
            },
            {
                "edge_id": "edge:path_to_endpoint:CHAIN-001",
                "source_node_id": "attack_path:CHAIN-001",
                "target_node_id": "endpoint:https_example_test_account",
                "edge_type": "HAS_ENDPOINT",
                "display_label": "affects",
                "evidence_state": "confirmed",
                "why_in_path": "The chain touches the endpoint",
                "source_refs": ["CHAIN-001"],
            },
        ],
        "metadata": {
            "session_id": "sess-001",
            "generated_at": "2026-07-21T00:05:00+00:00",
            "total_chains": 1,
        },
    }


class _FakeSession:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def __enter__(self) -> "_FakeSession":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False

    def run(self, query: str, **kwargs):
        self.calls.append((query, kwargs))
        return []


class _FakeDriver:
    def __init__(self) -> None:
        self.session_obj = _FakeSession()

    def session(self) -> _FakeSession:
        return self.session_obj


def test_build_attack_path_cypher_uses_endpoint_url_identity() -> None:
    from src.core.knowledge.attack_path_ingestor import build_attack_path_cypher

    script = build_attack_path_cypher(_sample_attack_path_payload())

    assert "MERGE (n:Endpoint {url: 'https://example.test/account'})" in script
    assert "MERGE (src)-[r:HAS_ENDPOINT {id: 'edge:path_to_endpoint:CHAIN-001'}]->(dst)" in script
    assert "SET n += {" in script


def test_ingest_attack_path_payload_writes_nodes_and_edges() -> None:
    from src.core.knowledge.attack_path_ingestor import ingest_attack_path_payload

    driver = _FakeDriver()

    summary = ingest_attack_path_payload(
        _sample_attack_path_payload(),
        driver=driver,
        apply_constraints=False,
    )

    assert summary["nodes_written"] == 3
    assert summary["edges_written"] == 2

    queries = [query for query, _kwargs in driver.session_obj.calls]
    assert any("MERGE (n:Endpoint {url: $identity_value})" in query for query in queries)
    assert any("MERGE (src)-[r:HAS_ENDPOINT {id: $edge_id}]->(dst)" in query for query in queries)

    endpoint_call = next(
        kwargs
        for query, kwargs in driver.session_obj.calls
        if "MERGE (n:Endpoint {url: $identity_value})" in query
    )
    assert endpoint_call["identity_value"] == "https://example.test/account"
