from __future__ import annotations

import json
import subprocess
from pathlib import Path


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _write_session(path: Path) -> None:
    payload = {
        "session_id": "attack-path-cli-001",
        "start_time": 1784592000.0,
        "context": {
            "target_info": {
                "url": "https://example.test",
                "domain": "example.test",
            },
        },
        "completed_tasks": [
            {
                "id": "task-001",
                "result": {
                    "findings": [
                        {
                            "id": "CHAIN-001",
                            "title": "Attack Chain: Account Takeover",
                            "severity": "critical",
                            "confidence": 0.95,
                            "target_url": "https://example.test/account",
                            "source_agent": "chain_builder",
                            "additional_info": {
                                "is_attack_chain": True,
                                "business_impact_sentence": "Attacker can take over the account.",
                                "component_titles": ["Stored XSS in profile"],
                                "decision_trace": {
                                    "selected_rule_id": "account_takeover_xss_csrf",
                                    "final_state": "confirmed",
                                    "excluded_reasons": [],
                                },
                            },
                        }
                    ]
                },
            }
        ],
    }
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")


def test_report_attack_paths_writes_json_and_cypher_outputs(tmp_path: Path) -> None:
    session_file = tmp_path / "session_attack_paths.json"
    output_file = tmp_path / "attack_paths.md"
    _write_session(session_file)

    result = subprocess.run(
        [
            "python3",
            "scripts/shigoku_ops_cli.py",
            "--json",
            "report",
            "attack-paths",
            "--session",
            str(session_file),
            "--output",
            str(output_file),
            "--json-output",
            "--cypher-output",
        ],
        cwd=_repo_root(),
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["status"] == "ok"
    assert output_file.exists()

    json_output = output_file.with_suffix(".json")
    cypher_output = output_file.with_suffix(".cypher")
    assert json_output.exists()
    assert cypher_output.exists()
    assert payload["json_output"] == str(json_output.resolve())
    assert payload["cypher_output"] == str(cypher_output.resolve())

    json_payload = json.loads(json_output.read_text(encoding="utf-8"))
    assert "nodes" in json_payload
    assert "edges" in json_payload

    cypher = cypher_output.read_text(encoding="utf-8")
    assert "MERGE (n:AttackPath" in cypher
    assert "MERGE (n:Endpoint" in cypher
    assert "HAS_ENDPOINT" in cypher
