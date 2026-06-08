import json
from pathlib import Path

import pytest

from src.core.intelligence.chain_builder import AttackChainBuilder
from src.core.engine.master_conductor import MasterConductor
from src.core.models.finding import Finding, Severity, VulnType


def _sample_xss() -> Finding:
    return Finding(
        vuln_type=VulnType.XSS,
        severity=Severity.MEDIUM,
        title="Reflected XSS in search endpoint",
        description="xss sink confirmed on /search?q=",
        target_url="https://example.com/search",
    )


def _sample_csrf_hint() -> Finding:
    return Finding(
        vuln_type=VulnType.DEBUG_ENABLED,
        severity=Severity.LOW,
        title="Missing CSRF token in profile update",
        description="Cross-site request forgery protection was not enforced.",
        target_url="https://example.com/profile",
    )


class TestAttackChainBuilder:
    def test_infers_chain_from_rules_db(self, tmp_path: Path):
        rules = tmp_path / "attack_chain_rules.json"
        rules.write_text(
            """
            {
              "version": 1,
              "rules": [
                {
                  "id": "r1",
                  "name": "ATO Chain",
                  "description": "XSS + CSRF",
                  "severity": "critical",
                  "required_signals": ["xss", "csrf"],
                  "min_components": 2
                }
              ]
            }
            """.strip(),
            encoding="utf-8",
        )

        builder = AttackChainBuilder(rules_path=str(rules))
        chains = builder.analyze([_sample_xss(), _sample_csrf_hint()])

        assert len(chains) == 1
        assert chains[0].rule_id == "r1"
        assert chains[0].severity == "critical"
        assert set(chains[0].matched_signals) == {"csrf", "xss"}

    def test_broken_rules_db_fallback(self, tmp_path: Path):
        broken = tmp_path / "broken.json"
        broken.write_text("{invalid", encoding="utf-8")

        builder = AttackChainBuilder(rules_path=str(broken))
        chains = builder.analyze([_sample_xss(), _sample_csrf_hint()])

        assert len(chains) >= 1
        assert any(c.rule_id == "account_takeover_xss_csrf" for c in chains)

    def test_to_finding_marks_attack_chain(self, tmp_path: Path):
        builder = AttackChainBuilder(rules_path=str(tmp_path / "missing.json"))
        chain = builder.analyze([_sample_xss(), _sample_csrf_hint()])[0]

        finding = chain.to_finding()
        assert finding.title.startswith("Attack Chain:")
        assert "attack_chain" in finding.tags
        assert finding.additional_info.get("is_attack_chain") is True
        assert finding.recommended_followup in {"report", "escalate"}

    def test_normalizes_command_injection_alias_for_upload_chain(self, tmp_path: Path):
        rules = tmp_path / "attack_chain_rules.json"
        rules.write_text(
            """
            {
              "version": 1,
              "rules": [
                {
                  "id": "upload_to_rce",
                  "name": "Upload to RCE",
                  "description": "upload + command injection",
                  "severity": "critical",
                  "required_signals": ["file_upload", "os_command_injection"],
                  "min_components": 2
                }
              ]
            }
            """.strip(),
            encoding="utf-8",
        )

        upload = Finding(
            vuln_type=VulnType.FILE_UPLOAD,
            severity=Severity.HIGH,
            title="Unrestricted file upload",
            description="upload endpoint allows php",
            target_url="https://example.com/upload",
        )
        cmd = Finding(
            vuln_type=VulnType.OTHER,
            severity=Severity.HIGH,
            title="OS command injection in ping",
            description="command_injection confirmed via payload",
            target_url="https://example.com/ping",
            tags=["command_injection"],
        )

        builder = AttackChainBuilder(rules_path=str(rules))
        chains = builder.analyze([upload, cmd])

        assert len(chains) == 1
        assert chains[0].rule_id == "upload_to_rce"
        assert "os_command_injection" in chains[0].matched_signals

    def test_promote_chain_uses_promotion_namespace_and_blocks_feasibility_failures(self, tmp_path: Path):
        builder = AttackChainBuilder(rules_path=str(tmp_path / "missing.json"), enforce_data_contract=True)

        result = builder.promote_chain(
            {
                "rule_id": "r1",
                "state": "confirmed",
                "excluded_reasons": ["feasibility:constraint_data_missing"],
                "falsification_checks": [],
                "replay_evidence": False,
            }
        )

        assert result["state"] != "actionable"
        assert "feasibility:constraint_data_missing" in result["excluded_reasons"]
        assert "promotion:falsification_checks_missing" in result["excluded_reasons"]
        assert "promotion:replay_evidence_missing" in result["excluded_reasons"]

    def test_prefers_industry_specific_rule_when_program_profile_matches(self, tmp_path: Path):
        rules = tmp_path / "attack_chain_rules.json"
        rules.write_text(
            """
            {
              "dsl_version": 1,
              "rules": [
                {
                  "id": "common_ato",
                  "name": "Common ATO",
                  "description": "Common rule",
                  "severity": "critical",
                  "required_signals": ["xss", "csrf"],
                  "min_components": 2
                },
                {
                  "id": "fintech_ato",
                  "name": "Fintech ATO",
                  "description": "Industry-specific rule",
                  "severity": "critical",
                  "required_signals": ["xss", "csrf"],
                  "min_components": 2,
                  "industry": "fintech"
                }
              ],
              "workflow_templates": {
                "common": {"template_id": "wf-common", "steps": ["probe-common"]},
                "fintech": {"template_id": "wf-fintech", "steps": ["probe-fintech"]}
              }
            }
            """.strip(),
            encoding="utf-8",
        )

        builder = AttackChainBuilder(rules_path=str(rules))

        findings = builder.analyze_with_context(
            [_sample_xss(), _sample_csrf_hint()],
            runtime_context={
                "program_profile": {
                    "industry": "fintech",
                    "auth_model": "oauth",
                    "surface": "graphql",
                }
            },
        )

        assert len(findings) == 1
        assert findings[0].additional_info["chain_rule_id"] == "fintech_ato"

    def test_falls_back_to_common_rule_when_industry_is_unknown(self, tmp_path: Path):
        rules = tmp_path / "attack_chain_rules.json"
        rules.write_text(
            """
            {
              "dsl_version": 1,
              "rules": [
                {
                  "id": "common_ato",
                  "name": "Common ATO",
                  "description": "Common rule",
                  "severity": "critical",
                  "required_signals": ["xss", "csrf"],
                  "min_components": 2
                },
                {
                  "id": "fintech_ato",
                  "name": "Fintech ATO",
                  "description": "Industry-specific rule",
                  "severity": "critical",
                  "required_signals": ["xss", "csrf"],
                  "min_components": 2,
                  "industry": "fintech"
                }
              ]
            }
            """.strip(),
            encoding="utf-8",
        )

        builder = AttackChainBuilder(rules_path=str(rules))

        findings = builder.analyze_with_context(
            [_sample_xss(), _sample_csrf_hint()],
            runtime_context={"program_profile": {"industry": "healthcare"}},
        )

        assert len(findings) == 1
        assert findings[0].additional_info["chain_rule_id"] == "common_ato"

    @pytest.mark.parametrize(
        ("profile", "expected"),
        [
            ({}, {"industry": "", "auth_model": "", "surface": ""}),
            ({"industry": None, "auth_model": "", "surface": None}, {"industry": "", "auth_model": "", "surface": ""}),
        ],
    )
    def test_normalizes_missing_program_profile_fields_in_decision_trace(self, tmp_path: Path, profile: dict, expected: dict):
        rules = tmp_path / "attack_chain_rules.json"
        rules.write_text(
            """
            {
              "dsl_version": 1,
              "rules": [
                {
                  "id": "common_ato",
                  "name": "Common ATO",
                  "description": "Common rule",
                  "severity": "critical",
                  "required_signals": ["xss", "csrf"],
                  "min_components": 2
                }
              ]
            }
            """.strip(),
            encoding="utf-8",
        )

        builder = AttackChainBuilder(rules_path=str(rules))
        findings = builder.analyze_with_context(
            [_sample_xss(), _sample_csrf_hint()],
            runtime_context={"program_profile": profile},
        )

        assert findings[0].additional_info["decision_trace"]["program_profile"] == expected

    def test_resolves_common_workflow_template_when_industry_template_missing(self, tmp_path: Path):
        rules = tmp_path / "attack_chain_rules.json"
        rules.write_text(
            """
            {
              "dsl_version": 1,
              "rules": [
                {
                  "id": "common_ato",
                  "name": "Common ATO",
                  "description": "Common rule",
                  "severity": "critical",
                  "required_signals": ["xss", "csrf"],
                  "min_components": 2
                }
              ],
              "workflow_templates": {
                "common": {"template_id": "wf-common", "steps": ["probe-common"], "source": "common"}
              }
            }
            """.strip(),
            encoding="utf-8",
        )

        builder = AttackChainBuilder(rules_path=str(rules))
        findings = builder.analyze_with_context(
            [_sample_xss(), _sample_csrf_hint()],
            runtime_context={"program_profile": {"industry": "fintech"}},
        )

        assert findings[0].additional_info["resolved_workflow_template"] == {
            "template_id": "wf-common",
            "steps": ["probe-common"],
            "source": "common",
        }

    def test_resolved_tactical_policy_exposes_minimal_contract(self, tmp_path: Path):
        rules = tmp_path / "attack_chain_rules.json"
        rules.write_text(
            """
            {
              "dsl_version": 1,
              "rules": [
                {
                  "id": "common_ato",
                  "name": "Common ATO",
                  "description": "Common rule",
                  "severity": "critical",
                  "required_signals": ["xss", "csrf"],
                  "min_components": 2
                }
              ],
              "program_overrides": {
                "fintech": {
                  "allow": ["scenario_probe"],
                  "deny": [],
                  "per_asset_qps_cap": 1,
                  "global_probe_budget": 2
                }
              }
            }
            """.strip(),
            encoding="utf-8",
        )

        builder = AttackChainBuilder(rules_path=str(rules))
        findings = builder.analyze_with_context(
            [_sample_xss(), _sample_csrf_hint()],
            runtime_context={"program_profile": {"industry": "fintech"}},
        )

        assert findings[0].additional_info["resolved_tactical_policy"] == {
            "allow": ["scenario_probe"],
            "deny": [],
            "per_asset_qps_cap": 1,
            "global_probe_budget": 2,
            "source": "program_override",
        }

    def test_schema_mismatch_required_key_missing_falls_back_to_safe_default(self, tmp_path: Path):
        rules = tmp_path / "attack_chain_rules.json"
        rules.write_text(
            """
            {
              "dsl_version": 1,
              "rules": [
                {
                  "id": "missing_required_signals",
                  "name": "Broken Rule",
                  "description": "Missing required signals",
                  "severity": "critical"
                }
              ]
            }
            """.strip(),
            encoding="utf-8",
        )

        builder = AttackChainBuilder(rules_path=str(rules))
        chains = builder.analyze([_sample_xss(), _sample_csrf_hint()])

        assert any(chain.rule_id == "account_takeover_xss_csrf" for chain in chains)

    def test_schema_mismatch_type_error_falls_back_to_safe_default(self, tmp_path: Path):
        rules = tmp_path / "attack_chain_rules.json"
        rules.write_text(
            """
            {
              "dsl_version": 1,
              "rules": [
                {
                  "id": "bad_types",
                  "name": "Broken Rule",
                  "description": "Invalid min_components type",
                  "severity": "critical",
                  "required_signals": ["xss", "csrf"],
                  "min_components": "two"
                }
              ]
            }
            """.strip(),
            encoding="utf-8",
        )

        builder = AttackChainBuilder(rules_path=str(rules))
        chains = builder.analyze([_sample_xss(), _sample_csrf_hint()])

        assert any(chain.rule_id == "account_takeover_xss_csrf" for chain in chains)

    def test_default_attack_chain_rules_define_common_and_industry_layout(self):
        rules_path = Path(__file__).resolve().parents[3] / "data" / "attack_chain_rules.json"
        payload = json.loads(rules_path.read_text(encoding="utf-8"))

        assert isinstance(payload.get("workflow_templates"), dict)
        assert "common" in payload["workflow_templates"]
        assert isinstance(payload.get("program_overrides"), dict)
        assert any(str(rule.get("industry", "")).strip() for rule in payload.get("rules", []) if isinstance(rule, dict))

    def test_chain_builder_and_master_conductor_keep_resolved_context_consistent(self, tmp_path: Path):
        rules = tmp_path / "attack_chain_rules.json"
        rules.write_text(
            """
            {
              "dsl_version": 1,
              "rules": [
                {
                  "id": "common_ato",
                  "name": "Common ATO",
                  "description": "Common rule",
                  "severity": "critical",
                  "required_signals": ["xss", "csrf"],
                  "min_components": 2
                },
                {
                  "id": "fintech_ato",
                  "name": "Fintech ATO",
                  "description": "Industry-specific rule",
                  "severity": "critical",
                  "required_signals": ["xss", "csrf"],
                  "min_components": 2,
                  "industry": "fintech"
                }
              ],
              "workflow_templates": {
                "common": {"template_id": "wf-common", "steps": ["probe-common"]},
                "fintech": {"template_id": "wf-fintech", "steps": ["probe-fintech"]}
              },
              "program_overrides": {
                "fintech": {
                  "allow": ["scenario_probe"],
                  "deny": [],
                  "per_asset_qps_cap": 1,
                  "global_probe_budget": 2
                }
              }
            }
            """.strip(),
            encoding="utf-8",
        )

        builder = AttackChainBuilder(rules_path=str(rules))
        findings = builder.analyze_with_context(
            [_sample_xss(), _sample_csrf_hint()],
            runtime_context={
                "program_profile": {
                    "industry": "fintech",
                    "auth_model": "oauth",
                    "surface": "graphql",
                }
            },
        )
        mc = MasterConductor.__new__(MasterConductor)

        resolved = mc.build_probe_runtime_context_from_chain_finding(findings[0].additional_info)

        assert resolved["workflow_template"] == findings[0].additional_info["resolved_workflow_template"]
        assert resolved["runtime_policy"] == findings[0].additional_info["resolved_tactical_policy"]
