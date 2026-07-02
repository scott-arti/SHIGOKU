"""
Unit tests for review_overrides.py.

Covers:
- review_findings.yaml schema validation (validate_review_findings)
- overrides.yaml schema validation (validate_overrides)
- Blocking pending finding detection (has_blocking_pending_findings, collect_blocking_finding_ids)
- Review status resolution (resolve_review_status)
- Override application (apply_overrides_to_rules)
- Review candidate merging (merge_review_candidates_with_findings)
- Override skeleton generation (generate_override_skeleton)
- File loading (load_review_findings, load_overrides)
"""

from pathlib import Path

import pytest

from src.core.security.program_adapter_base import ReviewCandidate
from src.core.security.review_overrides import (
    apply_overrides_to_rules,
    collect_blocking_finding_ids,
    generate_override_skeleton,
    has_blocking_pending_findings,
    load_overrides,
    load_review_findings,
    merge_review_candidates_with_findings,
    resolve_review_status,
    validate_overrides,
    validate_review_findings,
)

FIXTURES_BASE = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "program_bundle"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _valid_finding(**overrides):
    """Return a complete valid review finding dict."""
    finding = {
        "finding_id": "H1-AMB-001",
        "category": "temporal_scope",
        "subject": "https://developers.tiktok.com/minis/",
        "risk_level": "high",
        "source_refs": [
            "policy.md#temporary-exclusion",
            "scope_assets.csv#row=32",
        ],
        "machine_guess": {
            "effect": "deny",
            "effective_from_utc": "2026-02-22T22:49:06Z",
        },
        "status": "pending",
        "blocking": True,
        "note": "text and csv are consistent, but temporal handling must be reviewed",
    }
    finding.update(overrides)
    return finding


def _valid_overrides():
    """Return a complete valid overrides dict."""
    return {
        "overrides": {
            "scope": {
                "allow_hosts": [],
                "deny_hosts": [],
                "allow_url_prefixes": [],
                "deny_url_prefixes": [],
            },
            "attack_classes": {
                "social_engineering": {"mode": "deny"},
                "dos": {"mode": "deny"},
                "post_exploit": {"mode": "deny"},
                "ssrf": {
                    "mode": "allow_with_constraints",
                    "allowed_destinations": [
                        "https://ssrf-bait.byted.org/full-read-ssrf"
                    ],
                },
            },
            "auth": {"allowed_email_domains": []},
            "budgets": {"requests_per_minute": 60},
        }
    }


# ---------------------------------------------------------------------------
# validate_review_findings
# ---------------------------------------------------------------------------

class TestValidateReviewFindings:
    def test_validate_empty_review_findings(self):
        """Empty review_findings: [] is valid."""
        data = {"review_findings": []}
        errors = validate_review_findings(data)
        assert errors == []

    def test_validate_complete_finding(self):
        """Valid complete finding passes validation."""
        data = {"review_findings": [_valid_finding()]}
        errors = validate_review_findings(data)
        assert errors == []

    def test_validate_missing_required_field(self):
        """Missing finding_id returns error."""
        data = {"review_findings": [_valid_finding()]}
        del data["review_findings"][0]["finding_id"]
        errors = validate_review_findings(data)
        assert len(errors) >= 1
        assert any("finding_id" in err.lower() for err in errors)

    def test_validate_invalid_status(self):
        """status=unknown returns error."""
        data = {"review_findings": [_valid_finding(status="unknown")]}
        errors = validate_review_findings(data)
        assert len(errors) >= 1
        assert any("status" in err.lower() for err in errors)

    def test_validate_invalid_risk_level(self):
        """risk_level=extreme returns error."""
        data = {"review_findings": [_valid_finding(risk_level="extreme")]}
        errors = validate_review_findings(data)
        assert len(errors) >= 1
        assert any("risk_level" in err.lower() for err in errors)

    def test_validate_blocking_not_bool(self):
        """blocking="yes" returns error."""
        data = {"review_findings": [_valid_finding(blocking="yes")]}
        errors = validate_review_findings(data)
        assert len(errors) >= 1
        assert any("blocking" in err.lower() for err in errors)

    def test_validate_missing_review_findings_key(self):
        """Missing top-level review_findings key returns error."""
        data = {}
        errors = validate_review_findings(data)
        assert len(errors) >= 1

    def test_validate_review_findings_not_list(self):
        """review_findings not a list returns error."""
        data = {"review_findings": "not_a_list"}
        errors = validate_review_findings(data)
        assert len(errors) >= 1

    def test_validate_multiple_findings(self):
        """Multiple valid findings all pass."""
        data = {"review_findings": [
            _valid_finding(finding_id="H1-AMB-001"),
            _valid_finding(finding_id="H1-AMB-002"),
        ]}
        errors = validate_review_findings(data)
        assert errors == []

    def test_validate_machine_guess_missing(self):
        """Missing machine_guess field returns error."""
        data = {"review_findings": [_valid_finding()]}
        del data["review_findings"][0]["machine_guess"]
        errors = validate_review_findings(data)
        assert len(errors) >= 1


# ---------------------------------------------------------------------------
# validate_overrides
# ---------------------------------------------------------------------------

class TestValidateOverrides:
    def test_validate_overrides_empty(self):
        """Empty overrides: {} passes."""
        data = {"overrides": {}}
        errors = validate_overrides(data)
        assert errors == []

    def test_validate_overrides_complete(self):
        """Full overrides structure passes."""
        errors = validate_overrides(_valid_overrides())
        assert errors == []

    def test_validate_overrides_invalid_mode(self):
        """attack_class mode=unknown returns error."""
        data = _valid_overrides()
        data["overrides"]["attack_classes"]["dos"] = {"mode": "unknown"}
        errors = validate_overrides(data)
        assert len(errors) >= 1
        assert any("mode" in err.lower() for err in errors)

    def test_validate_overrides_missing_overrides_key(self):
        """Missing top-level overrides key returns error."""
        data = {}
        errors = validate_overrides(data)
        assert len(errors) >= 1

    def test_validate_overrides_scope_empty_ok(self):
        """Scope with empty sub-lists is valid."""
        data = {"overrides": {"scope": {}}}
        errors = validate_overrides(data)
        assert errors == []

    def test_validate_overrides_attack_classes_empty_ok(self):
        """Empty attack_classes dict is valid."""
        data = _valid_overrides()
        data["overrides"]["attack_classes"] = {}
        errors = validate_overrides(data)
        assert errors == []

    def test_validate_overrides_invalid_requests_per_minute(self):
        """requests_per_minute=0 returns error."""
        data = _valid_overrides()
        data["overrides"]["budgets"]["requests_per_minute"] = 0
        errors = validate_overrides(data)
        assert len(errors) >= 1


# ---------------------------------------------------------------------------
# has_blocking_pending_findings
# ---------------------------------------------------------------------------

class TestHasBlockingPendingFindings:
    def test_has_blocking_pending_true(self):
        """Finding with blocking=true, status=pending -> True."""
        findings = [_valid_finding(blocking=True, status="pending")]
        assert has_blocking_pending_findings(findings) is True

    def test_has_blocking_pending_false_accepted(self):
        """blocking=true but status=accepted -> False."""
        findings = [_valid_finding(blocking=True, status="accepted")]
        assert has_blocking_pending_findings(findings) is False

    def test_has_blocking_pending_false_nonblocking(self):
        """blocking=false, status=pending -> False."""
        findings = [_valid_finding(blocking=False, status="pending")]
        assert has_blocking_pending_findings(findings) is False

    def test_has_blocking_pending_false_dismissed(self):
        """blocking=true but status=dismissed -> False."""
        findings = [_valid_finding(blocking=True, status="dismissed")]
        assert has_blocking_pending_findings(findings) is False

    def test_has_blocking_pending_empty_list(self):
        """Empty list -> False."""
        assert has_blocking_pending_findings([]) is False


# ---------------------------------------------------------------------------
# collect_blocking_finding_ids
# ---------------------------------------------------------------------------

class TestCollectBlockingFindingIds:
    def test_collect_blocking_finding_ids(self):
        """Returns correct IDs for blocking+pending findings."""
        findings = [
            _valid_finding(finding_id="H1-AMB-001", blocking=True, status="pending"),
            _valid_finding(finding_id="H1-AMB-002", blocking=False, status="pending"),
            _valid_finding(finding_id="H1-AMB-003", blocking=True, status="accepted"),
            _valid_finding(finding_id="H1-AMB-004", blocking=True, status="pending"),
        ]
        result = collect_blocking_finding_ids(findings)
        assert result == ["H1-AMB-001", "H1-AMB-004"]

    def test_collect_empty(self):
        """Empty list returns empty list."""
        assert collect_blocking_finding_ids([]) == []

    def test_collect_none_blocking_pending(self):
        """No blocking+pending -> empty list."""
        findings = [
            _valid_finding(finding_id="X-1", blocking=False, status="pending"),
            _valid_finding(finding_id="X-2", blocking=True, status="accepted"),
        ]
        assert collect_blocking_finding_ids(findings) == []


# ---------------------------------------------------------------------------
# resolve_review_status
# ---------------------------------------------------------------------------

class TestResolveReviewStatus:
    def test_resolve_review_status_ready(self):
        """No blocking pending -> status=ready."""
        findings = [_valid_finding(blocking=False, status="pending")]
        result = resolve_review_status(findings)
        assert result["status"] == "ready"
        assert result["blocking_ids"] == []
        assert result["total_pending"] == 1

    def test_resolve_review_status_manual_review(self):
        """Blocking pending -> status=manual_review_required."""
        findings = [_valid_finding(blocking=True, status="pending")]
        result = resolve_review_status(findings)
        assert result["status"] == "manual_review_required"
        assert result["blocking_ids"] == ["H1-AMB-001"]
        assert result["total_pending"] == 1

    def test_resolve_mixed(self):
        """Mixed findings: blocking pending present."""
        findings = [
            _valid_finding(finding_id="A1", blocking=True, status="pending"),
            _valid_finding(finding_id="A2", blocking=False, status="pending"),
            _valid_finding(finding_id="A3", blocking=True, status="accepted"),
        ]
        result = resolve_review_status(findings)
        assert result["status"] == "manual_review_required"
        assert result["blocking_ids"] == ["A1"]
        assert result["total_pending"] == 2  # A1 and A2 are pending

    def test_resolve_empty(self):
        """Empty findings -> ready."""
        result = resolve_review_status([])
        assert result["status"] == "ready"
        assert result["blocking_ids"] == []
        assert result["total_pending"] == 0


# ---------------------------------------------------------------------------
# apply_overrides_to_rules
# ---------------------------------------------------------------------------

class TestApplyOverridesToRules:
    def test_apply_overrides_to_rules_adds_host(self):
        """Override adds allow_host, producing scope rules."""
        overrides = {"overrides": {"scope": {"allow_hosts": ["api.example.com"]}}}
        rule_candidates = []  # no existing rules
        result = apply_overrides_to_rules(overrides, rule_candidates)
        # Should contain a rule for the added host
        subjects = [r.get("subject", "") for r in result]
        assert "api.example.com" in subjects

    def test_apply_overrides_changes_attack_class_mode(self):
        """Override changes attack_class mode to deny, rule_candidate mode changes."""
        overrides = {
            "overrides": {
                "attack_classes": {"ssrf": {"mode": "deny"}}
            }
        }
        # Existing rule candidate with ssrf mode=allow_with_constraints
        rule_candidates = [
            {
                "rule_id": "attack_class.ssrf.1",
                "category": "attack_class",
                "decision": "allow",
                "subject": "ssrf",
                "constraints": {},
            }
        ]
        result = apply_overrides_to_rules(overrides, rule_candidates)
        ssrf_rules = [r for r in result if r.get("subject") == "ssrf"]
        assert len(ssrf_rules) >= 1
        # The overridden rule should have decision changed
        assert any(r.get("decision") == "deny" for r in ssrf_rules)

    def test_apply_overrides_empty_overrides_preserves_rules(self):
        """Empty overrides return original rules unchanged."""
        rule_candidates = [
            {
                "rule_id": "scope.host.allow.1",
                "category": "scope",
                "decision": "allow",
                "subject": "example.com",
            }
        ]
        result = apply_overrides_to_rules({"overrides": {}}, rule_candidates)
        assert result == rule_candidates

    def test_apply_overrides_empty_rules_with_overrides(self):
        """No rule candidates but overrides present -> override rules are created."""
        overrides = _valid_overrides()
        result = apply_overrides_to_rules(overrides, [])
        # Should produce rules from attack_classes
        categories = set(r.get("category", "") for r in result)
        assert "attack_class" in categories

    def test_apply_overrides_deny_url_prefixes(self):
        """Override deny_url_prefixes creates deny rules."""
        overrides = {
            "overrides": {
                "scope": {
                    "deny_url_prefixes": ["https://developers.tiktok.com/minis/"]
                }
            }
        }
        result = apply_overrides_to_rules(overrides, [])
        subjects = [r.get("subject", "") for r in result]
        assert "https://developers.tiktok.com/minis/" in subjects
        deny_rules = [r for r in result if "developers.tiktok.com" in r.get("subject", "")]
        assert all(r.get("decision") == "deny" for r in deny_rules)


# ---------------------------------------------------------------------------
# merge_review_candidates_with_findings
# ---------------------------------------------------------------------------

class TestMergeReviewCandidatesWithFindings:
    def test_merge_new_candidates_with_empty_findings(self):
        """New candidates get finding_id and status=pending."""
        candidates = [
            ReviewCandidate(
                finding_id="",  # not set yet
                category="temporal_scope",
                subject="https://example.com/test",
                risk_level="high",
                blocking=True,
                source_refs=["policy.md#section-1"],
            ),
        ]
        result = merge_review_candidates_with_findings(candidates, [])
        assert len(result) == 1
        assert result[0]["finding_id"] != ""  # auto-generated
        assert result[0]["status"] == "pending"
        assert result[0]["category"] == "temporal_scope"

    def test_merge_respects_existing_status(self):
        """Existing finding keeps its accepted status."""
        existing = [_valid_finding(finding_id="H1-AMB-001", status="accepted")]
        candidates = [
            ReviewCandidate(
                finding_id="H1-AMB-001",
                category="temporal_scope",
                subject="https://example.com/test",
                risk_level="high",
                blocking=True,
                source_refs=["policy.md#section-1"],
            ),
        ]
        result = merge_review_candidates_with_findings(candidates, existing)
        assert len(result) == 1
        assert result[0]["status"] == "accepted"  # existing status preserved

    def test_merge_new_candidate_with_existing(self):
        """Existing finding not in new candidates is preserved."""
        existing = [_valid_finding(finding_id="OLD-001", status="dismissed")]
        candidates = [
            ReviewCandidate(
                finding_id="",
                category="auth",
                subject="new subject",
                risk_level="medium",
                blocking=False,
            ),
        ]
        result = merge_review_candidates_with_findings(candidates, existing)
        # Should have both: the existing OLD-001 and the new candidate
        assert len(result) == 2
        ids = [r["finding_id"] for r in result]
        assert "OLD-001" in ids
        # New candidate gets a generated ID
        assert any(fid != "OLD-001" for fid in ids)

    def test_merge_updates_existing_fields(self):
        """Existing finding matched by finding_id gets fields updated from candidate."""
        existing = [_valid_finding(finding_id="H1-AMB-001", status="pending")]
        candidates = [
            ReviewCandidate(
                finding_id="H1-AMB-001",
                category="new_category",
                subject="updated subject",
                risk_level="critical",
                blocking=True,
                source_refs=["new_ref.md"],
            ),
        ]
        result = merge_review_candidates_with_findings(candidates, existing)
        assert len(result) == 1
        assert result[0]["category"] == "new_category"
        assert result[0]["subject"] == "updated subject"
        assert result[0]["risk_level"] == "critical"
        # Status persists (existing was 'pending')
        assert result[0]["status"] == "pending"

    def test_merge_empty_both(self):
        """Empty candidates and empty findings -> empty list."""
        result = merge_review_candidates_with_findings([], [])
        assert result == []


# ---------------------------------------------------------------------------
# generate_override_skeleton
# ---------------------------------------------------------------------------

class TestGenerateOverrideSkeleton:
    def test_generate_override_skeleton(self):
        """Generates skeleton with correct structure."""
        findings = [
            _valid_finding(finding_id="H1-AMB-001", blocking=True, status="pending"),
            _valid_finding(finding_id="H1-AMB-002", blocking=True, status="pending",
                           category="ssrf"),
        ]
        skeleton = generate_override_skeleton(findings)
        assert "overrides" in skeleton
        assert "scope" in skeleton["overrides"]
        assert "attack_classes" in skeleton["overrides"]
        assert "suggested_entries" in skeleton
        # Should reference the pending blocking findings
        suggested_ids = [s.get("finding_id") for s in skeleton.get("suggested_entries", [])]
        assert "H1-AMB-001" in suggested_ids
        assert "H1-AMB-002" in suggested_ids

    def test_generate_override_skeleton_empty(self):
        """Empty findings -> minimal skeleton."""
        skeleton = generate_override_skeleton([])
        assert "overrides" in skeleton
        assert skeleton.get("suggested_entries") == []

    def test_generate_override_skeleton_no_blocking(self):
        """Non-blocking pending findings are not in skeleton suggestions."""
        findings = [_valid_finding(blocking=False, status="pending")]
        skeleton = generate_override_skeleton(findings)
        assert skeleton.get("suggested_entries") == []


# ---------------------------------------------------------------------------
# load_review_findings / load_overrides
# ---------------------------------------------------------------------------

class TestLoadReviewFindings:
    def test_load_review_findings_from_tiktok_fixture(self):
        """Loads empty review_findings.yaml from tiktok fixture."""
        path = FIXTURES_BASE / "tiktok" / "review_findings.yaml"
        data = load_review_findings(str(path))
        assert "review_findings" in data
        assert data["review_findings"] == []

    def test_load_review_findings_from_fireblocks_fixture(self):
        """Loads empty review_findings.yaml from fireblocks fixture."""
        path = FIXTURES_BASE / "fireblocks" / "review_findings.yaml"
        data = load_review_findings(str(path))
        assert "review_findings" in data
        assert data["review_findings"] == []

    def test_load_review_findings_with_pathlib(self):
        """load_review_findings accepts Path object."""
        path = FIXTURES_BASE / "tiktok" / "review_findings.yaml"
        data = load_review_findings(path)
        assert "review_findings" in data

    def test_missing_review_file(self):
        """Loading nonexistent file raises error."""
        path = FIXTURES_BASE / "tiktok" / "nonexistent_review.yaml"
        with pytest.raises(FileNotFoundError):
            load_review_findings(path)

    def test_load_invalid_yaml(self):
        """Loading invalid YAML raises error."""
        # Use a file that is not valid YAML
        import tempfile
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as tmp:
            tmp.write(": invalid yaml :::")
            tmp_path = tmp.name
        try:
            with pytest.raises(Exception):
                load_review_findings(tmp_path)
        finally:
            Path(tmp_path).unlink(missing_ok=True)


class TestLoadOverrides:
    def test_load_overrides_from_fireblocks_fixture(self):
        """Loads empty overrides.yaml from fireblocks fixture."""
        path = FIXTURES_BASE / "fireblocks" / "overrides.yaml"
        data = load_overrides(str(path))
        assert "overrides" in data
        assert data["overrides"] == {}

    def test_load_overrides_from_tiktok_fixture(self):
        """Loads empty overrides.yaml from tiktok fixture."""
        path = FIXTURES_BASE / "tiktok" / "overrides.yaml"
        data = load_overrides(str(path))
        assert "overrides" in data
        assert data["overrides"] == {}

    def test_load_overrides_with_pathlib(self):
        """load_overrides accepts Path object."""
        path = FIXTURES_BASE / "fireblocks" / "overrides.yaml"
        data = load_overrides(path)
        assert "overrides" in data

    def test_missing_overrides_file(self):
        """Loading nonexistent overrides file raises error."""
        path = FIXTURES_BASE / "fireblocks" / "nonexistent_overrides.yaml"
        with pytest.raises(FileNotFoundError):
            load_overrides(path)

    def test_load_invalid_overrides_yaml(self):
        """Loading invalid YAML raises error."""
        import tempfile
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as tmp:
            tmp.write(": invalid yaml :::")
            tmp_path = tmp.name
        try:
            with pytest.raises(Exception):
                load_overrides(tmp_path)
        finally:
            Path(tmp_path).unlink(missing_ok=True)
