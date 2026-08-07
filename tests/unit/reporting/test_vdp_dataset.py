"""
SGK-2026-0423 Lane B — evaluation-data boundary tests (dataset manifests,
hidden holdout, leakage detection, frozen thresholds).

Covers requirements 1-13:
1.  build/load manifest roundtrip
2.  verify_manifest ok
3.  tampered file content -> invalid with reason
4.  tampered manifest_hash -> invalid
5.  wrong schema_version -> DatasetManifestError
6.  semantic duplicates: same endpoint structure + same payload family in
    different splits (hosts differ -> target_name_substitution) -> detected
7.  different payload families -> not duplicate
8.  across_sets_only False includes same-set pairs
9.  holdout labels: permission too broad -> HoldoutBoundaryError
10. assert_runtime_cannot_read: holdout dir inside runtime root -> error;
    outside -> ok
11. leakage scan finds known_url / product_name / expected_payload entries
    in runtime texts
12. frozen thresholds roundtrip + fingerprint stability
13. no product names / known URLs of real targets in any fixture

All fixtures are GENERIC (example.com-style hosts, syntax-marker payloads) —
never product names or known URLs/payloads of a specific target.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from src.reporting.vdp_dataset import (
    DatasetItem,
    DatasetManifestError,
    HiddenHoldoutBoundary,
    HoldoutBoundaryError,
    ThresholdMetric,
    build_manifest,
    freeze_thresholds,
    load_manifest,
    load_thresholds,
    payload_family_signature,
    scan_runtime_inputs_for_leakage,
    semantic_duplicates,
    thresholds_fingerprint,
    verify_manifest,
)

# ---------------------------------------------------------------------------
# Generic fixture material (requirement 13: must stay product-agnostic)
# ---------------------------------------------------------------------------

_GENERIC_URLS = [
    "https://alpha.example.com/api/v2/items?id=1",
    "https://beta.example.com/api/v2/items?id=2",
    "https://example.com/hidden/admin-panel",
    "https://gamma.example.com:8080/api/v2/items",
]

_GENERIC_PAYLOADS = [
    "' or 1=1",                       # sqli:quote marker
    "SELECT 1",                       # sqli:select marker
    "<script>alert(1)</script>",      # xss:script marker
    "id=1; rm -rf /tmp/x",            # cmd:semicolon marker
]

_GENERIC_PRODUCT_NAME = "acme-web-store"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write_item(tmp_path: Path, split: str, name: str, content: str) -> DatasetItem:
    path = tmp_path / f"{split}_{name}.txt"
    path.write_text(content, encoding="utf-8")
    return DatasetItem(
        file_id=name,
        path=str(path),
        sha256=_sha256_bytes(path.read_bytes()),
        split=split,
    )


def _manifest_kwargs(tmp_path: Path, sets: dict) -> dict:
    return dict(
        input_hash="sha256:" + "b" * 64,
        generator="fixture-builder-0.1",
        split_rules={"by_sha256_mod": 4},
        eval_version="ev-1",
        created_at="2026-08-04T00:00:00Z",
        sets=sets,
    )


def _standard_sets(tmp_path: Path) -> dict:
    dev = [_write_item(tmp_path, "development", "dev-001",
                       f"{_GENERIC_URLS[0]}\n{_GENERIC_PAYLOADS[0]}")]
    val = [_write_item(tmp_path, "validation", "val-001",
                       f"{_GENERIC_URLS[1]}\n{_GENERIC_PAYLOADS[0]}")]
    hold = [_write_item(tmp_path, "hidden_holdout", "hold-001",
                        f"{_GENERIC_URLS[2]}\n{_GENERIC_PAYLOADS[1]}")]
    return {"development": dev, "validation": val,
            "hidden_holdout": hold, "real": []}


def _write_manifest(tmp_path: Path, manifest) -> Path:
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest.to_dict(), sort_keys=True), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# 1. build/load manifest roundtrip
# ---------------------------------------------------------------------------


class TestManifestRoundtrip:
    def test_build_load_manifest_roundtrip(self, tmp_path):
        sets = _standard_sets(tmp_path)
        manifest = build_manifest(**_manifest_kwargs(tmp_path, sets))
        path = _write_manifest(tmp_path, manifest)

        loaded = load_manifest(path)
        assert loaded.schema_version == 1
        assert loaded.input_hash == manifest.input_hash
        assert loaded.generator == "fixture-builder-0.1"
        assert loaded.eval_version == "ev-1"
        assert loaded.created_at == "2026-08-04T00:00:00Z"
        assert loaded.manifest_hash == manifest.manifest_hash
        assert loaded.manifest_hash == loaded.compute_manifest_hash()
        assert loaded.sets["development"][0].file_id == "dev-001"
        assert loaded.sets["development"][0].sha256 == sets["development"][0].sha256
        assert loaded.sets["hidden_holdout"][0].split == "hidden_holdout"
        assert loaded.sets["real"] == []


# ---------------------------------------------------------------------------
# 2-4. verify_manifest
# ---------------------------------------------------------------------------


class TestVerifyManifest:
    def test_verify_manifest_ok(self, tmp_path):
        manifest = build_manifest(**_manifest_kwargs(tmp_path, _standard_sets(tmp_path)))
        result = verify_manifest(_write_manifest(tmp_path, manifest))
        assert result.valid is True
        assert result.reasons == []

    def test_tampered_file_content_invalid(self, tmp_path):
        manifest = build_manifest(**_manifest_kwargs(tmp_path, _standard_sets(tmp_path)))
        (tmp_path / "development_dev-001.txt").write_text("tampered", encoding="utf-8")
        result = verify_manifest(_write_manifest(tmp_path, manifest))
        assert result.valid is False
        assert any(r.startswith("sha256_mismatch:dev-001") for r in result.reasons)

    def test_tampered_manifest_hash_invalid(self, tmp_path):
        manifest = build_manifest(**_manifest_kwargs(tmp_path, _standard_sets(tmp_path)))
        manifest.manifest_hash = "0" * 64
        result = verify_manifest(_write_manifest(tmp_path, manifest))
        assert result.valid is False
        assert "manifest_hash_mismatch" in result.reasons


# ---------------------------------------------------------------------------
# 5. wrong schema_version
# ---------------------------------------------------------------------------


class TestSchemaVersion:
    def test_wrong_schema_version_raises(self, tmp_path):
        manifest = build_manifest(**_manifest_kwargs(tmp_path, _standard_sets(tmp_path)))
        data = manifest.to_dict()
        data["schema_version"] = 2
        path = tmp_path / "manifest.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        with pytest.raises(DatasetManifestError):
            load_manifest(path)


# ---------------------------------------------------------------------------
# 6-8. semantic duplicates
# ---------------------------------------------------------------------------


class TestSemanticDuplicates:
    def test_duplicate_across_splits_target_name_substitution(self, tmp_path):
        manifest = build_manifest(**_manifest_kwargs(tmp_path, _standard_sets(tmp_path)))
        pairs = semantic_duplicates(manifest)
        assert len(pairs) == 1
        pair = pairs[0]
        assert pair.kind == "target_name_substitution"
        assert pair.left.startswith("development:")
        assert pair.right.startswith("validation:")

    def test_different_payload_families_not_duplicate(self, tmp_path):
        dev = [_write_item(tmp_path, "development", "dev-001",
                           f"{_GENERIC_URLS[0]}\n{_GENERIC_PAYLOADS[0]}")]
        val = [_write_item(tmp_path, "validation", "val-001",
                           f"{_GENERIC_URLS[1]}\n{_GENERIC_PAYLOADS[1]}")]
        manifest = build_manifest(**_manifest_kwargs(tmp_path,
                                                     {"development": dev,
                                                      "validation": val}))
        assert semantic_duplicates(manifest) == []

    def test_across_sets_only_false_includes_same_set(self, tmp_path):
        dev = [
            _write_item(tmp_path, "development", "dev-001",
                        f"{_GENERIC_URLS[0]}\n{_GENERIC_PAYLOADS[0]}"),
            _write_item(tmp_path, "development", "dev-002",
                        f"{_GENERIC_URLS[0]}\n{_GENERIC_PAYLOADS[0]}"),
        ]
        manifest = build_manifest(**_manifest_kwargs(tmp_path,
                                                     {"development": dev,
                                                      "real": []}))
        assert semantic_duplicates(manifest, across_sets_only=True) == []
        pairs = semantic_duplicates(manifest, across_sets_only=False)
        assert len(pairs) == 1
        assert pairs[0].kind == "endpoint_structure"


# ---------------------------------------------------------------------------
# 9-10. hidden holdout boundary
# ---------------------------------------------------------------------------


class TestHiddenHoldoutBoundary:
    def test_holdout_labels_permission_too_broad(self, tmp_path):
        labels = {"class": {"urls": ["https://example.com/hidden/x"],
                            "payloads": [], "product_names": []}}
        path = tmp_path / "holdout_labels.json"
        path.write_text(json.dumps(labels), encoding="utf-8")
        path.chmod(0o644)
        with pytest.raises(HoldoutBoundaryError, match="holdout_labels_permission_too_broad"):
            HiddenHoldoutBoundary.load_holdout_labels(path)

        # Same-owner 0600 is now REJECTED too: evaluation must go through a
        # privileged channel (the artifact owner must differ from the
        # runtime uid — a same-user 0600 file is no boundary at all).
        path.chmod(0o600)
        with pytest.raises(HoldoutBoundaryError, match="holdout_same_owner_as_runtime"):
            HiddenHoldoutBoundary.load_holdout_labels(path)

    def test_os_isolation_rejects_same_owner(self, tmp_path):
        # The core fix: a same-owner 0600 file is refused — the OS would let
        # the runtime read it, so it cannot be a hidden holdout artifact.
        path = tmp_path / "labels.json"
        path.write_text(json.dumps({"class": {"urls": []}}), encoding="utf-8")
        path.chmod(0o600)
        with pytest.raises(HoldoutBoundaryError, match="holdout_same_owner_as_runtime"):
            HiddenHoldoutBoundary.assert_os_isolation(path)
        with pytest.raises(HoldoutBoundaryError, match="holdout_same_owner_as_runtime"):
            HiddenHoldoutBoundary.load_holdout_labels(path)

    def test_os_isolation_accepts_foreign_owner(self, tmp_path):
        # An owner-only regular file owned by a DIFFERENT user passes when
        # the runtime uid differs from the artifact owner.
        path = tmp_path / "labels.json"
        path.write_text(json.dumps({"class": {"urls": []}}), encoding="utf-8")
        path.chmod(0o600)
        HiddenHoldoutBoundary.assert_os_isolation(path, runtime_uid=99999)
        with pytest.raises(HoldoutBoundaryError, match="holdout_same_owner_as_runtime"):
            HiddenHoldoutBoundary.assert_os_isolation(path, runtime_uid=os.geteuid())

    def test_runtime_read_forbidden_by_construction(self, tmp_path):
        # The runtime has NO read path at all: runtime_context always raises
        # before any filesystem access (fail-closed by construction).
        path = tmp_path / "labels.json"
        path.write_text(json.dumps({"class": {"urls": []}}), encoding="utf-8")
        path.chmod(0o600)
        with pytest.raises(HoldoutBoundaryError, match="holdout_runtime_read_forbidden"):
            HiddenHoldoutBoundary.load_holdout_labels(path, runtime_context=True)
        with pytest.raises(HoldoutBoundaryError, match="holdout_runtime_read_forbidden"):
            HiddenHoldoutBoundary.load_holdout_labels(
                tmp_path / "missing.json", runtime_context=True)

    def test_os_isolation_rejects_symlink(self, tmp_path):
        # A symlink is not a regular file: lstat must see the link itself,
        # never a resolved target (no bypass via symlink indirection).
        target = tmp_path / "labels.json"
        target.write_text(json.dumps({"class": {"urls": []}}), encoding="utf-8")
        target.chmod(0o600)
        link = tmp_path / "link.json"
        link.symlink_to(target)
        with pytest.raises(HoldoutBoundaryError, match="holdout_not_regular_file"):
            HiddenHoldoutBoundary.assert_os_isolation(link)

    def test_os_isolation_rejects_non_regular(self, tmp_path):
        d = tmp_path / "adir"
        d.mkdir()
        with pytest.raises(HoldoutBoundaryError, match="holdout_not_regular_file"):
            HiddenHoldoutBoundary.assert_os_isolation(d)

    def test_real_permission_denied_from_runtime(self, tmp_path):
        """THE audit negative test: the runtime (uid 1000) gets a REAL
        EACCES from the OS for a root-owned holdout artifact — no app-level
        guard is involved. The privileged channel (root inside a local
        container) still reads it.
        """
        labels = {
            "class": {"urls": ["https://example.com/hidden/x"],
                      "payloads": [], "product_names": []},
            "ground_truth": [
                {"class": "authz", "capability": "authz_detector",
                 "method": "get", "endpoint": "/items/42"},
            ],
        }
        d = tmp_path / "holdout"
        d.mkdir()
        labels_path = d / "labels.json"
        labels_path.write_text(json.dumps(labels), encoding="utf-8")

        # Make the artifact root-owned with owner-only mode INSIDE a local
        # container (the bind mount shares the inode with the host).
        subprocess.run(
            ["docker", "run", "--rm", "-v", f"{d}:/w", "alpine:3",
             "sh", "-c", "chown -R 0:0 /w && chmod 700 /w/labels.json"],
            check=True, capture_output=True, timeout=120,
        )
        try:
            # The OS actually denies the runtime's read: EACCES, raised by
            # the kernel, not by application code.
            with pytest.raises(PermissionError):
                labels_path.read_text(encoding="utf-8")

            # The boundary accepts the root-owned artifact (owner != runtime
            # uid) and rejects nothing about it.
            HiddenHoldoutBoundary.assert_os_isolation(labels_path)

            # The privileged channel reads and parses it.
            loaded = HiddenHoldoutBoundary.load_holdout_labels_via_container(labels_path)
            assert loaded["urls"] == ["https://example.com/hidden/x"]
            assert loaded["ground_truth"][0]["capability"] == "authz_detector"
        finally:
            # Restore ownership so pytest can clean up tmp_path.
            subprocess.run(
                ["docker", "run", "--rm", "-v", f"{d}:/w", "alpine:3",
                 "sh", "-c", f"chown -R {os.geteuid()}:{os.getegid()} /w"],
                check=False, capture_output=True, timeout=120,
            )

    def test_holdout_labels_with_ground_truth_parse(self, tmp_path):
        # The shared normalization used by BOTH loaders: class lists are
        # normalized and the optional "ground_truth" key defaults to [].
        data = {
            "class": {"urls": ["https://example.com/hidden/x"],
                      "payloads": ["' or 1=1"],
                      "product_names": ["acme-web-store"]},
            "ground_truth": [
                {"class": "authz", "capability": "authz_detector",
                 "method": "get", "endpoint": "/items/42"},
                {"class": "sqli", "capability": "sqli_detector",
                 "method": "post", "endpoint": "/search/1"},
            ],
        }
        normalized = HiddenHoldoutBoundary._validate_labels_dict(data)
        assert normalized["urls"] == ["https://example.com/hidden/x"]
        assert normalized["payloads"] == ["' or 1=1"]
        assert normalized["product_names"] == ["acme-web-store"]
        assert normalized["ground_truth"] == [
            {"class": "authz", "capability": "authz_detector",
             "method": "get", "endpoint": "/items/42"},
            {"class": "sqli", "capability": "sqli_detector",
             "method": "post", "endpoint": "/search/1"},
        ]
        # absent ground_truth -> defaults to []
        assert HiddenHoldoutBoundary._validate_labels_dict(
            {"class": {"urls": []}})["ground_truth"] == []
        # non-dict entries are dropped; keys are str-normalized
        mixed = HiddenHoldoutBoundary._validate_labels_dict({
            "class": {"urls": []},
            "ground_truth": [{"class": "authz", "capability": None,
                              "method": 1, "endpoint": "/x/1"}, "junk"],
        })
        assert mixed["ground_truth"] == [
            {"class": "authz", "capability": "", "method": "1",
             "endpoint": "/x/1"},
        ]

    def test_holdout_labels_missing_or_malformed(self, tmp_path):
        with pytest.raises(HoldoutBoundaryError):
            HiddenHoldoutBoundary.load_holdout_labels(tmp_path / "missing.json")

        bad = tmp_path / "bad.json"
        bad.write_text("{not json", encoding="utf-8")
        bad.chmod(0o600)
        with pytest.raises(HoldoutBoundaryError):
            HiddenHoldoutBoundary.load_holdout_labels(bad)

        wrong_shape = tmp_path / "wrong_shape.json"
        wrong_shape.write_text(json.dumps({"class": ["not", "a", "dict"]}),
                               encoding="utf-8")
        wrong_shape.chmod(0o600)
        with pytest.raises(HoldoutBoundaryError):
            HiddenHoldoutBoundary.load_holdout_labels(wrong_shape)

    def test_assert_runtime_cannot_read_boundary(self, tmp_path):
        runtime = tmp_path / "runtime"
        holdout_inside = runtime / "holdout"
        holdout_inside.mkdir(parents=True)
        with pytest.raises(HoldoutBoundaryError,
                           match="holdout_inside_runtime_workspace"):
            HiddenHoldoutBoundary.assert_runtime_cannot_read(
                str(holdout_inside), runtime_root=str(runtime))

        outside = tmp_path / "holdout"
        outside.mkdir()
        HiddenHoldoutBoundary.assert_runtime_cannot_read(
            str(outside), runtime_root=str(runtime))
        HiddenHoldoutBoundary.assert_runtime_cannot_read(str(outside))


# ---------------------------------------------------------------------------
# 11. leakage scan
# ---------------------------------------------------------------------------


class TestLeakageScan:
    def test_finds_known_url_product_name_expected_payload(self):
        labels = {
            "urls": ["https://example.com/hidden/admin-panel"],
            "payloads": [_GENERIC_PAYLOADS[0]],
            "product_names": [_GENERIC_PRODUCT_NAME],
        }
        texts = [
            f"probe https://example.com/hidden/admin-panel with {_GENERIC_PRODUCT_NAME}",
            f"payload: {_GENERIC_PAYLOADS[0]}",
        ]
        hits = scan_runtime_inputs_for_leakage(texts, labels)
        kinds = {(h.kind, h.source_index, h.matched) for h in hits}
        assert ("known_url", 0, "https://example.com/hidden/admin-panel") in kinds
        assert ("product_name", 0, _GENERIC_PRODUCT_NAME) in kinds
        assert ("expected_payload", 1, _GENERIC_PAYLOADS[0]) in kinds
        # deterministic order: source_index ascending
        indices = [h.source_index for h in hits]
        assert indices == sorted(indices)

    def test_url_parse_match_ignores_scheme_host_port(self):
        # label has a port and host A; text contains host B without port —
        # normalized endpoint structure must still match.
        labels = {"urls": ["https://alpha.example.com:8080/api/v2/items"],
                  "payloads": [], "product_names": []}
        texts = ["observed http://beta.example.com/api/v2/items in scope scan"]
        hits = scan_runtime_inputs_for_leakage(texts, labels)
        assert hits and hits[0].kind == "known_url"
        assert hits[0].matched == "https://alpha.example.com:8080/api/v2/items"

    def test_no_hits(self):
        labels = {"urls": ["https://example.com/hidden/x"],
                  "payloads": [_GENERIC_PAYLOADS[0]],
                  "product_names": ["acme"]}
        assert scan_runtime_inputs_for_leakage(["clean text without markers"], labels) == []


# ---------------------------------------------------------------------------
# 12. frozen thresholds
# ---------------------------------------------------------------------------


class TestThresholds:
    def test_thresholds_roundtrip_and_fingerprint_stability(self, tmp_path):
        metrics = [
            ThresholdMetric(name="recall:class:authz_detector", value=0.9,
                            formula="confirmed / total", target_set="hidden_holdout"),
            ThresholdMetric(name="evidence_completeness", value=0.8,
                            formula="with_evidence / total", target_set="hidden_holdout"),
        ]
        t1 = freeze_thresholds(eval_version="ev-1",
                               decided_at="2026-08-04T00:00:00Z", metrics=metrics)
        path = tmp_path / "thresholds.json"
        path.write_text(json.dumps(t1.to_dict(), sort_keys=True), encoding="utf-8")

        t2 = load_thresholds(path)
        assert t2.eval_version == "ev-1"
        assert t2.schema_version == 1
        assert t2.decided_at == "2026-08-04T00:00:00Z"
        assert t2.metrics == metrics

        t1b = freeze_thresholds(eval_version="ev-1",
                                decided_at="2026-08-04T00:00:00Z", metrics=metrics)
        assert thresholds_fingerprint(t1) == thresholds_fingerprint(t1b)

        t3 = freeze_thresholds(eval_version="ev-1",
                               decided_at="2026-08-04T00:00:00Z",
                               metrics=[metrics[0]])
        assert thresholds_fingerprint(t1) != thresholds_fingerprint(t3)


# ---------------------------------------------------------------------------
# 13. fixture hygiene: no real target names / known URLs in any fixture
# ---------------------------------------------------------------------------


class TestFixtureHygiene:
    def test_fixtures_contain_no_real_target_names(self):
        # Host whitelist: every fixture URL must be on example.com, so no
        # real-target host can ever appear in fixture data (positive
        # structural check instead of a product-name denylist).
        for url in _GENERIC_URLS:
            host = urlsplit(url).hostname or ""
            assert host == "example.com" or host.endswith(".example.com")
        # Payloads are pure generic syntax markers: no URLs or domains inside.
        for payload in _GENERIC_PAYLOADS:
            assert "://" not in payload
            assert "example.com" not in payload
        # Free-text fixtures carry no URLs.
        assert "://" not in _GENERIC_PRODUCT_NAME

    def test_payloads_are_generic_syntax_markers(self):
        # Each fixture payload classifies into its documented generic marker
        # family — proving they are syntax signals, never target payloads.
        assert payload_family_signature(_GENERIC_PAYLOADS[0]) == "sqli:quote"
        assert payload_family_signature(_GENERIC_PAYLOADS[1]) == "sqli:select"
        assert payload_family_signature(_GENERIC_PAYLOADS[2]) == "xss:script"
        assert payload_family_signature(_GENERIC_PAYLOADS[3]) == "cmd:semicolon"
        assert payload_family_signature("plain text") == "none"
