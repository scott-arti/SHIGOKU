"""
SGK-2026-0425 — M0/M5 preflight: product-independence checker tests (TDD).

Covers:
- clean state → verdict pass, exit 0
- token hit in changed file → fail, reason token_scan_hit, exit 3
- import-closure violation (manifest hit reachable from clean profile) → fail
  + SCRIPT_ONLY exemption + closure token scan
- manifest content_hash tamper → manifest_hash fail
- missing manifest / missing denylist → blocked, exit 2
- model_context: role template containing a token → fail; missing template
  → blocked; yaml-like roles extraction
- denylist/manifest self-exclusion from token scan
- exit code mapping 0/2/3 via main() with monkeypatched args

All checks are exercised through the pure functions (explicit inputs:
changed_files list, denylist tokens, manifest dict, repo root) so no repo
mutation is required. main()-level tests pass --changed-files pointing at
tmp files to stay independent of the real repo's git status.
"""
from __future__ import annotations

import json
from pathlib import Path

import scripts.check_vdp_product_independence as checker

DENYLIST_TOKENS = ["juice", "dvwa", "owasp"]


def _write_manifest(path: Path, *, modules: list[str] | None = None,
                    hits: list[dict] | None = None,
                    extra: dict | None = None) -> None:
    manifest: dict = {
        "schema_version": 1,
        "manifest_version": "v1",
        "created_at": "2026-08-06",
        "generated_for_task": "SGK-2026-0425",
        "summary": {"vdp_runtime_closure_clean": True, "vdp_runtime_llm_calls": 0},
        "clean_profile_definition": {
            "modules": modules if modules is not None else [],
            "rule": "no product tokens",
        },
        "hits": hits if hits is not None else [],
    }
    if extra:
        manifest.update(extra)
    manifest["content_hash"] = checker.compute_manifest_hash(manifest)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, ensure_ascii=False), encoding="utf-8")


def _write_denylist(path: Path, tokens: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(tokens or DENYLIST_TOKENS) + "\n", encoding="utf-8")


def _write_changed_files(path: Path, entries: list[Path]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(str(e) for e in entries) + "\n", encoding="utf-8")


def _base_args(manifest: Path, denylist: Path, changed: Path) -> list[str]:
    return [
        "--manifest", str(manifest),
        "--profile", "clean-diagnostic",
        "--denylist", str(denylist),
        "--changed-files", str(changed),
        "--json",
    ]


# --- 1. clean state ---------------------------------------------------------

def test_clean_state_passes_with_exit_zero(tmp_path: Path, capsys) -> None:
    manifest = tmp_path / "manifest.json"
    _write_manifest(manifest)
    denylist = tmp_path / "denylist.txt"
    _write_denylist(denylist)
    clean_file = tmp_path / "clean.py"
    clean_file.write_text("print('hello')\n", encoding="utf-8")
    changed = tmp_path / "changed.txt"
    _write_changed_files(changed, [clean_file])

    code = checker.main(_base_args(manifest, denylist, changed))
    out = json.loads(capsys.readouterr().out)

    assert code == 0
    assert out["verdict"] == "pass"
    assert out["reason_codes"] == []
    assert out["checks"]["manifest_exists"]["status"] == "ok"
    assert out["checks"]["manifest_hash"]["status"] == "ok"
    assert out["checks"]["denylist_exists"]["status"] == "ok"
    assert out["checks"]["token_scan_changed_files"]["status"] == "ok"
    assert out["checks"]["import_closure"]["status"] == "ok"
    assert out["checks"]["model_context"]["status"] == "ok"


# --- 2. token hit -----------------------------------------------------------

def test_token_hit_fails_with_exit_three(tmp_path: Path, capsys) -> None:
    manifest = tmp_path / "manifest.json"
    _write_manifest(manifest)
    denylist = tmp_path / "denylist.txt"
    _write_denylist(denylist)
    dirty = tmp_path / "dirty.py"
    dirty.write_text(
        "target = 'http://example.test/'\nname = 'dvwa'\n", encoding="utf-8"
    )
    changed = tmp_path / "changed.txt"
    _write_changed_files(changed, [dirty])

    code = checker.main(_base_args(manifest, denylist, changed))
    out = json.loads(capsys.readouterr().out)

    assert code == 3
    assert out["verdict"] == "fail"
    assert "token_scan_hit" in out["reason_codes"]
    hits = out["checks"]["token_scan_changed_files"]["detail"]["hits"]
    assert hits == [{"file": str(dirty), "line": 2, "token": "dvwa"}]


# --- 3. closure violation ---------------------------------------------------

def test_closure_violation_fails(tmp_path: Path) -> None:
    root = tmp_path
    (root / "src" / "pkg").mkdir(parents=True)
    (root / "src" / "clean_mod.py").write_text(
        "from src.pkg.victim import helper\n", encoding="utf-8"
    )
    (root / "src" / "pkg" / "victim.py").write_text(
        "helper = True\n", encoding="utf-8"
    )
    manifest = {
        "clean_profile_definition": {"modules": ["src/clean_mod.py"]},
        "hits": [
            {
                "file": "src/pkg/victim.py",
                "lines": [1],
                "product": "X",
                "kind": "known",
                "reachability": "GENERAL_RUNTIME_ONLY",
            }
        ],
    }

    result = checker.check_import_closure(manifest, DENYLIST_TOKENS, root)
    assert result["status"] == "fail"
    assert "manifest_hit_in_closure" in result["reason_codes"]
    detail = result["detail"]
    assert detail["manifest_hits_in_closure"][0]["file"] == "src/pkg/victim.py"
    assert detail["manifest_hits_in_closure"][0]["lines"] == [1]
    assert "src/pkg/victim.py" in detail["closure_files"]

    # SCRIPT_ONLY hits are never importable → exempt
    script_only = dict(manifest)
    script_only["hits"] = [dict(manifest["hits"][0], reachability="SCRIPT_ONLY")]
    result = checker.check_import_closure(script_only, DENYLIST_TOKENS, root)
    assert result["status"] == "ok"
    assert result["reason_codes"] == []

    # denylist token inside a closure file → closure_token_hit
    (root / "src" / "pkg" / "victim.py").write_text(
        "helper = 'dvwa'\n", encoding="utf-8"
    )
    token_manifest = {"clean_profile_definition": {"modules": ["src/clean_mod.py"]}, "hits": []}
    result = checker.check_import_closure(token_manifest, DENYLIST_TOKENS, root)
    assert result["status"] == "fail"
    assert "closure_token_hit" in result["reason_codes"]
    assert result["detail"]["token_hits"] == [
        {"file": "src/pkg/victim.py", "line": 1, "token": "dvwa"}
    ]


# --- 4. manifest hash tamper ------------------------------------------------

def test_manifest_hash_tamper_fails(tmp_path: Path) -> None:
    manifest_path = tmp_path / "manifest.json"
    _write_manifest(manifest_path)
    original = json.loads(manifest_path.read_text(encoding="utf-8"))

    assert checker.check_manifest_hash(original)["status"] == "ok"

    tampered = dict(original)
    tampered["summary"] = {
        "vdp_runtime_closure_clean": False,
        "vdp_runtime_llm_calls": 1,
    }
    result = checker.check_manifest_hash(tampered)
    assert result["status"] == "fail"
    assert "manifest_hash_mismatch" in result["reason_codes"]
    assert result["detail"]["expected"] == original["content_hash"]
    assert result["detail"]["actual"] != original["content_hash"]


# --- 5. missing manifest / denylist -----------------------------------------

def test_missing_manifest_and_denylist_block(tmp_path: Path, capsys) -> None:
    denylist = tmp_path / "denylist.txt"
    _write_denylist(denylist)
    clean_file = tmp_path / "clean.py"
    clean_file.write_text("x = 1\n", encoding="utf-8")
    changed = tmp_path / "changed.txt"
    _write_changed_files(changed, [clean_file])

    code = checker.main(
        [
            "--manifest", str(tmp_path / "missing_manifest.json"),
            "--profile", "clean-diagnostic",
            "--denylist", str(denylist),
            "--changed-files", str(changed),
            "--json",
        ]
    )
    out = json.loads(capsys.readouterr().out)
    assert code == 2
    assert out["verdict"] == "blocked"
    assert "manifest_missing" in out["reason_codes"]

    manifest = tmp_path / "manifest.json"
    _write_manifest(manifest)
    code = checker.main(
        [
            "--manifest", str(manifest),
            "--profile", "clean-diagnostic",
            "--denylist", str(tmp_path / "missing_denylist.txt"),
            "--changed-files", str(changed),
            "--json",
        ]
    )
    out = json.loads(capsys.readouterr().out)
    assert code == 2
    assert out["verdict"] == "blocked"
    assert "denylist_missing" in out["reason_codes"]


# --- 6. model_context -------------------------------------------------------

def test_model_context_token_hit_fails(tmp_path: Path) -> None:
    root = tmp_path
    template = root / "src" / "prompts" / "conductor" / "planning.md"
    template.parent.mkdir(parents=True)
    template.write_text(
        "plan your steps\nuse dvwa for the example\n", encoding="utf-8"
    )
    roles = {"planner": {"system_prompt_template": "conductor/planning.md"}}

    result = checker.check_model_context(roles, DENYLIST_TOKENS, root)
    assert result["status"] == "fail"
    assert "model_context_token_hit" in result["reason_codes"]
    assert result["detail"]["hits"] == [
        {
            "file": "src/prompts/conductor/planning.md",
            "line": 2,
            "token": "dvwa",
            "role": "planner",
        }
    ]

    # declared template that does not exist → blocked (fail-closed)
    missing = {"missing_role": {"system_prompt_template": "roles/nope.md"}}
    result = checker.check_model_context(missing, DENYLIST_TOKENS, root)
    assert result["status"] == "blocked"
    assert "model_context_template_missing" in result["reason_codes"]


def test_roles_template_extractor_parses_yaml_like_text() -> None:
    text = "\n".join(
        [
            "llm:",
            "  roles:",
            "    planner:",
            "      profile: reasoning_api",
            "      system_prompt_template: conductor/planning.md",
            "    final_judgement:",
            "      system_prompt_template: roles/final_judgement.md",
            "ops_intent:",
            "  feature_flag: true",
        ]
    )
    roles = checker.extract_roles_templates(text)
    assert roles == {
        "planner": {"system_prompt_template": "conductor/planning.md"},
        "final_judgement": {"system_prompt_template": "roles/final_judgement.md"},
    }


# --- 7. denylist/manifest self-exclusion ------------------------------------

def test_denylist_and_manifest_self_exclusion(tmp_path: Path, capsys) -> None:
    manifest_path = tmp_path / "manifest.json"
    _write_manifest(manifest_path)
    denylist_path = tmp_path / "denylist.txt"
    _write_denylist(denylist_path)

    # pure function level: scanning the denylist + manifest themselves → 0 hits
    result = checker.check_token_scan(
        ["manifest.json", "denylist.txt"],
        DENYLIST_TOKENS,
        tmp_path,
        skip_files={manifest_path.resolve(), denylist_path.resolve()},
    )
    assert result["status"] == "ok"
    assert result["detail"]["hits"] == []

    # main() level: --changed-files lists the denylist and manifest themselves
    changed = tmp_path / "changed.txt"
    _write_changed_files(changed, [manifest_path, denylist_path])
    code = checker.main(_base_args(manifest_path, denylist_path, changed))
    out = json.loads(capsys.readouterr().out)
    assert code == 0
    assert out["checks"]["token_scan_changed_files"]["status"] == "ok"
    assert len(out["checks"]["token_scan_changed_files"]["detail"]["files_skipped"]) == 2
    assert sorted(out["checks"]["token_scan_changed_files"]["detail"]["files_skipped"]) == [
        str(denylist_path),
        str(manifest_path),
    ]


# --- 8. exit code mapping ---------------------------------------------------

def test_exit_code_mapping_via_main(tmp_path: Path, capsys) -> None:
    manifest = tmp_path / "manifest.json"
    _write_manifest(manifest)
    denylist = tmp_path / "denylist.txt"
    _write_denylist(denylist)
    clean_file = tmp_path / "clean.py"
    clean_file.write_text("x = 1\n", encoding="utf-8")
    changed = tmp_path / "changed.txt"
    _write_changed_files(changed, [clean_file])
    base = _base_args(manifest, denylist, changed)

    # 0 = pass
    assert checker.main(base) == 0
    assert json.loads(capsys.readouterr().out)["verdict"] == "pass"

    # 3 = fail (any FAIL check)
    dirty = tmp_path / "dirty.py"
    dirty.write_text("x = 'juice'\n", encoding="utf-8")
    changed2 = tmp_path / "changed2.txt"
    _write_changed_files(changed2, [dirty])
    assert checker.main(base[:-2] + [str(changed2), "--json"]) == 3
    assert json.loads(capsys.readouterr().out)["verdict"] == "fail"

    # 2 = blocked (missing manifest)
    assert checker.main(
        [
            "--manifest", str(tmp_path / "missing.json"),
            "--profile", "clean-diagnostic",
            "--denylist", str(denylist),
            "--changed-files", str(changed),
            "--json",
        ]
    ) == 2
    assert json.loads(capsys.readouterr().out)["verdict"] == "blocked"

    # 2 = blocked (missing denylist)
    assert checker.main(
        [
            "--manifest", str(manifest),
            "--profile", "clean-diagnostic",
            "--denylist", str(tmp_path / "missing.txt"),
            "--changed-files", str(changed),
            "--json",
        ]
    ) == 2
    assert json.loads(capsys.readouterr().out)["verdict"] == "blocked"


def test_aggregate_verdict_is_fail_closed() -> None:
    def check(status: str, codes: list[str] | None = None) -> dict:
        return {"status": status, "reason_codes": codes or []}

    assert checker.aggregate_verdict({"a": check("ok")}) == ("pass", [])
    assert checker.aggregate_verdict({"a": check("fail", ["x"])}) == ("fail", ["x"])
    assert checker.aggregate_verdict({"a": check("blocked", ["y"])}) == ("blocked", ["y"])
    # FAIL dominates BLOCKED (fail-closed)
    assert checker.aggregate_verdict(
        {"a": check("fail", ["x"]), "b": check("blocked", ["y"])}
    ) == ("fail", ["x"])


# --- 8. manifest-classified legacy deferral (SGK-2026-0425 ②) ----------------

def test_classified_legacy_hit_is_deferred_not_failed(tmp_path: Path) -> None:
    """A denylist hit in a manifest-classified legacy file is deferred (§15)."""
    legacy = tmp_path / "legacy_runtime.py"
    legacy.write_text("PATH = '/dvwa/login'  # legacy\n", encoding="utf-8")
    result = checker.check_token_scan(
        [str(legacy)], DENYLIST_TOKENS, tmp_path,
        classified_files=[str(legacy)],
    )
    assert result["status"] == "ok"
    assert result["detail"]["hits"] == []
    assert [h["token"] for h in result["detail"]["deferred_classified"]] == ["dvwa"]


def test_unclassified_hit_still_fails_even_with_other_classified(tmp_path: Path) -> None:
    """An unlisted file's hit still FAILs while a listed file is deferred."""
    classified = tmp_path / "known_legacy.py"
    classified.write_text("X = 'dvwa'\n", encoding="utf-8")
    rogue = tmp_path / "rogue.py"
    rogue.write_text("Y = 'juice'\n", encoding="utf-8")
    result = checker.check_token_scan(
        [str(classified), str(rogue)], DENYLIST_TOKENS, tmp_path,
        classified_files=[str(classified)],
    )
    assert result["status"] == "fail"
    assert {h["token"] for h in result["detail"]["hits"]} == {"juice"}
    assert {h["token"] for h in result["detail"]["deferred_classified"]} == {"dvwa"}


def test_manifest_classified_files_never_suppresses_own_artifacts_or_modules() -> None:
    """config/diagnostics/** and clean-profile modules are never deferrable."""
    manifest = {
        "clean_profile_definition": {"modules": ["src/reporting/vdp_canonical.py"]},
        "hits": [
            {"file": "src/legacy/x.py", "product": "DVWA"},
            {"file": "config/diagnostics/external_audit_v1.json", "product": "DVWA"},
            {"file": "src/reporting/vdp_canonical.py", "product": "DVWA"},
        ],
    }
    classified = checker.manifest_classified_files(manifest)
    assert classified == ["src/legacy/x.py"]
