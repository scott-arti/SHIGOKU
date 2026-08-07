#!/usr/bin/env python3
"""SGK-2026-0425 M0/M5 preflight: VDP product-independence gate (read-only, fail-closed).

Checks (each returns a per-check detail; the overall verdict is fail-closed):

1. manifest_exists        — manifest file exists and parses as JSON (else BLOCKED)
2. manifest_hash          — content_hash == "sha256:" + sha256 of the canonical
                            JSON body (manifest minus the content_hash key).
                            Mismatch → FAIL (manifest tampered).
3. denylist_exists        — sealed denylist file exists with non-empty tokens
                            (plain text one token per line, or a JSON array).
                            Missing/invalid → BLOCKED.
4. token_scan_changed_files — scan changed production files (git status
                            --porcelain filtered to src/, scripts/, config/,
                            recipes/, prompts/, data/; or --changed-files) for
                            denylist tokens (case-insensitive). A hit FAILs
                            UNLESS its file is enumerated in the manifest
                            ``hits[]`` (pre-existing legacy, classified with a
                            reachability + deferred to SGK-2026-0426 per plan
                            §15); those are recorded under ``deferred_classified``
                            and do not fail. Files under ``config/diagnostics/``
                            (this task's own artifacts) and clean-profile modules
                            are NEVER suppressible — a hit there always FAILs, so
                            new-artifact leakage cannot be waved away by the
                            manifest. Clean-profile reachability is guarded
                            independently by check #5 (import_closure).
5. import_closure         — transitive import closure (ast) of the clean
                            profile modules; any manifest hit file reachable
                            (unless SCRIPT_ONLY) or any denylist token inside
                            the closure → FAIL.
6. model_context          — llm.roles.*.system_prompt_template files from
                            config/shigoku.yaml scanned for denylist tokens
                            → any hit FAIL.

Exit codes: 0 pass, 2 blocked/input error, 3 fail (any FAIL check).

The checker is strictly read-only: it never modifies a scanned file and never
writes anything except stdout. The denylist file and the manifest file are
always excluded from their own token scans.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

PRODUCTION_PREFIXES = ("src/", "scripts/", "config/", "recipes/", "prompts/", "data/")

CHECK_NAMES = (
    "manifest_exists",
    "manifest_hash",
    "denylist_exists",
    "token_scan_changed_files",
    "import_closure",
    "model_context",
)


# ---------------------------------------------------------------------------
# small building blocks (pure)
# ---------------------------------------------------------------------------

def _blocked(reason: str, detail: Dict[str, Any]) -> Dict[str, Any]:
    return {"status": "blocked", "reason_codes": [reason], "detail": detail}


def canonical_manifest_body(manifest: Dict[str, Any]) -> str:
    """Deterministic JSON body: the manifest minus its content_hash key."""
    body = {key: value for key, value in manifest.items() if key != "content_hash"}
    return json.dumps(body, sort_keys=True, ensure_ascii=False)


def compute_manifest_hash(manifest: Dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(
        canonical_manifest_body(manifest).encode("utf-8")
    ).hexdigest()


def load_denylist_tokens(path: Path) -> List[str]:
    """Parse the sealed denylist: one token per line, or a JSON array of tokens.

    Returns lowercased, non-empty, de-duplicated tokens. Raises on invalid
    content (JSON that is not a list, or unreadable file).
    """
    raw = path.read_text(encoding="utf-8")
    stripped = raw.strip()
    if stripped.startswith("["):
        data = json.loads(stripped)
        if not isinstance(data, list):
            raise ValueError("denylist JSON must be a JSON array of token strings")
        tokens = [str(token).strip() for token in data]
    else:
        tokens = [line.strip() for line in raw.splitlines()]
    seen: set[str] = set()
    out: List[str] = []
    for token in tokens:
        token = token.lower()
        if token and token not in seen:
            seen.add(token)
            out.append(token)
    return out


def parse_changed_files_file(path: Path) -> List[str]:
    """Read --changed-files input: one path per line, '#' comments ignored."""
    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines()]
    return [line for line in lines if line and not line.startswith("#")]


def resolve_changed_path(entry: str, repo_root: Path) -> Path:
    path = Path(entry)
    return path if path.is_absolute() else repo_root / path


def scan_file_tokens(path: Path, denylist_tokens: List[str]) -> List[Dict[str, Any]]:
    """Case-insensitive per-line token scan. Returns [{line, token}, ...].

    Unreadable or non-UTF-8 files are skipped (no hits): the caller records
    file-level context, and missing files (e.g. deleted paths from git
    status) are a normal no-op.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    lowered = text.lower()
    hits: List[Dict[str, Any]] = []
    for lineno, line in enumerate(lowered.splitlines(), start=1):
        for token in denylist_tokens:
            if token in line:
                hits.append({"line": lineno, "token": token})
    return hits


def extract_roles_templates(text: str) -> Dict[str, Dict[str, Any]]:
    """Best-effort YAML-subset extractor for ``llm.roles.*.system_prompt_template``.

    Mirrors the layout of config/shigoku.yaml: ``roles:`` at 2-space indent,
    role entries at 4, fields at 6. Used only when PyYAML is unavailable.
    """
    roles: Dict[str, Dict[str, Any]] = {}
    current_role: Optional[str] = None
    in_roles = False
    for line in text.splitlines():
        if re.match(r"^  roles:\s*$", line):
            in_roles = True
            continue
        if not in_roles:
            continue
        role_match = re.match(r"^    ([A-Za-z0-9_]+):\s*$", line)
        if role_match:
            role_name = role_match.group(1)
            current_role = role_name
            roles[role_name] = roles.get(role_name) or {}
            continue
        if current_role:
            field_match = re.match(
                r"^      system_prompt_template:\s*(\S+)\s*$", line
            )
            if field_match:
                roles[current_role]["system_prompt_template"] = field_match.group(1)
                continue
        if re.match(r"^  [A-Za-z0-9_]+:", line):
            break  # left the roles block
    return {
        name: cfg
        for name, cfg in roles.items()
        if cfg.get("system_prompt_template")
    }


# ---------------------------------------------------------------------------
# check implementations (pure; explicit inputs)
# ---------------------------------------------------------------------------

def check_manifest_exists(path: Path) -> Dict[str, Any]:
    if not path.is_file():
        return _blocked("manifest_missing", {"path": str(path), "error": "file not found"})
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return _blocked("manifest_invalid_json", {"path": str(path), "error": str(exc)})
    clean_def = data.get("clean_profile_definition") or {}
    return {
        "status": "ok",
        "reason_codes": [],
        "detail": {
            "path": str(path),
            "schema_version": data.get("schema_version"),
            "modules": len(clean_def.get("modules") or []),
            "hit_count": len(data.get("hits") or []),
        },
    }


def check_manifest_hash(manifest: Dict[str, Any]) -> Dict[str, Any]:
    expected = manifest.get("content_hash")
    actual = compute_manifest_hash(manifest)
    if expected and expected == actual:
        return {"status": "ok", "reason_codes": [], "detail": {"expected": expected, "actual": actual}}
    return {
        "status": "fail",
        "reason_codes": ["manifest_hash_mismatch"],
        "detail": {"expected": expected, "actual": actual},
    }


def check_denylist_exists(path: Path) -> Dict[str, Any]:
    if not path.is_file():
        return _blocked("denylist_missing", {"path": str(path), "error": "file not found"})
    try:
        tokens = load_denylist_tokens(path)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return _blocked("denylist_invalid", {"path": str(path), "error": str(exc)})
    if not tokens:
        return _blocked("denylist_invalid", {"path": str(path), "error": "denylist contains no tokens"})
    return {
        "status": "ok",
        "reason_codes": [],
        "detail": {"path": str(path), "token_count": len(tokens)},
    }


def check_token_scan(
    changed_files: List[str],
    denylist_tokens: List[str],
    repo_root: Path,
    skip_files: Optional[Iterable[Path]] = None,
    classified_files: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """Scan changed production files for denylist tokens (case-insensitive).

    ``changed_files`` are entries as provided (repo-relative or absolute);
    ``skip_files`` are resolved absolute paths excluded from the scan (the
    manifest and denylist themselves). ``classified_files`` are repo-relative
    paths enumerated in the manifest ``hits[]`` as pre-existing legacy: a hit in
    one of these is recorded as ``deferred_classified`` (deferred to
    SGK-2026-0426 per plan §15) rather than failing. The caller is responsible
    for excluding never-suppressible paths (``config/diagnostics/**`` and
    clean-profile modules) from ``classified_files`` so new-artifact leakage
    still FAILs here; clean-profile reachability is guarded by import_closure.
    """
    skip = {Path(path).resolve() for path in (skip_files or set())}
    classified = {resolve_changed_path(f, repo_root).resolve() for f in (classified_files or set())}
    hits: List[Dict[str, Any]] = []
    deferred: List[Dict[str, Any]] = []
    scanned = 0
    skipped: List[str] = []
    for entry in sorted(set(changed_files)):
        path = resolve_changed_path(entry, repo_root).resolve()
        if path in skip:
            skipped.append(str(entry))
            continue
        if not path.is_file():
            continue
        scanned += 1
        sink = deferred if path in classified else hits
        for hit in scan_file_tokens(path, denylist_tokens):
            sink.append({"file": str(entry), **hit})
    status = "fail" if hits else "ok"
    return {
        "status": status,
        "reason_codes": ["token_scan_hit"] if hits else [],
        "detail": {
            "hits": hits,
            "deferred_classified": deferred,
            "files_scanned": scanned,
            "files_skipped": skipped,
            "token_count": len(denylist_tokens),
        },
    }


def manifest_classified_files(manifest: Dict[str, Any]) -> List[str]:
    """Files whose legacy product hits the token scan may DEFER (plan §15).

    A hit file is deferrable only if enumerated in the manifest ``hits[]`` and
    it is neither one of this task's own artifacts (``config/diagnostics/**``)
    nor a clean-profile module — those must never be waved away by the manifest,
    so new-artifact leakage still FAILs the token scan.
    """
    modules = set((manifest.get("clean_profile_definition") or {}).get("modules") or [])
    return [
        hit["file"]
        for hit in (manifest.get("hits") or [])
        if hit.get("file")
        and not str(hit["file"]).startswith("config/diagnostics/")
        and hit["file"] not in modules
    ]


def _module_parts(rel_path: str) -> List[str]:
    module = rel_path.removesuffix(".py").removeprefix("src/").replace("/", ".")
    return module.split(".")[:-1]


def _imported_module_names(node: ast.AST, pkg_parts: List[str]) -> List[str]:
    """Module names referenced by an import node, with relative resolution."""
    if isinstance(node, ast.Import):
        return [alias.name for alias in node.names]
    if isinstance(node, ast.ImportFrom):
        if node.level and node.level > 0:
            base = pkg_parts[: max(0, len(pkg_parts) - (node.level - 1))]
            if node.module:
                names = [".".join(base + node.module.split("."))]
            else:
                names = [".".join(base + [alias.name]) for alias in node.names]
        elif node.module:
            names = [node.module]
        else:
            return []
        # ``from X import a``: ``a`` may itself be a submodule of X
        if node.module:
            names += [node.module + "." + alias.name for alias in node.names]
        return names
    return []


def resolve_module_path(repo_root: Path, module_name: str) -> Optional[str]:
    """Resolve an import name to a repo-relative path under src/, if present.

    Stdlib/third-party modules never resolve (their path does not exist under
    src/), so they are ignored by the closure walk.
    """
    name = module_name
    if name.startswith("src."):
        name = name[len("src."):]
    rel = "src/" + name.replace(".", "/")
    for candidate in (rel + ".py", rel + "/__init__.py"):
        if (repo_root / candidate).is_file():
            return candidate
    return None


def compute_import_closure(repo_root: Path, modules: List[str]) -> Dict[str, Any]:
    """Transitive import closure (static, ast-based) of the given modules.

    Returns {"files": [...repo-relative paths...], "missing_modules": [...],
    "parse_errors": [...]}. Resolution only follows imports that exist under
    src/; everything else (stdlib, third-party) is treated as external.
    """
    queue = [module for module in modules if module]
    seen: set[str] = set()
    missing_modules: List[str] = []
    parse_errors: List[str] = []
    while queue:
        rel = queue.pop()
        if rel in seen:
            continue
        seen.add(rel)
        path = repo_root / rel
        if not path.is_file():
            missing_modules.append(rel)
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, SyntaxError) as exc:
            parse_errors.append(f"{rel}: {exc}")
            continue
        pkg_parts = _module_parts(rel)
        for node in ast.walk(tree):
            for name in _imported_module_names(node, pkg_parts):
                resolved = resolve_module_path(repo_root, name)
                if resolved and resolved not in seen:
                    queue.append(resolved)
    return {
        "files": sorted(seen),
        "missing_modules": sorted(set(missing_modules)),
        "parse_errors": parse_errors,
    }


def check_import_closure(
    manifest: Dict[str, Any],
    denylist_tokens: Optional[List[str]],
    repo_root: Path,
) -> Dict[str, Any]:
    """(a) manifest hits reachable from the clean profile closure → FAIL
    (SCRIPT_ONLY hits exempt: scripts are never importable);
    (b) denylist tokens inside closure files → FAIL.
    """
    clean_def = manifest.get("clean_profile_definition") or {}
    modules = clean_def.get("modules") or []
    closure = compute_import_closure(repo_root, modules)
    closure_files = set(closure["files"])

    manifest_hits: List[Dict[str, Any]] = []
    for hit in manifest.get("hits") or []:
        hit_file = hit.get("file")
        if not hit_file or hit.get("reachability") == "SCRIPT_ONLY":
            continue
        if hit_file in closure_files:
            manifest_hits.append(
                {
                    "file": hit_file,
                    "lines": hit.get("lines") or [],
                    "product": hit.get("product"),
                    "kind": hit.get("kind"),
                    "reachability": hit.get("reachability"),
                }
            )

    token_hits: List[Dict[str, Any]] = []
    tokens_available = denylist_tokens is not None
    if tokens_available:
        for rel in closure["files"]:
            path = repo_root / rel
            if not path.is_file():
                continue
            for hit in scan_file_tokens(path, denylist_tokens):
                token_hits.append({"file": rel, **hit})

    reason_codes: List[str] = []
    if manifest_hits:
        reason_codes.append("manifest_hit_in_closure")
    if token_hits:
        reason_codes.append("closure_token_hit")
    if closure["parse_errors"]:
        reason_codes.append("closure_parse_error")
    if closure["missing_modules"]:
        reason_codes.append("closure_missing_module")
    if not tokens_available:
        reason_codes.append("denylist_unavailable")

    status = "ok"
    if manifest_hits or token_hits or closure["parse_errors"] or closure["missing_modules"]:
        status = "fail"
    elif not tokens_available:
        status = "blocked"
    return {
        "status": status,
        "reason_codes": reason_codes,
        "detail": {
            "closure_files": closure["files"],
            "closure_size": len(closure["files"]),
            "manifest_hits_in_closure": manifest_hits,
            "token_hits": token_hits,
            "missing_modules": closure["missing_modules"],
            "parse_errors": closure["parse_errors"],
        },
    }


def check_model_context(
    roles: Dict[str, Dict[str, Any]],
    denylist_tokens: List[str],
    repo_root: Path,
) -> Dict[str, Any]:
    """Scan llm role system-prompt templates (resolved under src/prompts/).

    A declared template that does not exist → BLOCKED (model-facing context
    cannot be verified, fail-closed).
    """
    prompts_dir = repo_root / "src" / "prompts"
    hits: List[Dict[str, Any]] = []
    missing: List[str] = []
    scanned = 0
    for role in sorted(roles):
        template = (roles[role] or {}).get("system_prompt_template")
        if not template:
            continue
        path = prompts_dir / template
        if not path.is_file():
            missing.append(f"{role}: {template}")
            continue
        scanned += 1
        for hit in scan_file_tokens(path, denylist_tokens):
            hits.append(
                {
                    "file": path.relative_to(repo_root).as_posix(),
                    "role": role,
                    **hit,
                }
            )
    reason_codes: List[str] = []
    status = "ok"
    if hits:
        status = "fail"
        reason_codes.append("model_context_token_hit")
    elif missing:
        status = "blocked"
        reason_codes.append("model_context_template_missing")
    return {
        "status": status,
        "reason_codes": reason_codes,
        "detail": {
            "templates_scanned": scanned,
            "templates_missing": missing,
            "hits": hits,
        },
    }


# ---------------------------------------------------------------------------
# orchestration
# ---------------------------------------------------------------------------

def load_roles_config(path: Path) -> Optional[Dict[str, Dict[str, Any]]]:
    """Parse ``llm.roles.*.system_prompt_template`` from config/shigoku.yaml.

    Uses PyYAML when available; falls back to a regex-based extractor.
    Returns None when the config is missing or has no usable roles block.
    """
    if not path.is_file():
        return None
    text = path.read_text(encoding="utf-8")
    try:
        import yaml  # project dependency (pyyaml); optional at runtime
    except ImportError:
        return extract_roles_templates(text)
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        return None
    llm = data.get("llm") or {}
    roles = llm.get("roles") or {}
    if not isinstance(roles, dict):
        return None
    out: Dict[str, Dict[str, Any]] = {}
    for name, cfg in roles.items():
        if isinstance(cfg, dict) and cfg.get("system_prompt_template"):
            out[str(name)] = {"system_prompt_template": str(cfg["system_prompt_template"])}
    return out or None


def git_changed_production_files(repo_root: Path) -> Tuple[List[str], List[str]]:
    """Default changed-file set: git status --porcelain filtered to production dirs.

    Collapsed untracked directory entries (e.g. ``?? config/diagnostics/``)
    are expanded recursively so no production file escapes the scan.
    Returns (files, warnings); raises RuntimeError when git fails.
    """
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"git status --porcelain failed (exit {result.returncode}): "
            f"{result.stderr.strip()}"
        )
    entries: List[str] = []
    for line in result.stdout.splitlines():
        raw = line[3:].strip() if len(line) > 3 else line.strip()
        if " -> " in raw:  # rename entries: keep the destination
            raw = raw.split(" -> ", 1)[1].strip()
        if raw:
            entries.append(raw.strip('"'))
    files: List[str] = []
    dirs: List[str] = []
    for raw in entries:
        path = repo_root / raw
        if path.is_dir():
            dirs.append(raw)
        elif path.is_file():
            files.append(raw)
    files = [f for f in files if f.startswith(PRODUCTION_PREFIXES)]
    for directory in dirs:
        if not directory.startswith(PRODUCTION_PREFIXES):
            continue
        for child in sorted((repo_root / directory).rglob("*")):
            if child.is_file():
                files.append(str(child.relative_to(repo_root)))
    return sorted(set(files)), []


def run_all_checks(
    manifest_path: Path,
    denylist_path: Path,
    changed_files: Optional[List[str]],
    repo_root: Path,
    *,
    profile: str = "clean-diagnostic",
    config_path: Optional[Path] = None,
    changed_files_error: Optional[str] = None,
    skip_files: Optional[Iterable[Path]] = None,
) -> Dict[str, Dict[str, Any]]:
    """Run every check; blocked prerequisites cascade (fail-closed)."""
    checks: Dict[str, Dict[str, Any]] = {}

    manifest_exists = check_manifest_exists(manifest_path)
    checks["manifest_exists"] = manifest_exists
    manifest: Optional[Dict[str, Any]] = None
    if manifest_exists["status"] == "ok":
        loaded_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest = loaded_manifest
        checks["manifest_hash"] = check_manifest_hash(loaded_manifest)
    else:
        checks["manifest_hash"] = _blocked("manifest_unavailable", {})

    denylist_exists = check_denylist_exists(denylist_path)
    checks["denylist_exists"] = denylist_exists
    tokens: Optional[List[str]] = None
    if denylist_exists["status"] == "ok":
        tokens = load_denylist_tokens(denylist_path)

    if profile != "clean-diagnostic":
        checks["import_closure"] = _blocked("unknown_profile", {"profile": profile})
    elif manifest is None:
        checks["import_closure"] = _blocked("manifest_unavailable", {})
    else:
        checks["import_closure"] = check_import_closure(manifest, tokens, repo_root)

    if changed_files_error:
        checks["token_scan_changed_files"] = _blocked(
            "changed_files_unavailable", {"error": changed_files_error}
        )
    elif tokens is None:
        checks["token_scan_changed_files"] = _blocked("denylist_unavailable", {})
    else:
        # Manifest-classified legacy files are deferred (plan §15); the helper
        # never returns this task's own artifacts (config/diagnostics/**) or
        # clean-profile modules, so new-artifact leakage still FAILs here.
        classified_files: Optional[List[str]] = (
            manifest_classified_files(manifest) if manifest is not None else None
        )
        checks["token_scan_changed_files"] = check_token_scan(
            changed_files or [], tokens, repo_root,
            skip_files=skip_files, classified_files=classified_files,
        )

    if tokens is None:
        checks["model_context"] = _blocked("denylist_unavailable", {})
    else:
        roles = load_roles_config(config_path or (repo_root / "config" / "shigoku.yaml"))
        if roles is None:
            checks["model_context"] = _blocked("model_context_unavailable", {})
        else:
            checks["model_context"] = check_model_context(roles, tokens, repo_root)

    return checks


def aggregate_verdict(checks: Dict[str, Dict[str, Any]]) -> Tuple[str, List[str]]:
    """Fail-closed: any FAIL → fail; else any BLOCKED → blocked; else pass.

    Reason codes on a fail verdict come from the FAIL checks only; on a
    blocked verdict, from every non-ok check.
    """
    statuses = [check.get("status") for check in checks.values()]
    if "fail" in statuses:
        codes = sorted(
            {
                code
                for check in checks.values()
                if check.get("status") == "fail"
                for code in (check.get("reason_codes") or [])
            }
        )
        return "fail", codes
    if "blocked" in statuses:
        codes = sorted(
            {
                code
                for check in checks.values()
                if check.get("status") != "ok"
                for code in (check.get("reason_codes") or [])
            }
        )
        return "blocked", codes
    return "pass", []


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="M5 preflight: VDP product-independence gate (read-only, fail-closed)."
    )
    parser.add_argument("--manifest", required=True, help="M0 product-independence manifest JSON")
    parser.add_argument(
        "--profile",
        default="clean-diagnostic",
        help="clean profile name (default: clean-diagnostic)",
    )
    parser.add_argument("--denylist", required=True, help="sealed product denylist (text or JSON array)")
    parser.add_argument(
        "--changed-files",
        default=None,
        help="file with one changed path per line; default: git status --porcelain filtered to production dirs",
    )
    parser.add_argument("--json", action="store_true", help="emit a JSON payload")
    args = parser.parse_args(argv)

    repo_root = Path(__file__).resolve().parent.parent
    manifest_path = Path(args.manifest).resolve()
    denylist_path = Path(args.denylist).resolve()

    changed_files: Optional[List[str]] = None
    changed_files_error: Optional[str] = None
    if args.changed_files:
        try:
            changed_files = parse_changed_files_file(Path(args.changed_files))
        except OSError as exc:
            changed_files_error = f"cannot read --changed-files: {exc}"
    else:
        try:
            changed_files, _warnings = git_changed_production_files(repo_root)
        except RuntimeError as exc:
            changed_files_error = str(exc)

    checks = run_all_checks(
        manifest_path,
        denylist_path,
        changed_files,
        repo_root,
        profile=args.profile,
        changed_files_error=changed_files_error,
        skip_files=[manifest_path, denylist_path],
    )
    verdict, reason_codes = aggregate_verdict(checks)

    total_token_hits = 0
    for check in checks.values():
        detail = check.get("detail") or {}
        for key in ("hits", "token_hits"):
            value = detail.get(key)
            if isinstance(value, list):
                total_token_hits += len(value)

    summary = {
        "verdict": verdict,
        "checks_total": len(checks),
        "checks_failed": sum(1 for c in checks.values() if c["status"] == "fail"),
        "checks_blocked": sum(1 for c in checks.values() if c["status"] == "blocked"),
        "denylist_tokens": checks["denylist_exists"]["detail"].get("token_count", 0),
        "changed_files_input": len(changed_files) if changed_files is not None else 0,
        "files_scanned": checks["token_scan_changed_files"]["detail"].get("files_scanned", 0),
        "closure_files": checks["import_closure"]["detail"].get("closure_size", 0),
        "model_templates_scanned": checks["model_context"]["detail"].get("templates_scanned", 0),
        "total_token_hits": total_token_hits,
    }

    payload = {
        "verdict": verdict,
        "reason_codes": reason_codes,
        "checks": checks,
        "summary": summary,
    }

    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(f"verdict: {verdict}")
        print(f"reason_codes: {json.dumps(reason_codes, ensure_ascii=False)}")
        for name in CHECK_NAMES:
            check = checks.get(name)
            if not check:
                continue
            line = f"check {name}: {check['status']}"
            detail = check.get("detail") or {}
            if check["status"] == "fail":
                hits = (
                    detail.get("hits")
                    or detail.get("token_hits")
                    or detail.get("manifest_hits_in_closure")
                    or []
                )
                if hits:
                    line += " " + json.dumps(hits, ensure_ascii=False)
            print(line)
        print(f"summary: {json.dumps(summary, ensure_ascii=False)}")

    if verdict == "pass":
        return 0
    if verdict == "fail":
        return 3
    return 2


if __name__ == "__main__":
    sys.exit(main())
