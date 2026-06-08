"""
audit_secrets.py: 認証情報ローテーション監査スクリプト

走査対象: config/ および .env 系ファイル
検出条件: expires_at / last_rotated_at / created_at フィールドが
          ROTATION_MAX_AGE_DAYS (デフォルト 90 日) を超えた資格情報エントリ
出力: JSON (標準出力)

使用例:
    python3 scripts/audit_secrets.py
    python3 scripts/audit_secrets.py --max-age-days 60 --config-dir config/
"""

import argparse
import json
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

EXPIRY_FIELDS_PRIORITY = ["expires_at", "last_rotated_at", "created_at"]
DEFAULT_MAX_AGE_DAYS = 90
DEFAULT_CONFIG_DIRS = ["config"]
DEFAULT_ENV_PATTERNS = [".env", ".env.local", ".env.production", ".env.staging"]


def _parse_timestamp(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            return None
    if isinstance(value, str):
        for fmt in (
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d",
        ):
            try:
                dt = datetime.strptime(value, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                continue
    return None


def _resolve_expiry(entry: Dict[str, Any]) -> Optional[datetime]:
    for field in EXPIRY_FIELDS_PRIORITY:
        raw = entry.get(field)
        dt = _parse_timestamp(raw)
        if dt is not None:
            return dt
    return None


def _audit_dict_entries(
    data: Any,
    source_file: str,
    max_age: timedelta,
    now: datetime,
    results: List[Dict[str, Any]],
    path: str = "",
) -> None:
    if isinstance(data, dict):
        expiry = _resolve_expiry(data)
        if expiry is not None:
            age = now - expiry
            if age > max_age:
                results.append(
                    {
                        "source": source_file,
                        "path": path,
                        "expiry": expiry.isoformat(),
                        "age_days": round(age.total_seconds() / 86400, 1),
                        "overdue": True,
                        "expiry_unknown": False,
                    }
                )
        else:
            _hints = ("api_key", "secret", "password", "token", "credential", "key")
            has_secret_hint = any(
                hint in k.lower()
                for k in data
                for hint in _hints
            )
            if has_secret_hint:
                results.append(
                    {
                        "source": source_file,
                        "path": path,
                        "expiry_unknown": True,
                        "overdue": False,
                    }
                )
        for k, v in data.items():
            child_path = f"{path}.{k}" if path else k
            _audit_dict_entries(v, source_file, max_age, now, results, child_path)
    elif isinstance(data, list):
        for i, item in enumerate(data):
            _audit_dict_entries(item, source_file, max_age, now, results, f"{path}[{i}]")


def _scan_json_yaml_file(
    filepath: Path,
    max_age: timedelta,
    now: datetime,
    results: List[Dict[str, Any]],
) -> None:
    try:
        text = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return

    suffix = filepath.suffix.lower()
    data: Any = None

    if suffix in (".json",):
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return
    elif suffix in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore
            data = yaml.safe_load(text)
        except Exception:
            return
    elif suffix in (".toml",):
        try:
            import tomllib  # type: ignore
        except ImportError:
            try:
                import tomli as tomllib  # type: ignore
            except ImportError:
                return
        try:
            data = tomllib.loads(text)
        except Exception:
            return
    else:
        return

    if data is not None:
        _audit_dict_entries(data, str(filepath), max_age, now, results)


def _scan_env_file(
    filepath: Path,
    max_age: timedelta,
    now: datetime,
    results: List[Dict[str, Any]],
) -> None:
    try:
        lines = filepath.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return

    kv: Dict[str, str] = {}
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            k, _, v = line.partition("=")
            kv[k.strip()] = v.strip().strip('"').strip("'")

    _audit_dict_entries(kv, str(filepath), max_age, now, results)


def scan(
    config_dirs: Optional[List[str]] = None,
    env_patterns: Optional[List[str]] = None,
    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
    project_root: Optional[str] = None,
) -> List[Dict[str, Any]]:
    root = Path(project_root) if project_root else Path.cwd()
    max_age = timedelta(days=max_age_days)
    now = datetime.now(tz=timezone.utc)
    results: List[Dict[str, Any]] = []

    dirs_to_scan = config_dirs if config_dirs is not None else DEFAULT_CONFIG_DIRS
    for rel_dir in dirs_to_scan:
        scan_dir = root / rel_dir
        if not scan_dir.is_dir():
            continue
        for fp in scan_dir.rglob("*"):
            if fp.is_file():
                _scan_json_yaml_file(fp, max_age, now, results)

    env_pats = env_patterns if env_patterns is not None else DEFAULT_ENV_PATTERNS
    for pat in env_pats:
        fp = root / pat
        if fp.is_file():
            _scan_env_file(fp, max_age, now, results)

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit credential rotation age")
    parser.add_argument(
        "--max-age-days",
        type=int,
        default=DEFAULT_MAX_AGE_DAYS,
        help=f"Maximum allowed age in days (default: {DEFAULT_MAX_AGE_DAYS})",
    )
    parser.add_argument(
        "--config-dir",
        action="append",
        dest="config_dirs",
        default=None,
        help="Config directory to scan (repeatable, default: config/)",
    )
    parser.add_argument(
        "--project-root",
        type=str,
        default=None,
        help="Project root directory (default: cwd)",
    )
    parser.add_argument(
        "--env-pattern",
        action="append",
        dest="env_patterns",
        default=None,
        help=(
            "Additional .env filename pattern to scan (repeatable). "
            f"Defaults: {', '.join(DEFAULT_ENV_PATTERNS)}"
        ),
    )
    parser.add_argument(
        "--exit-nonzero-on-findings",
        action="store_true",
        default=False,
        help="Exit with code 1 if any overdue or unknown-expiry credentials found",
    )
    args = parser.parse_args()

    findings = scan(
        config_dirs=args.config_dirs,
        env_patterns=args.env_patterns,
        max_age_days=args.max_age_days,
        project_root=args.project_root,
    )

    output = {
        "scanned_at": datetime.now(tz=timezone.utc).isoformat(),
        "max_age_days": args.max_age_days,
        "total_findings": len(findings),
        "overdue_count": sum(1 for f in findings if f.get("overdue")),
        "expiry_unknown_count": sum(1 for f in findings if f.get("expiry_unknown")),
        "findings": findings,
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))

    if args.exit_nonzero_on_findings and findings:
        sys.exit(1)


if __name__ == "__main__":
    main()
