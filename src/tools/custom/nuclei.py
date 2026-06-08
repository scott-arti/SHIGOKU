"""
Custom Nuclei Tool - Enhanced version with Profile support for AI use.
Path: Controlled by src.config.settings.tool_nuclei_path
"""
from typing import Dict, Any, Optional, List
from pathlib import Path
import shlex
import logging
from src.tools.base import BaseTool
from src.config import settings
from src.tools import ToolRegistry
from src.core.utils.batch_utils import create_batch_file
from src.core.security.safe_subprocess import safe_run, SecurityViolationError
import subprocess

@ToolRegistry.register
class NucleiTool(BaseTool):
    """
    Nuclei Scanner Tool wrapper.
    
    Profiles:
    - quick: Common CVEs and misconfigs only (Low noise)
    - standard: Default scan with safety checks
    - deep: Extensive scanning including fuzzing templates
    - critical: Only Critical/High severity
    """
    
    name = "nuclei"
    description = """Execute Nuclei vulnerability scanner with safety profiles.
    
    Profiles:
    - quick: Fast scan for top vulnerabilities
    - standard: Balanced scan (Recommended)
    - deep: Comprehensive scan (Slow)
    - critical: High severity only
    
    Use 'extra_args' for specific flags like '-t cves/'.
    """
    
    def to_schema(self) -> Dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Target URL or host"
                        },
                        "mode": {
                            "type": "string",
                            "enum": ["quick", "standard", "deep", "critical"],
                            "description": "Scan profile/mode",
                            "default": "standard"
                        },
                        "headers": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Custom headers (e.g. ['Cookie: ...', 'Authorization: ...'])"
                        },
                        "extra_args": {
                            "type": "string",
                            "description": "Additional flags (sanitized). e.g., '-t cves/'"
                        }
                    },
                    "required": ["target"]
                }
            }
        }

    def _get_nuclei_templates_dir(self) -> Path | None:
        """
        Nucleiテンプレートディレクトリを検出する（Docker/ローカル両対応）。
        
        検索順序:
        1. /root/nuclei-templates (Docker内)
        2. /app/nuclei-templates (Docker内代替)
        3. ~/nuclei-templates (ローカル)
        4. ~/.local/nuclei-templates (ローカル代替)
        
        Returns:
            Path: テンプレートディレクトリ、見つからない場合はNone
        """
        candidates = [
            Path("/root/nuclei-templates"),      # Docker (root user)
            Path("/app/nuclei-templates"),       # Docker (app dir)
            Path.home() / "nuclei-templates",    # Local standard
            Path.home() / ".local" / "nuclei-templates",  # Local fallback
        ]
        
        for candidate in candidates:
            if candidate.exists() and candidate.is_dir():
                return candidate
        
        return None

    def _resolve_template_path(self, template_path: str) -> str:
        """
        Smartly resolve template path to handle V2 -> V3 migration and relative paths.
        
        Tries:
        1. Exact path
        2. Docker/Local template directories
        3. V3 http/ prefix migration
        4. Recursive search by filename
        """
        path_obj = Path(template_path)
        if path_obj.exists():
            return str(path_obj.resolve())

        # Base directory (Docker/Local auto-detect)
        nuclei_dir = self._get_nuclei_templates_dir()
        
        if nuclei_dir is None:
            return template_path  # Can't help if no templates


        # 1. Explicit Mappings for Common Hallucinations
        # LLMs often guess category names that don't strictly exist or don't match the folder structure
        mappings = {
            "exposed-secrets": "http/exposed-panels", # Corrected from http/exposures based on ls output
            "api-keys": "http/exposed-panels", # Closest logical match
            "secrets": "http/exposures/tokens",  # V3: exposures, not exposure
            "exposure/secrets": "http/exposures/tokens",  # Common LLM hallucination
            "secret-detection": "http/exposures/tokens",  # Common LLM hallucination
            "vulnerabilities/generic/secret-detection": "http/exposures/tokens",  # Full path hallucination
            "vulnerabilities/generic/secret-detection.yaml": "http/exposures/tokens",  # With .yaml
            "tokens": "http/token-spray",
            "token-spray": "http/token-spray",
            "request-smuggling": "http/vulnerabilities/smuggling", # Direct mapping for common failure
            "smuggling": "http/vulnerabilities/smuggling",
            "cors": "http/vulnerabilities/generic/cors-misconfig.yaml",
            "cors-misconfig": "http/vulnerabilities/generic/cors-misconfig.yaml",
            "xss": "http/vulnerabilities/generic/xss-reflected.yaml",
            "sqli": "http/vulnerabilities/generic/sql-injection.yaml",
            "open-redirect": "http/vulnerabilities/generic/open-redirect.yaml",
            "crlf": "http/vulnerabilities/crlf",  # Common template directory
            "crlf-injection": "http/vulnerabilities/crlf",
        }
        
        # Check explicit mappings
        if template_path in mappings:
            expected = nuclei_dir.joinpath(mappings[template_path])
            if expected.exists():
                return str(expected)
        
        # Check if basename matches a mapping key
        if path_obj.name in mappings:
            expected = nuclei_dir.joinpath(mappings[path_obj.name])
            if expected.exists():
                return str(expected)

        # Check explicit V2 -> V3 mappings
        # V3 splits into http, code, javascript etc. Most legacy are http.
        potential_paths = [
            nuclei_dir / template_path,
            nuclei_dir / "http" / template_path,
            nuclei_dir / "code" / template_path,
            nuclei_dir / "dast" / template_path, # Added dast check
            nuclei_dir / "headless" / template_path,
        ]
        
        for p in potential_paths:
            if p.exists():
                return str(p)

        # Fuzzy search by filename (last resort)
        # Using rglob might be slow if dir is huge, but usually fine for one template
        # Limit to 3 levels deep to avoid full scan
        try:
            filename = path_obj.name
            # Try specific subdirs first
            for subdir in ["http", "cves", "vulnerabilities", "misconfiguration"]:
                matches = list((nuclei_dir / subdir).rglob(filename))
                if matches:
                    return str(matches[0])
            
            # Global search if not found
            matches = list(nuclei_dir.rglob(filename))
            if matches:
                return str(matches[0])
            
            # 5. Directory Fuzzy Search (e.g. 'request-smuggling' -> 'vulnerabilities/smuggling')
            # If the input looks like a directory or category name (no extension)
            if not path_obj.suffix:
                dir_matches = [p for p in nuclei_dir.rglob(path_obj.name) if p.is_dir()]
                if dir_matches:
                    # Prefer paths containing 'vulnerabilities' or 'http' to prioritize standard locations
                    sorted_matches = sorted(dir_matches, key=lambda p: (
                        0 if 'vulnerabilities' in str(p) else 1,
                        0 if 'http' in str(p) else 1,
                        len(str(p))
                    ))
                    return str(sorted_matches[0])

        except Exception:
            pass # Fail gracefully

        return template_path

    def preflight_check(self, extra_args: Optional[str] = None) -> tuple[bool, str]:
        """
        実行前のプリフライトチェック。
        
        Args:
            extra_args: 実行時の追加引数
            
        Returns:
            tuple[bool, str]: (成功フラグ, エラーメッセージ)
        """
        # 1. テンプレートディレクトリの存在確認
        nuclei_dir = self._get_nuclei_templates_dir()
        if nuclei_dir is None:
            return False, "Nuclei templates directory not found. Run 'nuclei -update-templates' first."
        
        # 2. テンプレート指定がある場合、そのパスを確認
        if extra_args:
            try:
                args = shlex.split(extra_args)
                for i, arg in enumerate(args):
                    if arg in ["-t", "-templates"] and i + 1 < len(args):
                        tpl_path = args[i + 1]
                        resolved = self._resolve_template_path(tpl_path)
                        # 解決後もパスが見つからない場合
                        if resolved == tpl_path and not Path(tpl_path).exists():
                            return False, f"Template not found: {tpl_path}. Resolved path also not found."
                    elif arg == "-tags":
                        # タグ指定は事前検証困難なのでスキップ（実行時にフォールバック）
                        pass
            except ValueError as e:
                return False, f"Invalid extra_args format: {e}"
        
        return True, "OK"


    def run(self, target: Any, mode: str = "standard", headers: Optional[List[str]] = None, extra_args: Optional[str] = None) -> str:
        """Execute Nuclei with specified profile and optional headers."""
        
        # ターゲットがリストの場合はバッチ処理
        if isinstance(target, list):
            with create_batch_file(target) as batch_path:
                if not batch_path:
                    return "Error: No valid targets after scope check."
                return self._run_nuclei(batch_path, mode, headers, extra_args, is_batch=True)
        else:
            return self._run_nuclei(target, mode, headers, extra_args, is_batch=False)

    def _run_nuclei(self, target: str, mode: str, headers: Optional[List[str]], extra_args: Optional[str], is_batch: bool) -> str:
        """実際の実行ロジック"""
        cmd = [settings.tool_nuclei_path]
        if is_batch:
            cmd += ["-l", target]
        else:
            cmd += ["-u", target]
            
        cmd += ["-j", "-silent"]
        
        # 1. Profile Selection
        if mode == "quick":
            cmd += ["-tags", "cve,misconfig,exposure", "-rate-limit", "50", "-c", str(getattr(settings.scan, "threads", 10))]
        elif mode == "standard":
            cmd += ["-rate-limit", "150", "-c", str(getattr(settings.scan, "threads", 10))] # Default sane defaults
        elif mode == "deep":
            cmd += ["-rate-limit", "100", "-dast", "-c", str(getattr(settings.scan, "threads", 10))] # Slower, more comprehensive
        elif mode == "critical":
            cmd += ["-severity", "critical,high", "-c", str(getattr(settings.scan, "threads", 10))]
        
        # 2. Header Injection (for Auth)
        if headers:
            for header in headers:
                # Nuclei uses -H 'Name: Value'
                cmd += ["-H", header]
            
        # 3. Extra Args (Use shlex for safe splitting) & Path Resolution
        if extra_args:
            # Note: safe_run enforces shell=False, so injection is prevents at OS level
            try:
                args = shlex.split(extra_args)
                resolved_args = []
                skip_next = False
                
                for i, arg in enumerate(args):
                    if skip_next:
                        skip_next = False
                        continue
                        
                    if arg in ["-t", "-templates"]:
                        if i + 1 < len(args):
                            tpl_path = args[i+1]
                            resolved_path = self._resolve_template_path(tpl_path)
                            resolved_args.extend([arg, resolved_path])
                            skip_next = True
                        else:
                            resolved_args.append(arg)
                    else:
                        resolved_args.append(arg)
                        
                cmd += resolved_args
                
                # Auto-enable DAST mode if any DAST template is used
                # Nuclei v3 requires -dast flag for templates under dast/ directory
                dast_needed = False
                for arg in resolved_args:
                    if "/dast/" in arg.replace("\\", "/"):
                        dast_needed = True
                        break
                
                if dast_needed and "-dast" not in cmd:
                    cmd.append("-dast")
                
            except ValueError:
                return "Error: Invalid extra_args format."
            
        # Execute
        try:
            result = safe_run(
                cmd,
                capture_output=True,
                timeout=3600, # 1 hour max
                check=False
            )
            if result.returncode != 0:
                stderr_text = result.stderr or ""
                
                # タグ指定エラー時のフォールバック
                # "no templates provided" は指定したタグに一致するテンプレートがない場合に発生
                if "no templates provided" in stderr_text.lower():
                    logging.getLogger(__name__).warning(
                        "Nuclei tag error detected, attempting severity-based fallback"
                    )
                    # フォールバック: タグ指定を削除し、severity指定で再実行
                    fallback_cmd = [c for c in cmd if c not in ["-tags"]]
                    # -tags の次の引数も削除
                    try:
                        tags_idx = cmd.index("-tags")
                        if tags_idx + 1 < len(cmd):
                            fallback_cmd = [c for i, c in enumerate(cmd) 
                                          if i != tags_idx and i != tags_idx + 1]
                    except ValueError:
                        pass
                    
                    # severity fallback を追加
                    if "-severity" not in fallback_cmd:
                        fallback_cmd += ["-severity", "critical,high,medium"]
                    
                    fallback_result = safe_run(
                        fallback_cmd,
                        capture_output=True,
                        timeout=3600,
                        check=False
                    )
                    if fallback_result.returncode == 0:
                        return fallback_result.stdout or "No results found (fallback scan)."
                    else:
                        return f"Nuclei Error (fallback also failed):\n{fallback_result.stderr}"
                
                return f"Nuclei Error:\n{stderr_text}"
                 
            return result.stdout or "No results found."
            
        except FileNotFoundError:
            return f"Error: Nuclei binary not found at {settings.tool_nuclei_path}"
        except SecurityViolationError as e:
            return f"Security Error: {e}"
        except (subprocess.SubprocessError, IOError, ValueError) as e:
            return f"Error: {str(e)}"
