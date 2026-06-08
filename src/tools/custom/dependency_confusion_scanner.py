"""
Dependency Confusion Scanner - サプライチェーン攻撃検出ツール

package.json、requirements.txt等から内部パッケージ名を抽出し、
公開レジストリに同名パッケージが存在しないかを確認。
乗っ取り可能性のある内部パッケージを特定する。
"""
from typing import Dict, Any, List, Tuple
import subprocess
import json
import time
import re
from pathlib import Path
from src.tools.base import BaseTool
from src.tools import ToolRegistry


@ToolRegistry.register
class DependencyConfusionScannerTool(BaseTool):
    """
    DependencyConfusionScanner - サプライチェーン攻撃検出
    
    内部パッケージ名が公開レジストリで未登録の場合、
    攻撃者が先に登録して乗っ取る可能性を警告する。
    """
    
    name = "dependency_confusion_scanner"
    description = "Scan for dependency confusion vulnerabilities in package manifests."
    
    # サポートするパッケージマニフェスト
    SUPPORTED_MANIFESTS = {
        "npm": ["package.json"],
        "pypi": ["requirements.txt", "pyproject.toml", "setup.py"],
        "go": ["go.mod"],
    }
    
    # 内部パッケージの典型的パターン
    INTERNAL_PATTERNS = [
        r"^@[a-zA-Z0-9_-]+/",  # npm scoped (@company/pkg)
        r"^internal[-_]",      # internal-xxx
        r"^private[-_]",       # private-xxx
        r"[-_]internal$",      # xxx-internal
        r"[-_]private$",       # xxx-private
    ]
    
    # 明らかに公開パッケージ（チェック不要）
    KNOWN_PUBLIC = {
        "react", "vue", "angular", "express", "lodash", "axios",
        "requests", "flask", "django", "numpy", "pandas",
        "gin", "echo", "fiber", "cobra",
    }
    
    # レート制限設定
    RATE_LIMIT_DELAY = 0.5  # 500ms between requests

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
                            "description": "Path to manifest file or directory containing manifests"
                        },
                        "registry": {
                            "type": "string",
                            "enum": ["npm", "pypi", "go", "all"],
                            "description": "Package registry to check",
                            "default": "all"
                        },
                        "check_public": {
                            "type": "boolean",
                            "description": "Also check if internal packages exist in public registry",
                            "default": True
                        },
                        "max_packages": {
                            "type": "integer",
                            "description": "Maximum packages to check (rate limit protection)",
                            "default": 50
                        }
                    },
                    "required": ["target"]
                }
            }
        }

    def run(
        self, 
        target: str = "", 
        registry: str = "all",
        check_public: bool = True,
        max_packages: int = 50,
        **kwargs
    ) -> str:
        """
        依存関係の混乱脆弱性をスキャン
        """
        # 入力バリデーション
        if not target:
            return json.dumps({"error": "Target path is required"})
        
        if any(c in target for c in [";", "|", "&", "$", "`"]):
            return json.dumps({"error": "Unsafe characters in target path"})
        
        max_packages = min(max(max_packages, 5), 200)
        
        target_path = Path(target)
        if not target_path.exists():
            return json.dumps({"error": f"Path not found: {target}"})
        
        # マニフェストファイル収集
        manifests = self._find_manifests(target_path, registry)
        if not manifests:
            return json.dumps({
                "error": "No supported manifest files found",
                "supported": list(self.SUPPORTED_MANIFESTS.keys())
            })
        
        results: List[Dict[str, Any]] = []
        total_checked = 0
        
        for manifest_type, manifest_path in manifests:
            if total_checked >= max_packages:
                break
            
            # パッケージ抽出
            packages = self._extract_packages(manifest_type, manifest_path)
            
            # 内部パッケージ候補をフィルタ
            internal_candidates = self._filter_internal_candidates(packages)
            
            # 公開レジストリ確認
            if check_public:
                for pkg in internal_candidates[:max_packages - total_checked]:
                    exists, details = self._check_registry(manifest_type, pkg)
                    
                    results.append({
                        "manifest": str(manifest_path),
                        "registry": manifest_type,
                        "package": pkg,
                        "internal_pattern_matched": True,
                        "exists_in_public": exists,
                        "risk": "LOW" if exists else "HIGH",
                        "details": details,
                        "recommendation": (
                            "Package exists in public registry - verify ownership"
                            if exists else
                            "Package NOT in public registry - potential takeover target!"
                        )
                    })
                    
                    total_checked += 1
                    time.sleep(self.RATE_LIMIT_DELAY)
            else:
                # チェックせず候補のみ報告
                for pkg in internal_candidates[:max_packages - total_checked]:
                    results.append({
                        "manifest": str(manifest_path),
                        "registry": manifest_type,
                        "package": pkg,
                        "internal_pattern_matched": True,
                        "exists_in_public": None,
                        "risk": "UNKNOWN",
                        "recommendation": "Manual verification required"
                    })
                    total_checked += 1
        
        # 高リスクパッケージを抽出
        high_risk = [r for r in results if r.get("risk") == "HIGH"]
        
        return json.dumps({
            "target": str(target_path),
            "manifests_scanned": len(manifests),
            "packages_checked": total_checked,
            "high_risk_count": len(high_risk),
            "high_risk_packages": high_risk,
            "all_results": results,
            "recommendation": (
                f"CRITICAL: {len(high_risk)} packages are vulnerable to dependency confusion! "
                "Consider registering placeholder packages or using private registries."
                if high_risk else
                "No immediate dependency confusion risks detected."
            )
        }, indent=2)

    def _find_manifests(
        self, 
        target: Path,
        registry: str
    ) -> List[Tuple[str, Path]]:
        """マニフェストファイルを検索"""
        manifests = []
        
        registries = (
            [registry] if registry != "all" 
            else list(self.SUPPORTED_MANIFESTS.keys())
        )
        
        for reg in registries:
            for manifest_name in self.SUPPORTED_MANIFESTS.get(reg, []):
                if target.is_file() and target.name == manifest_name:
                    manifests.append((reg, target))
                elif target.is_dir():
                    # 再帰検索（深さ制限）
                    for found in target.rglob(manifest_name):
                        # node_modules, venv等を除外
                        if not any(
                            skip in str(found) 
                            for skip in ["node_modules", "venv", ".venv", "vendor", "__pycache__"]
                        ):
                            manifests.append((reg, found))
        
        return manifests[:20]  # 最大20ファイル

    def _extract_packages(
        self, 
        manifest_type: str, 
        manifest_path: Path
    ) -> List[str]:
        """マニフェストからパッケージ名を抽出"""
        try:
            content = manifest_path.read_text(encoding="utf-8")
        except Exception:
            return []
        
        if manifest_type == "npm":
            return self._extract_npm_packages(content)
        elif manifest_type == "pypi":
            return self._extract_pypi_packages(content, manifest_path.name)
        elif manifest_type == "go":
            return self._extract_go_packages(content)
        
        return []

    def _extract_npm_packages(self, content: str) -> List[str]:
        """package.jsonからパッケージ抽出"""
        packages = []
        try:
            data = json.loads(content)
            for key in ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]:
                if key in data and isinstance(data[key], dict):
                    packages.extend(data[key].keys())
        except json.JSONDecodeError:
            pass
        return packages

    def _extract_pypi_packages(self, content: str, filename: str) -> List[str]:
        """requirements.txt / pyproject.tomlからパッケージ抽出"""
        packages = []
        
        if filename == "requirements.txt":
            for line in content.split("\n"):
                line = line.strip()
                if line and not line.startswith("#") and not line.startswith("-"):
                    # パッケージ名のみ抽出（バージョン指定を除去）
                    match = re.match(r"^([a-zA-Z0-9_-]+)", line)
                    if match:
                        packages.append(match.group(1))
        
        elif filename == "pyproject.toml":
            # 簡易的なTOML解析
            in_dependencies = False
            for line in content.split("\n"):
                if "[project.dependencies]" in line or "[tool.poetry.dependencies]" in line:
                    in_dependencies = True
                    continue
                if in_dependencies:
                    if line.startswith("["):
                        in_dependencies = False
                        continue
                    match = re.match(r'^"?([a-zA-Z0-9_-]+)"?\s*[=<>]', line)
                    if match:
                        packages.append(match.group(1))
        
        return packages

    def _extract_go_packages(self, content: str) -> List[str]:
        """go.modからパッケージ抽出"""
        packages = []
        for line in content.split("\n"):
            line = line.strip()
            if line.startswith("require") or (line and not line.startswith("//")):
                # モジュールパス抽出
                match = re.match(r"^\s*([a-zA-Z0-9./\-_]+)\s+v", line)
                if match:
                    packages.append(match.group(1))
        return packages

    def _filter_internal_candidates(self, packages: List[str]) -> List[str]:
        """内部パッケージ候補をフィルタ"""
        candidates = []
        
        for pkg in packages:
            pkg_lower = pkg.lower()
            
            # 既知の公開パッケージはスキップ
            if pkg_lower in self.KNOWN_PUBLIC:
                continue
            
            # 内部パターンにマッチするか
            is_internal = any(
                re.search(pattern, pkg) 
                for pattern in self.INTERNAL_PATTERNS
            )
            
            if is_internal:
                candidates.append(pkg)
        
        return candidates

    def _check_registry(
        self, 
        registry_type: str, 
        package: str
    ) -> Tuple[bool, Dict[str, Any]]:
        """公開レジストリにパッケージが存在するか確認"""
        try:
            if registry_type == "npm":
                return self._check_npm(package)
            elif registry_type == "pypi":
                return self._check_pypi(package)
            elif registry_type == "go":
                return self._check_go_proxy(package)
        except Exception as e:
            return False, {"error": str(e)}
        
        return False, {"error": "Unknown registry type"}

    def _check_npm(self, package: str) -> Tuple[bool, Dict[str, Any]]:
        """npm registryを確認"""
        # スコープ付きパッケージのURL変換
        if package.startswith("@"):
            encoded = package.replace("/", "%2F")
        else:
            encoded = package
        
        url = f"https://registry.npmjs.org/{encoded}"
        
        result = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-m", "10", url],
            capture_output=True,
            text=True,
            timeout=15,
            check=False
        )
        
        status_code = result.stdout.strip()
        exists = status_code == "200"
        
        return exists, {"status_code": status_code, "registry_url": url}

    def _check_pypi(self, package: str) -> Tuple[bool, Dict[str, Any]]:
        """PyPI registryを確認"""
        url = f"https://pypi.org/pypi/{package}/json"
        
        result = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-m", "10", url],
            capture_output=True,
            text=True,
            timeout=15,
            check=False
        )
        
        status_code = result.stdout.strip()
        exists = status_code == "200"
        
        return exists, {"status_code": status_code, "registry_url": url}

    def _check_go_proxy(self, package: str) -> Tuple[bool, Dict[str, Any]]:
        """Go proxyを確認"""
        # Go proxyのURL変換
        encoded = package.replace("/", "/").lower()
        url = f"https://proxy.golang.org/{encoded}/@v/list"
        
        result = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "-m", "10", url],
            capture_output=True,
            text=True,
            timeout=15,
            check=False
        )
        
        status_code = result.stdout.strip()
        exists = status_code == "200"
        
        return exists, {"status_code": status_code, "registry_url": url}
