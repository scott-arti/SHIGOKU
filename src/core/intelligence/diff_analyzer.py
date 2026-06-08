"""
DiffAnalyzer - 継続的差分スキャン分析モジュール

前回スキャン結果と現在の結果を比較し、
新規発見、変更、消失を検出する。
"""
import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime
from dataclasses import dataclass, asdict, field


@dataclass
class DiffResult:
    """差分分析結果"""
    category: str  # urls, params, endpoints, js_files, etc.
    added: List[str] = field(default_factory=list)
    removed: List[str] = field(default_factory=list)
    modified: List[Dict[str, Any]] = field(default_factory=list)
    
    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.modified)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass 
class ScanSnapshot:
    """スキャン結果のスナップショット"""
    scan_id: str
    target: str
    timestamp: str
    urls: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    parameters: List[str] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanSnapshot":
        return cls(
            scan_id=data.get("scan_id", ""),
            target=data.get("target", ""),
            timestamp=data.get("timestamp", ""),
            urls=data.get("urls", []),
            endpoints=data.get("endpoints", []),
            parameters=data.get("parameters", []),
            js_files=data.get("js_files", []),
            subdomains=data.get("subdomains", []),
            technologies=data.get("technologies", []),
            headers=data.get("headers", {}),
            metadata=data.get("metadata", {}),
        )


class DiffAnalyzer:
    """
    継続的差分スキャン分析クラス
    
    SharedWorkspaceと連携し、スキャン結果の履歴管理と差分検出を行う。
    """
    
    def __init__(self, storage_path: Optional[Path] = None):
        """
        Args:
            storage_path: スナップショット保存ディレクトリ
        """
        self.storage_path = storage_path or Path("./workspace/snapshots")
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.snapshots: Dict[str, ScanSnapshot] = {}

    def take_snapshot(self, target: str, data: Dict[str, Any], label: Optional[str] = None) -> tuple[ScanSnapshot, str]:
        """
        現在のスキャンデータからスナップショットを作成し保存する。
        
        Args:
            target: ターゲットドメイン
            data: スナップショットに含めるデータ (urls, endpoints, etc.)
            label: スナップショットのラベル (例: 'before_fuzzing')
            
        Returns:
            (ScanSnapshot, snapshot_id) 
        """
        import time
        timestamp = time.time()
        
        snapshot = ScanSnapshot.from_dict({
            "target": target,
            "timestamp": str(timestamp),
            "scan_id": f"scan_{int(timestamp)}",
            **data
        })
        
        snapshot_id = f"{label or 'snap'}_{int(timestamp)}"
        self.snapshots[snapshot_id] = snapshot
        
        # 保存 (永続化)
        self.save_snapshot(snapshot)
        
        return snapshot, snapshot_id

    def save_snapshot(self, snapshot: ScanSnapshot) -> str:
        """
        スナップショットを保存
        
        Args:
            snapshot: スキャン結果スナップショット
            
        Returns:
            保存されたファイルパス
        """
        # ターゲット別ディレクトリ
        target_dir = self.storage_path / self._sanitize_target(snapshot.target)
        target_dir.mkdir(parents=True, exist_ok=True)
        
        # タイムスタンプ付きファイル名
        filename = f"snapshot_{snapshot.scan_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = target_dir / filename
        
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(snapshot.to_dict(), f, ensure_ascii=False, indent=2)
        
        return str(filepath)
    
    def get_latest_snapshot(self, target: str) -> Optional[ScanSnapshot]:
        """
        指定ターゲットの最新スナップショットを取得
        """
        target_dir = self.storage_path / self._sanitize_target(target)
        if not target_dir.exists():
            return None
        
        snapshots = sorted(target_dir.glob("snapshot_*.json"), reverse=True)
        if not snapshots:
            return None
        
        try:
            with open(snapshots[0], "r", encoding="utf-8") as f:
                return ScanSnapshot.from_dict(json.load(f))
        except (IOError, json.JSONDecodeError, KeyError) as e:
            import logging
            logging.getLogger(__name__).debug("Failed to load latest snapshot: %s", e)
            return None
    
    def get_previous_snapshot(self, target: str, skip: int = 1) -> Optional[ScanSnapshot]:
        """
        指定ターゲットの過去スナップショットを取得
        
        Args:
            target: ターゲットドメイン
            skip: スキップするスナップショット数（1=1つ前）
        """
        target_dir = self.storage_path / self._sanitize_target(target)
        if not target_dir.exists():
            return None
        
        snapshots = sorted(target_dir.glob("snapshot_*.json"), reverse=True)
        if len(snapshots) <= skip:
            return None
        
        try:
            with open(snapshots[skip], "r", encoding="utf-8") as f:
                return ScanSnapshot.from_dict(json.load(f))
        except (IOError, json.JSONDecodeError, KeyError) as e:
            import logging
            logging.getLogger(__name__).debug("Failed to load previous snapshot (skip=%d): %s", skip, e)
            return None
    
    def list_snapshots(self, target: str, limit: int = 10) -> List[Dict[str, Any]]:
        """
        指定ターゲットのスナップショット一覧を取得
        """
        target_dir = self.storage_path / self._sanitize_target(target)
        if not target_dir.exists():
            return []
        
        snapshots = sorted(target_dir.glob("snapshot_*.json"), reverse=True)[:limit]
        
        result = []
        for snap_path in snapshots:
            try:
                with open(snap_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    result.append({
                        "path": str(snap_path),
                        "scan_id": data.get("scan_id"),
                        "timestamp": data.get("timestamp"),
                        "stats": {
                            "urls": len(data.get("urls", [])),
                            "endpoints": len(data.get("endpoints", [])),
                            "subdomains": len(data.get("subdomains", [])),
                        }
                    })
            except (IOError, json.JSONDecodeError) as e:
                import logging
                logging.getLogger(__name__).debug("Failed to list snapshot %s: %s", snap_path, e)
                continue
        
        return result
    
    def compare(
        self, 
        current: ScanSnapshot, 
        previous: Optional[ScanSnapshot] = None,
        target: Optional[str] = None
    ) -> Dict[str, DiffResult]:
        """
        スナップショット間の差分を計算
        
        Args:
            current: 現在のスナップショット
            previous: 比較対象（Noneの場合は保存済みの前回を使用）
            target: 前回取得用ターゲット（previousがNoneの場合に使用）
            
        Returns:
            カテゴリ別のDiffResult辞書
        """
        if previous is None:
            if target is None:
                target = current.target
            previous = self.get_previous_snapshot(target)
        
        if previous is None:
            # 比較対象なし = 全て新規
            return self._create_initial_diff(current)
        
        results: Dict[str, DiffResult] = {}
        
        # URLの差分
        results["urls"] = self._diff_lists(
            "urls", 
            previous.urls, 
            current.urls
        )
        
        # エンドポイントの差分
        results["endpoints"] = self._diff_lists(
            "endpoints",
            previous.endpoints,
            current.endpoints
        )
        
        # パラメータの差分
        results["parameters"] = self._diff_lists(
            "parameters",
            previous.parameters,
            current.parameters
        )
        
        # JSファイルの差分
        results["js_files"] = self._diff_lists(
            "js_files",
            previous.js_files,
            current.js_files
        )
        
        # サブドメインの差分
        results["subdomains"] = self._diff_lists(
            "subdomains",
            previous.subdomains,
            current.subdomains
        )
        
        # テクノロジーの差分
        results["technologies"] = self._diff_lists(
            "technologies",
            previous.technologies,
            current.technologies
        )
        
        # ヘッダーの差分（修正検出あり）
        results["headers"] = self._diff_dicts(
            "headers",
            previous.headers,
            current.headers
        )
        
        return results
    
    def _diff_lists(
        self, 
        category: str, 
        previous: List[str], 
        current: List[str]
    ) -> DiffResult:
        """リスト間の差分を計算"""
        prev_set = set(previous)
        curr_set = set(current)
        
        added = list(curr_set - prev_set)
        removed = list(prev_set - curr_set)
        
        return DiffResult(
            category=category,
            added=sorted(added),
            removed=sorted(removed),
        )
    
    def _diff_dicts(
        self, 
        category: str, 
        previous: Dict[str, str],
        current: Dict[str, str]
    ) -> DiffResult:
        """辞書間の差分を計算（キー追加・削除・値変更）"""
        prev_keys = set(previous.keys())
        curr_keys = set(current.keys())
        
        added = [k for k in (curr_keys - prev_keys)]
        removed = [k for k in (prev_keys - curr_keys)]
        
        # 値の変更を検出
        modified = []
        for key in prev_keys & curr_keys:
            if previous[key] != current[key]:
                modified.append({
                    "key": key,
                    "previous": previous[key],
                    "current": current[key],
                })
        
        return DiffResult(
            category=category,
            added=sorted(added),
            removed=sorted(removed),
            modified=modified,
        )
    
    def _create_initial_diff(self, current: ScanSnapshot) -> Dict[str, DiffResult]:
        """初回スキャン用（全て新規）"""
        return {
            "urls": DiffResult("urls", added=current.urls),
            "endpoints": DiffResult("endpoints", added=current.endpoints),
            "parameters": DiffResult("parameters", added=current.parameters),
            "js_files": DiffResult("js_files", added=current.js_files),
            "subdomains": DiffResult("subdomains", added=current.subdomains),
            "technologies": DiffResult("technologies", added=current.technologies),
            "headers": DiffResult("headers", added=list(current.headers.keys())),
        }
    
    def generate_report(
        self, 
        diff_results: Dict[str, DiffResult],
        target: str,
        report_format: str = "json"
    ) -> str:
        """
        差分レポートを生成
        
        Args:
            diff_results: compare()の結果
            target: ターゲット
            report_format: "json" or "markdown"
        """
        summary = {
            "target": target,
            "generated_at": datetime.now().isoformat(),
            "has_changes": any(r.has_changes for r in diff_results.values()),
            "summary": {},
            "details": {},
        }
        
        for category, result in diff_results.items():
            summary["summary"][category] = {
                "added": len(result.added),
                "removed": len(result.removed),
                "modified": len(result.modified),
            }
            summary["details"][category] = result.to_dict()
        
        if report_format == "json":
            return json.dumps(summary, indent=2, ensure_ascii=False)
        
        elif report_format == "markdown":
            return self._format_markdown(summary)
        
        return json.dumps(summary, indent=2, ensure_ascii=False)
    
    def _format_markdown(self, summary: Dict[str, Any]) -> str:
        """Markdownフォーマットでレポート生成"""
        lines = [
            f"# Diff Report: {summary['target']}",
            f"Generated: {summary['generated_at']}",
            "",
            "## Summary",
            "",
            "| Category | Added | Removed | Modified |",
            "|----------|-------|---------|----------|",
        ]
        
        for cat, stats in summary["summary"].items():
            lines.append(
                f"| {cat} | {stats['added']} | {stats['removed']} | {stats['modified']} |"
            )
        
        lines.extend(["", "## Details", ""])
        
        for cat, details in summary["details"].items():
            if details["added"] or details["removed"] or details["modified"]:
                lines.append(f"### {cat.title()}")
                lines.append("")
                
                if details["added"]:
                    lines.append("**Added:**")
                    for item in details["added"][:20]:  # 上限20
                        lines.append(f"- `{item}`")
                    if len(details["added"]) > 20:
                        lines.append(f"- ... and {len(details['added']) - 20} more")
                    lines.append("")
                
                if details["removed"]:
                    lines.append("**Removed:**")
                    for item in details["removed"][:20]:
                        lines.append(f"- `{item}`")
                    if len(details["removed"]) > 20:
                        lines.append(f"- ... and {len(details['removed']) - 20} more")
                    lines.append("")
                
                if details["modified"]:
                    lines.append("**Modified:**")
        return "\n".join(lines)

    def analyze_body_diff(self, original: str, test: str) -> Dict[str, Any]:
        """
        2つのレスポンスボディのセマンティックな差異を分析
        """
        result = {
            "is_significant": False,
            "reason": "identical",
            "diff_count": 0,
            "structural_change": False,
            "new_fields": []
        }
        
        if original == test:
            return result
            
        # JSONの場合の構造比較
        try:
            orig_json = json.loads(original)
            test_json = json.loads(test)
            
            if isinstance(orig_json, dict) and isinstance(test_json, dict):
                new_keys = set(test_json.keys()) - set(orig_json.keys())
                if new_keys:
                    result["is_significant"] = True
                    result["reason"] = f"new_fields_detected: {list(new_keys)}"
                    result["new_fields"] = list(new_keys)
                    result["structural_change"] = True
                    return result
            
            if orig_json != test_json:
                result["is_significant"] = True
                result["reason"] = "json_content_mismatch"
                return result
                
        except json.JSONDecodeError:
            # テキストベースの比較
            import difflib
            diff = list(difflib.unified_diff(original.splitlines(), test.splitlines(), lineterm=""))
            added = [l for l in diff if l.startswith("+") and not l.startswith("+++")]
            
            if len(added) > 5: # しきい値
                result["is_significant"] = True
                result["reason"] = f"significant_text_diff: {len(added)} lines"
                result["diff_count"] = len(added)
                
        return result

    def _sanitize_target(self, target: str) -> str:
        """ターゲット名をファイルシステム安全な形式に変換"""
        return (
            target
            .replace("https://", "")
            .replace("http://", "")
            .replace("/", "_")
            .replace(":", "_")
            .replace("*", "_")
            .replace("?", "_")
        )


# シングルトンインスタンス
_default_diff_analyzer: Optional[DiffAnalyzer] = None


def get_diff_analyzer() -> DiffAnalyzer:
    """デフォルトのDiffAnalyzerインスタンスを取得"""
    global _default_diff_analyzer
    if _default_diff_analyzer is None:
        _default_diff_analyzer = DiffAnalyzer()
    return _default_diff_analyzer
