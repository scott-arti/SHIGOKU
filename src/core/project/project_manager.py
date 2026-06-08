"""
ProjectManager: プロジェクト単位でのハンティング管理

プロジェクトごとにフォルダを作成し、スキャン結果、脆弱性発見、
スクリーンショット、レポート、ハンティングログを整理して保存する。
"""

import logging
import json
import yaml
import shutil
import asyncio
import aiofiles
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

from src.core.infra.async_writer import get_async_writer

logger = logging.getLogger(__name__)


@dataclass
class ProjectConfig:
    """プロジェクト設定"""
    project_name: str
    target_url: str
    program_name: str = ""
    description: str = ""
    created_at: str = ""
    last_scan_at: str = ""
    tags: List[str] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
    
    def to_dict(self) -> dict:
        """辞書形式に変換"""
        return asdict(self)


class ProjectManager:
    """
    プロジェクト管理マネージャー
    
    責務:
    1. プロジェクトフォルダ構造の作成・管理
    2. ツール出力のフィルター前/後を区別して保存
    3. 統一された命名規則の適用
    
    使用例:
        pm = ProjectManager("example.com")
        pm.init_project(target_url="https://example.com")
        pm.save_raw_scan("subfinder", "subdomains", data)
    """
    
    # フォルダ構造定義
    FOLDER_STRUCTURE = {
        "scans": {
            "raw": "フィルター前のスキャン結果",
            "filtered": "フィルター後のスキャン結果"
        },
        "findings": "発見した脆弱性",
        "screenshots": "スクリーンショット",
        "reports": "レポート",
        "hunting_log": "AIハンティング履歴"
    }
    
    def __init__(
        self,
        project_name: str,
        base_dir: str = "workspace/projects"
    ):
        # プロジェクト名の正規化 (URLスキーム削除)
        if project_name.startswith("http://"):
            project_name = project_name[7:]
        elif project_name.startswith("https://"):
            project_name = project_name[8:]
            
        # 末尾のスラッシュ削除
        project_name = project_name.rstrip("/")
        
        self.project_name = project_name
        
        self.base_dir = Path(base_dir)
        self.project_dir = self.base_dir / project_name
        
        # プロジェクト設定
        self.config: Optional[ProjectConfig] = None
        
        logger.info(f"ProjectManager initialized for: {project_name}")
    
    def init_project(
        self,
        target_url: str,
        program_name: str = "",
        description: str = "",
        tags: Optional[List[str]] = None
    ) -> Path:
        """
        プロジェクトを初期化
        
        Args:
            target_url: ターゲットURL
            program_name: プログラム名（HackerOne等）
            description: プロジェクト説明
            tags: タグリスト
        
        Returns:
            プロジェクトディレクトリのPath
        """
        # 設定作成
        self.config = ProjectConfig(
            project_name=self.project_name,
            target_url=target_url,
            program_name=program_name,
            description=description,
            tags=tags or []
        )
        
        # フォルダ構造作成
        self._create_folder_structure()
        
        # メタ情報保存
        self._save_meta()
        
        logger.info(f"Project initialized at: {self.project_dir}")
        return self.project_dir
    
    def _create_folder_structure(self) -> None:
        """フォルダ構造を作成"""
        self.project_dir.mkdir(parents=True, exist_ok=True)
        
        # Add 'sessions' to folder structure dynamically if not present
        if "sessions" not in self.FOLDER_STRUCTURE:
            self.FOLDER_STRUCTURE["sessions"] = "セッション履歴"
            
        for key, value in self.FOLDER_STRUCTURE.items():
            if isinstance(value, dict):
                # ネストされたフォルダ
                for sub_key in value.keys():
                    sub_dir = self.project_dir / key / sub_key
                    sub_dir.mkdir(parents=True, exist_ok=True)
            else:
                # シンプルなフォルダ
                folder = self.project_dir / key
                folder.mkdir(parents=True, exist_ok=True)

    async def save_session(self, session_data: dict, filename: str = None) -> Path:
        """セッション状態を非同期で保存（アトミックな書き込み）"""
        sessions_dir = self.project_dir / "sessions"
        sessions_dir.mkdir(parents=True, exist_ok=True)
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"session_{timestamp}.json"
            
        output_path = sessions_dir / filename
        
        try:
            # JSONシリアライズと書き込みをスレッドプールで実行 (アトミック)
            await asyncio.to_thread(self._write_json_sync, output_path, session_data)
        except Exception as e:
            logger.error(f"Failed to save session: {e}")
            raise

        # latest.json の更新 (アトミックに差し替え)
        latest_path = sessions_dir / "latest.json"
        try:
            # latest.json も一度 tmp に書いてからリネームするか、output_path からコピー
            # ここでもアトミック性を確保するため、copy2 ではなく _write_json_sync のロジックにならうが、
            # 既に output_path があるので、単にアトミックなコピー(一時ファイル+リネーム)を行う
            await asyncio.to_thread(self._atomic_copy, output_path, latest_path)
        except Exception as e:
            logger.warning(f"Failed to update latest.json: {e}")
            
        logger.info(f"Saved session to project: {output_path}")
        return output_path

    def _write_json_sync(self, path: Path, data: dict):
        """同期JSON書き込み（一時ファイルを経由してアトミックにリネーム）"""
        tmp_path = path.with_suffix(".tmp")
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False, default=lambda o: o.to_dict() if hasattr(o, "to_dict") else str(o))
                f.flush()
                import os
                os.fsync(f.fileno())  # 確実にディスクに書き込む
            
            # リネーム (同一ファイルシステム内であればアトミック)
            tmp_path.replace(path)
        except Exception as e:
            if tmp_path.exists():
                tmp_path.unlink()
            raise e

    def _atomic_copy(self, src: Path, dst: Path):
        """アトミックなファイルコピー"""
        tmp_dst = dst.with_suffix(".tmp_copy")
        shutil.copy2(src, tmp_dst)
        tmp_dst.replace(dst)

    def list_sessions(self) -> List[dict]:
        """
        保存されたセッションの一覧を取得
        
        Returns:
            セッション情報のリスト [{"file": "...", "timestamp": "...", "id": "..."}]
        """
        sessions_dir = self.project_dir / "sessions"
        if not sessions_dir.exists():
            return []
            
        sessions = []
        for p in sessions_dir.glob("session_*.json"):
            # ファイル名から日時を抽出 (session_YYYYMMDD_HHMMSS.json)
            try:
                name_parts = p.stem.split("_")
                if len(name_parts) >= 3:
                    ts_str = f"{name_parts[1]}_{name_parts[2]}"
                    dt = datetime.strptime(ts_str, "%Y%m%d_%H%M%S")
                    timestamp = dt.strftime("%Y-%m-%d %H:%M:%S")
                else:
                    timestamp = datetime.fromtimestamp(p.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")

                sessions.append({
                    "filename": p.name,
                    "path": str(p),
                    "timestamp": timestamp,
                    "mtime": p.stat().st_mtime
                })
            except Exception:
                continue
                
        # 新しい順にソート
        return sorted(sessions, key=lambda x: x["mtime"], reverse=True)

    def get_reports_dir(self) -> Path:
        """レポートディレクトリを取得"""
        return self.project_dir / "reports"


    def _save_meta(self) -> None:
        """メタ情報を同期で保存"""
        if not self.config:
            return
        
        meta_path = self.project_dir / "meta.yaml"
        try:
            content = yaml.dump(self.config.to_dict(), allow_unicode=True, sort_keys=False)
            with open(meta_path, "w", encoding="utf-8") as f:
                f.write(content)
        except Exception as e:
            logger.error(f"Failed to save project meta: {e}")
    
    def load_meta(self) -> Optional[ProjectConfig]:
        """メタ情報を読み込み"""
        meta_path = self.project_dir / "meta.yaml"
        if not meta_path.exists():
            return None
        
        with open(meta_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        
        self.config = ProjectConfig(**data)
        return self.config
    
    def _generate_filename(
        self,
        tool_or_module: str,
        purpose: str,
        extension: str = "txt"
    ) -> str:
        """
        統一されたファイル名を生成
        
        命名規則: {YYYY-MM-DD}_{tool_or_module}_{purpose}_{project}.{ext}
        
        Args:
            tool_or_module: ツール名またはモジュール名 (例: "subfinder", "cartographer")
            purpose: 目的 (例: "subdomains", "sitemap")
            extension: 拡張子
        
        Returns:
            ファイル名
        """
        date_str = datetime.now().strftime("%Y-%m-%d")
        safe_project = self.project_name.replace(".", "_").replace("/", "_")
        
        return f"{date_str}_{tool_or_module}_{purpose}_{safe_project}.{extension}"
    
    async def save_raw_scan(
        self,
        tool_or_module: str,
        purpose: str,
        data: str,
        extension: str = "txt"
    ) -> Path:
        """スキャン結果を非同期で保存"""
        filename = self._generate_filename(tool_or_module, purpose, extension)
        output_path = self.project_dir / "scans" / "raw" / filename
        
        try:
            async with aiofiles.open(output_path, "w", encoding="utf-8") as f:
                await f.write(data)
            return output_path
        except Exception as e:
            logger.error(f"Failed to save raw scan: {e}")
            return output_path
    
    async def save_filtered_scan(
        self,
        tool_or_module: str,
        purpose: str,
        data: str,
        extension: str = "txt"
    ) -> Path:
        """フィルター後のスキャン結果を非同期で保存"""
        filename = self._generate_filename(tool_or_module, purpose, extension)
        output_path = self.project_dir / "scans" / "filtered" / filename
        
        try:
            async with aiofiles.open(output_path, "w", encoding="utf-8") as f:
                await f.write(data)
            return output_path
        except Exception as e:
            logger.error(f"Failed to save filtered scan: {e}")
            return output_path
    
    async def save_screenshot(
        self,
        url: str,
        screenshot_path: str
    ) -> Path:
        """スクリーンショットを非同期で保存"""
        import shutil
        source = Path(screenshot_path)
        if not source.exists():
             return Path(screenshot_path) # Fallback
        
        safe_url = url.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{timestamp}_{safe_url}{source.suffix}"
        dest = self.project_dir / "screenshots" / filename
        
        try:
            # SHIGOKU特有の要件: 大きな画像ファイルを非同期で読み書き
            async with aiofiles.open(source, mode='rb') as f_src:
                content = await f_src.read()
                async with aiofiles.open(dest, mode='wb') as f_dst:
                    await f_dst.write(content)
            return dest
        except Exception as e:
            logger.error(f"Failed to save screenshot: {e}")
            # Fallback to synchronous copy if async fails
            try:
                shutil.copy2(source, dest)
                return dest
            except:
                return source
    
    def get_scan_files(self, filter_type: str = "all") -> List[Path]:
        """
        スキャンファイルのリストを取得
        
        Args:
            filter_type: "raw", "filtered", or "all"
        
        Returns:
            ファイルパスのリスト
        """
        files = []
        
        if filter_type in ("raw", "all"):
            raw_dir = self.project_dir / "scans" / "raw"
            if raw_dir.exists():
                files.extend(raw_dir.glob("*"))
        
        if filter_type in ("filtered", "all"):
            filtered_dir = self.project_dir / "scans" / "filtered"
            if filtered_dir.exists():
                files.extend(filtered_dir.glob("*"))
        
        return sorted(files, key=lambda p: p.stat().st_mtime, reverse=True)
    
    async def save_finding(self, finding) -> Path:
        """
        発見した脆弱性を非同期で保存（DB + ファイル）
        """
        # Finding の ID を使用してファイル名を生成
        finding_id = getattr(finding, 'id', None) or datetime.now().strftime("%Y%m%d_%H%M%S")
        vuln_type = getattr(finding, 'vuln_type', None)
        vuln_type_str = vuln_type.value if hasattr(vuln_type, 'value') else str(vuln_type) if vuln_type else "unknown"
        
        filename = f"{finding_id}_{vuln_type_str}.json"
        output_path = self.project_dir / "findings" / filename
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # 辞書形式に変換
        if hasattr(finding, 'to_dict'):
            data = finding.to_dict()
        else:
            data = {"finding": str(finding)}
        
        data["saved_at"] = datetime.now().isoformat()
        
        # 1. DB (AsyncWriter) 経由で保存
        writer = get_async_writer()
        if writer:
            if hasattr(finding, 'to_dict') and not isinstance(finding, dict):
                await writer.enqueue_finding(finding)
            else:
                await writer.enqueue_jsonl(output_path, data)
        
        # 2. ファイルへの非同期出力
        try:
            content = json.dumps(data, indent=2, ensure_ascii=False, default=str)
            async with aiofiles.open(output_path, "w", encoding="utf-8") as f:
                await f.write(content)
        except Exception as e:
            logger.error(f"Failed to save finding file: {e}")
            
        logger.info(f"Saved finding: {output_path}")
        return output_path
    
    def get_findings(self) -> List[Path]:
        """
        保存された全Findingsを取得
        
        Returns:
            FindingファイルパスのList
        """
        findings_dir = self.project_dir / "findings"
        if not findings_dir.exists():
            return []
        return sorted(findings_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)

    @classmethod
    def list_projects(cls, base_dir: str = "workspace/projects") -> List[dict]:
        """
        全プロジェクトの一覧を取得

        Args:
            base_dir: プロジェクトのベースディレクトリ

        Returns:
            プロジェクト情報のリスト (辞書形式)
        """
        projects_node = Path(base_dir)
        if not projects_node.exists() or not projects_node.is_dir():
            return []

        project_list = []
        for project_dir in projects_node.iterdir():
            if project_dir.is_dir():
                # メタ情報を読み込んでみる
                meta_path = project_dir / "meta.yaml"
                if meta_path.exists():
                    try:
                        with open(meta_path, "r", encoding="utf-8") as f:
                            data = yaml.safe_load(f)
                            project_list.append(data)
                    except Exception as e:
                        logger.warning(f"Failed to load meta for {project_dir.name}: {e}")
                else:
                    # メタ情報がない場合でもディレクトリ名を表示するために追加
                    project_list.append({
                        "project_name": project_dir.name,
                        "target_url": "N/A",
                        "created_at": "N/A",
                        "last_scan_at": "N/A"
                    })
        
        # 最終スキャン日時順などでソートするのが望ましいが、とりあえず名前順
        project_list.sort(key=lambda x: x.get("project_name", ""))
        return project_list


    def ingest_file(self, tool_name: str, file_path: Path) -> bool:
        """
        ツール出力をKnowledge Graphに取り込む
        
        Args:
            tool_name: ツール名 ("katana", "nuclei")
            file_path: 取り込むファイルのパス
            
        Returns:
            bool: 成功したかどうか
        """
        try:
            from src.core.knowledge.ingestors.katana import KatanaIngestor
            from src.core.knowledge.ingestors.nuclei import NucleiIngestor
            
            logger.info(f"Ingesting {tool_name} output from {file_path} into Knowledge Graph...")
            
            ingestor = None
            if tool_name == "katana":
                ingestor = KatanaIngestor()
            elif tool_name == "nuclei":
                ingestor = NucleiIngestor()
            
            if ingestor:
                ingestor.ingest(Path(file_path), self.project_name)
                logger.info(f"Successfully ingested {file_path}")
                return True
            else:
                logger.warning(f"No ingestor found for tool: {tool_name}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to ingest file: {e}")
            return False

# グローバルインスタンス管理
_project_managers: Dict[str, ProjectManager] = {}


def get_project_manager(project_name: str) -> ProjectManager:
    """
    プロジェクト名に対応するProjectManagerを取得（シングルトン）
    
    Args:
        project_name: プロジェクト名
    
    Returns:
        ProjectManager インスタンス
    """
    if project_name not in _project_managers:
        _project_managers[project_name] = ProjectManager(project_name)
    
    return _project_managers[project_name]
