"""
Session Manager

ハンティングセッションの保存・再開機能
"""

import json
import pickle
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime
from dataclasses import dataclass, field, asdict
import logging

from src.core.models.finding import Finding

logger = logging.getLogger(__name__)


@dataclass
class Session:
    """ハンティングセッション"""
    session_id: str
    project_name: str
    mode: str
    target_url: str
    created_at: datetime
    last_updated: datetime
    
    # 進捗状態
    scan_progress: Dict[str, Any] = field(default_factory=dict)
    completed_targets: List[str] = field(default_factory=list)
    pending_targets: List[str] = field(default_factory=list)
    
    # 部分的な結果
    partial_findings: List[Dict] = field(default_factory=list)
    
    # メタデータ
    metadata: Dict[str, Any] = field(default_factory=dict)


class SessionManager:
    """
    セッション管理クラス
    
    長時間のハンティングを中断・再開可能にする
    """
    
    def __init__(self, project_dir: Path):
        self.project_dir = project_dir
        self.session_dir = project_dir / ".sessions"
        self.session_dir.mkdir(parents=True, exist_ok=True)
    
    def create_session(
        self,
        project_name: str,
        mode: str,
        target_url: str,
        metadata: Optional[Dict] = None
    ) -> Session:
        """
        新規セッション作成
        
        Args:
            project_name: プロジェクト名
            mode: ハンティングモード
            target_url: ターゲットURL
            metadata: 追加メタデータ
        
        Returns:
            作成されたセッション
        """
        # ターゲットから安全な短縮名を生成してセッションIDに含める
        safe_name = self._sanitize_target_name(target_url)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        session_id = f"{safe_name}_{timestamp}"
        
        session = Session(
            session_id=session_id,
            project_name=project_name,
            mode=mode,
            target_url=target_url,
            created_at=datetime.now(),
            last_updated=datetime.now(),
            metadata=metadata or {}
        )
        
        self.save_session(session)
        logger.info(f"Session created: {session_id}")
        return session
    
    def _sanitize_target_name(self, target_url: str) -> str:
        """
        ターゲットURLから安全なファイル名用の短縮名を生成
        
        Args:
            target_url: ターゲットURL
            
        Returns:
            ファイル名に使用可能な短縮名（最大20文字）
        """
        import re
        # プロトコルを除去
        name = target_url.replace("https://", "").replace("http://", "")
        # パスを除去（ドメインのみ）
        name = name.split("/")[0]
        # ポート番号を除去
        name = name.split(":")[0]
        # 安全でない文字を置換
        name = re.sub(r'[^a-zA-Z0-9\-_.]', '_', name)
        # 最大20文字に制限
        return name[:20]
    
    def save_session(self, session: Session) -> Path:
        """
        セッションを保存
        
        Args:
            session: セッション
        
        Returns:
            保存先パス
        """
        session.last_updated = datetime.now()
        
        # JSON形式で保存（可読性）
        session_file = self.session_dir / f"{session.session_id}.json"
        
        # datatimeをISO形式に変換
        session_dict = asdict(session)
        session_dict['created_at'] = session.created_at.isoformat()
        session_dict['last_updated'] = session.last_updated.isoformat()
        
        with open(session_file, 'w', encoding='utf-8') as f:
            json.dump(session_dict, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Session saved: {session.session_id}")
        return session_file
    
    def load_session(self, session_id: str) -> Optional[Session]:
        """
        セッションを読み込み
        
        Args:
            session_id: セッションID
        
        Returns:
            読み込まれたセッション（存在しない場合はNone）
        """
        session_file = self.session_dir / f"{session_id}.json"
        
        if not session_file.exists():
            logger.warning(f"Session not found: {session_id}")
            return None
        
        try:
            with open(session_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # datetimeを復元
            data['created_at'] = datetime.fromisoformat(data['created_at'])
            data['last_updated'] = datetime.fromisoformat(data['last_updated'])
            
            session = Session(**data)
            logger.info(f"Session loaded: {session_id}")
            return session
            
        except Exception as e:
            logger.error(f"Failed to load session {session_id}: {e}")
            return None
    
    def list_sessions(self) -> List[Session]:
        """
        すべてのセッションを一覧表示
        
        古いセッション（30日以上）は自動クリーンアップされる
        
        Returns:
            セッションのリスト
        """
        # 古いセッションを自動クリーンアップ
        self.cleanup_old_sessions()
        
        sessions = []
        
        for session_file in self.session_dir.glob("*.json"):
            session_id = session_file.stem
            session = self.load_session(session_id)
            if session:
                sessions.append(session)
        
        # 最終更新日時でソート
        sessions.sort(key=lambda s: s.last_updated, reverse=True)
        return sessions
    
    def cleanup_old_sessions(self, max_age_days: int = 30) -> int:
        """
        古いセッションを自動削除
        
        Args:
            max_age_days: この日数より古いセッションを削除（デフォルト30日）
        
        Returns:
            削除されたセッション数
        """
        from datetime import timedelta
        
        cutoff_date = datetime.now() - timedelta(days=max_age_days)
        deleted_count = 0
        
        for session_file in self.session_dir.glob("*.json"):
            try:
                with open(session_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                last_updated = datetime.fromisoformat(data.get('last_updated', ''))
                
                if last_updated < cutoff_date:
                    session_file.unlink()
                    deleted_count += 1
                    logger.info(f"Auto-deleted old session: {session_file.stem}")
                    
            except (json.JSONDecodeError, KeyError, ValueError):
                # 壊れたセッションファイルは無視
                continue
        
        if deleted_count > 0:
            logger.info(f"Cleaned up {deleted_count} old sessions (>{max_age_days} days)")
        
        return deleted_count
    
    def delete_session(self, session_id: str) -> bool:
        """
        セッションを削除
        
        Args:
            session_id: セッションID
        
        Returns:
            成功: True
        """
        session_file = self.session_dir / f"{session_id}.json"
        
        if session_file.exists():
            session_file.unlink()
            logger.info(f"Session deleted: {session_id}")
            return True
        
        logger.warning(f"Session not found: {session_id}")
        return False
    
    def update_progress(
        self,
        session: Session,
        completed: Optional[List[str]] = None,
        pending: Optional[List[str]] = None,
        findings: Optional[List[Finding]] = None
    ) -> None:
        """
        セッションの進捗を更新
        
        Args:
            session: セッション
            completed: 完了したターゲット
            pending: 未完了のターゲット
            findings: 部分的なFinding
        """
        if completed:
            session.completed_targets.extend(completed)
        
        if pending:
            session.pending_targets = pending
        
        if findings:
            # Findingを辞書形式で保存
            session.partial_findings.extend([f.to_dict() for f in findings])
        
        # 進捗率計算
        total = len(session.completed_targets) + len(session.pending_targets)
        if total > 0:
            progress = len(session.completed_targets) / total * 100
            session.scan_progress['progress_percent'] = progress
            session.scan_progress['completed_count'] = len(session.completed_targets)
            session.scan_progress['pending_count'] = len(session.pending_targets)
        
        self.save_session(session)
    
    def resume_session(self, session_id: str) -> Optional[Session]:
        """
        セッションを再開
        
        Args:
            session_id: セッションID
        
        Returns:
            再開されたセッション
        """
        session = self.load_session(session_id)
        
        if session:
            logger.info(
                f"Resuming session {session_id}: "
                f"{len(session.completed_targets)} completed, "
                f"{len(session.pending_targets)} pending"
            )
        
        return session


# ヘルパー関数
def get_session_manager(project_dir: Path) -> SessionManager:
    """SessionManagerインスタンスを取得"""
    return SessionManager(project_dir)
