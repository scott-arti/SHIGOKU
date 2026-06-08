"""
MultiSessionManager: 複数ロールのセッション（認証情報）を管理するマネージャ
"""

import logging
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)

class MultiSessionManager:
    """
    同一ターゲットに対する複数の認証プロファイル（ロール）を管理します。
    IDOR/BOLA の Cross-Session Matrix Testing で使用されます。
    """
    
    def __init__(self):
        # ロール名をキー、そのロールの標準的なヘッダー群を値とする
        self._sessions: Dict[str, Dict[str, str]] = {}
        # 各セッションのメタデータ（ユーザーID、説明など）
        self._metadata: Dict[str, Dict[str, Any]] = {}

    def add_session(self, role: str, headers: Dict[str, str], metadata: Optional[Dict[str, Any]] = None) -> None:
        """
        セッション（認証ヘッダー）を登録します。
        
        Args:
            role: ロール名 (e.g. 'admin', 'user_a', 'user_b', 'attacker')
            headers: 認証情報を含むHTTPヘッダー
            metadata: 任意。そのセッションに紐づく追加情報 (e.g. user_id: 123)
        """
        # ヘッダーを小文字化して正規化（Authorization 等の揺れを吸収）
        normalized_headers = {k.lower(): v for k, v in headers.items()}
        self._sessions[role] = normalized_headers
        self._metadata[role] = metadata or {}
        logger.info(f"[MultiSessionManager] Added session for role: {role}")

    def get_session(self, role: str) -> Optional[Dict[str, str]]:
        """
        指定したロールのセッション情報を取得します。
        """
        return self._sessions.get(role)

    def get_metadata(self, role: str) -> Optional[Dict[str, Any]]:
        """
        指定したロールのメタデータを取得します。
        """
        return self._metadata.get(role)

    def list_roles(self) -> List[str]:
        """
        登録されているロールの一覧を取得します。
        """
        return list(self._sessions.keys())

    def get_all_alternative_sessions(self, exclude_role: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
        """
        指定したロール以外の全セッションを取得します（検証マトリクス用）。
        
        Args:
            exclude_role: 除外するロール名（現在の実行ユーザーなど）。
            
        Returns:
            { role: { "headers": headers, "metadata": metadata }, ... }
        """
        result = {}
        for role in self._sessions:
            if exclude_role and role == exclude_role:
                continue
            result[role] = {
                "headers": self._sessions[role],
                "metadata": self._metadata[role]
            }
        return result

    def clear(self) -> None:
        """全セッションをクリアします。"""
        self._sessions.clear()
        self._metadata.clear()
        logger.debug("[MultiSessionManager] All sessions cleared.")

# シングルトン的なアクセスのためのインスタンス（任意）
_global_multi_session_manager: Optional[MultiSessionManager] = None

def get_multi_session_manager() -> MultiSessionManager:
    """共有の MultiSessionManager インスタンスを取得します。"""
    global _global_multi_session_manager
    if _global_multi_session_manager is None:
        _global_multi_session_manager = MultiSessionManager()
    return _global_multi_session_manager
