"""
RAG ON/OFF switch and singleton management.

Split from rag.py (SGK-2026-0302).
"""

import re
from typing import Optional

from src.core.rag_module.rag_types import RAGResult
from src.core.rag_module.rag_ingester import KnowledgeIngester


class RAGSwitch:
    """
    RAG利用のON/OFF切り替えコントローラー

    エージェントがRAGを使うかどうかを選択可能にする。
    OFFの場合でもフォールバックロジックで動作する。
    """

    def __init__(self, default_enabled: bool = True):
        self._enabled = default_enabled
        self._ingester: Optional[KnowledgeIngester] = None

    @property
    def enabled(self) -> bool:
        return self._enabled

    def toggle(self, state: bool) -> None:
        """RAGのON/OFFを切り替え"""
        self._enabled = state

    def enable(self) -> None:
        """RAGを有効化"""
        self._enabled = True

    def disable(self) -> None:
        """RAGを無効化"""
        self._enabled = False

    def set_ingester(self, ingester: KnowledgeIngester) -> None:
        """KnowledgeIngesterを設定"""
        self._ingester = ingester

    def retrieve(
        self,
        query: str,
        n_results: int = 5,
    ) -> list[RAGResult]:
        """
        RAG からドキュメントを取得（query のシノニム）

        agentic_rag.py / dispatch_service との API 契約を一本化するためのメソッド。
        実体は query() に委譲する。

        Args:
            query: 検索クエリ
            n_results: 返す結果数

        Returns:
            検索結果のリスト
        """
        return self.query(query, n_results=n_results)

    def query(
        self,
        question: str,
        n_results: int = 5,
        filter_tags: Optional[list[str]] = None,
        context: Optional[dict] = None,
        compress: bool = False,
    ) -> list[RAGResult]:
        """RAG検索を実行（有効な場合のみ）"""
        return self.query_if_enabled(question, n_results, filter_tags, context, compress) or []

    def query_if_enabled(
        self,
        question: str,
        n_results: int = 5,
        filter_tags: Optional[list[str]] = None,
        context: Optional[dict] = None,
        compress: bool = False,
    ) -> Optional[list[RAGResult]]:
        """
        RAGが有効な場合のみクエリを実行

        Returns:
            RAGが有効: 検索結果のリスト
            RAGが無効またはIngester未設定: None
        """
        if not self._enabled:
            return None

        if not self._ingester:
            return None

        return self._ingester.query(question, n_results, filter_tags, context, compress)

    def get_bypass_techniques(
        self,
        attack_type: str,
        context: Optional[dict] = None,
    ) -> list[dict]:
        """
        攻撃タイプに対するバイパス手法をRAGから取得

        Args:
            attack_type: 攻撃タイプ（例: "jwt_alg_none", "oauth_redirect"）
            context: 追加コンテキスト

        Returns:
            バイパス手法のリスト [{"technique": str, "payload": str, "source": str}, ...]
        """
        if not self._enabled or not self._ingester:
            return []

        # 攻撃タイプに特化したクエリを構築
        queries = {
            "jwt_alg_none": "JWT alg none signature bypass attack payload",
            "jwt_rs256_hs256": "JWT RS256 to HS256 algorithm confusion attack",
            "jwt_kid_injection": "JWT kid header injection attack",
            "oauth_redirect": "OAuth redirect_uri bypass open redirect",
            "oauth_pkce": "OAuth PKCE code_verifier bypass",
            "mfa_bypass": "MFA two-factor authentication bypass techniques",
        }

        query = queries.get(attack_type, f"{attack_type} bypass technique payload")

        results = self._ingester.query(query, n_results=3, filter_tags=None)

        techniques = []
        for result in results:
            # コンテンツからペイロードを抽出
            payloads = self._extract_payloads(result.content)
            for payload in payloads:
                techniques.append({
                    "technique": attack_type,
                    "payload": payload,
                    "source": result.source,
                    "score": result.score,
                })

        return techniques

    def _extract_payloads(self, content: str) -> list[str]:
        """コンテンツからコードブロックやペイロードを抽出"""
        payloads = []

        # Markdownコードブロックを抽出
        code_blocks = re.findall(r'```[\w]*\n(.*?)\n```', content, re.DOTALL)
        payloads.extend(code_blocks)

        # インラインコードを抽出
        inline_codes = re.findall(r'`([^`]+)`', content)
        payloads.extend([c for c in inline_codes if len(c) > 10])

        # JWTトークンパターンを抽出
        jwt_patterns = re.findall(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*', content)
        payloads.extend(jwt_patterns)

        return payloads

    def switch_mode(self, mode: str) -> None:
        """
        モードに応じたRAG設定を切り替え

        Args:
            mode: モード名 ("bugbounty", "vulntest", "ctf")
        """
        # モード別のRAGコレクション設定
        mode_collections = {
            "bugbounty": "obsidian_notes",  # デフォルト
            "vulntest": "obsidian_notes",
            "ctf": "obsidian_notes",
        }

        # モードに応じたコレクション切り替え（将来の拡張用）
        collection_name = mode_collections.get(mode, "obsidian_notes")

        if self._ingester:
            # コレクション名を更新（再初期化が必要な場合）
            if self._ingester.collection_name != collection_name:
                self._ingester.collection_name = collection_name
                self._ingester._initialized = False  # 再初期化を促す


# ===== グローバルインスタンス =====

_rag_switch: Optional[RAGSwitch] = None


def get_rag_switch() -> RAGSwitch:
    """RAGSwitchのシングルトンインスタンスを取得"""
    global _rag_switch
    if _rag_switch is None:
        _rag_switch = RAGSwitch()
    return _rag_switch


def init_rag(
    vault_path: str,
    chroma_host: str = "localhost",
    chroma_port: int = 8003,
    enabled: bool = True,
    reset_db: bool = False,
    exclude_patterns: Optional[list[str]] = None,
) -> bool:
    """
    RAGシステムを初期化

    Args:
        vault_path: Obsidian Vaultのパス
        chroma_host: ChromaDBホスト
        chroma_port: ChromaDBポート
        enabled: RAGを有効にするか
        reset_db: DBをリセット・再構築するか
        exclude_patterns: 除外パターン

    Returns:
        初期化成功: True
    """
    switch = get_rag_switch()
    switch.toggle(enabled)

    if not enabled:
        return True

    ingester = KnowledgeIngester(
        vault_path=vault_path,
        chroma_host=chroma_host,
        chroma_port=chroma_port,
    )

    if ingester.initialize():
        switch.set_ingester(ingester)
        # Vaultを取り込み
        count = ingester.ingest_vault(
            reset_db=reset_db,
            exclude_patterns=exclude_patterns
        )
        print(f"RAG initialized: {count} documents ingested")
        return True

    return False
