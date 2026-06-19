"""
Obsidian Vault → ChromaDB: Knowledge Ingester.

Split from rag.py (SGK-2026-0302).
"""

import os
import logging
import math
import re
import hashlib
from pathlib import Path
from typing import Optional

from src.core.rag_module.rag_types import RAGDocument, RAGResult
from src.core.rag_module.rag_pdf_ingester import PDFIngester

logger = logging.getLogger(__name__)


class KnowledgeIngester:
    """
    Obsidianノート → ChromaDB 格納

    Obsidian Vault内のMarkdownファイルをパースし、
    ベクトルDBに格納してセマンティック検索を可能にする。
    """

    def __init__(
        self,
        vault_path: Optional[str] = None,
        chroma_host: str = "localhost",
        chroma_port: int = 8003,
        collection_name: str = "obsidian_notes",
    ):
        self.vault_path = Path(vault_path) if vault_path else None
        self.chroma_host = chroma_host
        self.chroma_port = chroma_port
        self.collection_name = collection_name

        self._client = None
        self._collection = None
        self._initialized = False

    def initialize(self) -> bool:
        """ChromaDBに接続してコレクションを初期化"""
        try:
            import chromadb
            from chromadb.utils import embedding_functions

            # 日本語対応埋め込みモデル (環境変数で設定可能)
            model_name = os.environ.get("RAG_EMBEDDING_MODEL", "cl-nagoya/ruri-v3-310m")

            # --- Vector Cache Integration ---
            from src.core.rag_module.vector_cache import get_vector_cache
            self.vector_cache = get_vector_cache()

            # Custom Embedding Function Wrapper for Caching
            class CachedEmbeddingFunction(embedding_functions.EmbeddingFunction):
                def __init__(self, base_ef, cache, model_name):
                    self.base_ef = base_ef
                    self.cache = cache
                    self.model_name = model_name

                def __call__(self, input: object) -> object:
                    # input is usually list of strings
                    if isinstance(input, str):
                        input = [input]

                    vectors = []
                    texts_to_embed = []
                    indices_to_embed = []

                    # 1. Check Cache
                    for i, text in enumerate(input):
                        cached_vec = self.cache.get(text, self.model_name)
                        if cached_vec:
                            vectors.append(cached_vec)
                        else:
                            vectors.append(None)  # Placeholder
                            texts_to_embed.append(text)
                            indices_to_embed.append(i)

                    # 2. Call API for misses
                    if texts_to_embed:
                        try:
                            new_vectors = self.base_ef(texts_to_embed)
                            # 3. Update Cache & Merge
                            for j, vec in enumerate(new_vectors):
                                orig_idx = indices_to_embed[j]
                                text = texts_to_embed[j]
                                vectors[orig_idx] = vec
                                self.cache.set(text, self.model_name, vec)
                        except Exception as e:
                            print(f"Embedding generation failed: {e}")
                            raise

                    return vectors

            base_emb_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
                model_name=model_name
            )
            emb_fn = CachedEmbeddingFunction(base_emb_fn, self.vector_cache, model_name)
            # --------------------------------

            self._client = chromadb.HttpClient(
                host=self.chroma_host,
                port=self.chroma_port
            )
            self._collection = self._client.get_or_create_collection(
                name=self.collection_name,
                embedding_function=emb_fn,
                metadata={
                    "description": "Obsidian notes for bug bounty knowledge",
                    "hnsw:space": "cosine",
                }
            )
            self._initialized = True
            print(f"RAG initialized with embedding model: {model_name} (Cached)")
            return True
        except Exception as e:
            print(f"ChromaDB initialization failed: {e}")
            return False

    def ingest_vault(
        self,
        vault_path: Optional[str] = None,
        reset_db: bool = False,
        exclude_patterns: Optional[list[str]] = None,
    ) -> int:
        """
        Obsidian Vaultを読み込んでChromaDBに格納

        Args:
            vault_path: Vaultのパス
            reset_db: 既存データを削除して再構築するか
            exclude_patterns: 除外するパスのパターン（glob形式）

        Returns:
            取り込んだドキュメント数
        """
        if vault_path:
            self.vault_path = Path(vault_path)

        if not self.vault_path or not self.vault_path.exists():
            print(f"Vault path not found: {self.vault_path}")
            return 0

        if not self._initialized:
            if not self.initialize():
                return 0

        # コレクションのリセット
        if reset_db:
            try:
                print("Resetting collection...")
                self._client.delete_collection(self.collection_name)
                self._collection = self._client.get_or_create_collection(
                    name=self.collection_name,
                    metadata={"description": "Obsidian notes for bug bounty knowledge"}
                )
            except Exception as e:
                print(f"Failed to reset collection: {e}")

        documents = []
        default_excludes = {".git", ".obsidian", ".trash", ".stversions", ".idea", ".vscode"}
        exclude_list = exclude_patterns or []

        # Markdownファイルを再帰的に検索
        for md_file in self.vault_path.rglob("*.md"):
            # 除外チェック
            rel_path = str(md_file.relative_to(self.vault_path))

            # 隠しディレクトリなどのチェック
            parts = set(md_file.relative_to(self.vault_path).parts)
            if not parts.isdisjoint(default_excludes):
                continue

            # パターンマッチングによる除外
            if any(p in rel_path for p in exclude_list):
                continue

            try:
                docs = self._parse_markdown(md_file)
                if docs:
                    documents.extend(docs)
            except Exception as e:
                print(f"Failed to parse {md_file}: {e}")

        if not documents:
            return 0

        # ChromaDBに格納（バッチ処理推奨だが今回は一括）
        # 大きすぎる場合は分割が必要
        batch_size = 100
        total_docs = len(documents)

        batches = math.ceil(total_docs / batch_size)

        print(f"Ingesting {total_docs} documents in {batches} batches...")

        for i in range(batches):
            start = i * batch_size
            end = min((i + 1) * batch_size, total_docs)
            batch = documents[start:end]

            ids = [doc.id for doc in batch]
            contents = [doc.content for doc in batch]
            metadatas = [doc.metadata for doc in batch]

            try:
                self._collection.upsert(
                    ids=ids,
                    documents=contents,
                    metadatas=metadatas
                )
            except Exception as e:
                print(f"Failed to upsert batch {i+1}: {e}")

        return total_docs

    def ingest_vault_differential(
        self,
        vault_path: Optional[str] = None,
        exclude_patterns: Optional[list[str]] = None,
    ) -> dict:
        """
        差分更新: 変更されたファイルのみを同期

        Args:
            vault_path: Vaultのパス
            exclude_patterns: 除外するパスのパターン

        Returns:
            {"added": int, "updated": int, "deleted": int, "unchanged": int}
        """
        if vault_path:
            self.vault_path = Path(vault_path)

        if not self.vault_path or not self.vault_path.exists():
            print(f"Vault path not found: {self.vault_path}")
            return {"added": 0, "updated": 0, "deleted": 0, "unchanged": 0}

        if not self._initialized:
            if not self.initialize():
                return {"added": 0, "updated": 0, "deleted": 0, "unchanged": 0}

        default_excludes = {".git", ".obsidian", ".trash", ".stversions", ".idea", ".vscode"}
        exclude_list = exclude_patterns or []

        # 1. 現在のVault内のファイルを収集
        current_files: dict[str, float] = {}  # doc_id -> mtime
        file_paths: dict[str, Path] = {}  # doc_id -> file_path

        for md_file in self.vault_path.rglob("*.md"):
            rel_path = str(md_file.relative_to(self.vault_path))
            parts = set(md_file.relative_to(self.vault_path).parts)

            if not parts.isdisjoint(default_excludes):
                continue
            if any(p in rel_path for p in exclude_list):
                continue

            doc_id = hashlib.md5(rel_path.encode()).hexdigest()
            current_files[doc_id] = md_file.stat().st_mtime
            file_paths[doc_id] = md_file

        # 2. ChromaDB内の既存ドキュメントを取得
        # チャンクIDは "{base_doc_id}_chunk_{N}" 形式なのでベースIDを抽出
        existing_base_ids: dict[str, float] = {}  # base_id -> max_mtime
        existing_chunk_ids: dict[str, list[str]] = {}  # base_id -> [chunk_ids]
        try:
            all_data = self._collection.get()
            for chunk_id, meta in zip(all_data["ids"], all_data["metadatas"]):
                mtime = float(meta.get("mtime", 0)) if meta else 0.0

                # チャンクIDからベースIDを抽出
                if "_chunk_" in chunk_id:
                    base_id = chunk_id.rsplit("_chunk_", 1)[0]
                else:
                    base_id = chunk_id  # 古い形式のID（非チャンク）

                # ベースIDごとに最大mtimeを記録
                if base_id not in existing_base_ids:
                    existing_base_ids[base_id] = mtime
                    existing_chunk_ids[base_id] = []
                else:
                    existing_base_ids[base_id] = max(existing_base_ids[base_id], mtime)

                existing_chunk_ids[base_id].append(chunk_id)
        except Exception as e:
            print(f"Failed to get existing docs: {e}")
            existing_base_ids = {}
            existing_chunk_ids = {}

        # 3. 差分を計算 (ファイル単位で比較)
        current_ids = set(current_files.keys())
        existing_ids = set(existing_base_ids.keys())

        added_ids = current_ids - existing_ids
        deleted_ids = existing_ids - current_ids
        common_ids = current_ids & existing_ids

        # 更新が必要なファイル (mtimeが変わっている)
        updated_ids = {
            doc_id for doc_id in common_ids
            if current_files[doc_id] > existing_base_ids[doc_id]
        }
        unchanged_ids = common_ids - updated_ids

        stats = {
            "added": len(added_ids),
            "updated": len(updated_ids),
            "deleted": len(deleted_ids),
            "unchanged": len(unchanged_ids),
        }

        print(f"Differential sync: +{stats['added']} ~{stats['updated']} -{stats['deleted']} ={stats['unchanged']}")

        # 4. 削除処理 (削除されたファイルに属する全チャンクを削除)
        chunks_to_delete = []
        for base_id in deleted_ids:
            if base_id in existing_chunk_ids:
                chunks_to_delete.extend(existing_chunk_ids[base_id])

        # 更新されるファイルの古いチャンクも削除 (新しいチャンクでリプレース)
        for base_id in updated_ids:
            if base_id in existing_chunk_ids:
                chunks_to_delete.extend(existing_chunk_ids[base_id])

        if chunks_to_delete:
            try:
                self._collection.delete(ids=chunks_to_delete)
                print(f"  Deleted {len(chunks_to_delete)} chunks from {len(deleted_ids | updated_ids)} files")
            except Exception as e:
                print(f"  Failed to delete: {e}")

        # 5. 追加・更新処理
        docs_to_upsert = []
        for doc_id in added_ids | updated_ids:
            try:
                docs = self._parse_markdown(file_paths[doc_id])
                if docs:
                    docs_to_upsert.extend(docs)
            except Exception as e:
                print(f"  Failed to parse {file_paths[doc_id]}: {e}")

        if docs_to_upsert:
            batch_size = 100
            batches = math.ceil(len(docs_to_upsert) / batch_size)

            for i in range(batches):
                start = i * batch_size
                end = min((i + 1) * batch_size, len(docs_to_upsert))
                batch = docs_to_upsert[start:end]

                try:
                    self._collection.upsert(
                        ids=[doc.id for doc in batch],
                        documents=[doc.content for doc in batch],
                        metadatas=[doc.metadata for doc in batch]
                    )
                except Exception as e:
                    print(f"  Failed to upsert batch {i+1}: {e}")

            print(f"  Upserted {len(docs_to_upsert)} documents")

        return stats

    def _split_markdown_by_headers(self, content: str) -> list[str]:
        """
        Markdownを見出し（#, ##, ###）単位で分割

        見出しがない場合はテキスト全体を1つの要素として返す。

        Args:
            content: Markdownテキスト（フロントマター除去済み）

        Returns:
            分割されたテキストチャンクのリスト
        """
        # 見出しパターン: 行頭の # (1-6個) + スペース + テキスト
        header_pattern = re.compile(r'^(#{1,6})\s+(.+)$', re.MULTILINE)

        matches = list(header_pattern.finditer(content))

        if not matches:
            # 見出しがない場合は全体を1チャンクとして返す
            stripped = content.strip()
            return [stripped] if stripped else []

        chunks = []

        # 見出し前のテキスト（あれば）
        if matches[0].start() > 0:
            preamble = content[:matches[0].start()].strip()
            if preamble:
                chunks.append(preamble)

        # 各見出しセクションを抽出
        for i, match in enumerate(matches):
            start = match.start()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(content)
            chunk = content[start:end].strip()
            if chunk:
                chunks.append(chunk)

        return chunks

    def _parse_markdown(self, file_path: Path) -> list[RAGDocument]:
        """
        Markdownファイルをパースし、見出し単位でチャンク分割

        Args:
            file_path: Markdownファイルのパス

        Returns:
            RAGDocumentのリスト（各チャンクが1つのドキュメント）
        """
        content = file_path.read_text(encoding="utf-8")

        # 空ファイルはスキップ
        if not content.strip():
            return []

        # ファイル名からベースIDを生成
        relative_path = str(file_path.relative_to(self.vault_path))
        base_doc_id = hashlib.md5(relative_path.encode()).hexdigest()

        # ファイルの更新日時を取得（差分更新用）
        mtime = file_path.stat().st_mtime

        # 共通メタデータ（フロントマターから抽出）
        base_metadata = {
            "source": relative_path,
            "mtime": mtime,
        }

        body_content = content

        # フロントマター（YAML）を抽出
        if content.startswith("---"):
            parts = content.split("---", 2)
            if len(parts) >= 3:
                try:
                    import yaml
                    fm = yaml.safe_load(parts[1])
                    if isinstance(fm, dict):
                        # ChromaDB対応: リスト値は文字列に変換
                        for key, value in fm.items():
                            if isinstance(value, list):
                                base_metadata[key] = ",".join(str(v) for v in value)
                            elif isinstance(value, (str, int, float, bool)) or value is None:
                                base_metadata[key] = value
                    body_content = parts[2]
                except Exception:
                    pass

        # タグを抽出（#tag形式）- 見出し(##)と区別するため行頭以外のみ
        # 行頭以外の#tagを検出 (例: インライン#tag)
        tags = re.findall(r'(?<!^)#(\w+)', body_content, re.MULTILINE)
        # 行頭の見出しではないタグも含める (行頭でない#tag)
        inline_tags = re.findall(r'(?<=\s)#(\w+)', body_content)
        all_tags = list(set(tags + inline_tags))
        if all_tags:
            base_metadata["tags"] = ",".join(all_tags)

        # 見出し単位でチャンク分割
        chunks = self._split_markdown_by_headers(body_content)

        if not chunks:
            return []

        documents = []
        for i, chunk_content in enumerate(chunks):
            # 各チャンクに一意のIDを付与
            chunk_id = f"{base_doc_id}_chunk_{i}"

            # メタデータをコピーして各チャンクに適用
            chunk_metadata = base_metadata.copy()
            chunk_metadata["chunk_index"] = i
            chunk_metadata["total_chunks"] = len(chunks)

            # チャンクの見出しを抽出してメタデータに追加
            first_line = chunk_content.split("\n")[0]
            header_match = re.match(r'^(#{1,6})\s+(.+)$', first_line)
            if header_match:
                chunk_metadata["header_level"] = len(header_match.group(1))
                chunk_metadata["header_title"] = header_match.group(2)

            documents.append(RAGDocument(
                id=chunk_id,
                content=chunk_content.strip(),
                metadata=chunk_metadata,
                source_file=relative_path,
            ))

        return documents

    def compress_context(self, question: str, results: list[RAGResult]) -> str:
        """
        ローカルLLMを使用して検索結果を圧縮・要約する（同期）

        Args:
            question: ユーザーの質問
            results: RAGの検索結果リスト

        Returns:
            要約されたコンテキスト文字列
        """
        if not results:
            return ""

        try:
            # 循環参照を避けるための動的インポート
            from src.core.llm.local_provider import LocalLLMProvider
            local_llm = LocalLLMProvider()

            # Ollamaが利用可能かチェック
            if not local_llm.is_available():
                logger.warning("Local LLM not available for compression, falling back to raw context.")
                return "\n---\n".join([r.content for r in results])

            context_text = "\n---\n".join([f"Source: {r.source}\nContent: {r.content}" for r in results])

            prompt = [
                {"role": "system", "content": "You are a specialized security context compressor. Extract only key information relevant to the question."},
                {"role": "user", "content": f"### Question\n{question}\n\n### Documentation Snippets\n{context_text}\n\n### Instructions\nProvide a concise summary of technical facts relevant to the question. No chatter."}
            ]

            # Qwen等の高速モデルを使用
            response = local_llm.generate(prompt, temperature=0.0)
            if response and hasattr(response, 'choices') and response.choices:
                compressed = response.choices[0].message.content.strip()
                if compressed:
                    logger.info(f"Context compressed from {len(context_text)} to {len(compressed)} chars.")
                    return compressed
        except Exception as e:
            logger.warning(f"Context compression failed: {e}")

        # 失敗時は全コンテンツを結合
        return "\n---\n".join([r.content for r in results])

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
        """
        セマンティック検索を実行

        Args:
            question: 検索クエリ
            n_results: 返す結果数
            filter_tags: タグでフィルタ（オプション）
            context: 実行コンテキスト（オプション）
            compress: 結果をローカルLLMで圧縮するか

        Returns:
            検索結果のリスト（compress=Trueの場合は要約された1件の結果を含む）
        """
        if not self._initialized:
            if not self.initialize():
                return []

        enhanced_question = question
        if context:
            tech_stack = context.get("tech_stack", [])
            if isinstance(tech_stack, list) and tech_stack:
                enhanced_question = f"[Tech: {', '.join(tech_stack)}] {question}"

        try:
            where_filter = None
            if filter_tags:
                where_filter = {"tags": {"$in": filter_tags}}

            results = self._collection.query(
                query_texts=[enhanced_question],
                n_results=n_results,
                where=where_filter,
            )

            rag_results = []
            if results and results.get("documents"):
                results_docs = results["documents"][0]
                results_distances = results.get("distances", [[]])[0]
                results_metadatas = results.get("metadatas", [[]])[0]

                for i, doc in enumerate(results_docs):
                    distance = results_distances[i] if i < len(results_distances) else 0
                    score = 1 / (1 + distance)

                    metadata = results_metadatas[i] if i < len(results_metadatas) else {}

                    rag_results.append(RAGResult(
                        content=doc,
                        score=score,
                        source=metadata.get("source", "unknown"),
                        metadata=metadata,
                    ))

            # 圧縮（多段階RAG）が有効な場合
            if compress and rag_results:
                compressed_content = self.compress_context(question, rag_results)
                # 元のメタデータを統合した単一の結果を返す
                return [RAGResult(
                    content=compressed_content,
                    score=1.0,
                    source="compressed_rag_context",
                    metadata={"original_count": len(rag_results)}
                )]

            return rag_results

        except Exception as e:
            logger.error(f"RAG query failed: {e}")
            return []

    def ingest_pdf(
        self,
        pdf_path: str,
        chunk_size: int = 1000,
        chunk_overlap: int = 100,
    ) -> int:
        """
        PDFファイルを取り込み

        Args:
            pdf_path: PDFファイルのパス
            chunk_size: チャンクの最大文字数
            chunk_overlap: チャンク間のオーバーラップ文字数

        Returns:
            取り込んだドキュメント数
        """
        if not self._initialized:
            if not self.initialize():
                return 0

        pdf_ingester = PDFIngester(chunk_size=chunk_size, chunk_overlap=chunk_overlap)
        documents = pdf_ingester.parse_pdf(pdf_path)

        if not documents:
            return 0

        # ChromaDBに格納
        try:
            self._collection.upsert(
                ids=[doc.id for doc in documents],
                documents=[doc.content for doc in documents],
                metadatas=[doc.metadata for doc in documents]
            )
            print(f"PDF ingested: {len(documents)} chunks from {pdf_path}")
            return len(documents)
        except Exception as e:
            print(f"Failed to ingest PDF: {e}")
            return 0

    def ingest_directory(
        self,
        directory_path: str,
        include_pdf: bool = True,
        include_markdown: bool = True,
        reset_db: bool = False,
    ) -> dict:
        """
        ディレクトリ内のファイルを一括取り込み

        Args:
            directory_path: ディレクトリパス
            include_pdf: PDFを含めるか
            include_markdown: Markdownを含めるか
            reset_db: DB をリセットするか

        Returns:
            {"markdown": int, "pdf": int, "total": int}
        """
        if not self._initialized:
            if not self.initialize():
                return {"markdown": 0, "pdf": 0, "total": 0}

        if reset_db:
            try:
                self._client.delete_collection(self.collection_name)
                self._collection = self._client.get_or_create_collection(
                    name=self.collection_name,
                    metadata={"description": "Obsidian notes for bug bounty knowledge"}
                )
            except Exception as e:
                print(f"Failed to reset collection: {e}")

        stats = {"markdown": 0, "pdf": 0, "total": 0}
        dir_path = Path(directory_path)

        if not dir_path.exists():
            print(f"Directory not found: {directory_path}")
            return stats

        # Markdownファイル
        if include_markdown:
            self.vault_path = dir_path
            md_count = self.ingest_vault()
            stats["markdown"] = md_count
            stats["total"] += md_count

        # PDFファイル
        if include_pdf:
            for pdf_file in dir_path.rglob("*.pdf"):
                count = self.ingest_pdf(str(pdf_file))
                stats["pdf"] += count
                stats["total"] += count

        return stats

    def get_stats(self) -> dict:
        """コレクションの統計情報を取得"""
        if not self._initialized:
            return {"status": "not_initialized"}

        try:
            count = self._collection.count()
            return {
                "status": "active",
                "collection": self.collection_name,
                "document_count": count,
                "vault_path": str(self.vault_path) if self.vault_path else None,
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}
