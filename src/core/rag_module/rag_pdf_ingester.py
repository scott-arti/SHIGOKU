"""
PDF → RAGDocument: extraction and chunking.

Split from rag.py (SGK-2026-0302).
"""

import hashlib
from pathlib import Path

from src.core.rag_module.rag_types import RAGDocument


class PDFIngester:
    """
    PDF → RAGDocument 変換

    PyMuPDFを使用してPDFからテキストを抽出し、
    チャンク分割してRAGDocumentを生成する。
    """

    def __init__(
        self,
        chunk_size: int = 1000,
        chunk_overlap: int = 100,
    ):
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap

    def parse_pdf(self, pdf_path: str) -> list[RAGDocument]:
        """
        PDFファイルをパース

        Args:
            pdf_path: PDFファイルのパス

        Returns:
            RAGDocumentのリスト
        """
        try:
            import fitz  # PyMuPDF
        except ImportError:
            print("PyMuPDF not installed. Run: pip install pymupdf")
            return []

        pdf_path = Path(pdf_path)
        if not pdf_path.exists():
            print(f"PDF not found: {pdf_path}")
            return []

        documents = []

        try:
            doc = fitz.open(pdf_path)

            for page_num, page in enumerate(doc):
                text = page.get_text()

                if not text.strip():
                    continue

                # チャンク分割
                chunks = self._split_into_chunks(text)

                for chunk_idx, chunk in enumerate(chunks):
                    doc_id = hashlib.md5(
                        f"{pdf_path.name}:p{page_num}:c{chunk_idx}".encode()
                    ).hexdigest()

                    documents.append(RAGDocument(
                        id=doc_id,
                        content=chunk,
                        metadata={
                            "source": str(pdf_path.name),
                            "page": page_num + 1,
                            "chunk": chunk_idx,
                            "type": "pdf",
                        },
                        source_file=str(pdf_path),
                    ))

            doc.close()

        except Exception as e:
            print(f"Failed to parse PDF {pdf_path}: {e}")

        return documents

    def _split_into_chunks(self, text: str) -> list[str]:
        """テキストをチャンクに分割"""
        if len(text) <= self.chunk_size:
            return [text.strip()]

        chunks = []
        start = 0

        while start < len(text):
            end = start + self.chunk_size

            # 文の境界で分割を試みる
            if end < len(text):
                # 。や\nで区切る
                for sep in ["。", "\n\n", "\n", ". ", " "]:
                    last_sep = text.rfind(sep, start, end)
                    if last_sep > start:
                        end = last_sep + len(sep)
                        break

            chunk = text[start:end].strip()
            if chunk:
                chunks.append(chunk)

            start = end - self.chunk_overlap
            if start >= len(text):
                break

        return chunks
