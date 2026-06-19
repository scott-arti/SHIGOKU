"""
RAG Commands - RAG関連のCLIコマンド

RAGナレッジベースの操作コマンド:
- ingest: ファイル/ディレクトリ取り込み
- query: セマンティック検索
- stats: 統計情報表示
"""

import json
from pathlib import Path
from src.commands import print_banner, print_header, print_step, print_result


def run_rag_ingest(path: str, pdf_only: bool = False, reset: bool = False):
    """
    RAG Ingest Mode
    
    ナレッジベースにファイル/ディレクトリを取り込み。
    """
    print_banner()
    print_header("📚 RAG Ingest")
    
    try:
        from src.core.rag_module.rag import KnowledgeIngester
    except ImportError as e:
        print_result(False, f"Import error: {e}")
        return
    
    ingester = KnowledgeIngester()
    
    path_obj = Path(path)
    
    if path_obj.is_file():
        if path.lower().endswith(".pdf"):
            print_step("📄", f"Ingesting PDF: {path}")
            count = ingester.ingest_pdf(path)
            print_result(count > 0, f"Ingested {count} chunks")
        else:
            print_result(False, "Single file must be PDF")
    elif path_obj.is_dir():
        print_step("📁", f"Ingesting directory: {path}")
        stats = ingester.ingest_directory(
            path,
            include_pdf=True,
            include_markdown=not pdf_only,
            reset_db=reset,
        )
        print_result(True, f"Markdown: {stats['markdown']}, PDF: {stats['pdf']}, Total: {stats['total']}")
    else:
        print_result(False, f"Path not found: {path}")


def run_rag_query(question: str, n_results: int = 5, output_json: bool = False):
    """
    RAG Query Mode
    
    ナレッジベースを検索。
    """
    if not output_json:
        print_banner()
        print_header("🔍 RAG Query")
    
    try:
        from src.core.rag_module.rag import KnowledgeIngester
    except ImportError as e:
        if output_json:
            print(json.dumps({"error": str(e)}))
        else:
            print_result(False, f"Import error: {e}")
        return
    
    ingester = KnowledgeIngester()
    results = ingester.query(question, n_results=n_results)
    
    if output_json:
        output = [
            {
                "content": r.content[:500],
                "score": r.score,
                "source": r.source,
            }
            for r in results
        ]
        print(json.dumps(output, ensure_ascii=False, indent=2))
    else:
        if not results:
            print_result(False, "No results found")
            return
        
        for i, r in enumerate(results, 1):
            print(f"\n  [{i}] Score: {r.score:.2f} | Source: {r.source}")
            print(f"      {r.content[:200]}...")


def run_rag_stats(output_json: bool = False):
    """
    RAG Stats Mode
    
    ナレッジベースの統計情報を表示。
    """
    if not output_json:
        print_banner()
        print_header("📊 RAG Stats")
    
    try:
        from src.core.rag_module.rag import KnowledgeIngester
    except ImportError as e:
        if output_json:
            print(json.dumps({"error": str(e)}))
        else:
            print_result(False, f"Import error: {e}")
        return
    
    ingester = KnowledgeIngester()
    stats = ingester.get_stats()
    
    if output_json:
        print(json.dumps(stats, ensure_ascii=False, indent=2))
    else:
        for key, value in stats.items():
            print(f"  {key}: {value}")
