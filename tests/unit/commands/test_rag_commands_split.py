"""
Command-layer regression tests for RAG module split (SGK-2026-0302).

Verifies that after the split, the command-layer functions in src/commands/rag.py
can import KnowledgeIngester from the correct facade path without ImportError.
"""

import sys


class TestRagCommandsImportPaths:
    """Verify that rag command functions resolve their import paths correctly."""

    def test_run_rag_query_imports_correctly(self):
        """run_rag_query uses src.core.rag_module.rag facade."""
        from src.commands.rag import run_rag_query
        assert run_rag_query is not None

    def test_run_rag_stats_imports_correctly(self):
        """run_rag_stats uses src.core.rag_module.rag facade."""
        from src.commands.rag import run_rag_stats
        assert run_rag_stats is not None

    def test_run_rag_ingest_imports_correctly(self):
        """
        run_rag_ingest was fixed from broken `src.core.rag` to
        `src.core.rag_module.rag` facade. Verify it loads without ImportError.
        """
        from src.commands.rag import run_rag_ingest
        assert run_rag_ingest is not None

    def test_run_rag_ingest_does_not_raise_on_bad_path(self):
        """
        Calling run_rag_ingest with a nonexistent path should not raise
        an unhandled ImportError. It should fail gracefully.
        """
        from src.commands.rag import run_rag_ingest
        # Should not raise ImportError - the import inside the function
        # uses the correct facade path from src.core.rag_module.rag
        try:
            run_rag_ingest("/nonexistent/path/for/test")
        except ImportError:
            assert False, "run_rag_ingest raised ImportError - facade path broken"
        except Exception:
            # Other errors (Path not found) are expected and OK
            pass

    def test_all_three_functions_use_same_import_surface(self):
        """
        All three command functions should import KnowledgeIngester
        from the same facade path after the fix.
        """
        import inspect
        from src.commands.rag import run_rag_ingest, run_rag_query, run_rag_stats

        for fn in (run_rag_ingest, run_rag_query, run_rag_stats):
            source = inspect.getsource(fn)
            # All should reference the correct module path
            assert "src.core.rag_module.rag" in source, \
                f"{fn.__name__} does not use src.core.rag_module.rag facade"
            # None should reference the dead path
            assert "src.core.rag import" not in source, \
                f"{fn.__name__} still references dead path src.core.rag"
