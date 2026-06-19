"""
Characterization test for RAG module split (SGK-2026-0302).

Verifies that the public import surface from `src.core.rag_module.rag` is preserved
after splitting rag.py into facade + sibling modules.

Tests:
  1. Import smoke: all public symbols importable from rag module
  2. get_rag_switch() singleton
  3. init_rag() basic call
  4. KnowledgeIngester instantiation
  5. PDFIngester instantiation
  6. RAGSwitch instantiation
  7. RAGDocument / RAGResult dataclass smoke
"""

import sys
import pytest


class TestRagImportSurface:
    """Import smoke: verify all public symbols are importable."""

    def test_import_knowledge_ingester(self):
        from src.core.rag_module.rag import KnowledgeIngester
        assert KnowledgeIngester is not None

    def test_import_pdf_ingester(self):
        from src.core.rag_module.rag import PDFIngester
        assert PDFIngester is not None

    def test_import_rag_switch(self):
        from src.core.rag_module.rag import RAGSwitch
        assert RAGSwitch is not None

    def test_import_get_rag_switch(self):
        from src.core.rag_module.rag import get_rag_switch
        assert get_rag_switch is not None

    def test_import_init_rag(self):
        from src.core.rag_module.rag import init_rag
        assert init_rag is not None

    def test_import_rag_document(self):
        from src.core.rag_module.rag import RAGDocument
        assert RAGDocument is not None

    def test_import_rag_result(self):
        from src.core.rag_module.rag import RAGResult
        assert RAGResult is not None

    def test_all_public_symbols_in_single_import(self):
        from src.core.rag_module.rag import (
            KnowledgeIngester,
            PDFIngester,
            RAGSwitch,
            get_rag_switch,
            init_rag,
            RAGDocument,
            RAGResult,
        )
        assert KnowledgeIngester is not None
        assert PDFIngester is not None
        assert RAGSwitch is not None
        assert get_rag_switch is not None
        assert init_rag is not None
        assert RAGDocument is not None
        assert RAGResult is not None


class TestRagSwitchSingleton:
    """Singleton / initialization regression."""

    def test_get_rag_switch_returns_instance(self):
        from src.core.rag_module.rag import get_rag_switch
        switch = get_rag_switch()
        assert switch is not None

    def test_get_rag_switch_same_instance(self):
        from src.core.rag_module.rag import get_rag_switch
        s1 = get_rag_switch()
        s2 = get_rag_switch()
        assert s1 is s2

    def test_init_rag_callable(self):
        """init_rag should not raise when called (may fail gracefully)."""
        from src.core.rag_module.rag import init_rag
        # Call with a non-existent path should not crash, just return False
        result = init_rag("/nonexistent/vault/path", enabled=False)
        # enabled=False means no ingest attempt, should return True
        assert result is True


class TestInstantiation:
    """Minimal instantiation smoke."""

    def test_knowledge_ingester_instantiate(self):
        from src.core.rag_module.rag import KnowledgeIngester
        ingester = KnowledgeIngester()
        assert ingester is not None
        assert ingester._initialized is False

    def test_pdf_ingester_instantiate(self):
        from src.core.rag_module.rag import PDFIngester
        ingester = PDFIngester()
        assert ingester is not None
        assert ingester.chunk_size == 1000
        assert ingester.chunk_overlap == 100

    def test_rag_switch_instantiate(self):
        from src.core.rag_module.rag import RAGSwitch
        switch = RAGSwitch()
        assert switch is not None
        assert switch.enabled is True

    def test_rag_switch_instantiate_disabled(self):
        from src.core.rag_module.rag import RAGSwitch
        switch = RAGSwitch(default_enabled=False)
        assert switch.enabled is False


class TestDataclassSmoke:
    """RAGDocument / RAGResult dataclass smoke."""

    def test_rag_document_create(self):
        from src.core.rag_module.rag import RAGDocument
        doc = RAGDocument(id="test-1", content="hello", source_file="test.md")
        assert doc.id == "test-1"
        assert doc.content == "hello"
        assert doc.source_file == "test.md"
        assert doc.metadata == {}

    def test_rag_result_create(self):
        from src.core.rag_module.rag import RAGResult
        result = RAGResult(content="test", score=0.95, source="test.md")
        assert result.content == "test"
        assert result.score == 0.95
        assert result.source == "test.md"
        assert result.metadata == {}


class TestRagSwitchMethods:
    """RAGSwitch method smoke."""

    def test_toggle(self):
        from src.core.rag_module.rag import RAGSwitch
        switch = RAGSwitch(default_enabled=True)
        switch.toggle(False)
        assert switch.enabled is False
        switch.toggle(True)
        assert switch.enabled is True

    def test_enable_disable(self):
        from src.core.rag_module.rag import RAGSwitch
        switch = RAGSwitch()
        switch.disable()
        assert switch.enabled is False
        switch.enable()
        assert switch.enabled is True

    def test_query_if_enabled_disabled(self):
        from src.core.rag_module.rag import RAGSwitch
        switch = RAGSwitch(default_enabled=False)
        result = switch.query_if_enabled("test query")
        assert result is None

    def test_set_ingester(self):
        from src.core.rag_module.rag import RAGSwitch, KnowledgeIngester
        switch = RAGSwitch()
        ingester = KnowledgeIngester()
        switch.set_ingester(ingester)
        assert switch._ingester is ingester


class TestInitRagIdempotence:
    """init_rag() idempotence regression (plan §3.1, line 68).

    Uses mocks to avoid real ChromaDB connection during repeated calls.
    """

    def _reset_singleton(self):
        """Reset the RAG global singleton so each test starts clean."""
        import src.core.rag_module.rag_switch as switch_mod
        switch_mod._rag_switch = None

    def test_init_rag_disabled_does_not_initialize(self):
        """When enabled=False, init_rag should return True without touching ingester."""
        self._reset_singleton()
        from src.core.rag_module.rag import init_rag, get_rag_switch
        result = init_rag("/fake/vault", enabled=False)
        assert result is True
        switch = get_rag_switch()
        assert switch._ingester is None

    def test_init_rag_idempotent_two_calls_no_fatal_side_effect(self):
        """
        Call init_rag twice with mocks. Second call should not crash
        and the singleton should be reused.
        """
        self._reset_singleton()
        from unittest.mock import patch, MagicMock
        from src.core.rag_module.rag_ingester import KnowledgeIngester

        with patch.object(KnowledgeIngester, 'initialize', return_value=True), \
             patch.object(KnowledgeIngester, 'ingest_vault', return_value=0):

            from src.core.rag_module.rag import init_rag, get_rag_switch

            # First call
            result1 = init_rag("/fake/vault")
            assert result1 is True
            switch1 = get_rag_switch()

            # Second call - must not raise, must return True
            result2 = init_rag("/fake/vault")
            assert result2 is True
            switch2 = get_rag_switch()

            # Same singleton instance
            assert switch1 is switch2

    def test_init_rag_reuse_singleton_when_already_initialized(self):
        """
        After first successful init_rag, the singleton's _ingester
        should be set, and a second call should reuse the same switch
        (and not create a dangling ingester).
        """
        self._reset_singleton()
        from unittest.mock import patch, MagicMock
        from src.core.rag_module.rag_ingester import KnowledgeIngester

        with patch.object(KnowledgeIngester, 'initialize', return_value=True), \
             patch.object(KnowledgeIngester, 'ingest_vault', return_value=42):

            from src.core.rag_module.rag import init_rag, get_rag_switch

            init_rag("/fake/vault")
            switch = get_rag_switch()
            assert switch._ingester is not None

            # Second init_rag should not destroy existing ingester
            # (it creates a new ingester but overwrites via set_ingester)
            init_rag("/fake/vault")
            assert switch._ingester is not None
            assert switch.enabled is True
