import pytest
import os
from unittest.mock import MagicMock, patch, AsyncMock
from src.core.agents.swarm.base import Task
from src.core.agents.swarm.fuzzing.manager import DirBruteSpecialist, FuzzingSwarm
from src.core.models.fuzzing import FuzzResult

@pytest.fixture
def mock_task_skip():
    return Task(
        id="test_skip",
        name="test_skip",
        target="http://example.com",
        tags=["api_endpoint"] # No force_fuzz
    )

@pytest.fixture
def mock_task_force():
    return Task(
        id="test_force",
        name="test_force",
        target="http://example.com",
        tags=["force_fuzz"]
    )

@pytest.mark.asyncio
class TestDirBruteSpecialist:
    
    async def test_skip_with_db_save(self, mock_task_skip):
        # KnowledgeGraph の Mock (ローカルインポートされるので、実際のパスをpatchする必要がある)
        with patch("src.core.infra.knowledge_graph.KnowledgeGraph") as MockKG:
            mock_kg_instance = MockKG.return_value
            
            specialist = DirBruteSpecialist()
            # __init__ で作られた mock instance が None になるかもしれないので明示的にセット
            specialist.kg = mock_kg_instance 
            
            findings = await specialist.execute(mock_task_skip)
            
            # Skip通知は finding 化しない
            assert findings == []
            
            # save_pending_task が呼ばれたことを確認
            mock_kg_instance.save_pending_task.assert_called_once()

    async def test_native_fallback(self, mock_task_force):
        with patch("src.core.agents.swarm.fuzzing.manager.NativeFuzzer") as MockNative:
            mock_native_instance = MockNative.return_value
            mock_native_instance.run = AsyncMock(return_value=[
                FuzzResult(url="http://example.com/admin", status=200, length=100, words=10, lines=5)
            ])
            
            specialist = DirBruteSpecialist()
            specialist.native_fuzzer = mock_native_instance
            specialist._run_with_adapter = AsyncMock(side_effect=RuntimeError("adapter failed"))
            
            findings = await specialist.execute(mock_task_force)
            
            assert len(findings) == 1
            assert findings[0].title == "Discovered Path: http://example.com/admin"
            mock_native_instance.run.assert_called_once()

    async def test_ffuf_execution(self, mock_task_force):
        with patch("src.core.agents.swarm.fuzzing.manager.NativeFuzzer") as MockNative:
            specialist = DirBruteSpecialist()
            specialist.native_fuzzer = MockNative.return_value
            specialist._run_with_adapter = AsyncMock(return_value=[
                FuzzResult(url="http://example.com/login", status=200, length=200, words=20, lines=10)
            ])
            
            findings = await specialist.execute(mock_task_force)
            
            assert len(findings) == 1
            assert findings[0].title == "Discovered Path: http://example.com/login"
            specialist._run_with_adapter.assert_called_once()

class TestFuzzingSwarm:
    def test_routing(self):
        swarm = FuzzingSwarm()
        specs = swarm.get_specialists(["random_tag"])
        assert len(specs) == 1
        assert specs[0].name == "DirBruteSpecialist"
