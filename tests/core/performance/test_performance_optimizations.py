
import pytest
from unittest.mock import MagicMock, patch
import json
import asyncio
from src.core.rag_module.vector_cache import VectorCache, get_vector_cache

# --- Vector Cache Tests ---

def test_vector_cache_init(tmp_path):
    db_path = tmp_path / "test_cache.sqlite"
    cache = VectorCache(str(db_path))
    assert db_path.exists()
    
def test_vector_cache_set_get(tmp_path):
    db_path = tmp_path / "test_cache.sqlite"
    cache = VectorCache(str(db_path))
    
    text = "test query"
    model = "test-model"
    vector = [0.1, 0.2, 0.3]
    
    # Initial get should limit miss
    assert cache.get(text, model) is None
    stats = cache.get_stats()
    assert stats["misses"] >= 1
    
    # Set
    cache.set(text, model, vector)
    
    # Get should return vector
    retrieved = cache.get(text, model)
    assert retrieved == vector
    stats = cache.get_stats()
    assert stats["hits"] >= 1

# --- Task Adjacency List Tests ---

@pytest.mark.asyncio
async def test_adjacency_list_generation():
    from src.core.engine.master_conductor import MasterConductor
    from src.core.domain.model.task import Task
    
    # Mock dependencies
    conductor = MasterConductor(
        graph=MagicMock(), 
        pam=MagicMock(), 
        rag=MagicMock(),
        recipe_loader=MagicMock(),
        project_manager=MagicMock()
    )
    
    # Create Task Tree
    # Root -> Child1 -> GrandChild1
    #      -> Child2
    root = Task(name="Root", id="root", action="test")
    child1 = Task(name="Child1", id="c1", parent_id="root", action="test")
    child2 = Task(name="Child2", id="c2", parent_id="root", action="test")
    grandchild1 = Task(name="GrandChild1", id="gc1", parent_id="c1", action="test")
    
    conductor.task_queue.add(root)
    conductor.task_queue.add(child1)
    conductor.task_queue.add(child2)
    conductor.task_queue.add(grandchild1)
    
    # Mock save_session to intercept data
    future = asyncio.Future()
    future.set_result(None)
    conductor.project_manager.save_session.return_value = future
    
    await conductor.async_save_session("dummy.json")
    
    # Check arguments passed to save_session
    args, _ = conductor.project_manager.save_session.call_args
    session_data = args[0]
    
    assert "adjacency_list" in session_data
    adj = session_data["adjacency_list"]
    
    assert "root" in adj
    assert "c1" in adj["root"]
    assert "c2" in adj["root"]
    
    assert "c1" in adj
    assert "gc1" in adj["c1"]
    
    assert "c2" not in adj # No children
