
import pytest
import json
import asyncio
from pathlib import Path
from unittest.mock import MagicMock, patch
from src.core.project.project_manager import ProjectManager

@pytest.mark.asyncio
async def test_atomic_write_success(tmp_path):
    # Setup
    pm = ProjectManager("test_project", base_dir=str(tmp_path))
    pm.init_project("http://example.com")
    
    session_data = {"task_id": "1", "status": "success"}
    
    # Execute
    output_path = await pm.save_session(session_data, filename="session_test.json")
    
    # Verify
    assert output_path.exists()
    assert not output_path.with_suffix(".tmp").exists()
    
    with open(output_path, "r") as f:
        data = json.load(f)
        assert data["task_id"] == "1"

@pytest.mark.asyncio
async def test_atomic_write_removes_tmp_on_failure(tmp_path):
    # Setup
    pm = ProjectManager("test_project_fail", base_dir=str(tmp_path))
    pm.init_project("http://example.com")
    
    session_data = {"key": "value"}
    target_path = pm.project_dir / "sessions" / "session_fail.json"
    
    # Mock json.dump to fail to simulate write error
    with patch("src.core.project.project_manager.json.dump", side_effect=Exception("Write failed")):
        with pytest.raises(Exception, match="Write failed"):
            await pm.save_session(session_data, filename="session_fail.json")
            
    # Verify
    assert not target_path.exists()
    assert not target_path.with_suffix(".tmp").exists()

@pytest.mark.asyncio
async def test_atomic_copy(tmp_path):
    # Setup
    pm = ProjectManager("test_project_copy", base_dir=str(tmp_path))
    pm.init_project("http://example.com")
    
    src = tmp_path / "src.txt"
    dst = tmp_path / "dst.txt"
    src.write_text("content")
    
    # Execute (using internal method via run_in_executor in real code, but calling helper directly here)
    await asyncio.to_thread(pm._atomic_copy, src, dst)
    
    # Verify
    assert dst.exists()
    assert dst.read_text() == "content"
    assert not dst.with_suffix(".tmp_copy").exists()
