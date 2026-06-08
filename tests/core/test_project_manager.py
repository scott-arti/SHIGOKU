
import pytest
import shutil
from pathlib import Path
from datetime import datetime
import json
from src.core.project.project_manager import ProjectManager, ProjectConfig

@pytest.fixture
def temp_project_dir(tmp_path):
    """Temporary directory for project tests"""
    # Use a temporary directory for projects
    projects_root = tmp_path / "projects"
    projects_root.mkdir()
    return projects_root

@pytest.fixture
def project_manager(temp_project_dir):
    """ProjectManager instance with temp dir"""
    return ProjectManager("test_project", base_dir=str(temp_project_dir))

def test_init_project(project_manager):
    """Test project initialization"""
    target = "example.com"
    project_manager.init_project(target, description="Test Description")
    
    assert project_manager.project_dir.exists()
    assert (project_manager.project_dir / "sessions").exists()
    assert (project_manager.project_dir / "reports").exists()
    assert (project_manager.project_dir / "meta.yaml").exists()
    
    # Check config
    assert project_manager.config.target_url == target
    assert project_manager.config.project_name == "test_project"

@pytest.mark.asyncio
async def test_save_session(project_manager):
    """Test session saving"""
    project_manager.init_project("example.com")
    
    session_data = {"test": "data", "timestamp": "2026-01-01"}
    saved_path = await project_manager.save_session(session_data, filename="test_session.json")
    
    assert saved_path.exists()
    with open(saved_path) as f:
        data = json.load(f)
        assert data["test"] == "data"
        
    # Check latest.json
    latest = project_manager.project_dir / "sessions" / "latest.json"
    assert latest.exists()
    with open(latest) as f:
        latest_data = json.load(f)
        assert latest_data["test"] == "data"

@pytest.mark.asyncio
async def test_list_sessions(project_manager):
    """Test listing sessions"""
    project_manager.init_project("example.com")
    
    # Save a few sessions
    await project_manager.save_session({"id": 1}, filename="session_20260101_100000.json")
    await project_manager.save_session({"id": 2}, filename="session_20260101_110000.json") # Newer
    
    sessions = project_manager.list_sessions()
    assert len(sessions) >= 2
    # Should be sorted new to old
    assert sessions[0]["filename"] == "session_20260101_110000.json"
    assert sessions[1]["filename"] == "session_20260101_100000.json"

@pytest.mark.asyncio
async def test_save_finding(project_manager):
    """Test saving findings"""
    project_manager.init_project("example.com")
    
    # Mock finding object
    class MockFinding:
        def __init__(self, id, type):
            self.id = id
            self.vuln_type = type
        def to_dict(self):
            return {"id": self.id, "type": str(self.vuln_type)}
            
    finding = MockFinding("FIND-001", "sqli")
    path = await project_manager.save_finding(finding)
    
    assert path.exists()
    assert "FIND-001_sqli.json" in path.name
    
    findings = project_manager.get_findings()
    assert len(findings) == 1
    assert findings[0].name == path.name

def test_list_projects(temp_project_dir):
    """Test listing all projects"""
    # Create multiple projects
    pm1 = ProjectManager("proj1", base_dir=str(temp_project_dir))
    pm1.init_project("t1.com")
    
    pm2 = ProjectManager("proj2", base_dir=str(temp_project_dir))
    pm2.init_project("t2.com")
    
    # List
    projects = ProjectManager.list_projects(base_dir=str(temp_project_dir))
    assert len(projects) == 2
    names = sorted([p["project_name"] for p in projects])
    assert names == ["proj1", "proj2"]
