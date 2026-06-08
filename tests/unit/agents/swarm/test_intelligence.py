import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from src.core.agents.swarm.intelligence.manager import GitHubReconSpecialist, IntelligenceSwarm
from src.tools.osint.leak_detector import LeakDetector
from src.core.agents.swarm.base import Task

class TestLeakDetector:
    def test_regex_matching(self):
        detector = LeakDetector()
        
        # Positive case
        text1 = "Here is the key: AKIAIOSFODNN7EXAMPLE"
        findings1 = detector.scan_text(text1, "http://url")
        assert len(findings1) == 1
        assert "AKIAIOSFODNN7EXAMPLE" in findings1[0]["evidence"]
        
        # Positive case 2
        text2 = "password = supersecret"
        findings2 = detector.scan_text(text2, "http://url")
        assert len(findings2) == 1
        
        # Negative case
        text3 = "This is a key concept." # not assignment
        findings3 = detector.scan_text(text3, "http://url")
        assert len(findings3) == 0

class TestGitHubReconSpecialist:
    @pytest.mark.asyncio
    async def test_execution_flow(self):
        # Mock GitHubClient
        # Patch where it is imported (manager.py)
        with patch("src.core.agents.swarm.intelligence.manager.GitHubClient") as MockGH, \
             patch("src.core.agents.swarm.intelligence.manager.LeakDetector") as MockLD:
            
            mock_gh = MockGH.return_value
            mock_ld = MockLD.return_value
            
            # Mock Repos
            mock_gh.search_org_repos = AsyncMock(return_value=[
                {"name": "repo1", "clone_url": "https://git/repo1", "html_url": "https://url/repo1", "full_name": "org/repo1"}
            ])
            # Mock Comments
            mock_gh.get_recent_issue_comments = AsyncMock(return_value=[
                {"body": "debug mode on", "user": "dev", "url": "http://issue/1"}
            ])
            
            # Mock Scan Repo
            mock_ld.scan_repo = AsyncMock(return_value=[
                {"rule": "AWS Key", "file": "config.py", "snippet": "AKIA..."}
            ])
            # Mock Scan Text
            mock_ld.scan_text.return_value = []
            
            specialist = GitHubReconSpecialist()
            task = Task(id="1", name="recon", target="org_name", tags=["osint"])
            
            findings = await specialist.execute(task)
            
            assert len(findings) == 1
            assert "Secret Leak" in findings[0].title
            assert "repo1" in findings[0].title
            
            mock_gh.search_org_repos.assert_called_with("org_name")
            mock_ld.scan_repo.assert_called_with("https://git/repo1")

class TestIntelligenceSwarm:
    def test_init(self):
        swarm = IntelligenceSwarm()
        assert len(swarm._specialists) == 1
        assert isinstance(swarm._specialists[0], GitHubReconSpecialist)
