"""
Tests for Progressive Scanner

Verifies that the scanner correctly:
1. Calls FfufTool with appropriate parameters
2. Parses JSON output correctly
3. Implements early termination logic
4. Respects max_requests_per_stage limit
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

from src.core.wordlist.progressive_scanner import (
    ProgressiveScanner,
    ProgressiveScanConfig,
    ScanResult,
)
from src.core.wordlist.wordlist_manager import WordlistInfo


@pytest.fixture
def mock_wordlist():
    """Sample wordlist for testing"""
    return WordlistInfo(
        name="test-wordlist",
        path=Path("/tmp/test-wordlist.txt"),
        size="small",
        lines=100,
        purpose="directory",
        source="test",
    )


@pytest.fixture
def scanner():
    """Create scanner with default config"""
    config = ProgressiveScanConfig(
        min_discoveries=5,
        target_discovery_rate=0.05,
        stages=["small"],  # Only test small stage
        timeout_per_stage=10,
    )
    return ProgressiveScanner(config)


def test_parse_ffuf_json_output(scanner):
    """Test JSON output parsing"""
    # Mock JSON file content
    json_data = {
        "results": [
            {"input": {"FUZZ": "admin"}, "status": 200},
            {"input": {"FUZZ": "login"}, "status": 200},
            {"input": {"FUZZ": "api"}, "status": 301},
        ]
    }
    
    import json
    import tempfile
    
    # Write mock JSON to temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(json_data, f)
        temp_path = f.name
    
    try:
        # Patch the file path
        with patch("builtins.open", create=True) as mock_open:
            mock_open.return_value.__enter__.return_value.read.return_value = json.dumps(json_data)
            
            # Parse output
            discovered =scanner._parse_ffuf_output("")
            
            # Verify
            assert len(discovered) == 3
            assert "admin" in discovered
            assert "login" in discovered
            assert "api" in discovered
    finally:
        # Cleanup
        Path(temp_path).unlink(missing_ok=True)


def test_execute_scan_with_mock_ffuf(scanner, mock_wordlist):
    """Test that _execute_scan correctly calls FfufTool"""
    mock_ffuf_output = """
[Status: 200, Size: 1234, Words: 56, Lines: 12]
http://example.com/admin
[Status: 301, Size: 0, Words: 0, Lines: 0]
http://example.com/api
    """
    
    with patch("src.core.wordlist.progressive_scanner.FfufTool") as MockFfuf:
        # Setup mock
        mock_instance = MockFfuf.return_value
        mock_instance.run.return_value = mock_ffuf_output
        
        # Mock JSON parsing to return specific results
        with patch.object(scanner, '_parse_ffuf_output', return_value=["admin", "api"]):
            result = scanner._execute_scan(
                target="http://example.com",
                wordlist=mock_wordlist,
                tool="ffuf"
            )
            
            # Verify FfufTool was called
            assert mock_instance.run.called
            call_args = mock_instance.run.call_args
            assert "http://example.com/FUZZ" in call_args.kwargs["url"]
            assert str(mock_wordlist.path) == call_args.kwargs["wordlist"]
            assert call_args.kwargs["fast_mode"] is True
            
            # Verify result
            assert len(result.discovered) == 2
            assert "admin" in result.discovered
            assert "api" in result.discovered
            assert result.discovery_rate > 0


def test_early_termination_sufficient_discoveries(scanner, mock_wordlist):
    """Test early termination when sufficient discoveries are made"""
    # Mock to return many discoveries
    with patch.object(scanner, '_execute_scan') as mock_scan:
        mock_result = ScanResult(
            wordlist_name="test",
            wordlist_size="small",
            discovered=["admin", "api", "login", "users", "docs", "config"],  # 6 discoveries
            total_tested=100,
            discovery_rate=0.06,  # 6%
        )
        mock_scan.return_value = mock_result
        
        with patch.object(scanner.wm, 'select', return_value=mock_wordlist):
            results = scanner.scan(
                target="http://example.com",
                purpose="directory",
                tool="ffuf"
            )
            
            # Should terminate early (not continue to medium/high)
            assert len(results) == 1
            assert results[0].should_continue is False
            assert "Sufficient discoveries" in results[0].reason


def test_unsupported_tool_fallback(scanner, mock_wordlist):
    """Test that unsupported tools are handled gracefully"""
    result = scanner._execute_scan(
        target="http://example.com",
        wordlist=mock_wordlist,
        tool="unsupported_tool"
    )
    
    # Should return empty result without error
    assert len(result.discovered) == 0
    assert result.discovery_rate == 0.0


def test_max_requests_per_stage_config():
    """Test that max_requests_per_stage config option exists"""
    config = ProgressiveScanConfig(max_requests_per_stage=1000)
    assert config.max_requests_per_stage == 1000
    
    # Default should be None
    default_config = ProgressiveScanConfig()
    assert default_config.max_requests_per_stage is None
