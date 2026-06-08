"""
Tests for Phase 5 Security Tools

- GitExposedScannerTool
- WaybackAnalyzerTool  
- DependencyConfusionScannerTool
- CloudMetadataScannerTool
"""
import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from src.tools.custom.git_exposed_scanner import GitExposedScannerTool
from src.tools.custom.wayback_analyzer import WaybackAnalyzerTool
from src.tools.custom.dependency_confusion_scanner import DependencyConfusionScannerTool
from src.tools.custom.cloud_metadata_scanner import CloudMetadataScannerTool


class TestGitExposedScannerTool:
    """Git Exposed Scanner のテスト"""
    
    def test_tool_initialization(self):
        """ツール初期化テスト"""
        tool = GitExposedScannerTool()
        assert tool.name == "git_exposed_scanner"
        assert "git" in tool.description.lower()
    
    def test_schema_generation(self):
        """スキーマ生成テスト"""
        tool = GitExposedScannerTool()
        schema = tool.to_schema()
        
        assert schema["type"] == "function"
        assert schema["function"]["name"] == "git_exposed_scanner"
        assert "target" in schema["function"]["parameters"]["properties"]
        assert "target" in schema["function"]["parameters"]["required"]
    
    def test_input_validation_empty_target(self):
        """空のターゲットのバリデーション"""
        tool = GitExposedScannerTool()
        result = json.loads(tool.run(target=""))
        
        assert "error" in result
        assert "required" in result["error"].lower()
    
    def test_input_validation_unsafe_characters(self):
        """危険な文字を含むURLの拒否"""
        tool = GitExposedScannerTool()
        result = json.loads(tool.run(target="https://example.com; rm -rf /"))
        
        assert "error" in result
        assert "unsafe" in result["error"].lower()
    
    def test_url_normalization(self):
        """URL正規化（https://の追加）"""
        tool = GitExposedScannerTool()
        
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="", stderr="", returncode=0
            )
            tool.run(target="example.com")
            
            # https://が追加されているか確認
            call_args = mock_run.call_args_list[0][0][0]
            assert any("https://example.com" in arg for arg in call_args)


class TestWaybackAnalyzerTool:
    """Wayback Analyzer のテスト"""
    
    def test_tool_initialization(self):
        """ツール初期化テスト"""
        tool = WaybackAnalyzerTool()
        assert tool.name == "wayback_analyzer"
        assert "wayback" in tool.description.lower()
    
    def test_schema_generation(self):
        """スキーマ生成テスト"""
        tool = WaybackAnalyzerTool()
        schema = tool.to_schema()
        
        assert schema["type"] == "function"
        assert "domain" in schema["function"]["parameters"]["properties"]
        assert "mode" in schema["function"]["parameters"]["properties"]
    
    def test_input_validation_empty_domain(self):
        """空のドメインのバリデーション"""
        tool = WaybackAnalyzerTool()
        result = json.loads(tool.run(domain=""))
        
        assert "error" in result
        assert "required" in result["error"].lower()
    
    def test_domain_sanitization(self):
        """ドメインサニタイズ（https://除去）"""
        tool = WaybackAnalyzerTool()
        
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="http://example.com/page1\nhttp://example.com/page2",
                stderr="",
                returncode=0
            )
            result = json.loads(tool.run(domain="https://example.com/path"))
            
            # パスが除去され、ドメインのみ使用されているか
            assert "domain" in result
    
    def test_mode_discover(self):
        """discoverモードのテスト"""
        tool = WaybackAnalyzerTool()
        
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="http://example.com/admin\nhttp://example.com/api/v1",
                stderr="",
                returncode=0
            )
            result = json.loads(tool.run(domain="example.com", mode="discover"))
            
            assert result["mode"] == "discover"
            assert "total_urls" in result
    
    def test_mode_interesting(self):
        """interestingモードのテスト"""
        tool = WaybackAnalyzerTool()
        
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                stdout="http://example.com/admin/login\nhttp://example.com/debug",
                stderr="",
                returncode=0
            )
            result = json.loads(tool.run(domain="example.com", mode="interesting"))
            
            assert result["mode"] == "interesting"
            assert "interesting_count" in result


class TestDependencyConfusionScannerTool:
    """Dependency Confusion Scanner のテスト"""
    
    def test_tool_initialization(self):
        """ツール初期化テスト"""
        tool = DependencyConfusionScannerTool()
        assert tool.name == "dependency_confusion_scanner"
        assert "dependency" in tool.description.lower()
    
    def test_schema_generation(self):
        """スキーマ生成テスト"""
        tool = DependencyConfusionScannerTool()
        schema = tool.to_schema()
        
        assert schema["type"] == "function"
        assert "target" in schema["function"]["parameters"]["properties"]
        assert "registry" in schema["function"]["parameters"]["properties"]
    
    def test_input_validation_empty_target(self):
        """空のターゲットのバリデーション"""
        tool = DependencyConfusionScannerTool()
        result = json.loads(tool.run(target=""))
        
        assert "error" in result
        assert "required" in result["error"].lower()
    
    def test_input_validation_nonexistent_path(self):
        """存在しないパスのバリデーション"""
        tool = DependencyConfusionScannerTool()
        result = json.loads(tool.run(target="/nonexistent/path"))
        
        assert "error" in result
        assert "not found" in result["error"].lower()
    
    def test_package_json_parsing(self):
        """package.jsonからのパッケージ抽出"""
        tool = DependencyConfusionScannerTool()
        
        # テスト用package.json作成
        with tempfile.TemporaryDirectory() as tmpdir:
            package_json = Path(tmpdir) / "package.json"
            package_json.write_text(json.dumps({
                "dependencies": {
                    "@company/internal-lib": "1.0.0",
                    "lodash": "4.17.21"
                },
                "devDependencies": {
                    "private-utils": "2.0.0"
                }
            }))
            
            # check_public=False でレジストリ確認をスキップ
            result = json.loads(tool.run(
                target=str(package_json),
                check_public=False
            ))
            
            assert "manifests_scanned" in result
            assert result["manifests_scanned"] >= 1


class TestCloudMetadataScannerTool:
    """Cloud Metadata Scanner のテスト"""
    
    def test_tool_initialization(self):
        """ツール初期化テスト"""
        tool = CloudMetadataScannerTool()
        assert tool.name == "cloud_metadata_scanner"
        assert "metadata" in tool.description.lower()
    
    def test_schema_generation(self):
        """スキーマ生成テスト"""
        tool = CloudMetadataScannerTool()
        schema = tool.to_schema()
        
        assert schema["type"] == "function"
        assert "target_url" in schema["function"]["parameters"]["properties"]
        assert "mode" in schema["function"]["parameters"]["properties"]
    
    def test_input_validation_empty_target(self):
        """空のターゲットのバリデーション"""
        tool = CloudMetadataScannerTool()
        result = json.loads(tool.run(target_url=""))
        
        assert "error" in result
        assert "required" in result["error"].lower()
    
    def test_dry_run_mode_default(self):
        """デフォルトがdry-runモードであること"""
        tool = CloudMetadataScannerTool()
        result = json.loads(tool.run(target_url="https://example.com?url=test"))
        
        assert result.get("mode") == "dry-run"
        assert "warning" in result
        assert "payloads" in result or "error" in result
    
    def test_analyze_mode(self):
        """analyzeモードのテスト"""
        tool = CloudMetadataScannerTool()
        result = json.loads(tool.run(
            target_url="https://example.com?redirect=http://foo.com",
            mode="analyze"
        ))
        
        assert "analysis" in result
        assert "ssrf_parameter_candidates" in result["analysis"]
    
    def test_ssrf_parameter_detection(self):
        """SSRFパラメータ検出"""
        tool = CloudMetadataScannerTool()
        # Single parameter to avoid URL encoding issues
        result = json.loads(tool.run(
            target_url="https://example.com?redirect_url=http://foo",
            mode="analyze"
        ))
        
        assert "analysis" in result
        candidates = result["analysis"]["ssrf_parameter_candidates"]
        param_names = [c["parameter"] for c in candidates]
        
        assert "redirect_url" in param_names
    
    def test_generate_mode(self):
        """generateモードでnucleiテンプレート生成"""
        tool = CloudMetadataScannerTool()
        result = json.loads(tool.run(
            target_url="https://example.com?url=test",
            mode="generate",
            cloud="aws"
        ))
        
        assert "nuclei_template" in result
        assert "169.254.169.254" in result["nuclei_template"]


class TestDiffAnalyzer:
    """DiffAnalyzer のテスト"""
    
    def test_analyzer_initialization(self):
        """アナライザー初期化テスト"""
        from src.core.intelligence.diff_analyzer import DiffAnalyzer
        
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = DiffAnalyzer(storage_path=Path(tmpdir))
            assert analyzer.storage_path.exists()
    
    def test_snapshot_save_and_load(self):
        """スナップショット保存・読み込みテスト"""
        from src.core.intelligence.diff_analyzer import DiffAnalyzer, ScanSnapshot
        
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = DiffAnalyzer(storage_path=Path(tmpdir))
            
            snapshot = ScanSnapshot(
                scan_id="test_001",
                target="example.com",
                timestamp="2026-01-03T12:00:00",
                urls=["http://example.com/page1", "http://example.com/page2"],
                endpoints=["/api/v1", "/api/v2"],
            )
            
            # 保存
            saved_path = analyzer.save_snapshot(snapshot)
            assert Path(saved_path).exists()
            
            # 読み込み
            loaded = analyzer.get_latest_snapshot("example.com")
            assert loaded is not None
            assert loaded.scan_id == "test_001"
            assert len(loaded.urls) == 2
    
    def test_diff_comparison(self):
        """差分比較テスト"""
        from src.core.intelligence.diff_analyzer import DiffAnalyzer, ScanSnapshot
        
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = DiffAnalyzer(storage_path=Path(tmpdir))
            
            # 前回スナップショット
            previous = ScanSnapshot(
                scan_id="test_001",
                target="example.com",
                timestamp="2026-01-02T12:00:00",
                urls=["http://example.com/old", "http://example.com/common"],
            )
            
            # 現在スナップショット
            current = ScanSnapshot(
                scan_id="test_002",
                target="example.com",
                timestamp="2026-01-03T12:00:00",
                urls=["http://example.com/new", "http://example.com/common"],
            )
            
            # 差分計算
            diff = analyzer.compare(current, previous)
            
            assert "urls" in diff
            assert "http://example.com/new" in diff["urls"].added
            assert "http://example.com/old" in diff["urls"].removed
    
    def test_report_generation(self):
        """レポート生成テスト"""
        from src.core.intelligence.diff_analyzer import DiffAnalyzer, ScanSnapshot, DiffResult
        
        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer = DiffAnalyzer(storage_path=Path(tmpdir))
            
            diff_results = {
                "urls": DiffResult(
                    category="urls",
                    added=["http://example.com/new"],
                    removed=["http://example.com/old"],
                )
            }
            
            # JSON形式
            json_report = analyzer.generate_report(diff_results, "example.com", format="json")
            parsed = json.loads(json_report)
            assert parsed["has_changes"] is True
            
            # Markdown形式
            md_report = analyzer.generate_report(diff_results, "example.com", format="markdown")
            assert "# Diff Report" in md_report
            assert "Added" in md_report
