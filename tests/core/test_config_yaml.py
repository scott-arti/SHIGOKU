import pytest
from src.config import settings, _load_yaml_cached
from src.core.reports.auto_reporter import AutoReporter
from src.core.models.finding import Finding, VulnType, Severity, Evidence
from pathlib import Path


class TestConfigYAMLLoader:
    """Phase 3: 設定外部化の検証テスト"""
    
    def test_load_yaml_cached_vulnerabilities(self):
        """vulnerabilities.yamlが正しくロードされるか"""
        data = _load_yaml_cached("vulnerabilities.yaml")
        
        assert "vuln_types" in data
        assert "JWT_ALG_NONE" in data["vuln_types"]
        
        jwt_info = data["vuln_types"]["JWT_ALG_NONE"]
        assert jwt_info["title"] == "JWT Algorithm Confusion (alg=none)"
        assert jwt_info["cwe"] == "CWE-347"
        assert jwt_info["category"] == "Broken Authentication"
        assert "remediation" in jwt_info
    
    def test_load_yaml_cached_tools(self):
        """tools.yamlが正しくロードされるか"""
        data = _load_yaml_cached("tools.yaml")
        
        assert "nuclei" in data
        assert "profiles" in data["nuclei"]
        assert "quick" in data["nuclei"]["profiles"]
        
        quick_profile = data["nuclei"]["profiles"]["quick"]
        assert "args" in quick_profile
        assert "description" in quick_profile
    
    def test_get_vuln_info(self):
        """settings.get_vuln_info()が正しく動作するか"""
        info = settings.get_vuln_info("JWT_ALG_NONE")
        
        assert info["title"] == "JWT Algorithm Confusion (alg=none)"
        assert info["cwe"] == "CWE-347"
        assert "remediation" in info
    
    def test_get_vuln_info_nonexistent(self):
        """存在しない脆弱性タイプでも空辞書を返すか"""
        info = settings.get_vuln_info("NONEXISTENT_VULN")
        
        assert info == {}
    
    def test_get_tool_profile(self):
        """settings.get_tool_profile()が正しく動作するか"""
        profile = settings.get_tool_profile("nuclei", "quick")
        
        assert "args" in profile
        assert "description" in profile
        assert profile["description"] == "高速スキャン（主要な脆弱性のみ）"
    
    def test_get_tool_profile_default(self):
        """デフォルトプロファイル（standard）が取得できるか"""
        profile = settings.get_tool_profile("nuclei")
        
        assert "args" in profile
        assert profile["description"] == "標準スキャン（推奨）"
    
    def test_yaml_caching(self):
        """YAMLファイルのキャッシングが機能しているか"""
        # 1回目
        data1 = _load_yaml_cached("vulnerabilities.yaml")
        # 2回目（キャッシュから取得されるはず）
        data2 = _load_yaml_cached("vulnerabilities.yaml")
        
        # 同一オブジェクトが返されるか（キャッシュ確認）
        assert data1 is data2


class TestAutoReporterWithYAML:
    """auto_reporter.pyのYAML統合テスト"""
    
    def test_generate_report_uses_yaml_config(self):
        """AutoReporterがYAML設定を使用して正しくレポートを生成するか
        
        自己チェックポイント:
        - インターフェース: generate_report()の引数・戻り値は変更なし
        - ロジック: 脆弱性情報取得のみ変更（辞書 → YAML）
        - 副作用: YAMLファイル読み込み追加（意図的）
        """
        reporter = AutoReporter()
        
        # テスト用Finding作成
        finding = Finding(
            vuln_type=VulnType.JWT_ALG_NONE,
            severity=Severity.CRITICAL,
            title="Test JWT Bypass",
            description="Test description",
            evidence=[
                Evidence(
                    type="request",
                    content="GET /api/test HTTP/1.1",
                    timestamp="2026-01-05T00:00:00"
                )
            ]
        )
        
        # レポート生成（YAMLから脆弱性情報を取得するはず）
        report = reporter.generate_report(finding, format="hackerone")
        
        # YAML設定の内容がレポートに反映されているか
        assert "## Vulnerability Type" in report
        assert "JWT Algorithm Confusion (alg=none)" in report
        assert "CWE-347" in report
        assert "Broken Authentication" in report
    
    def test_reporter_interface_unchanged(self):
        """AutoReporterのインターフェースが変更されていないか確認
        
        自己チェック: 引数・戻り値の型・数が同一であることを確認
        """
        reporter = AutoReporter()
        
        # __init__の引数確認（pam, rag_switch, triage_simulator）
        assert reporter._pam is None
        assert reporter._rag_switch is None
        assert reporter._triage_simulator is None
        
        # Findingオブジェクト作成
        finding = Finding(
            vuln_type=VulnType.IDOR,
            severity=Severity.HIGH,
            title="Test IDOR",
            description="Test"
        )
        
        # generate_report()の戻り値型確認（str）
        report = reporter.generate_report(finding)
        assert isinstance(report, str)
        
        # JSON形式でも正常動作するか
        report_json = reporter.generate_report(finding, format="json")
        assert isinstance(report_json, str)
