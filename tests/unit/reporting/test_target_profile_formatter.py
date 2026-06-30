"""
Tests for TargetProfileFormatter: session JSON → Japanese Markdown profile report.
"""
import pytest

from src.reporting.target_profile_formatter import TargetProfileFormatter


@pytest.fixture
def full_session():
    return {
        "session_id": "test-profile-session",
        "start_time": 1719240000.0,
        "context": {
            "target_info": {
                "url": "http://example.com",
                "domain": "example.com",
                "domains": ["example.com", "api.example.com"],
                "ip_addresses": ["10.0.0.1", "10.0.0.2"],
                "tech_stack": {"framework": "Django 4.2", "server": "nginx/1.24", "language": "Python 3.11"},
                "fingerprint_metadata": {"cms": "WordPress 6.5", "plugins": ["woocommerce"]},
                "detected_services": [
                    {"name": "nginx", "port": 443, "version": "1.24"},
                    {"name": "postgresql", "port": 5432, "version": "15"},
                ],
                "pages_discovered": [
                    {"url": "http://example.com/login", "path": "/login"},
                    {"url": "http://example.com/admin", "path": "/admin"},
                ],
                "api_endpoints": [
                    {"url": "http://api.example.com/v1/users", "path": "/v1/users"},
                    {"url": "http://api.example.com/v1/products", "path": "/v1/products"},
                ],
                "auth_mechanisms": ["JWT", "OAuth2"],
                "session_management": "Cookie-based session with HttpOnly",
                "authorization_model": "RBAC",
            },
            "discovered_assets": [
                {"url": "http://example.com/assets/script.js", "type": "page"},
            ],
            "pending_hitl": [{"title": "Manual review of auth bypass", "description": "Skip deferred"}],
            "scenario_coverage": {
                "missing_scenarios": ["scn_01_idor_bola_object_access", "scn_05_rate_limiting_abuse"],
                "covered_count": 10,
                "required_count": 12,
                "coverage_items": [
                    {"scenario_id": "scn_01_idor_bola_object_access", "number": 1,
                     "title": "IDOR/BOLA Object Access", "route": "shigoku_only", "covered": False, "count": 0},
                    {"scenario_id": "scn_02_mass_assignment_object_update", "number": 2,
                     "title": "Mass Assignment Object Update", "route": "shigoku_only", "covered": True, "count": 3},
                ],
            },
            "coverage_gate": {
                "required_families": ["access_control", "injection", "xss", "csrf", "auth", "business_logic", "api"],
                "reached_families": ["access_control", "xss"],
                "missing_families": ["injection", "csrf", "auth", "business_logic", "api"],
                "gate_passed": False,
            },
        },
        "completed_tasks": [
            {"id": "task_1", "target_url": "http://example.com/profile",
             "result": {"findings": [
                 {"title": "IDOR on user profile", "severity": "high", "type": "idor",
                  "target_url": "http://example.com/profile?user=1", "heuristic_candidate": True},
             ]}},
            {"id": "task_2", "target_url": "http://example.com/search?q=test",
             "result": {"findings": [
                 {"title": "Reflected XSS", "severity": "medium", "type": "xss",
                  "target_url": "http://example.com/search?q=test", "heuristic_candidate": False},
             ]}},
            {"id": "task_xss", "target_url": "http://example.com/search",
             "result": {"findings": [
                 {"title": "Confirmed XSS", "severity": "medium", "type": "xss",
                  "target_url": "http://example.com/search?q=PAYLOAD", "finding_id": "F001", "heuristic_candidate": False},
             ]}},
            {"id": "task_auth", "target_url": "http://example.com/oauth/callback",
             "tags": ["auth", "oauth"], "note": "OAuth2 flow detected"},
        ],
        "task_execution_records": [
            {"task_id": "task_1", "target_url": "http://example.com/profile", "result": "success"},
        ],
        "scenario_coverage": {
            "missing_scenarios": ["scn_01_idor_bola_object_access", "scn_05_rate_limiting_abuse"],
            "covered_count": 10, "required_count": 12,
            "coverage_items": [
                {"scenario_id": "scn_01_idor_bola_object_access", "number": 1,
                 "title": "IDOR/BOLA", "route": "shigoku_only", "covered": False, "count": 0},
                {"scenario_id": "scn_02_mass_assignment_object_update", "number": 2,
                 "title": "Mass Assignment", "route": "shigoku_only", "covered": True, "count": 3},
            ],
        },
        "coverage_gate": {
            "required_families": ["access_control", "injection", "xss", "csrf", "auth", "business_logic", "api"],
            "reached_families": ["access_control", "xss"],
            "missing_families": ["injection", "csrf", "auth", "business_logic", "api"],
            "gate_passed": False,
        },
        "decision_traces": [
            {"decision_id": "dec_skip", "action": "skip", "target": "scn_08_oob_external_channel_flow",
             "reason": "low priority"},
        ],
    }


# ---------------------------------------------------------------------------
# Basic formatting
# ---------------------------------------------------------------------------

def test_format_returns_string(full_session):
    formatter = TargetProfileFormatter()
    result = formatter.format(full_session)
    assert isinstance(result, str)
    assert len(result) > 0


def test_format_contains_header(full_session):
    formatter = TargetProfileFormatter()
    result = formatter.format(full_session)
    assert "# ターゲットプロファイルレポート" in result
    assert "test-profile-session" in result


# ---------------------------------------------------------------------------
# Section 1: ターゲット概要
# ---------------------------------------------------------------------------

def test_section_1_target_overview(full_session):
    formatter = TargetProfileFormatter()
    result = formatter.format(full_session)
    assert "## 1. ターゲット概要" in result
    assert "`http://example.com/`" in result
    assert "`example.com`" in result
    assert "`10.0.0.1`" in result
    assert "`10.0.0.2`" in result
    assert "test-profile-session" in result


# ---------------------------------------------------------------------------
# Section 2: 検出機能概要
# ---------------------------------------------------------------------------

def test_section_2_discovered_features(full_session):
    formatter = TargetProfileFormatter()
    result = formatter.format(full_session)
    assert "## 2. 検出機能概要" in result
    # pages discovered
    assert "### ページ" in result
    assert "`http://example.com/login`" in result
    assert "`http://example.com/admin`" in result
    # api endpoints
    assert "### APIエンドポイント" in result
    assert "`http://api.example.com/v1/users`" in result
    assert "`http://api.example.com/v1/products`" in result


# ---------------------------------------------------------------------------
# Section 3: 技術スタック
# ---------------------------------------------------------------------------

def test_section_3_tech_stack(full_session):
    formatter = TargetProfileFormatter()
    result = formatter.format(full_session)
    assert "## 3. 技術スタック" in result
    assert "Django 4.2" in result
    assert "nginx/1.24" in result
    assert "Python 3.11" in result
    assert "WordPress 6.5" in result
    # detected_services
    assert "### 検出サービス" in result
    assert "nginx" in result
    assert "postgresql" in result


# ---------------------------------------------------------------------------
# Section 4: 認証機構
# ---------------------------------------------------------------------------

def test_section_4_auth_mechanisms(full_session):
    formatter = TargetProfileFormatter()
    result = formatter.format(full_session)
    assert "## 4. 認証機構" in result
    assert "JWT" in result
    assert "OAuth2" in result
    assert "Cookie-based session with HttpOnly" in result
    assert "RBAC" in result
    # auth info from completed_tasks
    assert "OAuth2 flow detected" in result


# ---------------------------------------------------------------------------
# Section 5: URL・API・ページ統計
# ---------------------------------------------------------------------------

def test_section_5_url_statistics(full_session):
    formatter = TargetProfileFormatter()
    result = formatter.format(full_session)
    assert "## 5. URL・API・ページ統計" in result
    # table headers
    assert "| 種別 | URL | 発見元 | 備考 |" in result
    # url entries should be present (normalized, query params stripped)
    assert "`http://example.com/profile`" in result
    assert "`http://example.com/assets/script.js`" in result
    assert "`http://example.com/oauth/callback`" in result
    # summary section
    assert "### 集計サマリ" in result
    assert "総ユニークURL数" in result
    assert "ページ数" in result
    assert "重複排除" in result


# ---------------------------------------------------------------------------
# Section 6: 攻撃面分析
# ---------------------------------------------------------------------------

def test_section_6_attack_surface(full_session):
    formatter = TargetProfileFormatter()
    result = formatter.format(full_session)
    assert "## 6. 攻撃面分析" in result
    assert "総Finding数" in result
    # should have attack surface categories
    assert "| 攻撃面カテゴリ | Finding数 | 割合 |" in result
    # idor → 認可, xss → 入力検証
    assert "認可" in result
    assert "入力検証" in result


# ---------------------------------------------------------------------------
# Section 7: Finding・仮説一覧
# ---------------------------------------------------------------------------

def test_section_7_findings_list(full_session):
    formatter = TargetProfileFormatter()
    result = formatter.format(full_session)
    assert "## 7. Finding・仮説一覧" in result
    assert "| Finding | Finding ID | 深刻度 | 種別 | URL | 確度 | 発見元 |" in result
    # findings should appear (ordered by severity: high first, then medium)
    assert "IDOR on user profile" in result
    assert "Reflected XSS" in result
    assert "Confirmed XSS" in result
    # severity emoji markers
    assert "🟠" in result  # high
    assert "🟡" in result  # medium


# ---------------------------------------------------------------------------
# Section 8: 次回推奨シナリオ
# ---------------------------------------------------------------------------

def test_section_8_recommended_scenarios(full_session):
    formatter = TargetProfileFormatter()
    result = formatter.format(full_session)
    assert "## 8. 次回推奨シナリオ" in result
    # missing scenarios as recommendations
    assert "scn_01_idor_bola_object_access" in result
    assert "scn_05_rate_limiting_abuse" in result
    # uncovered items
    assert "IDOR/BOLA" in result or "IDOR/BOLA Object Access" in result
    # missing families
    assert "### 未カバー脆弱性ファミリー" in result
    assert "injection" in result
    assert "csrf" in result
    assert "auth" in result
    assert "business_logic" in result
    assert "api" in result


# ---------------------------------------------------------------------------
# Section 9: 未検証領域
# ---------------------------------------------------------------------------

def test_section_9_unverified_areas(full_session):
    formatter = TargetProfileFormatter()
    result = formatter.format(full_session)
    assert "## 9. 未検証領域" in result
    # missing scenarios
    assert "### 未実施シナリオ" in result
    assert "scn_01_idor_bola_object_access" in result
    assert "scn_05_rate_limiting_abuse" in result
    # missing families
    assert "### 未カバー脆弱性ファミリー" in result
    assert "injection" in result
    assert "csrf" in result
    # pending HITL
    assert "### 保留中HITL項目" in result
    assert "Manual review of auth bypass" in result
    # skipped areas
    assert "### スキップされた領域" in result
    assert "scn_08_oob_external_channel_flow" in result


# ===========================================================================
# Edge Cases
# ===========================================================================

class TestTargetProfileFormatterEdgeCases:

    def test_empty_session_not_crash(self):
        formatter = TargetProfileFormatter()
        result = formatter.format({})
        assert isinstance(result, str)
        assert len(result) > 0
        assert "# ターゲットプロファイルレポート" in result
        # should contain fallback messages for empty sections
        assert "No data in source session" in result

    def test_session_none_not_crash(self):
        formatter = TargetProfileFormatter()
        result = formatter.format(None)
        assert isinstance(result, str)
        assert "# ターゲットプロファイルレポート" in result

    def test_session_with_minimal_target_info(self):
        session = {
            "session_id": "min-session",
            "context": {
                "target_info": {
                    "url": "http://min.example.com",
                }
            }
        }
        formatter = TargetProfileFormatter()
        result = formatter.format(session)
        assert "## 1. ターゲット概要" in result
        assert "http://min.example.com" in result
        # other sections should show fallback
        assert "No data in source session" in result or "なし" in result

    def test_url_masking_strips_query_params(self):
        session = {
            "session_id": "url-mask-session",
            "context": {
                "target_info": {
                    "url": "http://example.com",
                },
                "discovered_assets": [
                    {"url": "http://example.com/page?secret=abc123", "type": "page"},
                ],
            },
            "completed_tasks": [
                {"id": "t1", "target_url": "http://example.com/api?token=xyz&user=1"},
            ],
            "findings": [],
        }
        formatter = TargetProfileFormatter()
        result = formatter.format(session)
        # query params should be stripped
        assert "secret=abc123" not in result
        assert "token=xyz" not in result
        assert "?user=1" not in result
        # base URLs should be present
        assert "http://example.com/page" in result
        assert "http://example.com/api" in result

    def test_finding_confidence_markers(self):
        session = {
            "session_id": "conf-test",
            "completed_tasks": [
                {"id": "t1", "target_url": "http://example.com",
                 "result": {"findings": [
                     {"title": "Confirmed Bug", "severity": "high", "type": "xss",
                      "target_url": "http://example.com", "heuristic_candidate": False},
                 ]}},
                {"id": "t2", "target_url": "http://example.com",
                 "result": {"findings": [
                     {"title": "Heuristic Hit", "severity": "medium", "type": "sqli",
                      "target_url": "http://example.com", "heuristic_candidate": True},
                 ]}},
            ],
        }
        formatter = TargetProfileFormatter()
        result = formatter.format(session)
        # heuristic_candidate=False → 確認
        assert "確認" in result
        # heuristic_candidate=True → 推定
        assert "推定" in result

    def test_scenario_coverage_in_context_and_root(self):
        """scenario_coverage exists in both context and root level.
        Formatter should prefer context.scenario_coverage."""
        session = {
            "session_id": "dual-coverage",
            "context": {
                "scenario_coverage": {
                    "missing_scenarios": ["scn_context_only"],
                    "coverage_items": [],
                },
            },
            "scenario_coverage": {
                "missing_scenarios": ["scn_root_only"],
                "coverage_items": [],
            },
        }
        formatter = TargetProfileFormatter()
        result = formatter.format(session)
        # context value should win
        assert "scn_context_only" in result
        assert "scn_root_only" not in result

    def test_completed_tasks_with_tags_classifies_auth(self):
        session = {
            "session_id": "auth-tag-test",
            "context": {"target_info": {}},
            "completed_tasks": [
                {"id": "t_auth", "target_url": "http://example.com/login",
                 "tags": ["auth", "oauth"], "note": "OAuth endpoint"},
            ],
        }
        formatter = TargetProfileFormatter()
        result = formatter.format(session)
        # in section 2: should classify as 認証関連機能
        assert "認証関連機能" in result or "auth-related" in result
        # in section 4: note should appear
        assert "OAuth endpoint" in result

    def test_section_5_collects_urls_from_target_info_pages_and_apis(self):
        """Verify that context.target_info.pages_discovered and api_endpoints
        contribute to Section 5 URL statistics, even when completed_tasks and
        task_execution_records are empty."""
        session = {
            "session_id": "target-info-url-test",
            "context": {
                "target_info": {
                    "pages_discovered": [
                        {"url": "http://example.com/page1"},
                        {"url": "http://example.com/page2?id=1"},
                    ],
                    "api_endpoints": [
                        {"url": "http://api.example.com/v1/users"},
                    ],
                },
            },
            "completed_tasks": [],
            "task_execution_records": [],
        }
        formatter = TargetProfileFormatter()
        result = formatter.format(session)
        # Should not show "URL/APIデータなし"
        assert "URL/APIデータなし" not in result
        # Should contain the target_info-originating URLs
        assert "example.com/page1" in result
        assert "api.example.com/v1/users" in result
        # Should count at least 3 unique URLs (2 pages + 1 API)
        assert "総ユニークURL数:" in result

    def test_section_7_includes_finding_id_column(self):
        """Verify that Section 7 table has a Finding ID column with traceability references."""
        session = {
            "session_id": "finding-id-test",
            "findings": [
                {"title": "XSS", "severity": "high", "vuln_type": "xss",
                 "target_url": "http://example.com/search", "finding_id": "F-001"},
            ],
        }
        formatter = TargetProfileFormatter()
        result = formatter.format(session)
        # Table header should include Finding ID
        assert "Finding ID" in result
        # Row should contain the finding_id value
        assert "F-001" in result

    def test_no_vulnerabilities_shows_no_findings(self):
        session = {
            "session_id": "no-vulns",
            "context": {"target_info": {"url": "http://example.com"}},
            "findings": [],
            "completed_tasks": [],
        }
        formatter = TargetProfileFormatter()
        result = formatter.format(session)
        assert "## 7. Finding" in result
        assert "発見事項なし" in result

    def test_findings_extracted_from_result_deep_paths(self):
        """Verify target_profile extracts findings from all result.* paths."""
        session = {
            "completed_tasks": [
                {
                    "id": "task_1",
                    "result": {
                        "findings": [{"title": "Deep Finding", "severity": "high", "type": "idor"}],
                    },
                },
            ],
        }
        formatter = TargetProfileFormatter()
        result = formatter.format(session)
        assert "Deep Finding" in result

    def test_section_8_scenarios_not_duplicated(self):
        """Verify that when coverage_items and missing_scenarios overlap,
        Section 8 does not produce duplicate rows."""
        session = {
            "scenario_coverage": {
                "coverage_items": [
                    {"scenario_id": "scn_01_idor_bola_object_access", "number": 1,
                     "title": "IDOR", "route": "shigoku_only", "covered": False, "count": 0},
                ],
                "missing_scenarios": [
                    "scn_01_idor_bola_object_access",  # same as coverage_item
                    "scn_02_mass_assignment_object_update",  # unique
                ],
                "covered_count": 10,
                "required_count": 12,
            },
        }
        formatter = TargetProfileFormatter()
        result = formatter.format(session)
        # Extract only Section 8 portion to avoid counting Section 9 references
        section_8_start = result.find("## 8. 次回推奨シナリオ")
        section_9_start = result.find("## 9. 未検証領域")
        section_8 = result[section_8_start:section_9_start] if section_9_start != -1 else result[section_8_start:]
        # scn_01 should appear exactly once within Section 8
        assert section_8.count("scn_01_idor_bola_object_access") == 1
        # scn_02 should still appear
        assert "scn_02_mass_assignment_object_update" in section_8


def test_section_5_aggregation_method_includes_target_info_sources():
    """Verify that the aggregation method description in Section 5
    lists target_info.pages_discovered and target_info.api_endpoints."""
    session = {
        "context": {
            "target_info": {
                "pages_discovered": [{"url": "http://example.com/page1"}],
                "api_endpoints": [{"url": "http://api.example.com/v1/"}],
            },
        },
        "completed_tasks": [],
        "task_execution_records": [],
    }
    formatter = TargetProfileFormatter()
    result = formatter.format(session)
    assert "集計方法:" in result
    assert "context.target_info.pages_discovered" in result
    assert "context.target_info.api_endpoints" in result


# ---------------------------------------------------------------------------
# Phase 1 (SGK-2026-0310): formatter compatibility with execution contract metadata
# ---------------------------------------------------------------------------

class TestTargetProfileFormatterPhase1Metadata:
    """TargetProfileFormatter must not crash when session dicts contain Phase 1 metadata."""

    def test_metadata_in_completed_tasks_does_not_crash(self, full_session):
        """Metadata in completed_tasks entries must not cause formatter errors."""
        if full_session.get("completed_tasks"):
            full_session["completed_tasks"][0]["metadata"] = {
                "target_key": "http://example.com",
                "origin_key": "recon://scenario-1",
                "schema_version": 1,
                "lifecycle_status": "admitted",
            }
        full_session["task_queue"] = full_session.get("task_queue", [])
        if full_session["task_queue"]:
            full_session["task_queue"][0]["metadata"] = {"correlation_id": "corr-abc"}

        formatter = TargetProfileFormatter()
        report = formatter.format(full_session)

        assert isinstance(report, str)
        assert len(report) > 0

    def test_empty_metadata_in_tasks_does_not_crash(self, full_session):
        """Empty metadata dicts must not cause formatter errors."""
        if full_session.get("completed_tasks"):
            full_session["completed_tasks"][0]["metadata"] = {}
        full_session["task_queue"] = full_session.get("task_queue", [])
        if full_session["task_queue"]:
            full_session["task_queue"][0]["metadata"] = {}

        formatter = TargetProfileFormatter()
        report = formatter.format(full_session)

        assert isinstance(report, str)
        assert len(report) > 0

    def test_minimal_session_with_only_metadata_does_not_crash(self):
        """A minimal session with only metadata in tasks must not crash."""
        session = {
            "start_time": 100.0,
            "timestamp": 200.0,
            "context": {
                "target_info": {
                    "url": "http://example.com",
                    "program": "Test",
                    "start_time": 100.0,
                }
            },
            "completed_tasks": [
                {
                    "id": "task-1",
                    "name": "Test Task",
                    "state": "success",
                    "metadata": {
                        "target_key": "http://example.com",
                        "origin_key": "recon://scenario-1",
                        "schema_version": 1,
                        "lifecycle_status": "admitted",
                    },
                }
            ],
            "task_queue": [],
        }

        formatter = TargetProfileFormatter()
        report = formatter.format(session)

        assert isinstance(report, str)
        assert len(report) > 0
