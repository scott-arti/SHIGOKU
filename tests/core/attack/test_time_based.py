"""
Time-based Blind Injection Tester ユニットテスト
"""
import pytest
from src.core.attack.time_based_tester import (
    TimeBasedBlindTester,
    BlindInjectionType,
    create_time_based_tester,
)


class TestTimeBasedBlindTester:
    """TimeBasedBlindTester テストクラス"""

    @pytest.fixture
    def tester(self):
        return create_time_based_tester(delay_seconds=5, baseline_samples=2)

    def test_sql_delay_payloads_exist(self, tester):
        """SQLi遅延ペイロードが存在"""
        assert len(tester.SQL_DELAY_PAYLOADS) > 0
        payloads = [p[0] for p in tester.SQL_DELAY_PAYLOADS]
        # SLEEP関数を含む
        assert any("SLEEP" in p for p in payloads)
        # pg_sleepを含む
        assert any("pg_sleep" in p for p in payloads)

    def test_nosql_delay_payloads_exist(self, tester):
        """NoSQLi遅延ペイロードが存在"""
        assert len(tester.NOSQL_DELAY_PAYLOADS) > 0
        payloads = [p[0] for p in tester.NOSQL_DELAY_PAYLOADS]
        assert any("$where" in p for p in payloads)

    def test_command_delay_payloads_exist(self, tester):
        """コマンドインジェクション遅延ペイロードが存在"""
        assert len(tester.COMMAND_DELAY_PAYLOADS) > 0
        payloads = [p[0] for p in tester.COMMAND_DELAY_PAYLOADS]
        assert any("sleep" in p for p in payloads)

    def test_get_payloads_sql(self, tester):
        """SQLペイロード取得"""
        payloads = tester._get_payloads(BlindInjectionType.SQL)
        assert len(payloads) == len(tester.SQL_DELAY_PAYLOADS)

    def test_get_payloads_nosql(self, tester):
        """NoSQLペイロード取得"""
        payloads = tester._get_payloads(BlindInjectionType.NOSQL)
        assert len(payloads) == len(tester.NOSQL_DELAY_PAYLOADS)

    def test_measure_baseline(self, tester):
        """ベースライン測定"""
        baseline = tester._measure_baseline(
            url="http://example.com",
            parameter="q",
            method="GET",
        )
        # シミュレーション値として0.1秒前後
        assert baseline > 0

    def test_test_payload_not_vulnerable(self, tester):
        """ペイロードテスト（非脆弱）"""
        result = tester._test_payload(
            url="http://example.com",
            parameter="q",
            payload="' AND SLEEP(5)--",
            injection_type=BlindInjectionType.SQL,
            baseline=0.1,
            method="GET",
        )
        assert result is not None
        # シミュレーションでは遅延なし
        assert result.vulnerable is False

    def test_test_with_confirmation(self, tester):
        """確認テスト"""
        result = tester.test_with_confirmation(
            url="http://example.com",
            parameter="id",
            payload_true="' AND 1=1 AND SLEEP(5)--",
            payload_false="' AND 1=2 AND SLEEP(5)--",
        )
        assert result is not None
        assert result.injection_type == BlindInjectionType.SQL

    def test_get_summary(self, tester):
        """サマリー取得"""
        tester.test(
            url="http://example.com",
            parameters=["id"],
            injection_types=[BlindInjectionType.SQL],
        )
        
        summary = tester.get_summary()
        assert "total_tests" in summary
        assert "delay_seconds" in summary
        assert summary["delay_seconds"] == 5

    def test_payload_template_substitution(self, tester):
        """ペイロードテンプレート置換"""
        template = "' AND SLEEP({delay})--"
        substituted = template.format(delay=tester.delay_seconds)
        assert "SLEEP(5)" in substituted
