"""
Time-based Blind Injection Tester - 時間ベースブラインドインジェクション検出

レスポンス遅延を統計的に検知し、
ブラインドSQLi/NoSQLi/コマンドインジェクション等を検出。

⚠️ 注意: 非破壊的なSLEEP/DELAYのみ使用
"""

import logging
import time
import statistics
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Callable
from enum import Enum

logger = logging.getLogger(__name__)


class BlindInjectionType(Enum):
    """ブラインドインジェクションタイプ"""
    SQL = "sql"
    NOSQL = "nosql"
    COMMAND = "command"
    XPATH = "xpath"
    LDAP = "ldap"
    TEMPLATE = "template"


@dataclass
class TimingResult:
    """タイミング測定結果"""
    url: str
    parameter: str
    injection_type: BlindInjectionType
    payload: str
    baseline_time: float  # ベースラインレスポンス時間
    injected_time: float  # インジェクション後のレスポンス時間
    time_diff: float      # 差分
    expected_delay: float # 期待された遅延
    vulnerable: bool = False
    confidence: float = 0.0
    severity: str = "high"
    
    def to_dict(self) -> Dict:
        return {
            "url": self.url,
            "parameter": self.parameter,
            "type": self.injection_type.value,
            "baseline": f"{self.baseline_time:.2f}s",
            "injected": f"{self.injected_time:.2f}s",
            "diff": f"{self.time_diff:.2f}s",
            "vulnerable": self.vulnerable,
            "confidence": self.confidence,
        }


class TimeBasedBlindTester:
    """
    Time-based Blind Injection Tester
    
    機能:
    - ベースライン測定（複数回）
    - 統計的遅延検知
    - 複数回確認によるFP削減
    - SQLi/NoSQLi/Command Injection対応
    
    ⚠️ 非破壊的なSLEEP系ペイロードのみ
    """
    
    # SQLi用遅延ペイロード
    SQL_DELAY_PAYLOADS = [
        # MySQL
        ("' AND SLEEP({delay})--", "mysql"),
        ("' AND SLEEP({delay}) AND '1'='1", "mysql"),
        ("1' AND SLEEP({delay})#", "mysql"),
        # PostgreSQL
        ("'; SELECT pg_sleep({delay})--", "postgresql"),
        ("' AND (SELECT pg_sleep({delay}))='", "postgresql"),
        # MSSQL
        ("'; WAITFOR DELAY '0:0:{delay}'--", "mssql"),
        ("' AND 1=1; WAITFOR DELAY '0:0:{delay}'--", "mssql"),
        # SQLite
        ("' AND (SELECT CASE WHEN (1=1) THEN (SELECT randomblob({delay}00000000)) END)--", "sqlite"),
        # Oracle
        ("' AND DBMS_LOCK.SLEEP({delay})--", "oracle"),
    ]
    
    # NoSQLi用遅延ペイロード
    NOSQL_DELAY_PAYLOADS = [
        # MongoDB (JavaScript)
        ('{"$where": "sleep({delay}000)"}', "mongodb"),
        ('{"$where": "function() { sleep({delay}000); return true; }"}', "mongodb"),
    ]
    
    # Command Injection用遅延ペイロード
    COMMAND_DELAY_PAYLOADS = [
        # Linux
        ("; sleep {delay}", "linux"),
        ("| sleep {delay}", "linux"),
        ("$(sleep {delay})", "linux"),
        ("`sleep {delay}`", "linux"),
        # Windows
        ("& ping -n {delay} 127.0.0.1 &", "windows"),
        ("| ping -n {delay} 127.0.0.1", "windows"),
    ]
    
    # XPathインジェクション
    XPATH_DELAY_PAYLOADS = [
        # XPath 2.0以降
        ("' and count(//*)>{delay}0000 and '1'='1", "xpath"),
    ]
    
    def __init__(
        self,
        delay_seconds: int = 5,
        baseline_samples: int = 3,
        confirmation_rounds: int = 2,
        threshold_ratio: float = 0.8,
        timeout: float = 30.0,
    ):
        """
        Args:
            delay_seconds: インジェクションで期待する遅延（秒）
            baseline_samples: ベースライン測定回数
            confirmation_rounds: 確認ラウンド数
            threshold_ratio: 脆弱性判定の閾値（期待遅延の割合）
            timeout: HTTPタイムアウト（秒）
        """
        self.delay_seconds = delay_seconds
        self.baseline_samples = baseline_samples
        self.confirmation_rounds = confirmation_rounds
        self.threshold_ratio = threshold_ratio
        self.timeout = timeout
        self.results: List[TimingResult] = []
    
    def test(
        self,
        url: str,
        parameters: List[str],
        method: str = "GET",
        injection_types: Optional[List[BlindInjectionType]] = None,
    ) -> List[TimingResult]:
        """
        時間ベースブラインドインジェクションテスト
        
        Args:
            url: テスト対象URL
            parameters: テスト対象パラメータ
            method: HTTPメソッド
            injection_types: テストするインジェクションタイプ
        
        Returns:
            検出結果リスト
        """
        if injection_types is None:
            injection_types = [BlindInjectionType.SQL]
        
        results = []
        
        for param in parameters:
            # ベースライン測定
            baseline = self._measure_baseline(url, param, method)
            
            for inj_type in injection_types:
                param_results = self._test_injection_type(
                    url=url,
                    parameter=param,
                    method=method,
                    injection_type=inj_type,
                    baseline=baseline,
                )
                results.extend(param_results)
        
        self.results.extend(results)
        return results
    
    def _measure_baseline(
        self,
        url: str,
        parameter: str,
        method: str,
    ) -> float:
        """
        ベースラインレスポンス時間を測定
        
        Returns:
            平均レスポンス時間（秒）
        """
        times = []
        
        for _ in range(self.baseline_samples):
            start = time.time()
            # プレースホルダー: 実際はリクエスト送信
            # requests.get(url, params={parameter: "normal_value"}, timeout=self.timeout)
            time.sleep(0.1)  # シミュレーション
            elapsed = time.time() - start
            times.append(elapsed)
        
        if times:
            return statistics.mean(times)
        return 0.5  # デフォルト
    
    def _test_injection_type(
        self,
        url: str,
        parameter: str,
        method: str,
        injection_type: BlindInjectionType,
        baseline: float,
    ) -> List[TimingResult]:
        """特定のインジェクションタイプをテスト"""
        results = []
        payloads = self._get_payloads(injection_type)
        
        for payload_template, variant in payloads:
            payload = payload_template.format(delay=self.delay_seconds)
            
            result = self._test_payload(
                url=url,
                parameter=parameter,
                payload=payload,
                injection_type=injection_type,
                baseline=baseline,
                method=method,
            )
            
            if result and result.vulnerable:
                results.append(result)
                # 1つ見つかれば次のパラメータへ
                break
        
        return results
    
    def _get_payloads(
        self,
        injection_type: BlindInjectionType,
    ) -> List[tuple]:
        """インジェクションタイプに応じたペイロード取得"""
        payload_map = {
            BlindInjectionType.SQL: self.SQL_DELAY_PAYLOADS,
            BlindInjectionType.NOSQL: self.NOSQL_DELAY_PAYLOADS,
            BlindInjectionType.COMMAND: self.COMMAND_DELAY_PAYLOADS,
            BlindInjectionType.XPATH: self.XPATH_DELAY_PAYLOADS,
        }
        return payload_map.get(injection_type, [])
    
    def _test_payload(
        self,
        url: str,
        parameter: str,
        payload: str,
        injection_type: BlindInjectionType,
        baseline: float,
        method: str,
    ) -> Optional[TimingResult]:
        """
        単一ペイロードテスト
        """
        logger.info(
            "Testing time-based blind: %s=%s on %s",
            parameter, payload[:30], url
        )
        
        times = []
        
        for round_num in range(self.confirmation_rounds):
            start = time.time()
            # プレースホルダー: 実際はリクエスト送信
            # requests.get(url, params={parameter: payload}, timeout=self.timeout)
            time.sleep(0.1)  # シミュレーション
            elapsed = time.time() - start
            times.append(elapsed)
        
        if not times:
            return None
        
        avg_time = statistics.mean(times)
        time_diff = avg_time - baseline
        expected_delay = float(self.delay_seconds)
        
        # 脆弱性判定
        vulnerable = False
        confidence = 0.0
        
        if time_diff >= expected_delay * self.threshold_ratio:
            vulnerable = True
            # 信頼度計算
            if time_diff >= expected_delay:
                confidence = 0.9
            else:
                confidence = 0.5 + (time_diff / expected_delay) * 0.4
        
        return TimingResult(
            url=url,
            parameter=parameter,
            injection_type=injection_type,
            payload=payload,
            baseline_time=baseline,
            injected_time=avg_time,
            time_diff=time_diff,
            expected_delay=expected_delay,
            vulnerable=vulnerable,
            confidence=confidence,
        )
    
    def test_with_confirmation(
        self,
        url: str,
        parameter: str,
        payload_true: str,
        payload_false: str,
        injection_type: BlindInjectionType = BlindInjectionType.SQL,
    ) -> Optional[TimingResult]:
        """
        真偽条件による確認テスト
        
        Args:
            url: テスト対象URL
            parameter: テスト対象パラメータ
            payload_true: 条件が真のときのペイロード
            payload_false: 条件が偽のときのペイロード
            injection_type: インジェクションタイプ
        
        Returns:
            検出結果
        """
        # 真条件のテスト
        true_times = self._measure_response_times(url, parameter, payload_true)
        
        # 偽条件のテスト
        false_times = self._measure_response_times(url, parameter, payload_false)
        
        if not true_times or not false_times:
            return None
        
        true_avg = statistics.mean(true_times)
        false_avg = statistics.mean(false_times)
        
        # 有意な差があれば脆弱
        time_diff = abs(true_avg - false_avg)
        
        return TimingResult(
            url=url,
            parameter=parameter,
            injection_type=injection_type,
            payload=f"TRUE: {payload_true[:20]}... / FALSE: {payload_false[:20]}...",
            baseline_time=false_avg,
            injected_time=true_avg,
            time_diff=time_diff,
            expected_delay=float(self.delay_seconds),
            vulnerable=time_diff >= self.delay_seconds * self.threshold_ratio,
            confidence=min(0.95, 0.5 + time_diff / self.delay_seconds * 0.45),
        )
    
    def _measure_response_times(
        self,
        url: str,
        parameter: str,
        payload: str,
        rounds: int = 3,
    ) -> List[float]:
        """複数回レスポンス時間を測定"""
        times = []
        
        for _ in range(rounds):
            start = time.time()
            # プレースホルダー
            time.sleep(0.1)
            elapsed = time.time() - start
            times.append(elapsed)
        
        return times
    
    def get_vulnerable(self) -> List[TimingResult]:
        """脆弱と判定された結果のみ"""
        return [r for r in self.results if r.vulnerable]
    
    def get_summary(self) -> Dict:
        """サマリー"""
        by_type = {}
        
        for r in self.results:
            by_type[r.injection_type.value] = by_type.get(r.injection_type.value, 0) + (1 if r.vulnerable else 0)
        
        return {
            "total_tests": len(self.results),
            "vulnerable": len(self.get_vulnerable()),
            "by_type": by_type,
            "delay_seconds": self.delay_seconds,
        }
    
    def get_summary_for_ai(self) -> str:
        """AI向けサマリー"""
        summary = self.get_summary()
        return (
            f"Time-based Blind Test: {summary['total_tests']} tests\n"
            f"Vulnerable: {summary['vulnerable']}\n"
            f"By type: {summary['by_type']}\n"
            f"Delay: {summary['delay_seconds']}s"
        )


def create_time_based_tester(
    delay_seconds: int = 5,
    baseline_samples: int = 3,
) -> TimeBasedBlindTester:
    """TimeBasedBlindTester作成ヘルパー"""
    return TimeBasedBlindTester(
        delay_seconds=delay_seconds,
        baseline_samples=baseline_samples,
    )
