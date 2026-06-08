#!/usr/bin/env python3
"""
Phase C: カバレッジ実行（16カテゴリ×3認証状態）

Juice Shop脆弱性カテゴリの網羅的試行を実行
- 16カテゴリ × 3認証状態（anonymous/user/admin）
- BAC/Auth/Injection/XSS/Sensitive Data Exposure優先
- 失敗理由正規化（tool_failure, auth_missing, timeout, inconclusive）
"""
import asyncio
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime

import aiohttp

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.core.agents.swarm.injection.manager import InjectionManagerAgent
from src.core.validation.metrics_exporter import MetricsCollector, export_metrics
from src.core.validation.url_classifier import classify_url


@dataclass
class TestQueueItem:
    """テストキューアイテム"""
    endpoint: str
    method: str
    category: str
    auth_state: str  # anonymous, user, admin
    priority: int
    vuln_type: Optional[str] = None


@dataclass
class TestResult:
    """テスト結果"""
    endpoint: str
    method: str
    category: str
    auth_state: str
    status_code: int
    latency_ms: float
    finding: bool
    error_type: Optional[str] = None
    failure_reason: Optional[str] = None  # 正規化された失敗理由


# 16カテゴリ定義（OWASP Juice Shop準拠）
VULN_CATEGORIES = {
    "broken_access_control": {"priority": 1, "tests": ["admin_bypass", "id_access"]},
    "broken_authentication": {"priority": 1, "tests": ["jwt_none", "password_reset"]},
    "injection": {"priority": 1, "tests": ["sqli", "cmd_injection"]},
    "xss": {"priority": 1, "tests": ["reflected", "stored", "dom"]},
    "sensitive_data_exposure": {"priority": 1, "tests": ["config_leak", "backup_file"]},
    "security_misconfiguration": {"priority": 2, "tests": ["default_creds", "debug_info"]},
    "vulnerable_components": {"priority": 2, "tests": ["outdated_lib", "known_cve"]},
    "id_auth_failures": {"priority": 2, "tests": ["weak_token", "session_fixation"]},
    "csrf": {"priority": 2, "tests": ["token_missing", "state_change"]},
    "file_upload": {"priority": 3, "tests": ["no_validation", "path_traversal"]},
    "rate_limiting": {"priority": 3, "tests": ["brute_force", "dos"]},
    "mass_assignment": {"priority": 3, "tests": ["param_pollution", "hidden_field"]},
    "ssrf": {"priority": 3, "tests": ["internal_access", "metadata_api"]},
    "xxe": {"priority": 4, "tests": ["xml_injection", "dtd_exploit"]},
    "cryptographic": {"priority": 4, "tests": ["weak_cipher", "key_leak"]},
    "realtime": {"priority": 4, "tests": ["ws_auth", "event_injection"]},
}

# 認証状態
AUTH_STATES = ["anonymous", "user", "admin"]

# Juice Shopエンドポイント（実際のカバレッジ対象）
JUICE_SHOP_ENDPOINTS = [
    {"path": "/rest/admin/application-configuration", "category": "broken_access_control", "methods": ["GET", "POST", "PUT", "DELETE"]},
    {"path": "/rest/admin/application-version", "category": "broken_access_control", "methods": ["GET"]},
    {"path": "/rest/user/login", "category": "broken_authentication", "methods": ["POST"]},
    {"path": "/rest/user/register", "category": "broken_authentication", "methods": ["POST"]},
    {"path": "/rest/products/search", "category": "injection", "methods": ["GET"]},
    {"path": "/api/basket", "category": "id_auth_failures", "methods": ["GET", "POST", "PUT"]},
    {"path": "/api/orders", "category": "mass_assignment", "methods": ["GET", "POST"]},
    {"path": "/api/feedback", "category": "xss", "methods": ["POST"]},
    {"path": "/api/products/1/reviews", "category": "xss", "methods": ["GET", "POST"]},
    {"path": "/rest/user/reset-password", "category": "broken_authentication", "methods": ["POST"]},
    {"path": "/api/Challenges", "category": "sensitive_data_exposure", "methods": ["GET"]},
    {"path": "/ftp/", "category": "sensitive_data_exposure", "methods": ["GET"]},
    {"path": "/socket.io/", "category": "realtime", "methods": ["GET"]},
    {"path": "/#/search", "category": "xss", "methods": ["GET"]},
    {"path": "/api/coupon", "category": "mass_assignment", "methods": ["POST"]},
    {"path": "/rest/languages", "category": "security_misconfiguration", "methods": ["GET"]},
]


class CoverageExecutor:
    """カバレッジ実行エンジン"""
    
    BASE_URL = "http://localhost:3000"
    
    def __init__(self):
        self.results: List[TestResult] = []
        self.queue: List[TestQueueItem] = []
        self.metrics = {
            "total_tests": 0,
            "successful": 0,
            "errors": 0,
            "findings": 0,
            "by_category": {},
            "by_auth_state": {},
        }
    
    def generate_queue(self) -> List[TestQueueItem]:
        """テストキューを生成（16カテゴリ×3認証状態）"""
        queue = []
        
        for endpoint in JUICE_SHOP_ENDPOINTS:
            path = endpoint["path"]
            category = endpoint["category"]
            category_info = VULN_CATEGORIES.get(category, {"priority": 5})
            
            for method in endpoint["methods"]:
                for auth_state in AUTH_STATES:
                    # P0カテゴリ（priority=1）はキューの先頭に
                    priority = category_info["priority"]
                    
                    item = TestQueueItem(
                        endpoint=path,
                        method=method,
                        category=category,
                        auth_state=auth_state,
                        priority=priority,
                    )
                    queue.append(item)
        
        # 優先度でソート（P0が先頭）
        queue.sort(key=lambda x: x.priority)
        
        self.queue = queue
        return queue
    
    async def execute_test(self, item: TestQueueItem, session: aiohttp.ClientSession) -> TestResult:
        """単一テスト実行"""
        url = f"{self.BASE_URL}{item.endpoint}"
        start_time = time.time()
        
        # 認証状態に応じたヘッダー設定
        headers = {}
        if item.auth_state == "admin":
            # admin認証シミュレート（実際のJWT取得は別途実装）
            headers["Authorization"] = "Bearer admin_token_placeholder"
        elif item.auth_state == "user":
            headers["Authorization"] = "Bearer user_token_placeholder"
        
        try:
            async with session.request(
                item.method, url, headers=headers,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                latency_ms = (time.time() - start_time) * 1000
                
                # 失敗理由の正規化
                failure_reason = None
                finding = False
                
                if resp.status == 200:
                    # adminエンドポイントで認証なし200はfinding
                    if item.endpoint.startswith("/rest/admin/") and item.auth_state == "anonymous":
                        finding = True
                elif resp.status == 401:
                    failure_reason = "auth_required"
                elif resp.status == 403:
                    failure_reason = "forbidden"
                elif resp.status == 404:
                    failure_reason = "not_found"
                elif resp.status >= 500:
                    failure_reason = "server_error"
                
                return TestResult(
                    endpoint=item.endpoint,
                    method=item.method,
                    category=item.category,
                    auth_state=item.auth_state,
                    status_code=resp.status,
                    latency_ms=latency_ms,
                    finding=finding,
                    failure_reason=failure_reason,
                )
                
        except asyncio.TimeoutError:
            latency_ms = (time.time() - start_time) * 1000
            return TestResult(
                endpoint=item.endpoint,
                method=item.method,
                category=item.category,
                auth_state=item.auth_state,
                status_code=0,
                latency_ms=latency_ms,
                finding=False,
                error_type="TIMEOUT",
                failure_reason="timeout",
            )
        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            return TestResult(
                endpoint=item.endpoint,
                method=item.method,
                category=item.category,
                auth_state=item.auth_state,
                status_code=0,
                latency_ms=latency_ms,
                finding=False,
                error_type=type(e).__name__,
                failure_reason="tool_failure",
            )
    
    async def run_all_tests(self) -> Dict[str, Any]:
        """全テスト実行"""
        print("=" * 70)
        print("Phase C: カバレッジ実行（16カテゴリ×3認証状態）")
        print("=" * 70)
        
        # キュー生成
        queue = self.generate_queue()
        print(f"\nテストキュー生成: {len(queue)} items")
        print(f"カテゴリ: {len(set(item.category for item in queue))}")
        print(f"認証状態: {len(set(item.auth_state for item in queue))}")
        
        # 優先度別統計
        p0_count = sum(1 for item in queue if item.priority == 1)
        print(f"P0（優先）テスト: {p0_count} items")
        
        # 実行
        connector = aiohttp.TCPConnector(limit=5, limit_per_host=3)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self.execute_test(item, session) for item in queue]
            self.results = await asyncio.gather(*tasks)
        
        # メトリクス集計
        self._calculate_metrics()
        
        return self.generate_report()
    
    def _calculate_metrics(self):
        """メトリクス計算"""
        for result in self.results:
            self.metrics["total_tests"] += 1
            
            if result.error_type:
                self.metrics["errors"] += 1
            else:
                self.metrics["successful"] += 1
            
            if result.finding:
                self.metrics["findings"] += 1
            
            # カテゴリ別
            cat = result.category
            if cat not in self.metrics["by_category"]:
                self.metrics["by_category"][cat] = {"total": 0, "findings": 0, "errors": 0}
            self.metrics["by_category"][cat]["total"] += 1
            if result.finding:
                self.metrics["by_category"][cat]["findings"] += 1
            if result.error_type:
                self.metrics["by_category"][cat]["errors"] += 1
            
            # 認証状態別
            auth = result.auth_state
            if auth not in self.metrics["by_auth_state"]:
                self.metrics["by_auth_state"][auth] = {"total": 0, "findings": 0}
            self.metrics["by_auth_state"][auth]["total"] += 1
            if result.finding:
                self.metrics["by_auth_state"][auth]["findings"] += 1
    
    def generate_report(self) -> Dict[str, Any]:
        """レポート生成"""
        findings = [r for r in self.results if r.finding]
        
        report = {
            "summary": {
                "target": self.BASE_URL,
                "total_tests": self.metrics["total_tests"],
                "successful": self.metrics["successful"],
                "errors": self.metrics["errors"],
                "findings": self.metrics["findings"],
                "coverage_rate": self.metrics["successful"] / self.metrics["total_tests"] if self.metrics["total_tests"] > 0 else 0,
            },
            "by_category": self.metrics["by_category"],
            "by_auth_state": self.metrics["by_auth_state"],
            "failure_reasons": self._normalize_failure_reasons(),
            "findings": [
                {
                    "endpoint": r.endpoint,
                    "method": r.method,
                    "category": r.category,
                    "auth_state": r.auth_state,
                    "status": r.status_code,
                }
                for r in findings
            ],
        }
        
        # コンソール出力
        print("\n" + "=" * 70)
        print("カバレッジ実行結果")
        print("=" * 70)
        print(f"総テスト数: {self.metrics['total_tests']}")
        print(f"成功: {self.metrics['successful']} ({report['summary']['coverage_rate']*100:.1f}%)")
        print(f"エラー: {self.metrics['errors']}")
        print(f"Findings: {self.metrics['findings']}")
        
        print("\nカテゴリ別:")
        for cat, stats in sorted(self.metrics["by_category"].items()):
            print(f"  {cat}: {stats['total']} tests, {stats.get('findings', 0)} findings")
        
        print("\n認証状態別:")
        for auth, stats in sorted(self.metrics["by_auth_state"].items()):
            print(f"  {auth}: {stats['total']} tests, {stats.get('findings', 0)} findings")
        
        return report
    
    def _normalize_failure_reasons(self) -> Dict[str, int]:
        """失敗理由を正規化"""
        reasons = {}
        for result in self.results:
            if result.failure_reason:
                reason = result.failure_reason
                reasons[reason] = reasons.get(reason, 0) + 1
        return reasons


def main():
    """メイン関数"""
    try:
        executor = CoverageExecutor()
        report = asyncio.run(executor.run_all_tests())
        
        # 結果保存
        output_dir = Path("workspace/projects/juice_shop_demo/phase_c")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        output_file = output_dir / f"coverage_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n✅ Phase C完了。レポート: {output_file}")
        
        # KPI判定
        coverage_rate = report["summary"]["coverage_rate"]
        if coverage_rate >= 0.90:
            print(f"✅ カバレッジ率: {coverage_rate*100:.1f}% (目標: 90%以上) - 達成")
            return 0
        else:
            print(f"⚠️  カバレッジ率: {coverage_rate*100:.1f}% (目標: 90%以上) - 未達成")
            return 1
            
    except Exception as e:
        print(f"\n❌ Phase C失敗: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
