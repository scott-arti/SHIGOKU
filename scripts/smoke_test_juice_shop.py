#!/usr/bin/env python3
"""
Juice Shop Smoke Test - CTO推奨対応#1

実際のJuice Shopインスタンス（http://localhost:3000）での検証
- エンドポイント到達性確認
- 認可制御の脆弱性検出
- レイテンシ計測
- HTTPメソッド横断テスト
"""
import asyncio
import json
import time
import sys
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

import aiohttp


@dataclass
class SmokeTestResult:
    """スモークテスト結果"""
    endpoint: str
    method: str
    status_code: int
    response_size: int
    latency_ms: float
    error: Optional[str] = None
    response_sample: str = ""
    finding: bool = False
    finding_details: Dict[str, Any] = field(default_factory=dict)


class JuiceShopSmokeTest:
    """Juice Shopスモークテスト"""
    
    BASE_URL = "http://localhost:3000"
    
    # テスト対象エンドポイント
    TEST_ENDPOINTS = [
        # admin系統
        {"path": "/rest/admin/application-configuration", "methods": ["GET", "POST", "PUT", "DELETE"]},
        {"path": "/rest/admin/application-version", "methods": ["GET", "POST", "PUT", "DELETE"]},
        # auth系統
        {"path": "/rest/user/login", "methods": ["POST"]},
        {"path": "/rest/user/register", "methods": ["POST"]},
        # product_search系統
        {"path": "/rest/products/search", "methods": ["GET"]},
        # api_data系統
        {"path": "/api/Challenges", "methods": ["GET", "POST"]},
        {"path": "/rest/basket", "methods": ["GET", "POST"]},
        # client_route_dom
        {"path": "/#/", "methods": ["GET"]},
        # realtime
        {"path": "/socket.io/", "methods": ["GET"]},
    ]
    
    def __init__(self):
        self.results: List[SmokeTestResult] = []
        self.metrics = {
            "total_requests": 0,
            "successful": 0,
            "errors": 0,
            "findings": 0,
            "avg_latency_ms": 0.0,
        }
    
    async def test_endpoint(self, path: str, method: str, session: aiohttp.ClientSession) -> SmokeTestResult:
        """単一エンドポイントのテスト"""
        url = f"{self.BASE_URL}{path}"
        start_time = time.time()
        
        try:
            async with session.request(method, url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                latency_ms = (time.time() - start_time) * 1000
                response_size = 0
                response_sample = ""
                
                try:
                    body = await response.text()
                    response_size = len(body)
                    response_sample = body[:500]  # 先頭500文字
                except:
                    pass
                
                # 脆弱性検出ロジック
                finding = False
                finding_details = {}
                
                # adminエンドポイントが認証なしで200を返す場合
                if path.startswith("/rest/admin/") and response.status == 200 and response_size > 1000:
                    finding = True
                    finding_details = {
                        "type": "broken_access_control",
                        "severity": "HIGH",
                        "description": f"Admin endpoint {path} accessible without authentication",
                        "evidence": f"Status: {response.status}, Size: {response_size} bytes",
                    }
                
                # 書き込みメソッドが許可される場合
                if method in ["POST", "PUT", "DELETE"] and response.status in [200, 201, 204]:
                    finding = True
                    finding_details = {
                        "type": "broken_access_control",
                        "severity": "MEDIUM",
                        "description": f"Write method {method} allowed on {path} without authentication",
                        "evidence": f"Status: {response.status}",
                    }
                
                return SmokeTestResult(
                    endpoint=path,
                    method=method,
                    status_code=response.status,
                    response_size=response_size,
                    latency_ms=latency_ms,
                    response_sample=response_sample,
                    finding=finding,
                    finding_details=finding_details,
                )
                
        except asyncio.TimeoutError:
            latency_ms = (time.time() - start_time) * 1000
            return SmokeTestResult(
                endpoint=path,
                method=method,
                status_code=0,
                response_size=0,
                latency_ms=latency_ms,
                error="TIMEOUT",
            )
        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            return SmokeTestResult(
                endpoint=path,
                method=method,
                status_code=0,
                response_size=0,
                latency_ms=latency_ms,
                error=str(type(e).__name__),
            )
    
    async def run_all_tests(self) -> Dict[str, Any]:
        """全テスト実行"""
        print("=" * 70)
        print("Juice Shop Smoke Test - CTO推奨対応")
        print("=" * 70)
        print(f"Target: {self.BASE_URL}")
        print(f"Endpoints: {len(self.TEST_ENDPOINTS)}")
        print()
        
        connector = aiohttp.TCPConnector(limit=10, limit_per_host=5)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = []
            for endpoint in self.TEST_ENDPOINTS:
                path = endpoint["path"]
                for method in endpoint["methods"]:
                    tasks.append(self.test_endpoint(path, method, session))
            
            self.results = await asyncio.gather(*tasks)
        
        # メトリクス計算
        total_latency = 0
        for result in self.results:
            self.metrics["total_requests"] += 1
            if result.error:
                self.metrics["errors"] += 1
            else:
                self.metrics["successful"] += 1
            if result.finding:
                self.metrics["findings"] += 1
            total_latency += result.latency_ms
        
        if self.metrics["total_requests"] > 0:
            self.metrics["avg_latency_ms"] = total_latency / self.metrics["total_requests"]
        
        return self.generate_report()
    
    def generate_report(self) -> Dict[str, Any]:
        """レポート生成"""
        findings = [r for r in self.results if r.finding]
        errors = [r for r in self.results if r.error]
        
        report = {
            "summary": {
                "target": self.BASE_URL,
                "total_requests": self.metrics["total_requests"],
                "successful": self.metrics["successful"],
                "errors": self.metrics["errors"],
                "findings": self.metrics["findings"],
                "avg_latency_ms": round(self.metrics["avg_latency_ms"], 2),
            },
            "findings": [
                {
                    "endpoint": r.endpoint,
                    "method": r.method,
                    "status": r.status_code,
                    "type": r.finding_details.get("type"),
                    "severity": r.finding_details.get("severity"),
                    "description": r.finding_details.get("description"),
                    "evidence": r.finding_details.get("evidence"),
                }
                for r in findings
            ],
            "errors": [
                {
                    "endpoint": r.endpoint,
                    "method": r.method,
                    "error": r.error,
                    "latency_ms": round(r.latency_ms, 2),
                }
                for r in errors
            ],
            "all_results": [
                {
                    "endpoint": r.endpoint,
                    "method": r.method,
                    "status": r.status_code,
                    "size": r.response_size,
                    "latency_ms": round(r.latency_ms, 2),
                    "finding": r.finding,
                }
                for r in self.results
            ],
        }
        
        # コンソール出力
        print("-" * 70)
        print("FINDINGS:")
        print("-" * 70)
        for f in findings:
            print(f"🔴 [{f.finding_details.get('severity', 'UNKNOWN')}] {f.method} {f.endpoint}")
            print(f"   {f.finding_details.get('description', '')}")
            print(f"   Status: {f.status_code}, Size: {f.response_size} bytes")
            print()
        
        if errors:
            print("-" * 70)
            print("ERRORS:")
            print("-" * 70)
            for e in errors:
                print(f"⚠️  {e.method} {e.endpoint}: {e.error}")
            print()
        
        print("-" * 70)
        print("METRICS:")
        print("-" * 70)
        print(f"Total Requests: {self.metrics['total_requests']}")
        print(f"Successful: {self.metrics['successful']}")
        print(f"Errors: {self.metrics['errors']}")
        print(f"Findings: {self.metrics['findings']}")
        print(f"Avg Latency: {self.metrics['avg_latency_ms']:.2f} ms")
        
        return report


def main():
    """メイン関数"""
    try:
        tester = JuiceShopSmokeTest()
        report = asyncio.run(tester.run_all_tests())
        
        # 結果保存
        output_dir = Path("workspace/projects/juice_shop_demo/smoke_test")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        output_file = output_dir / "smoke_test_report.json"
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n✅ Smoke test complete. Report saved to: {output_file}")
        
        # 終了コード: findingsがあれば1（CI失敗）、なければ0
        return 1 if report["summary"]["findings"] > 0 else 0
        
    except Exception as e:
        print(f"\n❌ Smoke test failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
