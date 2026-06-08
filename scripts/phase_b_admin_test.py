#!/usr/bin/env python3
"""
Phase B: Adminエンドポイントend-to-end試行スクリプト

Juice Shop adminエンドポイントの認可バイパス試行を実行
"""
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from src.core.agents.swarm.injection.manager import InjectionManagerAgent


async def test_admin_check():
    """adminエンドポイント試行テスト"""
    print("=" * 60)
    print("Phase B: Adminエンドポイント試行")
    print("=" * 60)
    
    # InjectionManagerAgent初期化
    agent = InjectionManagerAgent()
    
    # テスト対象URL（Juice Shop adminエンドポイント）
    test_urls = [
        "http://localhost:3000/rest/admin/application-configuration",
        "http://localhost:3000/rest/admin/application-version",
    ]
    
    results = []
    
    for url in test_urls:
        print(f"\nテスト対象: {url}")
        
        # ベースパラメータ
        params = {
            "auth_headers": {},
            "cookies": "",
            "method": "GET",
        }
        
        try:
            # adminチェック実行
            result = await agent.run_admin_check(url, params)
            results.append({
                "url": url,
                "result": result,
            })
            
            print(f"  findings_count: {result.get('findings_count', 0)}")
            print(f"  tested_params: {result.get('tested_params', [])}")
            
            if result.get('findings_count', 0) > 0:
                print(f"  ⚠️  Potential vulnerability found!")
            else:
                print(f"  ✅ No obvious admin bypass detected")
                
        except Exception as e:
            print(f"  ❌ Error: {e}")
            results.append({
                "url": url,
                "error": str(e),
            })
    
    # クリーンアップ
    await agent.close()
    
    # 結果保存
    output_dir = Path("workspace/projects/juice_shop_demo/admin_test")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    output_file = output_dir / "admin_test_results.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"\n結果保存: {output_file}")
    
    # サマリー
    total = len(results)
    findings = sum(1 for r in results if r.get('result', {}).get('findings_count', 0) > 0)
    errors = sum(1 for r in results if 'error' in r)
    
    print("\n" + "=" * 60)
    print("試行サマリー")
    print("=" * 60)
    print(f"  合計: {total} endpoints")
    print(f"  findings: {findings}")
    print(f"  errors: {errors}")
    
    return results


def main():
    """メイン関数"""
    try:
        results = asyncio.run(test_admin_check())
        print("\n✅ Phase B admin試行完了")
        return 0
    except Exception as e:
        print(f"\n❌ Phase B admin試行失敗: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
