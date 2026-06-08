#!/usr/bin/env python3
"""
E2E Test: MC → SwarmDispatcher Flow (No LLM)

このテストはLLMを使わずにSwarmDispatcherのルーティングロジックを検証する。

テスト対象:
1. determine_swarms() - タグ→Swarm名のルーティング
2. dispatch() - Swarm選択とコンテキスト渡し (モックSwarmを使用)
3. dispatch_rich_url() - RichUrlContext経由のディスパッチ

モック対象:
- Swarm.execute() - 実際のLLM呼び出しを回避
"""
import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch
from dataclasses import dataclass, field

# プロジェクトルートをパスに追加
PROJECT_ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

# ログ設定
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("e2e_swarm_routing")


# =========================================
# Test Data
# =========================================

# MCからSwarmに渡されるサンプルデータ (step8_return_to_mc形式)
SAMPLE_MC_PAYLOAD = {
    "auth": {
        "count": 5,
        "description": "認証関連のエンドポイント",
        "tags": ["auth_endpoint", "auth_required"],
    },
    "id_param": {
        "count": 3,
        "description": "IDパラメータを含むエンドポイント",
        "tags": ["id_param", "has_params"],
    },
    "file_param": {
        "count": 2,
        "description": "ファイルパラメータを含むエンドポイント",
        "tags": ["file_param"],
    },
    "debug_info": {
        "count": 1,
        "description": "デバッグ情報が露出しているエンドポイント",
        "tags": ["debug_info"],
    },
    "uncategorized": {
        "count": 10,
        "description": "分類に該当しなかったエンドポイント",
        "tags": ["unknown_path"],
    },
    "_tech_stack": {
        "technologies": ["PHP:5.6.40", "Nginx:1.19.0"],
        "tags": ["php_app", "nginx_server"],
    }
}

# 期待されるルーティング結果
EXPECTED_ROUTING = {
    # tags -> expected swarm names
    ("auth_endpoint", "auth_required"): ["auth"],
    ("id_param", "has_params"): ["injection"],
    ("file_param",): ["injection"],
    ("debug_info",): ["discovery"],
    ("unknown_path",): ["discovery"],
    # 複数Swarm該当ケース
    ("auth_endpoint", "id_param"): ["auth", "injection"],
    ("jwt_token", "has_params", "payment_flow"): ["auth", "injection", "logic"],
}


def test_determine_swarms():
    """Test 1: determine_swarms() ルーティングロジック"""
    from src.core.engine.swarm_dispatcher import SwarmDispatcher
    
    logger.info("=" * 60)
    logger.info("Test 1: determine_swarms() Routing Logic")
    logger.info("=" * 60)
    
    dispatcher = SwarmDispatcher()
    results = []
    
    for tags, expected in EXPECTED_ROUTING.items():
        actual = dispatcher.determine_swarms(list(tags))
        passed = actual == expected
        
        results.append({
            "tags": tags,
            "expected": expected,
            "actual": actual,
            "passed": passed,
        })
        
        status = "✅" if passed else "❌"
        logger.info("%s Tags %s -> Expected: %s, Got: %s",
                   status, tags, expected, actual)
    
    passed_count = sum(1 for r in results if r["passed"])
    logger.info("Result: %d/%d passed", passed_count, len(results))
    
    return {
        "test": "determine_swarms",
        "passed": passed_count,
        "total": len(results),
        "details": results,
    }


def test_tag_to_swarm_mapping():
    """Test 2: TAG_TO_SWARMマッピングの整合性"""
    from src.core.engine.swarm_dispatcher import TAG_TO_SWARM, SUBDOMAIN_TAG_TO_SWARM, URL_TAG_TO_SWARM
    
    logger.info("=" * 60)
    logger.info("Test 2: TAG_TO_SWARM Mapping Integrity")
    logger.info("=" * 60)
    
    results = []
    
    # tagging_rules.yaml のタグがマッピングに存在するか
    expected_url_tags = [
        "auth", "admin", "admin_blocked", "id_param", "redirect_param",
        "file_param", "upload", "debug_info", "jwt_detected",
    ]
    
    for tag in expected_url_tags:
        exists = tag in TAG_TO_SWARM
        swarm = TAG_TO_SWARM.get(tag, "NOT_FOUND")
        
        results.append({
            "tag": tag,
            "exists_in_mapping": exists,
            "swarm": swarm,
        })
        
        status = "✅" if exists else "❌"
        logger.info("%s Tag '%s' -> Swarm: %s", status, tag, swarm)
    
    # MC Payload のタグもチェック
    for category, data in SAMPLE_MC_PAYLOAD.items():
        if category.startswith("_"):
            continue
        for tag in data.get("tags", []):
            exists = tag in TAG_TO_SWARM
            if not exists and tag not in [r["tag"] for r in results]:
                results.append({
                    "tag": tag,
                    "exists_in_mapping": exists,
                    "swarm": TAG_TO_SWARM.get(tag, "NOT_FOUND"),
                })
                logger.info("⚠️  MC Payload tag '%s' -> %s",
                           tag, "Found" if exists else "NOT_FOUND")
    
    passed = sum(1 for r in results if r["exists_in_mapping"])
    logger.info("Result: %d/%d tags mapped", passed, len(results))
    
    return {
        "test": "tag_to_swarm_mapping",
        "mapped": passed,
        "total": len(results),
        "details": results,
    }


async def test_dispatch_with_mock_swarm():
    """Test 3: dispatch() でモックSwarmが正しくコンテキストを受け取るか"""
    from src.core.engine.swarm_dispatcher import SwarmDispatcher
    from src.core.models.swarm import SwarmResult
    
    logger.info("=" * 60)
    logger.info("Test 3: dispatch() with Mock Swarm")
    logger.info("=" * 60)
    
    dispatcher = SwarmDispatcher()
    
    # モックSwarmを作成
    mock_swarm = MagicMock()
    mock_swarm.dispatch = AsyncMock(return_value=SwarmResult(
        findings=[{"type": "mock_finding", "severity": "info"}],
        status="success",
        execution_log=[{"step": "mock_execution"}],
        swarm_name="mock_swarm",
        total_specialists=1,
        successful_specialists=1,
    ))
    
    received_tasks = []
    
    # dispatch() 内の swarm.dispatch() をキャプチャ
    original_get_swarm = dispatcher._get_or_create_swarm
    
    def mock_get_swarm(swarm_name):
        logger.info("  Creating mock for Swarm: %s", swarm_name)
        mock = MagicMock()
        
        async def mock_dispatch(task):
            received_tasks.append({
                "swarm_name": swarm_name,
                "task_id": task.id,
                "task_name": task.name,
                "target": task.target,
                "tags": task.tags,
                "params": task.params,
            })
            return SwarmResult(
                findings=[{"type": f"mock_finding_{swarm_name}"}],
                status="success",
                execution_log=[],
                swarm_name=swarm_name,
            )
        
        mock.dispatch = mock_dispatch
        return mock
    
    dispatcher._get_or_create_swarm = mock_get_swarm
    
    # テスト実行
    test_cases = [
        {
            "tags": ["auth_endpoint", "auth_required"],
            "target": "http://example.com/login",
            "expected_swarms": ["auth"],
        },
        {
            "tags": ["id_param", "has_params"],
            "target": "http://example.com/user?id=123",
            "expected_swarms": ["injection"],
        },
        {
            "tags": ["auth_endpoint", "id_param"],
            "target": "http://example.com/admin/user?id=1",
            "expected_swarms": ["auth", "injection"],
        },
    ]
    
    results = []
    
    for case in test_cases:
        received_tasks.clear()
        
        result = await dispatcher.dispatch(
            tags=case["tags"],
            target=case["target"],
            task_name="test_task",
            params={"context": "test"},
        )
        
        swarms_called = [t["swarm_name"] for t in received_tasks]
        passed = swarms_called == case["expected_swarms"]
        
        results.append({
            "tags": case["tags"],
            "target": case["target"],
            "expected_swarms": case["expected_swarms"],
            "actual_swarms": swarms_called,
            "passed": passed,
            "received_params": [t["params"] for t in received_tasks],
        })
        
        status = "✅" if passed else "❌"
        logger.info("%s Tags %s -> Swarms: %s (expected: %s)",
                   status, case["tags"], swarms_called, case["expected_swarms"])
        
        # コンテキストが渡されているか
        for task in received_tasks:
            logger.info("  Task params: %s", list(task["params"].keys()))
    
    passed_count = sum(1 for r in results if r["passed"])
    logger.info("Result: %d/%d passed", passed_count, len(results))
    
    return {
        "test": "dispatch_with_mock",
        "passed": passed_count,
        "total": len(results),
        "details": results,
    }


async def test_mc_payload_to_swarm_routing():
    """Test 4: MCペイロードからSwarmへの完全ルーティング"""
    from src.core.engine.swarm_dispatcher import SwarmDispatcher
    
    logger.info("=" * 60)
    logger.info("Test 4: MC Payload → Swarm Full Routing")
    logger.info("=" * 60)
    
    dispatcher = SwarmDispatcher()
    
    results = []
    
    for category, data in SAMPLE_MC_PAYLOAD.items():
        if category.startswith("_"):
            continue
        
        tags = data.get("tags", [])
        swarms = dispatcher.determine_swarms(tags)
        
        result = {
            "category": category,
            "count": data.get("count", 0),
            "tags": tags,
            "routed_to_swarms": swarms,
            "has_routing": len(swarms) > 0,
        }
        results.append(result)
        
        status = "✅" if swarms else "⚠️"
        logger.info("%s Category '%s' (%d URLs) -> Tags %s -> Swarms: %s",
                   status, category, data.get("count", 0), tags, swarms or "NONE")
    
    routed = sum(1 for r in results if r["has_routing"])
    logger.info("Result: %d/%d categories have routing", routed, len(results))
    
    return {
        "test": "mc_payload_routing",
        "routed": routed,
        "total": len(results),
        "details": results,
    }


async def run_all_tests():
    """全テスト実行"""
    
    all_results = {
        "status": "unknown",
        "tests": [],
        "summary": {},
    }
    
    try:
        # Test 1: determine_swarms
        result1 = test_determine_swarms()
        all_results["tests"].append(result1)
        
        # Test 2: TAG_TO_SWARM mapping
        result2 = test_tag_to_swarm_mapping()
        all_results["tests"].append(result2)
        
        # Test 3: dispatch with mock
        result3 = await test_dispatch_with_mock_swarm()
        all_results["tests"].append(result3)
        
        # Test 4: MC payload routing
        result4 = await test_mc_payload_to_swarm_routing()
        all_results["tests"].append(result4)
        
        # Summary
        total_passed = 0
        total_tests = 0
        
        for test in all_results["tests"]:
            if "passed" in test:
                total_passed += test["passed"]
                total_tests += test["total"]
            elif "routed" in test:
                total_passed += test["routed"]
                total_tests += test["total"]
            elif "mapped" in test:
                total_passed += test["mapped"]
                total_tests += test["total"]
        
        all_results["summary"] = {
            "total_passed": total_passed,
            "total_tests": total_tests,
            "pass_rate": f"{100 * total_passed / total_tests:.1f}%" if total_tests > 0 else "N/A",
        }
        
        all_results["status"] = "success" if total_passed == total_tests else "partial_failure"
        
    except Exception as e:
        logger.exception("Test failed: %s", e)
        all_results["status"] = "error"
        all_results["error"] = str(e)
    
    return all_results


def main():
    """メイン関数"""
    print("\n" + "=" * 60)
    print("SHIGOKU MC → Swarm Routing E2E Test (No LLM)")
    print("=" * 60 + "\n")
    
    results = asyncio.run(run_all_tests())
    
    # 結果出力
    print("\n" + "=" * 60)
    print("FINAL RESULTS:")
    print("=" * 60)
    print(json.dumps(results["summary"], indent=2, ensure_ascii=False))
    
    # テストごとの結果
    for test in results["tests"]:
        test_name = test.get("test", "unknown")
        if "passed" in test:
            print(f"  - {test_name}: {test['passed']}/{test['total']} passed")
        elif "mapped" in test:
            print(f"  - {test_name}: {test['mapped']}/{test['total']} mapped")
        elif "routed" in test:
            print(f"  - {test_name}: {test['routed']}/{test['total']} routed")
    
    # 終了コード
    if results["status"] == "success":
        print("\n✅ All Tests PASSED - Swarm routing works correctly without LLM")
        sys.exit(0)
    elif results["status"] == "partial_failure":
        print("\n⚠️ Some Tests FAILED - Check routing configuration")
        sys.exit(1)
    else:
        print("\n❌ Tests ERROR")
        sys.exit(1)


if __name__ == "__main__":
    main()
