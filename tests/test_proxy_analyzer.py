#!/usr/bin/env python3
"""
ProxyLogAnalyzer 動作確認テスト
"""
import sys
from pathlib import Path

project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from src.intelligence.proxy_log_analyzer import (
    ProxyLogAnalyzer,
    analyze_and_dispatch,
)


def test_proxy_analyzer():
    print("=" * 70)
    print("🔍 ProxyLogAnalyzer 動作テスト")
    print("=" * 70)
    
    # サンプルログを解析
    analyzer = ProxyLogAnalyzer(scope_domains=["example.com"])
    plans = analyzer.analyze("tests/sample_proxy_log.json")
    
    # サマリー表示
    print()
    print(analyzer.get_summary(plans))
    
    # 詳細表示
    print("\n" + "=" * 70)
    print("📋 Attack Plan Details")
    print("=" * 70)
    
    for i, plan in enumerate(plans, 1):
        print(f"\n[{i}] {plan.candidate.smell_type.value}")
        print(f"    Method: {plan.method}")
        print(f"    URL: {plan.target_url}")
        print(f"    Agent: {plan.recommended_agent}")
        print(f"    Priority: {plan.priority}/5")
        print(f"    Rationale: {plan.rationale}")
        print(f"    Evidence: {plan.candidate.evidence}")
        if plan.attack_params:
            print(f"    Attack Params: {list(plan.attack_params.keys())}")
    
    print("\n" + "=" * 70)
    print("✅ テスト完了")
    print("=" * 70)
    
    return plans


def test_dispatch_interface():
    """MasterConductor統合インターフェースのテスト"""
    print("\n" + "=" * 70)
    print("🔗 analyze_and_dispatch() インターフェーステスト")
    print("=" * 70)
    
    plans = analyze_and_dispatch(
        "tests/sample_proxy_log.json",
        scope_domains=["example.com"]
    )
    
    print(f"\n✅ {len(plans)} attack plans generated via dispatch interface")
    
    # 辞書形式での出力テスト
    print("\n📤 JSON出力形式:")
    import json
    for plan in plans[:3]:
        print(json.dumps(plan.to_dict(), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    test_proxy_analyzer()
    test_dispatch_interface()
