"""
修正内容の検証テスト

1. execute_tool_with_guardrail の同期ツール処理
2. Nuclei テンプレートパス解決
3. エージェント名の正規化
"""
import asyncio
import sys
from pathlib import Path

# プロジェクトルートをパスに追加
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

async def test_sync_tool_execution():
    """同期ツール (linux_cmd) の実行テスト"""
    print("\n=== Test 1: 同期ツール実行 ===")
    from src.core.agents.general.command import CommandAgent
    from src.core.agents.base import AgentConfig
    
    # テスト用エージェント設定
    config = AgentConfig(
        name="test_agent",
        description="Test",
        model="gemini/gemini-2.0-flash-exp",
        instructions="Test agent"
    )
    
    agent = CommandAgent(config)
    agent.current_context = {"auth_headers": {"Cookie": "test=value"}}
    
    # auth_headers コンテキスト下で同期ツールを実行
    try:
        result = await agent.execute_tool_with_guardrail(
            tool_name="linux_cmd",
            args={"command": "echo 'test'"},
            tools=list(agent.tools.values()),
            context_params=agent.current_context
        )
        print(f"✓ 実行成功: {result[:100] if len(result) > 100 else result}")
        return True
    except Exception as e:
        print(f"✗ 実行失敗: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_nuclei_template_resolution():
    """Nuclei テンプレートパス解決テスト"""
    print("\n=== Test 2: Nuclei テンプレートパス解決 ===")
    from src.tools.custom.nuclei import NucleiTool
    
    tool = NucleiTool()
    
    test_cases = [
        ("exposure/secrets", "http/exposures/tokens に解決されるべき"),
        ("secret-detection", "http/exposures/tokens に解決されるべき"),
        ("vulnerabilities/generic/secret-detection.yaml", "http/exposures/tokens に解決されるべき"),
        ("crlf", "http/vulnerabilities/crlf に解決されるべき"),
        ("smuggling", "http/vulnerabilities/smuggling に解決されるべき"),
    ]
    
    success_count = 0
    for template_path, description in test_cases:
        resolved = tool._resolve_template_path(template_path)
        # パス解決が変換されたか確認（元のパスと異なれば成功）
        if resolved != template_path:
            print(f"✓ {template_path} → {resolved}")
            success_count += 1
        else:
            print(f"✗ {template_path} → 変換されず")
    
    print(f"\n成功: {success_count}/{len(test_cases)}")
    return success_count == len(test_cases)

def test_agent_name_normalization():
    """エージェント名正規化テスト"""
    print("\n=== Test 3: エージェント名正規化 ===")
    from src.core.engine.agent_registry import normalize_agent_name, get_agent_class
    
    test_cases = [
        ("VulnerabilityScanner", "reconbot"),
        ("vulnerability_scanner", "reconbot"),
        ("web_scanner", "reconbot"),
        ("scanner", "reconbot"),
        ("reconnaissance", "reconbot"),
        ("exploit", "redteambot"),
        ("reconbot", "reconbot"),  # 既存の名前はそのまま
    ]
    
    success_count = 0
    for input_name, expected in test_cases:
        result = normalize_agent_name(input_name)
        if result == expected:
            print(f"✓ {input_name} → {result}")
            success_count += 1
        else:
            print(f"✗ {input_name} → {result} (期待: {expected})")
    
    print(f"\n成功: {success_count}/{len(test_cases)}")
    return success_count == len(test_cases)

async def main():
    """全テスト実行"""
    print("=" * 60)
    print("SHIGOKU 修正内容の検証テスト")
    print("=" * 60)
    
    results = []
    
    # Test 1: 同期ツール実行
    results.append(await test_sync_tool_execution())
    
    # Test 2: Nuclei テンプレート解決
    results.append(test_nuclei_template_resolution())
    
    # Test 3: エージェント名正規化
    results.append(test_agent_name_normalization())
    
    # 結果サマリー
    print("\n" + "=" * 60)
    print("テスト結果サマリー")
    print("=" * 60)
    passed = sum(results)
    total = len(results)
    print(f"合格: {passed}/{total}")
    
    if passed == total:
        print("\n✓ すべてのテストが成功しました！")
        return 0
    else:
        print(f"\n✗ {total - passed} 個のテストが失敗しました。")
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
