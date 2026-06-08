"""
Audit/Status Commands
"""
import json
from src.commands import print_banner, print_header, print_result

def run_tool_status(output_json: bool = False):
    """
    Tool Status Mode
    
    登録されているツールの状態を表示。
    """
    if not output_json:
        print_banner()
        print_header("🔧 Tool Status")
    
    try:
        from src.core.tool_registry import get_tool_registry
    except ImportError as e:
        if output_json:
            print(json.dumps({"error": str(e)}))
        else:
            print_result(False, f"Import error: {e}")
        return
    
    registry = get_tool_registry()
    tools = registry.list_all_tools()
    
    if output_json:
        print(json.dumps({
            "total": len(tools),
            "tools": [
                {
                    "name": t.name,
                    "display_name": t.display_name,
                    "category": t.category,
                    "enabled": t.enabled,
                }
                for t in tools
            ]
        }, ensure_ascii=False, indent=2))
    else:
        intel_tools = [t for t in tools if t.category == "intel"]
        attack_tools = [t for t in tools if t.category == "attack"]
        
        print(f"\n  📊 Total: {len(tools)} tools")
        
        print(f"\n  🔍 Intel ({len(intel_tools)}):")
        for t in intel_tools:
            status = "✅" if t.enabled else "❌"
            print(f"     {status} {t.display_name}")
        
        print(f"\n  ⚔️ Attack ({len(attack_tools)}):")
        for t in attack_tools:
            status = "✅" if t.enabled else "❌"
            print(f"     {status} {t.display_name}")
