"""
Attack Commands
"""
import json
from src.commands import print_banner, print_header, print_step, print_result

def run_param_fuzz(target_url: str, output_json: bool = False):
    """
    Parameter Fuzzing Mode
    
    隠しパラメータ発見と反射検出。
    """
    if not output_json:
        print_banner()
        print_header("🔍 Parameter Fuzzing")
    
    try:
        from src.core.attack.param_fuzzer import create_param_fuzzer
    except ImportError as e:
        if output_json:
            print(json.dumps({"error": str(e)}))
        else:
            print_result(False, f"Import error: {e}")
        return
    
    print_step("🎯", f"Target: {target_url}")
    
    import asyncio
    fuzzer = create_param_fuzzer()
    
    async def _run_fuzzing():
        try:
            return await fuzzer.fuzz(target_url)
        finally:
            await fuzzer.close()
            
    results = asyncio.run(_run_fuzzing())

    
    if output_json:
        output = [
            {
                "param": r.param_name,
                "found": r.found,
                "reflected": r.reflected,
                "reflection_type": r.reflection_type.value if r.reflection_type else None,
            }
            for r in results
        ]
        print(json.dumps(output, ensure_ascii=False, indent=2))
    else:
        summary = fuzzer.get_summary()
        print_result(True, f"Tested: {summary['total_tested']} params")
        print_step("🔎", f"Found: {summary['found']}")
        print_step("📡", f"Reflected: {summary['reflected']}")
        
        for r in fuzzer.get_reflected_params():
            print(f"     └─ {r.param_name} ({r.reflection_type.value if r.reflection_type else 'unknown'})")


def run_openapi_test(target_url: str, output_json: bool = False):
    """
    OpenAPI Testing Mode
    
    Swagger/OpenAPI仕様を自動テスト。
    """
    if not output_json:
        print_banner()
        print_header("📋 OpenAPI Testing")
    
    try:
        from src.core.attack.openapi_tester import create_openapi_tester
    except ImportError as e:
        if output_json:
            print(json.dumps({"error": str(e)}))
        else:
            print_result(False, f"Import error: {e}")
        return
    
    print_step("🎯", f"Target: {target_url}")
    
    tester = create_openapi_tester(target_url)
    
    # 仕様URLを発見
    spec_urls = tester.discover_spec_urls(target_url)
    
    if output_json:
        print(json.dumps({
            "discovered_specs": spec_urls,
            "endpoints": [],  # 実際のテスト結果
        }, ensure_ascii=False, indent=2))
    else:
        print_step("📄", f"Discovered spec URLs: {len(spec_urls)}")
        for url in spec_urls[:5]:
            print(f"     └─ {url}")
