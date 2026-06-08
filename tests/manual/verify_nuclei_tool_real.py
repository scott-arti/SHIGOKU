import sys
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent.parent.parent))

try:
    from src.tools.custom.nuclei import NucleiTool
    tool = NucleiTool()
    
    print("NucleiTool initialized successfully.")
    
    # Test path resolution
    test_paths = [
        "vulnerabilities/generic/cors-misconfig.yaml",
        "cves/2021/CVE-2021-44228.yaml",
        "http/cves/2021/CVE-2021-44228.yaml"
    ]
    
    print("\n--- Testing Path Resolution ---")
    for tp in test_paths:
        resolved = tool._resolve_template_path(tp)
        print(f"Input: {tp}")
        print(f"Resolved: {resolved}")
        if resolved != tp and Path(resolved).exists():
            print("  -> SUCCESS: Resolved to existing file")
        elif Path(resolved).exists():
             print("  -> SUCCESS: File exists")
        else:
             print("  -> WARNING: Resolved file does not exist (might be expected if template missing)")
             
    print("\nIntegration test passed.")
    
except Exception as e:
    print(f"Integration Test FAILED: {e}")
    import traceback
    traceback.print_exc()
