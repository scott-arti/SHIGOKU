import sys
import os
from pathlib import Path

# Add project root to sys.path
sys.path.append(str(Path(__file__).parent.parent.parent))

from src.tools.custom.nuclei import NucleiTool
from src.config import settings

def verify_nuclei_tool():
    print(f"[*] Testing NucleiTool with correct flag...")
    tool = NucleiTool()
    target = "http://localhost:4280/"
    headers = ["Cookie: PHPSESSID=TEST_COOKIE_VALUE"]
    
    print(f"[*] Running NucleiTool targeting {target}...")
    
    # Using 'quick' mode
    # Note: run() captures output. If successful, it returns JSON (or JSONL string).
    # If failed, it returns "Nuclei Error: ..."
    result = tool.run(target, mode="quick", headers=headers)
    
    print("[*] Result Snippet:")
    print(str(result)[:500])
    
    if "Nuclei Error" in result:
        print("[-] Verification FAILED: Nuclei Error returned.")
    elif "Error:" in result:
         print(f"[-] Verification FAILED: {result}")
    else:
        print("[+] Verification SUCCESS: NucleiTool ran without error.")

if __name__ == "__main__":
    verify_nuclei_tool()
