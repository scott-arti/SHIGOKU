import sys
import os
import subprocess
import shutil

def debug_nuclei_direct():
    nuclei_path = "nuclei"
    resolved = shutil.which(nuclei_path)
    print(f"[*] Resolved nuclei: {resolved}")
    
    if not resolved:
        print("[-] Nuclei not in PATH")
        # Try absolute path
        nuclei_path = "/home/bbb/go/bin/nuclei"
        print(f"[*] Trying absolute path: {nuclei_path}")
        if not os.path.exists(nuclei_path):
             print("[-] Absolute path also invalid.")
             return

    # 1. Version Check
    try:
        print("[*] Checking version...")
        res = subprocess.run([nuclei_path, "-version"], capture_output=True, text=True)
        print(f"Stdout: {res.stdout}")
        print(f"Stderr: {res.stderr}")
    except Exception as e:
        print(f"[-] Version check failed: {e}")

    # 2. Run with arguments similar to NucleiTool but NO SILENT
    target = "http://localhost:4280/"
    cmd = [
        nuclei_path,
        "-u", target,
        "-j",
        # "-silent",  <-- REMOVED
        "-tags", "cve,misconfig,exposure",
        "-rate-limit", "50",
        "-H", "Cookie: PHPSESSID=TEST_COOKIE_VALUE"
    ]
    
    print(f"[*] Executing: {' '.join(cmd)}")
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        print(f"Return Code: {res.returncode}")
        print(f"Stdout (first 500 chars):\n{res.stdout[:500]}")
        print(f"Stderr:\n{res.stderr}")
    except Exception as e:
        print(f"[-] Execution failed: {e}")

if __name__ == "__main__":
    debug_nuclei_direct()
