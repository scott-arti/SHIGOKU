#!/usr/bin/env python3
"""
DVWA Authenticated Attack Script
"""
import asyncio
import logging
import sys
from urllib.parse import urljoin

# Add project root to path
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from src.core.infra.network_client import create_network_client
from src.core.attack.param_fuzzer import create_param_fuzzer
from src.commands import print_banner, print_step, print_result, print_header

# Constants
TARGET_BASE = "http://localhost:8081"
LOGIN_URL = urljoin(TARGET_BASE, "login.php")
VULN_ENDPOINT = urljoin(TARGET_BASE, "vulnerabilities/exec/")
USERNAME = "admin"
PASSWORD = "password"

async def main():
    print_banner()
    print_header("🛡️ DVWA Attack Scenario")
    
    client = create_network_client()
    fuzzer = None
    
    try:
        # 1. Access Login Page to get CSRF token
        print_step("DOOR", "Accessing Login Page for CSRF token...")
        resp = await client.request("GET", LOGIN_URL)
        if not resp:
            print_result(False, "Failed to access login page")
            return

        # Parse user_token
        import re
        token_match = re.search(r"name='user_token' value='([a-f0-9]+)'", resp.text)
        user_token = token_match.group(1) if token_match else None
        
        if user_token:
             print_step("KEYS", f"Got CSRF Token: {user_token[:8]}...")
        else:
             print_step("WARN", "No CSRF token found (might not be needed)")

        # 2. Login
        print_step("KEYS", "Attempting Login (admin:password)...")
        login_data = {
            "username": USERNAME,
            "password": PASSWORD,
            "Login": "Login"
        }
        if user_token:
            login_data["user_token"] = user_token
            
        resp = await client.request("POST", LOGIN_URL, data=login_data, allow_redirects=False)
        
        if resp.status == 302 and "login.php" not in resp.headers.get("Location", ""):
             loc = resp.headers.get('Location')
             print_result(True, f"Login Successful! (Redirected to {loc})")
             
             # PRINT COOKIES FOR CLI
             cookies = client.get_cookies()
             cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
             print(f"\n[!] TO USE IN CLI: --cookie \"{cookie_str}\"\n")
             
             # Handle Setup if needed
             if "setup.php" in loc:
                 print_step("SETUP", "Performing Database Setup...")
                 setup_url = urljoin(TARGET_BASE, "setup.php")
                 # Need CSRF token for setup too? Usually passed as POST param `create_db`
                 # Check setup page content first
                 setup_page = await client.request("GET", setup_url)
                 token_match = re.search(r"name='user_token' value='([a-f0-9]+)'", setup_page.text)
                 setup_token = token_match.group(1) if token_match else None
                 
                 setup_data = {"create_db": "Create / Reset Database"}
                 if setup_token:
                     setup_data["user_token"] = setup_token
                     
                 await client.request("POST", setup_url, data=setup_data)
                 print_result(True, "Database Setup Request Sent")

        else:
             check_resp = await client.request("GET", urljoin(TARGET_BASE, "index.php"))
             if check_resp and "Welcome to Damn Vulnerable Web App" in check_resp.text:
                  print_result(True, "Login Successful! (Index accessible)")
                  
                  # PRINT COOKIES FOR CLI
                  cookies = client.get_cookies()
                  cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
                  print(f"\n[!] TO USE IN CLI: --cookie \"{cookie_str}\"\n")
             else:
                  print_result(False, f"Login Failed. Status: {resp.status}, Location: {resp.headers.get('Location')}")
                  
        # 3. Set Security Level to Low
        print_step("CONFIG", "Setting Security Level to LOW...")
        # DVWA uses a cookie 'security'
        # Check how to set cookie in AsyncNetworkClient. 
        # Aiohttp session cookie jar updates automatically, but we want to force set.
        client._session.cookie_jar.update_cookies({"security": "low"})
        print_result(True, "Security Level set to LOW")
             # Print body for debug
             # print(resp.body[:500])
             # return 
             # Continue anyway to see what happens

        # 3. Fuzz Vulnerable Endpoint
        print_step("🔥", f"Attacking Endpoint: {VULN_ENDPOINT}")
        
        # Create Fuzzer sharing the SAME client (to keep cookies)
        fuzzer = create_param_fuzzer(client=client)
        
        # Custom wordlist targeting Command Injection + noise
        wordlist = ["id", "ip", "cmd", "exec", "ping", "query", "search", "name", "file"]
        
        print_step("⚡", f"Fuzzing parameters: {', '.join(wordlist)}")
        # DEBUG: Check access with one manual request
        debug_resp = await client.request("GET", VULN_ENDPOINT)
        if debug_resp:
             print(f"DEBUG: Endpoint Access. Status: {debug_resp.status}, Body Len: {len(debug_resp.body)}")
             if "Login" in debug_resp.text:
                 print("DEBUG: Redirected to Login Page (Auth Failed)")
             elif "Ping for FREE" in debug_resp.text:
                 print("DEBUG: Vulnerable Page Accessible")
             else:
                 print("DEBUG: Page content unknown")
                 # print(debug_resp.text[:600])

             # EXTRACT CSRF TOKEN FROM FORM IF PRESENT
             token_match = re.search(r"name='user_token' value='([a-f0-9]+)'", debug_resp.text)
             vuln_token = token_match.group(1) if token_match else None
             if vuln_token:
                 print(f"DEBUG: Found CSRF Token on Vuln Page: {vuln_token}")
             
             # MANUAL TEST
             print("DEBUG: Running Manual Test (127.0.0.1)...")
             manual_data = {"ip": "127.0.0.1", "Submit": "Submit"}
             if vuln_token:
                 manual_data["user_token"] = vuln_token
             
             man_resp = await client.request("POST", VULN_ENDPOINT, data=manual_data)
             if "bytes from 127.0.0.1" in man_resp.text:
                 print("DEBUG: Manual Test SUCCESS (Ping output found)")
             elif "ping: unknown host" in man_resp.text:
                 print("DEBUG: Manual Test SUCCESS (Error output found)") # Should not happen for 127.0.0.1
             else:
                 print(f"DEBUG: Manual Test FAILED. Status: {man_resp.status}")
                 # print(man_resp.text[:500])

             # If token found, add to extra_params
             extra = {"Submit": "Submit"}
             if vuln_token:
                 extra["user_token"] = vuln_token

        results = await fuzzer.fuzz(
            VULN_ENDPOINT, 
            method="POST", 
            wordlist=wordlist,
            extra_params=extra
        )
        
        # 4. Report
        print("\n" + "="*60)
        print(f"  [+] Attack Completed. Found: {len(results)}")
        print("="*60)
        
        for res in results:
            if res.vulnerable:
                print(f"\n  🚨  VULNERABLE PARAMETER FOUND: [{res.parameter}]")
                print(f"      Confidence: {res.confidence}")
                print(f"      Evidence: {res.evidence}")
        
    except Exception as e:
        print_result(False, f"Error: {e}")
    finally:
        if fuzzer:
            await fuzzer.close() # Closes client too
        elif client:
            await client.close()

if __name__ == "__main__":
    asyncio.run(main())
