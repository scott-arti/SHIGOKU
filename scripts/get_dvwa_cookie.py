#!/usr/bin/env python3
import argparse
import requests
import sys
from urllib.parse import urljoin

def get_dvwa_cookie(base_url, username, password):
    # Session to hold cookies
    s = requests.Session()
    
    # 1. Access Login Page to get initial CSRF info (if any) and Session ID
    login_url = urljoin(base_url, "login.php")
    try:
        r = s.get(login_url)
        r.raise_for_status()
    except requests.exceptions.ConnectionError:
        print(f"Error: Could not connect to {base_url}. Is Docker container running?")
        sys.exit(1)

    # 2. Login
    # DVWA usually requires a user_token (CSRF) on login
    # Simple parsing to find user_token
    token = ""
    if "user_token" in r.text:
        import re
        match = re.search(r"name='user_token' value='([0-9a-f]+)'", r.text)
        if match:
            token = match.group(1)
    
    login_data = {
        "username": "admin",
        "password": "password",
        "Login": "Login",
        "user_token": token
    }
    
    r = s.post(login_url, data=login_data)
    
    # Verify Login
    if "Welcome to Damn Vulnerable Web App" not in r.text:
        print("[!] Login failed. Checking if database setup is required...")
        
        # Try to Setup DB
        setup_url = urljoin(base_url, "setup.php")
        r_setup = s.get(setup_url)
        
        # Get CSRF for setup
        setup_token = ""
        if "user_token" in r_setup.text:
            match = re.search(r"name='user_token' value='([0-9a-f]+)'", r_setup.text)
            if match:
                setup_token = match.group(1)
        
        print(f"[*] Attempting to Create / Reset Database at {setup_url}...")
        setup_data = {
            "create_db": "Create / Reset Database",
            "user_token": setup_token
        }
        r_setup_post = s.post(setup_url, data=setup_data)
        
        # Process redirection after setup (usually goes to login.php)
        # Retry Login
        print("[*] Retrying Login...")
        # Get FRESH login page for new CSRF
        r = s.get(login_url)
        token = ""
        if "user_token" in r.text:
            match = re.search(r"name='user_token' value='([0-9a-f]+)'", r.text)
            if match:
                token = match.group(1)
        
        login_data["user_token"] = token
        r = s.post(login_url, data=login_data)
        
        if "Welcome to Damn Vulnerable Web App" not in r.text:
            print("Error: Login failed even after DB reset. Check credentials.")
            sys.exit(1)
        else:
            print("[+] Login Success after DB Setup!")

    # 3. Set Security Level to Low
    security_url = urljoin(base_url, "security.php")
    # Fetch security page to get CSRF token for this form too
    r = s.get(security_url)
    token = ""
    if "user_token" in r.text:
        import re
        match = re.search(r"name='user_token' value='([0-9a-f]+)'", r.text)
        if match:
            token = match.group(1)

    security_data = {
        "security": "low",
        "seclev_submit": "Submit",
        "user_token": token
    }
    
    s.post(security_url, data=security_data)
    
    # 4. Construct Cookie String
    # Start with explicit PHPSESSID
    cookies = s.cookies.get_dict()
    cookie_str = f"PHPSESSID={cookies.get('PHPSESSID', '')}; security=low"
    
    return cookie_str

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fetch DVWA Auth Cookies")
    parser.add_argument("--url", default="http://localhost:4280", help="Base URL of DVWA (root)")
    parser.add_argument("-u", "--username", default="admin", help="Username")
    parser.add_argument("-p", "--password", default="password", help="Password")
    
    args = parser.parse_args()
    
    print(f"[*] Connecting to {args.url}...")
    cookie = get_dvwa_cookie(args.url, args.username, args.password)
    
    print("\n[+] SUCCESS! Use this cookie string:")
    print("-" * 60)
    print(cookie)
    print("-" * 60)
    print(f"\nExample Command:")
    print(f'python3 -m src.main --target "{args.url}/vulnerabilities/exec/" --cookie "{cookie}" --mode vulntest')
