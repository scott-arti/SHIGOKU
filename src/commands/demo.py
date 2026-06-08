"""
Grand Demo Mode Command
"""
import time
from src.commands import print_banner, print_header, print_step, print_result, print_finding

def run_grand_demo():
    """
    Grand Demo Mode
    
    システムの全機能をデモンストレーション。
    シミュレーションで各コンポーネントの動作を可視化。
    """
    from src.core.security.scope_parser import ScopeParser, get_ethics_guard
    from src.core.security.ethics_guard import ScopeDefinition
    from src.core.intel.commit_watcher import CommitWatcher
    from src.intelligence.proxy_log_analyzer import (
        ProxyLogAnalyzer, SmellType, FindingCandidate
    )
    from src.core.agents.swarm import JWTInspector, create_bizlogic_hunter
    from src.core.models.finding import Finding, Evidence, Severity, VulnType
    from src.core.reports.auto_reporter import AutoReporter
    
    print_banner()
    
    # ===== Scene 1: Initialization =====
    print_header("🚀 SCENE 1: SYSTEM INITIALIZATION")
    
    print_step("🛡️", "Initializing EthicsGuard...")
    guard = get_ethics_guard()
    guard.scope = ScopeDefinition(
        program_name="Target Corp Bug Bounty",
        in_scope_domains=["*.target-corp.com", "api.target-corp.com"],
        in_scope_ips=[],
        out_of_scope_domains=["*.google.com"],
        out_of_scope_paths=[],
        max_requests_per_minute=60,
    )
    print_result(True, "EthicsGuard initialized")
    print(f"       └─ In-Scope: *.target-corp.com")
    print(f"       └─ Rate Limit: 60/min")
    
    print_step("📚", "RAG Switch: Available (Obsidian connected)")
    print_step("🔧", "All agents loaded: JWTInspector, OAuthDancer, MFABypasser, BizLogicHunter")
    
    time.sleep(1)
    
    # ===== Scene 2: GitHub Monitoring =====
    print_header("👁️ SCENE 2: GITHUB MONITORING (Simulated)")
    
    print_step("🔍", "CommitWatcher scanning target-corp/backend...")
    time.sleep(0.5)
    
    # シミュレーション: シークレット漏洩検知
    print()
    print("  ┌─────────────────────────────────────────────────────┐")
    print("  │  🚨 SECRET LEAKED IN COMMIT abc1234                 │")
    print("  │  ─────────────────────────────────────────────────  │")
    print("  │  File: config/settings.py                          │")
    print("  │  Line: +JWT_SECRET = 'super_secret_key_12345'       │")
    print("  │  Severity: 🔴 CRITICAL                              │")
    print("  └─────────────────────────────────────────────────────┘")
    
    leaked_secret = "super_secret_key_12345"
    print_result(True, f"Captured JWT secret: {leaked_secret[:10]}...")
    
    time.sleep(1)
    
    # ===== Scene 3: JWT Attack =====
    print_header("⚔️ SCENE 3: JWT ATTACK (Exploiting Leaked Secret)")
    
    print_step("🔑", "JWTInspector activated")
    print_step("🎯", "Target: https://api.target-corp.com/users/me")
    print()
    
    # シミュレーション: alg=none攻撃
    print("  ┌─────────────────────────────────────────────────────┐")
    print("  │  Attempting alg=none attack...                     │")
    print("  │  ─────────────────────────────────────────────────  │")
    print("  │  Original: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... │")
    print("  │  Forged:   eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0...   │")
    print("  │                                                     │")
    print("  │  📤 Request: GET /users/me                          │")
    print("  │  📥 Response: 200 OK                                │")
    print("  │     {\"id\": 1, \"username\": \"admin\", \"role\": \"admin\"}  │")
    print("  │                                                     │")
    print("  │  ✅ BYPASS SUCCESSFUL!                              │")
    print("  └─────────────────────────────────────────────────────┘")
    
    jwt_finding = Finding(
        vuln_type=VulnType.JWT_ALG_NONE,
        severity=Severity.CRITICAL,
        title="JWT Authentication Bypass via alg=none",
        description="The application accepts JWT tokens with alg=none header.",
        target_url="https://api.target-corp.com/users/me",
        target_program="Target Corp Bug Bounty",
        evidence=Evidence(
            request_method="GET",
            request_url="https://api.target-corp.com/users/me",
            response_status=200,
            response_body='{"id": 1, "username": "admin", "role": "admin"}',
        ),
        reproduction_steps=[
            "1. Capture a valid JWT token",
            "2. Decode and change 'alg' to 'none'",
            "3. Remove the signature",
            "4. Send modified token",
        ],
        source_agent="jwt_inspector",
        confidence=0.95,
    )
    
    print_finding(jwt_finding)
    
    time.sleep(1)
    
    # ===== Scene 4: Caido Log Analysis =====
    print_header("🔍 SCENE 4: CAIDO LOG ANALYSIS (Simulated)")
    
    print_step("📂", "Loading proxy log: caido_session.json")
    print_step("🔇", "Filtering noise: 150 → 42 entries")
    print_step("👃", "Detecting smells...")
    print()
    
    print("  ┌─────────────────────────────────────────────────────┐")
    print("  │  SMELL DETECTION RESULTS                           │")
    print("  │  ─────────────────────────────────────────────────  │")
    print("  │  🔴 [P5] JWT: /api/auth/token                       │")
    print("  │  🔴 [P5] Admin: /admin/dashboard                    │")
    print("  │  🟠 [P4] IDOR: /api/users/100/profile               │")
    print("  │  🟠 [P4] Hidden Param: role=user                    │")
    print("  │  🟡 [P3] Auth Anomaly: Cookie-only API              │")
    print("  └─────────────────────────────────────────────────────┘")
    
    time.sleep(1)
    
    # ===== Scene 5: IDOR Attack =====
    print_header("⚔️ SCENE 5: IDOR ATTACK (BizLogicHunter)")
    
    print_step("🎯", "Target: /api/users/100/profile")
    print_step("🔧", "BizLogicHunter.verify_idor() executing...")
    print()
    
    print("  ┌─────────────────────────────────────────────────────┐")
    print("  │  Testing ID manipulation...                        │")
    print("  │  ─────────────────────────────────────────────────  │")
    print("  │  Original: GET /api/users/100/profile → 200 OK     │")
    print("  │  Test #1:  GET /api/users/1/profile   → 200 OK     │")
    print("  │                                                     │")
    print("  │  📥 Response for ID=1:                              │")
    print("  │     {\"id\": 1, \"email\": \"admin@corp.com\",            │")
    print("  │      \"name\": \"Administrator\", \"ssn\": \"***-**-1234\"}  │")
    print("  │                                                     │")
    print("  │  ❗ PII EXPOSED: email, name, ssn                   │")
    print("  │  ✅ IDOR CONFIRMED!                                 │")
    print("  └─────────────────────────────────────────────────────┘")
    
    idor_finding = Finding(
        vuln_type=VulnType.IDOR,
        severity=Severity.HIGH,
        title="IDOR: Unauthorized Access to User Profiles",
        description="By changing user ID from 100 to 1, admin's PII was exposed.",
        target_url="https://api.target-corp.com/api/users/1/profile",
        target_program="Target Corp Bug Bounty",
        evidence=Evidence(
            request_method="GET",
            request_url="https://api.target-corp.com/api/users/1/profile",
            response_status=200,
            response_body='{"id": 1, "email": "admin@corp.com", "name": "Administrator"}',
        ),
        reproduction_steps=[
            "1. Login as regular user",
            "2. Navigate to /api/users/100/profile",
            "3. Change 100 to 1",
            "4. Observe admin's data",
        ],
        source_agent="bizlogic_hunter",
        confidence=0.9,
    )
    
    print_finding(idor_finding)
    
    time.sleep(1)
    
    # ===== Scene 6: Report Generation =====
    print_header("📝 SCENE 6: AUTO-REPORTER")
    
    reporter = AutoReporter()
    
    print_step("📄", "Generating HackerOne-format reports...")
    
    for finding in [jwt_finding, idor_finding]:
        report = reporter.generate_report(finding)
        # レポートのプレビュー
        preview = report[:200].replace("\n", "\n       ")
        print()
        print(f"  ┌─ {finding.title[:45]}...")
        print(f"  │  Severity: {finding.get_severity_icon()} {finding.severity.value.upper()}")
        print(f"  │  CWE: {finding.cwe_id or 'N/A'}")
        print(f"  └─ Report generated ✅")
    
    time.sleep(1)
    
    # ===== Final Summary =====
    print_header("🏆 HUNT COMPLETE")
    
    print()
    print("  ╔═══════════════════════════════════════════════════════╗")
    print("  ║                   MISSION SUMMARY                     ║")
    print("  ╠═══════════════════════════════════════════════════════╣")
    print("  ║  🔍 Sources Analyzed:                                 ║")
    print("  ║     • GitHub Commits: 1 secret leaked                 ║")
    print("  ║     • Caido Logs: 42 requests filtered                ║")
    print("  ║                                                       ║")
    print("  ║  ⚔️ Attacks Executed:                                 ║")
    print("  ║     • JWT alg=none: SUCCESS                           ║")
    print("  ║     • IDOR user_id: SUCCESS                           ║")
    print("  ║                                                       ║")
    print("  ║  📝 Reports Generated: 2                              ║")
    print("  ║     • JWT Authentication Bypass via alg=none          ║")
    print("  ║     • IDOR: Unauthorized Access to User Profiles      ║")
    print("  ║                                                       ║")
    print("  ║  💰 Estimated Bounty: $5,000 - $15,000                ║")
    print("  ╚═══════════════════════════════════════════════════════╝")
    print()
    print("  🎯 SHIGOKU: From Recon to Report, Fully Autonomous.")
    print()
