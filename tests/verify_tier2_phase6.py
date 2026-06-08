"""
Verification script for Tier 2 Phase 6: PII Protection & Pattern Discovery
"""
import asyncio
import logging
from src.core.intelligence.self_reflection import SelfReflection, ExecutionRecord, ExecutionOutcome
from src.core.intelligence.error_analyzer import ErrorAnalyzer, ErrorRecord
from src.core.learning.repository import get_learning_repository
from src.core.learning.pattern_discovery import get_pattern_discovery
from src.core.security.pii_masker import get_pii_masker

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("verify_learning")

async def verify_pii_protection():
    repo = get_learning_repository()
    reflection = SelfReflection(repository=repo)
    analyzer = ErrorAnalyzer(repository=repo)
    masker = get_pii_masker()
    
    # 1. SelfReflection PII Masking Test
    print("\n--- Testing SelfReflection PII Masking ---")
    record = ExecutionRecord(
        task_id="test_pii_001",
        action_type="sql_injection",
        target="https://example.com/api",
        outcome=ExecutionOutcome.SUCCESS,
        duration_seconds=1.2,
        payload_used="' UNION SELECT credit_card FROM users WHERE email='user@example.com'--",
        findings=["Found leak for admin@internal.shigoku.io"]
    )
    reflection.record(record)
    
    # Retrieve from repo directly to check raw data
    raw_data = repo.retrieve("success_payloads", "sql_injection:https://example.com/api")
    print(f"Raw data in repository: {raw_data}")
    
    if "user@example.com" in raw_data["payload_used"] or "admin@internal.shigoku.io" in str(raw_data["findings"]):
        print("❌ FAILED: PII found in repository!")
    else:
        print("✅ SUCCESS: PII was masked in repository.")

    # 2. ErrorAnalyzer PII Masking Test
    print("\n--- Testing ErrorAnalyzer PII Masking ---")
    error_record = ErrorRecord(
        error_message="Validation error: Invalid API Key 'sk-5555666677778888'",
        status_code=400,
        target_url="https://api.victim.com/v1/data",
    )
    analysis = analyzer.analyze(error_record)
    
    raw_error_data = repo.retrieve("error_knowledge", "validation_error:https://api.victim.com/v1/data")
    print(f"Raw error data in repository: {raw_error_data}")
    
    if "sk-5555" in raw_error_data["likely_cause"]:
        print("❌ FAILED: API Key found in error knowledge!")
    else:
        print("✅ SUCCESS: API Key was masked in error knowledge.")

async def verify_pattern_discovery():
    print("\n--- Testing PatternDiscovery ---")
    pd = get_pattern_discovery()
    
    # Inject more dummy successes to trigger pattern detection
    repo = get_learning_repository()
    for i in range(5):
        repo.store("success_payloads", f"test_pattern_{i}", {
            "payload_used": f"<script>alert({i})</script>",
            "action_type": "xss"
        })
        
    patterns = pd.discover_success_tokens(min_confidence=0.5)
    print(f"Discovered patterns: {patterns}")
    
    if any(p.value in ["<script>", "alert"] for p in patterns):
        print("✅ SUCCESS: Common patterns detected.")
    else:
        print("⚠️ WARNING: Pattern discovery failed to find expected tokens (may need more data).")

async def main():
    await verify_pii_protection()
    await verify_pattern_discovery()

if __name__ == "__main__":
    asyncio.run(main())
