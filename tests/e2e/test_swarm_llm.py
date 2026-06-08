#!/usr/bin/env python3
"""
E2E Test: Swarm with DeepSeek LLM

実際のSwarm実装をDeepSeek LLMでテストする。
testphp.vulnweb.com を安全なテストターゲットとして使用。
"""
import asyncio
import logging
import os
import sys
from pathlib import Path
from dotenv import load_dotenv
import httpx
from unittest.mock import patch

# プロジェクトルートをパスに追加
PROJECT_ROOT = Path(__file__).parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

# .env 読み込み
load_dotenv(PROJECT_ROOT / ".env")

# ログ設定
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("e2e_swarm_llm")

# 環境変数チェック
os.environ["SHIGOKU_DEV_MODE"] = "true"

# DeepSeek モデル設定
DEEPSEEK_MODEL = "deepseek/deepseek-chat"

# テストターゲット (公開脆弱テストサイト)
TEST_TARGET = "http://testphp.vulnweb.com/listproducts.php?cat=1"


async def test_injection_swarm():
    """InjectionSwarm をテスト (SQLi検出)"""
    from src.core.agents.swarm.injection import InjectionSwarm
    from src.core.agents.swarm.base import Task
    
    logger.info("=" * 60)
    logger.info("Test: InjectionSwarm with DeepSeek")
    logger.info("Target: %s", TEST_TARGET)
    logger.info("=" * 60)
    
    # Swarm 初期化
    swarm = InjectionSwarm(config={"model": DEEPSEEK_MODEL})
    
    # タスク作成
    task = Task(
        id="test_injection_1",
        name="SQLi Detection Test",
        target=TEST_TARGET,
        tags=["id_param", "has_params"],
        params={
            "method": "GET",
            "param_name": "cat",
        }
    )
    
    try:
        result = await swarm.dispatch(task)
        
        logger.info("=" * 60)
        logger.info("RESULT:")
        logger.info("  Status: %s", result.status)
        logger.info("  Findings: %d", len(result.findings))
        logger.info("  Input Tags: %s", result.input_tags)
        logger.info("  Output Tags: %s", result.output_tags)
        
        for finding in result.findings:
            logger.info("  [Finding] %s (%s) - %s",
                       finding.title, finding.severity.value, finding.vuln_type.value)
        
        return {
            "swarm": "InjectionSwarm",
            "status": result.status,
            "findings": len(result.findings),
            "input_tags": result.input_tags,
            "output_tags": result.output_tags,
        }
        
    except Exception as e:
        logger.exception("InjectionSwarm test failed: %s", e)
        return {
            "swarm": "InjectionSwarm",
            "status": "error",
            "error": str(e),
        }


async def test_auth_swarm():
    """AuthSwarm をテスト (JWT/Session検査)"""
    import base64
    import json
    import hmac
    import hashlib
    
    from src.core.agents.swarm.auth import AuthSwarm
    from src.core.agents.swarm.base import Task
    
    logger.info("=" * 60)
    logger.info("Test: AuthSwarm with Mock JWT Token")
    logger.info("=" * 60)
    
    # テスト用JWTトークンを生成（弱い秘密鍵 "secret" で署名）
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "1234567890", "name": "Test User", "iat": 1516239022}
    
    header_b64 = base64.urlsafe_b64encode(
        json.dumps(header, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()
    
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()
    
    message = f"{header_b64}.{payload_b64}".encode()
    signature = base64.urlsafe_b64encode(
        hmac.new(b"secret", message, hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    
    test_jwt = f"{header_b64}.{payload_b64}.{signature}"
    
    logger.info("Generated test JWT with weak secret 'secret'")
    logger.info("Token: %s...", test_jwt[:50])
    
    swarm = AuthSwarm(config={"model": DEEPSEEK_MODEL})
    
    task = Task(
        id="test_auth_1",
        name="JWT Weak Secret Test",
        target="http://httpbin.org/get",  # 認証エンドポイントのモック
        tags=["auth_endpoint", "jwt_token"],
        params={
            "token": test_jwt,
            "test_endpoint": "http://httpbin.org/get",
        }
    )
    
    try:
        result = await swarm.dispatch(task)
        
        logger.info("=" * 60)
        logger.info("RESULT:")
        logger.info("  Status: %s", result.status)
        logger.info("  Findings: %d", len(result.findings))
        logger.info("  Specialists: %d successful, %d failed", 
                   result.successful_specialists, result.failed_specialists)
        
        for finding in result.findings:
            logger.info("  [Finding] %s (%s)", finding.title, finding.vuln_type.value)
        
        return {
            "swarm": "AuthSwarm",
            "status": result.status,
            "findings": len(result.findings),
        }
        
    except Exception as e:
        logger.exception("AuthSwarm test failed: %s", e)
        return {"swarm": "AuthSwarm", "status": "error", "error": str(e)}


async def test_discovery_swarm():
    """DiscoverySwarm をテスト (JS解析)"""
    from src.core.agents.swarm.discovery import DiscoverySwarm
    from src.core.agents.swarm.base import Task
    
    logger.info("=" * 60)
    logger.info("Test: DiscoverySwarm (JS Analysis)")
    logger.info("=" * 60)
    
    swarm = DiscoverySwarm(config={"model": DEEPSEEK_MODEL})
    
    # testphp.vulnweb.com の JS ファイル
    task = Task(
        id="test_discovery_1",
        name="JS Analysis Test",
        target="http://testphp.vulnweb.com/",
        tags=["js_file"],
        params={
            "js_urls": [
                "http://testphp.vulnweb.com/Flash/add.js",
            ]
        }
    )
    
    try:
        result = await swarm.dispatch(task)
        
        logger.info("=" * 60)
        logger.info("RESULT:")
        logger.info("  Status: %s", result.status)
        logger.info("  Findings: %d", len(result.findings))
        
        for finding in result.findings:
            logger.info("  [Finding] %s (%s)", finding.title, finding.vuln_type.value)
        
        return {
            "swarm": "DiscoverySwarm",
            "status": result.status,
            "findings": len(result.findings),
        }
        
    except Exception as e:
        logger.exception("DiscoverySwarm test failed: %s", e)
        return {"swarm": "DiscoverySwarm", "status": "error", "error": str(e)}


async def test_discovery_swarm_found():
    """DiscoverySwarm Found Test (Mock JS Content)"""
    from src.core.agents.swarm.discovery import DiscoverySwarm
    from src.core.agents.swarm.base import Task
    from unittest.mock import patch, AsyncMock
    
    logger.info("=" * 60)
    logger.info("Test: DiscoverySwarm Found Test (Mock JS)")
    logger.info("=" * 60)
    
    # Mock Payload with Secrets
    # AKIA... (AWS Key pattern)
    # 32-char hex string (Generic API Key pattern)
    mock_js_content = """
    function init() {
        console.log("Initializing app...");
        var awsKey = "AKIAIOSFODNN7EXAMPLE";
        var apiKey = "1234567890abcdef1234567890abcdef";
        var debug = true;
    }
    """
    
    swarm = DiscoverySwarm(config={"model": DEEPSEEK_MODEL})
    
    task = Task(
        id="test_discovery_found",
        name="JS Secret Discovery Test",
        target="http://example.com/app.js",
        tags=["js_file"],
        params={"js_urls": ["http://example.com/app.js"]}
    )
    
    # Patch _fetch_js_content
    with patch("src.core.agents.swarm.discovery.manager.JSInspector._fetch_js_content", new_callable=AsyncMock) as mock_fetch:
        mock_fetch.return_value = mock_js_content
        
        try:
            result = await swarm.dispatch(task)
            
            logger.info("=" * 60)
            logger.info("RESULT:")
            logger.info("  Status: %s", result.status)
            logger.info("  Findings: %d", len(result.findings))
            
            for finding in result.findings:
                logger.info("  [Finding] %s (%s)", finding.title, finding.vuln_type.value)
                
            return {
                "swarm": "DiscoverySwarm (Found)",
                "status": result.status,
                "findings": len(result.findings)
            }
            
        except Exception as e:
            logger.exception("DiscoverySwarm found test failed: %s", e)
            return {"swarm": "DiscoverySwarm (Found)", "status": "error", "error": str(e)}



async def test_auth_swarm_escalation():
    """AuthSwarm LLM Escalation Test (IDOR/PrivEsc)"""
    from src.core.agents.swarm.auth import AuthSwarm
    from src.core.agents.swarm.base import Task
    import time
    import base64
    import json
    import hmac
    import hashlib
    from unittest.mock import patch, AsyncMock
    
    logger.info("=" * 60)
    logger.info("Test: AuthSwarm LLM Escalation (Context Analysis)")
    logger.info("=" * 60)
    
    def create_mock_jwt(payload, secret="secret"):
        header = {"alg": "HS256", "typ": "JWT"}
        
        def b64url(data):
            return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")
            
        h_str = b64url(header)
        p_str = b64url(payload)
        
        sig = hmac.new(
            secret.encode(),
            f"{h_str}.{p_str}".encode(),
            hashlib.sha256
        ).digest()
        s_str = base64.urlsafe_b64encode(sig).decode().rstrip("=")
        
        return f"{h_str}.{p_str}.{s_str}"

    # 1. Create a "User" Token
    payload = {
        "sub": "user_123",
        "role": "user",
        "group_id": 99,
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600
    }
    encoded_token = create_mock_jwt(payload)
    
    swarm = AuthSwarm(config={"model": DEEPSEEK_MODEL, "mode": "aggressive"})
    
    task = Task(
        id="test_auth_escalation",
        name="Privilege Escalation Test",
        target="http://example.com/api/admin/resource/99",
        tags=["jwt_detected"], 
        params={
            "token": encoded_token,
            "original_status": 403
        }
    )
    
    # Patch _verify_payload to simulate successful admin access
    with patch("src.core.agents.swarm.auth.llm_specialists.LLMAuthEscalator._verify_payload", new_callable=AsyncMock) as mock_verify:
        
        async def verify_side_effect(client, url, payload_info, original_status=None):
            desc = payload_info.get("description", "").lower()
            claims = payload_info.get("modified_claims", {})
            logger.info(f"  [Simulating Attack] {desc} -> Claims: {claims}")
            
            # Simulate Success Criteria
            if claims.get("role") == "admin" or \
               claims.get("role") == "administrator" or \
               claims.get("is_admin") == True or \
               claims.get("group_id") == 1:
                return True, "Simulated Success: 200 OK (Admin Access)"
            return False, "403 Forbidden"
            
        mock_verify.side_effect = verify_side_effect
        
        try:
            result = await swarm.dispatch(task)
            
            logger.info("=" * 60)
            logger.info("RESULT:")
            logger.info("  Status: %s", result.status)
            logger.info("  Findings: %d", len(result.findings))
            
            for finding in result.findings:
                logger.info("  [Finding] %s (%s)", finding.title, finding.vuln_type.value)
                
            return {
                "swarm": "AuthSwarm (Escalation)",
                "status": result.status,
                "findings": len(result.findings)
            }
            
        except Exception as e:
            logger.exception("AuthSwarm escalation test failed: %s", e)
            return {"swarm": "AuthSwarm (Escalation)", "status": "error", "error": str(e)}




async def test_discovery_swarm_llm_auditor():
    """DiscoverySwarm: LLMSecretScanner Error Reduction Test"""
    from src.core.agents.swarm.discovery.manager import DiscoverySwarm
    from src.core.agents.swarm.base import Task
    from src.core.models.finding import VulnType

    logger.info("=" * 60)
    logger.info("Test: DiscoverySwarm LLM Auditor")
    logger.info("=" * 60)

    # 1. Mock JS Content with Real & Dummy Secrets
    mock_js_content = """
    // Real looking secret
    const awsKey = "AKIAIOSFODNN7EXAMPLE";
    
    // Dummy / Test secret
    const testKey = "TEST_KEY_12345";
    """

    async def mock_handler(request):
        return httpx.Response(200, text=mock_js_content, headers={"Content-Type": "application/javascript"})

    mock_router = httpx.MockTransport(mock_handler)

    task = Task(
        id="test_discovery_llm_1",
        name="LLM Secret Auditor Test",
        target="http://example.com/app.js",
        params={},
        tags=["js_url"]
    )

    logging.getLogger().setLevel(logging.DEBUG)
    
    # Capture real client class to avoid recursion in patch
    RealAsyncClient = httpx.AsyncClient

    # Re-impl with LLM Mocking for stability
    # Use side_effect to create a NEW client instance each time using the REAL class + MockTransport
    with patch("src.core.agents.swarm.discovery.llm_specialists.httpx.AsyncClient", side_effect=lambda *args, **kwargs: RealAsyncClient(transport=mock_router)):
        with patch("src.core.models.llm.LLMClient.agenerate") as mock_llm:
            # Setup Side Effects
            # Setup Side Effects
            async def llm_side_effect(messages, **kwargs):
                content = messages[0]["content"] if isinstance(messages, list) else messages
                # Check for variable names in context (since secret is masked and comment might be truncated)
                if "awsKey" in content:
                    return '{"is_real_secret": true, "reason": "Looks like AWS key"}'
                if "testKey" in content:
                    return '{"is_real_secret": false, "reason": "Test key pattern"}'
                return '{"is_real_secret": false}'
            
            mock_llm.side_effect = llm_side_effect
            
            manager = DiscoverySwarm()
            result = await manager.dispatch(task)

            logger.info("Findings Count: %d", len(result.findings))
            llm_findings = []
            for i, f in enumerate(result.findings):
                logger.info("  [Finding %d] Title: %s", i, f.title)
                if "Confidential Secret" in f.title:
                    llm_findings.append(f)

            # Assertions
            assert result.status == "success"
            # We expect at least 1 finding from LLM Auditor (plus 1 from JSInspector)
            assert len(llm_findings) == 1
            assert "aws_access_key" in llm_findings[0].description
            
            return {
                "swarm": "DiscoverySwarm (LLM Auditor)",
                "status": "success",
                "findings": len(llm_findings)
            }


async def run_all_tests():
    """全テスト実行"""
    if not os.environ.get("DEEPSEEK_API_KEY"):
        logger.error("DEEPSEEK_API_KEY not set!")
        return {"status": "error", "message": "DEEPSEEK_API_KEY not set"}
    
    logger.info("DeepSeek API Key: SET")
    logger.info("Model: %s", DEEPSEEK_MODEL)
    
    results = []
    
    # Test 1: InjectionSwarm (LLM)
    result1 = await test_injection_swarm()
    results.append(result1)
    
    # Test 2: AuthSwarm (Mock JWT - Rule Based)
    result2 = await test_auth_swarm()
    results.append(result2)
    
    # Test 3: AuthSwarm (LLM Escalation)
    result3 = await test_auth_swarm_escalation()
    results.append(result3)
    
    # Test 4: DiscoverySwarm (Real Target - Expect 0)
    result4 = await test_discovery_swarm()
    results.append(result4)
    
    # Test 5: DiscoverySwarm (Mock Found - Expect >0)
    result5 = await test_discovery_swarm_found()
    results.append(result5)

    # Test 6: DiscoverySwarm LLM Auditor
    result6 = await test_discovery_swarm_llm_auditor()
    results.append(result6)

    # Test 7: LogicSwarm LLM (BizLogicHunter)
    result7 = await test_logic_swarm_llm()
    results.append(result7)
    
    # Test 8: ScannerSwarm LLM (CryptoAnalyzer)
    result8 = await test_scanner_swarm_llm_crypto()
    results.append(result8)
    
    # Test 9: SecretSwarm LLM (CloudMisconfig)
    result9 = await test_secret_swarm_llm_cloud()
    results.append(result9)
    
    return {"status": "completed", "results": results}


async def test_logic_swarm_llm():
    """LogicSwarm LLM Test (BizLogicHunter)"""
    from src.core.agents.swarm.logic.manager import LogicSwarm
    from src.core.agents.swarm.base import Task
    from unittest.mock import patch, AsyncMock

    logger.info("=" * 60)
    logger.info("Test: LogicSwarm LLM (BizLogicHunter)")
    logger.info("=" * 60)

    task = Task(
        id="test_logic_llm_1",
        name="Logic Flaw Analysis",
        target="http://example.com/api/users/100",
        params={"method": "GET"},
        tags=["api_endpoint"]
    )

    # Mock LLM Response
    mock_llm_response = """
    ```json
    {
        "tests": [
            {"type": "idor", "param": "url_id", "payload": "1", "reason": "Try accessing admin ID 1"},
            {"type": "priv_esc", "param": "role", "payload": "admin", "reason": "Attempt role manipulation"}
        ]
    }
    ```
    """

    with patch("src.core.models.llm.LLMClient.agenerate", new_callable=AsyncMock) as mock_generate:
        mock_generate.return_value = mock_llm_response
        
        swarm = LogicSwarm(config={"model": DEEPSEEK_MODEL})
        result = await swarm.dispatch(task)
        
        logger.info("Findings Count: %d", len(result.findings))
        for i, f in enumerate(result.findings):
            logger.info("  [Finding %d] Title: %s", i, f.title)

        # Assertions
        assert result.status == "success"
        # Expect 2 findings based on the mock response
        assert len(result.findings) >= 2
        
        titles = [f.title for f in result.findings]
        assert any("Potential IDOR" in t for t in titles)
        assert any("Potential PRIV_ESC" in t for t in titles)

        return {
            "swarm": "LogicSwarm (LLM)",
            "status": "success",
            "findings": len(result.findings)
        }


async def test_scanner_swarm_llm_crypto():
    """ScannerSwarm LLM Test (CryptoAnalyzer)"""
    from src.core.agents.swarm.scanner.manager import ScannerSwarm
    from src.core.agents.swarm.base import Task
    from unittest.mock import AsyncMock
    
    logger.info("=" * 60)
    logger.info("Test: ScannerSwarm LLM (Crypto)")
    logger.info("=" * 60)
    
    # モックSSL/TLS設定データ
    mock_crypto_data = {
        "target": "example.com",
        "tls_versions": ["TLS 1.0", "TLS 1.2", "TLS 1.3"],
        "cipher_suites": [
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_RSA_WITH_RC4_128_SHA",  # 弱い暗号
            "TLS_RSA_WITH_3DES_EDE_CBC_SHA"  # 非推奨
        ],
        "certificate": {
            "valid": True,
            "issuer": "Let's Encrypt",
            "key_size": 2048
        }
    }
    
    with patch("src.core.models.llm.LLMClient.agenerate") as mock_llm:
        # LLMのモックレスポンス（TLS 1.0と弱い暗号を検出）
        mock_llm.return_value = """
{
  "vulnerabilities": [
    {
      "title": "非推奨TLS 1.0が有効",
      "description": "TLS 1.0は既知の脆弱性があり、PCI DSSでも非推奨です。TLS 1.2以上のみを許可してください。",
      "severity": "high",
      "confidence": 0.95,
      "tags": ["tls_1.0", "deprecated_protocol"]
    },
    {
      "title": "弱い暗号スイート検出",
      "description": "RC4と3DESは安全でないため使用を中止してください。AES-GCMのような強力なアルゴリズムのみを使用してください。",
      "severity": "high",
      "confidence": 0.9,
      "tags": ["weak_cipher", "rc4", "3des"]
    }
  ]
}
"""
        
        # ScannerSwarmを実行（crypto_dataをパラメータで渡す）
        task = Task(
            id="test-scanner",
            name="Crypto Analysis Test",
            target="https://example.com",
            params={"crypto_data": mock_crypto_data}
        )
        
        swarm = ScannerSwarm(config={"model": DEEPSEEK_MODEL})
        result = await swarm.dispatch(task)
        
        # Assertions
        assert result.status == "success"
        crypto_findings = [f for f in result.findings if f.source_agent == "LLMCryptoAnalyzer"]
        
        # LLMCryptoAnalyzerからの2つのFindingを期待
        assert len(crypto_findings) >= 2, f"Expected 2+ findings, got {len(crypto_findings)}"
        
        # 重要度の確認
        high_findings = [f for f in crypto_findings if f.severity.value == "high"]
        assert len(high_findings) >= 2, f"Expected 2+ high-severity findings"
        
        logger.info(f"Crypto Findings: {len(crypto_findings)}")
        for f in crypto_findings:
            logger.info(f"  [Finding] {f.title}")
        
        return {
            "swarm": "ScannerSwarm (LLM Crypto)",
            "status": "success",
            "findings": len(crypto_findings)
        }


async def test_secret_swarm_llm_cloud():
    """SecretSwarm LLM Test (CloudMisconfigAnalyzer)"""
    from src.core.agents.swarm.secret.manager import SecretSwarm
    from src.core.agents.swarm.base import Task
    
    logger.info("=" * 60)
    logger.info("Test: SecretSwarm LLM (Cloud Misconfig)")
    logger.info("=" * 60)
    
    # モックS3バケット設定データ
    mock_cloud_data = {
        "bucket_name": "example-company-data",
        "region": "us-east-1",
        "acl": "public-read",  # 危険な設定
        "bucket_policy": {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",  # パブリックアクセス
                "Action": ["s3:GetObject"],
                "Resource": "arn:aws:s3:::example-company-data/*"
            }]
        },
        "encryption": None,  # 暗号化なし
        "logging": False
    }
    
    with patch("src.core.models.llm.LLMClient.agenerate") as mock_llm:
        # LLMのモックレスポンス
        mock_llm.return_value = """
{
  "vulnerabilities": [
    {
      "title": "S3バケットがパブリックアクセス可能",
      "description": "バケットポリシーで Principal:'*' が設定されており、インターネット上の誰でもオブジェクトにアクセスできます。",
      "severity": "critical",
      "confidence": 0.95,
      "tags": ["s3_public", "bucket_policy"]
    },
    {
      "title": "サーバーサイド暗号化が無効",
      "description": "S3バケットでサーバーサイド暗号化が設定されていません。保存データの暗号化を有効にしてください。",
      "severity": "high",
      "confidence": 0.9,
      "tags": ["no_encryption", "compliance"]
    }
  ]
}
"""
        
        # SecretSwarmを実行
        task = Task(
            id="test-secret",
            name="Cloud Misconfig Test",
            target="s3://example-company-data",
            params={"cloud_data": mock_cloud_data}
        )
        
        swarm = SecretSwarm(config={"model": DEEPSEEK_MODEL})
        result = await swarm.dispatch(task)
        
        # Assertions
        assert result.status == "success"
        cloud_findings = [f for f in result.findings if f.source_agent == "LLMCloudMisconfigAnalyzer"]
        
        # LLMCloudMisconfigAnalyzerからの2つのFindingを期待
        assert len(cloud_findings) >= 2, f"Expected 2+ findings, got {len(cloud_findings)}"
        
        logger.info(f"Cloud Findings: {len(cloud_findings)}")
        for f in cloud_findings:
            logger.info(f"  [Finding] {f.title}")
        
        return {
            "swarm": "SecretSwarm (LLM Cloud)",
            "status": "success",
            "findings": len(cloud_findings)
        }


def main():
    print("\n" + "=" * 60)
    print("SHIGOKU Swarm E2E Test (DeepSeek LLM)")
    print("=" * 60 + "\n")
    
    results = asyncio.run(run_all_tests())
    
    print("\n" + "=" * 60)
    print("FINAL RESULTS:")
    print("=" * 60)
    
    if results.get("status") == "error":
        print(f"❌ Error: {results.get('message')}")
        sys.exit(1)
    
    for r in results.get("results", []):
        status_icon = "✅" if r.get("status") == "success" else "⚠️"
        print(f"  {status_icon} {r.get('swarm', r.get('test'))}: {r.get('status')} ({r.get('findings', 0)} findings)")
    
    print("\n✅ E2E Test Completed")


if __name__ == "__main__":
    main()
