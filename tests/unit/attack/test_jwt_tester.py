import base64
import json
import pytest
from src.core.attack.jwt_tester import JWTTester

@pytest.fixture
def sample_jwt():
    # Header: {"alg": "HS256", "typ": "JWT"} -> eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9
    # Payload: {"sub": "123", "role": "user"} -> eyJzdWIiOiAiMTIzIiwgInJvbGUiOiAidXNlciJ9
    # Signature: dummy_signature
    
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "123", "role": "user"}
    
    h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
    p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
    
    return f"{h_b64}.{p_b64}.dummy_signature"

def test_jwt_extract_claims(sample_jwt):
    tester = JWTTester()
    claims = tester.extract_claims(sample_jwt)
    assert claims["sub"] == "123"
    assert claims["role"] == "user"

def test_jwt_extract_header(sample_jwt):
    tester = JWTTester()
    header = tester.extract_header(sample_jwt)
    assert header["alg"] == "HS256"
    assert header["typ"] == "JWT"

def test_jwt_generate_alg_none(sample_jwt):
    tester = JWTTester()
    attack_tokens = tester.generate_alg_none(sample_jwt)
    
    # 4 variations * 2 types (with trailing dot, without trailing dot) = 8 tokens
    assert len(attack_tokens) == 8
    
    # Check if 'none' is in the headers of generated tokens
    for token in attack_tokens:
        h = tester.extract_header(token + ".dummy" if token.endswith(".") or len(token.split('.')) < 3 else token)
        # Because we added .dummy, extract_header will work
        if token.endswith("."):
            h = tester.extract_header(token + "dummy")
        elif len(token.split('.')) == 2:
            h = tester.extract_header(token + ".dummy")
            
        assert h["alg"].lower() == "none"

def test_jwt_generate_modified_payload(sample_jwt):
    tester = JWTTester()
    modifications = {"role": "admin", "uid": 1}
    mod_token = tester.generate_modified_payload(sample_jwt, modifications, keep_signature=False)
    
    claims = tester.extract_claims(mod_token + "dummy")
    assert claims["role"] == "admin"
    assert claims["uid"] == 1
    assert claims["sub"] == "123" # original claim preserved
    assert mod_token.endswith(".") # keep_signature=False ends with a dot

    mod_token_with_sig = tester.generate_modified_payload(sample_jwt, modifications, keep_signature=True)
    assert mod_token_with_sig.endswith(".dummy_signature")
