import pytest
import json
from src.core.attack.jwt_attacker import JWTAttacker, JWTAttackResult

class TestJWTAttacker:
    
    @pytest.fixture
    def attacker(self):
        return JWTAttacker()
    
    @pytest.fixture
    def sample_token(self, attacker):
        # Header: {"alg": "HS256", "typ": "JWT"}
        # Payload: {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}
        # Secret: "secret"
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}
        secret = b"secret"
        return attacker.forge_token(header, payload, secret, alg="HS256")

    def test_decode(self, attacker, sample_token):
        header, payload, signature = attacker.decode(sample_token)
        assert header["alg"] == "HS256"
        assert payload["name"] == "John Doe"
        assert len(signature) > 0

    def test_attack_none_algorithm(self, attacker, sample_token):
        results = attacker.attack_none_algorithm(sample_token)
        assert len(results) >= 1
        
        found_none = False
        for res in results:
            if "none" in res.description or "None" in res.description:
                header, _, sig = attacker.decode(res.forged_token)
                assert header["alg"].lower() == "none"
                assert sig == ""
                found_none = True
        assert found_none

    def test_attack_kid_manipulation(self, attacker):
        # Header with KID
        header = {"alg": "HS256", "typ": "JWT", "kid": "key1"}
        payload = {"user": "admin"}
        secret = b"secret"
        token = attacker.forge_token(header, payload, secret)
        
        injections = ["../../../../etc/passwd", "/dev/null"]
        results = attacker.attack_kid_manipulation(token, injections)
        
        assert len(results) == 2
        
        # Check first injection
        res = results[0]
        header, _, _ = attacker.decode(res.forged_token)
        assert header["kid"] == "../../../../etc/passwd"
        
    def test_attack_algo_confusion(self, attacker):
        # Simulate RS256 token
        header = {"alg": "RS256", "typ": "JWT"}
        payload = {"user": "admin"}
        # Note: In real RS256, forge_token needs private key, but for test input simulation we use dummy sig
        # or we just use forge_token with alg="none" then manually patch header for test input
        
        # Helper to create "fake" RS256 token for input
        t_header = attacker._base64url_encode(json.dumps(header).encode())
        t_payload = attacker._base64url_encode(json.dumps(payload).encode())
        t_sig = "dummy_rsa_signature"
        rs256_token = f"{t_header}.{t_payload}.{t_sig}"
        
        public_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----"
        
        results = attacker.attack_algo_confusion(rs256_token, public_key)
        
        assert len(results) == 1
        res = results[0]
        
        header, _, _ = attacker.decode(res.forged_token)
        assert header["alg"] == "HS256"
        # Signature should be HMAC(pubkey, content)
        # We can't verify sig easily without reimplementing logic, but we checked alg name
