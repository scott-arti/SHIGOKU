import pytest
from src.core.attack.mass_assignment_tester import MassAssignmentTester, ContentType

class TestMassAssignmentTester:
    
    @pytest.fixture
    def tester(self):
        return MassAssignmentTester()
    
    def test_generate_payloads_json(self, tester):
        original = {"username": "user", "email": "test@example.com"}
        payloads = tester.generate_payloads(original, ContentType.JSON)
        
        # Check basic injections
        param_names = [p.param_name for p in payloads]
        assert "is_admin" in param_names
        assert "role" in param_names
        
        # Check payload structure
        for p in payloads:
            if p.param_name == "is_admin":
                assert p.payload_sent["is_admin"] == True
                assert p.payload_sent["username"] == "user"

    def test_generate_payloads_nested_json(self, tester):
        original = {"user": {"name": "test"}}
        payloads = tester.generate_payloads(original, ContentType.JSON)
        
        # Should attempt to inject into top level AND into nested object
        nested_injections = [p for p in payloads if p.format == "nested_object"]
        assert len(nested_injections) > 0
        
        sample = nested_injections[0]
        # e.g. user.admin = True
        key = sample.param_name.split(".")[-1] # "admin" or similar
        assert key in sample.payload_sent["user"]

    def test_analyze_response(self, tester):
        # Case 1: Vulnerable (Reflection)
        attempt = list(tester.generate_payloads({"u":"t"}, ContentType.JSON))[0]
        # Suppose we injected is_admin=True
        injected_resp = {"id": 1, "u": "t", "is_admin": True} 
        
        # Find the attempt corresponding to is_admin=True
        target_attempt = None
        for p in tester.generate_payloads({"u":"t"}, ContentType.JSON):
            if p.param_name == "is_admin":
                target_attempt = p
                break
        
        assert target_attempt
        assert tester.analyze_response({}, injected_resp, target_attempt) is True

        # Case 2: Secure (Ignored)
        secure_resp = {"id": 1, "u": "t"}
        assert tester.analyze_response({}, secure_resp, target_attempt) is False
