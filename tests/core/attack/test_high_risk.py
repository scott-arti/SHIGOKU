import pytest
from src.core.attack.high_risk_tester import SmugglingTester, CachePoisoner

class TestHighRiskTester:
    
    @pytest.fixture
    def smuggling_tester(self):
        return SmugglingTester()
        
    @pytest.fixture
    def cache_poisoner(self):
        return CachePoisoner()
    
    def test_cl_te_generation(self, smuggling_tester):
        payload = smuggling_tester.generate_cl_te_payload("example.com", "GET /404 HTTP/1.1")
        assert payload.attack_type == "CL.TE"
        assert "Content-Length" in payload.headers
        assert "Transfer-Encoding" in payload.headers
        assert b"0\r\n\r\n" in payload.body
        
    def test_te_cl_generation(self, smuggling_tester):
        payload = smuggling_tester.generate_te_cl_payload("example.com", "GET /404 HTTP/1.1")
        assert payload.attack_type == "TE.CL"
        assert payload.headers["Content-Length"] == "4" # Fake length
        
    def test_unkeyed_input_detection(self, cache_poisoner):
        # Mock responses
        original = "<html>Hello</html>"
        injected = {
            "X-Forwarded-Host": "<html>Hello CANARY</html>", # Reflected
            "X-Foo": "<html>Hello</html>" # Not reflected
        }
        
        # We assume values contained "CANARY" if reflected
        # detect_unkeyed_input logic checks for "CANARY" inside the response string provided
        # Wait, the method signature takes response strings, but expects us to map header->response
        # Let's verify the method logic: if "CANARY" in resp -> header is suspect
        
        reflected = cache_poisoner.detect_unkeyed_input(original, injected)
        assert "X-Forwarded-Host" in reflected
        assert "X-Foo" not in reflected
