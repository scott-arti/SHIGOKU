import pytest
from src.tools.custom.gopher_tool import GopherTool

class TestGopherTool:
    
    @pytest.fixture
    def tool(self):
        return GopherTool()
    
    def test_redis_payload(self, tool):
        cmds = ["SET key val", "QUIT"]
        payload = tool.generate_redis_payload("127.0.0.1", 6379, cmds)
        
        assert payload.startswith("gopher://127.0.0.1:6379/_")
        # Check for encoded parts
        # *2 -> %2A2 (double quoted?) -> quote('*') is %2A.
        # implementation uses quote(quote(payload))
        # *2\r\n -> %2A2%0D%0A -> %252A2%250D%250A
        
        assert "%252A" in payload # Double encoded *
        assert "%250D%250A" in payload # Double encoded CRLF

    def test_smtp_payload(self, tool):
        payload = tool.generate_smtp_payload("victim@example.com", "Test", "Hello")
        assert "gopher://" in payload
        assert "MAIL%2520FROM" in payload # Double encoded space
