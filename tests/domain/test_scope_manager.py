
import pytest
from pathlib import Path
from src.core.domain.scope.scope_manager import ScopeManager
from src.core.domain.model.target import TargetType

@pytest.fixture
def scope_file(tmp_path):
    f = tmp_path / "scope.txt"
    f.write_text("""
# In-Scope
https://example.com
*.sub.example.com
192.168.1.1

# Out-of-Scope
http://admin.example.com
/logout
""")
    return f

def test_scope_loader(scope_file):
    manager = ScopeManager(str(scope_file))
    targets = manager.load_scope()
    
    # Assertions
    # https://example.com -> SINGLE_URL_PUBLIC
    # *.sub.example.com -> WILDCARD_DOMAIN
    # 192.168.1.1 -> SINGLE_URL_INTERNAL
    
    urls = [t.raw_input for t in targets]
    assert "https://example.com" in urls
    assert "*.sub.example.com" in urls
    assert "192.168.1.1" in urls
    
    # Check Filter (Out of Scope)
    # The current implementation relies on ScopeParser to parse "Out-of-Scope" sections from text.
    # However, ScopeParser.parse_from_text logic might be tricky with simple line-by-line seed extraction.
    # Let's verify if "http://admin.example.com" is excluded.
    # In scope_parser.py, if a domain is in Out-of-Scope section, validate_target returns False.
    # But ScopeManager also iterates lines.
    
    # If "http://admin.example.com" is effectively parsed as out-of-scope domain "admin.example.com",
    # then validate_target("http://admin.example.com") should return False.
    
    assert "http://admin.example.com" not in urls
    assert "/logout" not in urls

def test_empty_scope(tmp_path):
    f = tmp_path / "empty_scope.txt"
    f.write_text("")
    manager = ScopeManager(str(f))
    targets = manager.load_scope()
    assert len(targets) == 0

