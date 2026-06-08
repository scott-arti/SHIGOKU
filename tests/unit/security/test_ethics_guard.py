import pytest
from src.core.security.ethics_guard import EthicsGuard, ActionResult, ActionType, ScopeDefinition

@pytest.fixture
def test_scope():
    return ScopeDefinition(
        program_name="Test Bug Bounty",
        in_scope_domains=["target.com"],
        strict_mode=False
    )

@pytest.fixture
def ethics_guard(test_scope):
    return EthicsGuard(scope=test_scope)

def test_ethics_guard_allowed(ethics_guard):
    """通常のHTTPリクエストがスコープ内で許可されること"""
    result, reason = ethics_guard.check_action(
        ActionType.HTTP_REQUEST, "http://target.com"
    )
    assert result == ActionResult.ALLOWED

def test_ethics_guard_blocked_command(ethics_guard):
    """危険なシェルコマンドが BLOCKED になること"""
    result, reason = ethics_guard.check_action(
        ActionType.SHELL_COMMAND, "rm -rf /tmp/data"
    )
    assert result == ActionResult.BLOCKED
    assert "Dangerous command pattern" in reason

def test_ethics_guard_requires_approval(ethics_guard):
    """params で requests_approval が渡された場合、REQUIRES_APPROVAL になること"""
    result, reason = ethics_guard.check_action(
        ActionType.SHELL_COMMAND, "nmap -p- target.com",
        params={"requires_approval": True}
    )
    assert result == ActionResult.REQUIRES_APPROVAL
    assert "High-risk action" in reason

def test_ethics_guard_strict_mode(test_scope):
    """strict_mode が有効な場合、設定外のドメインがブロックされること"""
    test_scope.strict_mode = True
    test_scope.in_scope_domains = ["target.com"]
    guard = EthicsGuard(scope=test_scope)
    
    result, reason = guard.check_action(
        ActionType.HTTP_REQUEST, "http://api.target.com"
    )
    
    assert result == ActionResult.BLOCKED
    assert "NOT in scope" in reason


def test_ethics_guard_allows_in_scope_domain_with_port():
    """in_scope がホストのみでも、URL側にポートが付く通常ケースを許可すること"""
    guard = EthicsGuard(
        scope=ScopeDefinition(
            program_name="Local Test",
            in_scope_domains=["127.0.0.1"],
            strict_mode=False,
        )
    )

    result, reason = guard.check_action(
        ActionType.HTTP_REQUEST, "http://127.0.0.1:8888/account"
    )

    assert result == ActionResult.ALLOWED
    assert "in scope" in reason.lower()


def test_ethics_guard_blocks_when_out_of_scope_pattern_includes_port():
    """out_of_scope に host:port が指定されている場合は netloc 一致で遮断されること"""
    guard = EthicsGuard(
        scope=ScopeDefinition(
            program_name="Port Specific Scope",
            in_scope_domains=["target.com"],
            out_of_scope_domains=["target.com:8443"],
            strict_mode=False,
        )
    )

    result, reason = guard.check_action(
        ActionType.HTTP_REQUEST, "https://target.com:8443/admin"
    )

    assert result == ActionResult.BLOCKED
    assert "OUT OF SCOPE" in reason
