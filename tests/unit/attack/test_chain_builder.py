import pytest
from src.core.attack.chain_builder import ChainBuilder, ExploitChain
from src.core.models.finding import Finding, VulnType, Severity

@pytest.fixture
def sample_findings():
    return [
        Finding(
            vuln_type=VulnType.XSS,
            severity=Severity.MEDIUM,
            title="Reflected XSS on search parameter",
            description="A cross-site scripting vulnerability was found on /search?q=",
            target_url="http://example.com/search",
        ),
        Finding(
            vuln_type=VulnType.DEBUG_ENABLED,
            severity=Severity.LOW,
            title="Missing CSRF Token on update profile",
            description="The profile update endpoint does not enforce CSRF protection",
            target_url="http://example.com/profile/update",
        ),
        Finding(
            vuln_type=VulnType.MASS_ASSIGNMENT,
            severity=Severity.HIGH,
            title="IDOR on user details",
            description="Insecure Direct Object Reference on /users/123",
            target_url="http://example.com/users/123",
        )
    ]

def test_chain_builder_analyze(sample_findings):
    builder = ChainBuilder()
    chains = builder.analyze(sample_findings)
    
    assert len(chains) == 1
    chain = chains[0]
    
    # XSS + CSRF = Account Takeover が構成されているか
    assert chain.name == "Account Takeover via XSS and Missing CSRF"
    assert chain.severity == "CRITICAL"
    assert len(chain.component_findings) == 2
    
    titles = [f.title for f in chain.component_findings]
    assert any("XSS" in t for t in titles)
    assert any("CSRF" in t for t in titles)

def test_exploit_chain_to_finding(sample_findings):
    builder = ChainBuilder()
    chains = builder.analyze(sample_findings)
    chain = chains[0]
    
    finding = chain.to_finding()
    assert finding.title == "Attack Chain: Account Takeover via XSS and Missing CSRF"
    assert finding.severity == Severity.CRITICAL
    assert finding.target_url == "http://example.com/search"  # primary endpoint from the first component
    assert "This is a chained exploit combining 2 findings:" in finding.additional_info.get("chain_details", "")
    assert "Reflected XSS on search parameter" in finding.additional_info.get("chain_details", "")
    assert "Missing CSRF Token on update profile" in finding.additional_info.get("chain_details", "")

def test_build_custom_chain(sample_findings):
    builder = ChainBuilder()
    custom_chain = builder.build_custom_chain(
        name="Custom Chain Attack",
        description="LLM dynamically built this chain",
        severity="HIGH",
        findings=sample_findings[:2],
        poc="fetch('/profile/update');"
    )
    
    assert custom_chain.name == "Custom Chain Attack"
    assert len(custom_chain.component_findings) == 2
    
    finding = custom_chain.to_finding()
    assert "fetch('/profile/update');" in finding.additional_info.get("chain_details", "")
