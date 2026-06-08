import hashlib
from src.core.attack.session_tester import SessionAnalyzer

def test_analyze_randomness_static():
    analyzer = SessionAnalyzer()
    cookies = ["session1", "session1", "session1"]
    result = analyzer.analyze_randomness(cookies)
    assert result["is_predictable"] is True
    assert result["pattern"] == "static"
    assert result["vuln_type"] == "session_fixation"

def test_analyze_randomness_increment():
    analyzer = SessionAnalyzer()
    cookies = ["101", "102", "103", "104"]
    result = analyzer.analyze_randomness(cookies)
    assert result["is_predictable"] is True
    assert result["pattern"] == "increment"
    assert result["vuln_type"] == "weak_session_id"

def test_analyze_randomness_hashed_increment():
    analyzer = SessionAnalyzer()
    cookies = [
        hashlib.md5(b"1").hexdigest(),
        hashlib.md5(b"2").hexdigest(),
        hashlib.md5(b"3").hexdigest()
    ]
    result = analyzer.analyze_randomness(cookies)
    assert result["is_predictable"] is True
    assert result["pattern"] == "hashed_increment"
    assert result["vuln_type"] == "weak_session_id"

def test_analyze_randomness_timestamp_sequence():
    analyzer = SessionAnalyzer()
    cookies = ["1711111111", "1711111112", "1711111113"]
    result = analyzer.analyze_randomness(cookies)
    assert result["is_predictable"] is True
    assert result["pattern"] == "timestamp"
    assert result["vuln_type"] == "weak_session_id"

def test_analyze_randomness_random():
    analyzer = SessionAnalyzer()
    cookies = ["abc123xyz", "def456uvw", "ghi789rst"]
    result = analyzer.analyze_randomness(cookies)
    assert result["is_predictable"] is False
    assert result["vuln_type"] is None

def test_generate_bypass_payloads():
    analyzer = SessionAnalyzer()
    payloads = analyzer.generate_bypass_payloads("admin", "0")
    # should contain admin=1 or admin=true
    values = [p["admin"] for p in payloads]
    assert "1" in values or "true" in values


def test_extract_cookie_value_from_set_cookie_headers():
    analyzer = SessionAnalyzer()
    headers = [
        "security=low; path=/; HttpOnly",
        "PHPSESSID=abc123; path=/; HttpOnly; SameSite=Strict",
    ]
    value = analyzer.extract_cookie_value(headers, "PHPSESSID")
    assert value == "abc123"


def test_infer_vuln_type_from_analysis():
    analyzer = SessionAnalyzer()

    result_static = analyzer.infer_vuln_type({"is_predictable": True, "pattern": "static"})
    result_increment = analyzer.infer_vuln_type({"is_predictable": True, "pattern": "increment"})
    result_timestamp = analyzer.infer_vuln_type({"is_predictable": True, "pattern": "timestamp"})
    result_safe = analyzer.infer_vuln_type({"is_predictable": False, "pattern": "random"})

    assert result_static == "session_fixation"
    assert result_increment == "weak_session_id"
    assert result_timestamp == "weak_session_id"
    assert result_safe is None
