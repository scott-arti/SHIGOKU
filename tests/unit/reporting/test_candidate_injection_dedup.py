"""SGK-2026-0464: injection/reflected 候補の脆弱性署名単位 重複排除の回帰テスト。

保存型XSS confirmed=1 走行で、同一脆弱性（同 class/endpoint/method/param）の候補が
汚染URL（内部メタキー＋注入payload）ごとに別候補として大量に残っていた
（Candidate 189）。候補側 `_candidate_dedup_key` を confirmed 側と同型の root-cause
署名へ拡張し、汚染URL違いは1件へ収束・別 param/endpoint は分離することを検証する。
"""
from src.reporting.haddix_submission_internal_formatter import (
    HaddixSubmissionInternalFormatter,
)


def _xss_candidate(param: str, payload: str, *, url: str) -> dict:
    return {
        "title": f"XSS in parameter '{param}'",
        "severity": "high",
        "vuln_type": "xss",
        "target_url": url,
        "summary": "reflected payload",
        "impact": "session theft",
        "poc_request": f"POST /comment HTTP/1.1\nHost: 127.0.0.1:5008\n\n{param}={payload}",
        "poc_response": "",
        "payloads_used": [payload],
        "additional_info": {"parameter": param, "payload": payload},
    }


def _make(findings):
    f = HaddixSubmissionInternalFormatter()
    f.set_target("http://127.0.0.1:5008")
    for d in findings:
        f.add_finding_from_dict(d)
    confirmed, candidates, _ = f._get_enforced_split()
    return confirmed, candidates


def test_same_param_polluted_urls_collapse_to_one():
    # Same vuln (name-XSS on /comment) but polluted query differs per payload.
    base = "http://127.0.0.1:5008/comment"
    findings = [
        _xss_candidate("name", "<script>alert(1)</script>",
                       url=base + "?method=GET&url_evidence=%27&detection_mode=phase1&name=%3Cscript%3Ealert(1)%3C/script%3E"),
        _xss_candidate("name", "<svg/onload=alert(1)>",
                       url=base + "?method=GET&url_evidence=PUT&detection_mode=phase1&name=%3Csvg/onload=alert(1)%3E"),
        _xss_candidate("name", '"><script>alert(1)</script>',
                       url=base + "?method=GET&url_evidence=%7B%7D&detection_mode=1&name=%22%3E%3Cscript%3E"),
    ]
    _confirmed, candidates = _make(findings)
    assert len(candidates) == 1, [c.target_url for c in candidates]


def test_distinct_params_stay_separate():
    base = "http://127.0.0.1:5008/comment"
    findings = [
        _xss_candidate("name", "<script>alert(1)</script>", url=base + "?name=a&detection_mode=phase1"),
        _xss_candidate("comment", "<script>alert(1)</script>", url=base + "?comment=b&detection_mode=phase1"),
    ]
    _confirmed, candidates = _make(findings)
    params = sorted((c.additional_info or {}).get("parameter") for c in candidates)
    assert len(candidates) == 2, params
    assert params == ["comment", "name"]


def test_merged_count_recorded():
    base = "http://127.0.0.1:5008/comment"
    findings = [
        _xss_candidate("name", "p1", url=base + "?name=1"),
        _xss_candidate("name", "p2", url=base + "?name=2"),
    ]
    _confirmed, candidates = _make(findings)
    assert len(candidates) == 1
    assert int((candidates[0].additional_info or {}).get("merged_duplicate_count", 1)) == 2
