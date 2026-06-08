import json
import logging
from dataclasses import dataclass
from typing import List, Dict, Optional, Any, Tuple
from src.core.models.finding import Severity

logger = logging.getLogger(__name__)

@dataclass
class ComparisonInput:
    baseline_status: int
    baseline_body: str
    baseline_headers: Dict[str, str]
    test_status: int
    test_body: str
    test_headers: Dict[str, str]
    original_id: str
    test_id: str

@dataclass
class ComparisonResult:
    is_vulnerable: bool
    confidence: float
    signals: List[str]
    severity_hint: Severity
    report: str

class ResponseComparator:
    """
    IDOR/BOLA テストの結果を正規レスポンスと比較して診断するエンジン
    """

    ERROR_INDICATORS = [
        "error", "message", "unauthorized", "forbidden", "not found",
        "invalid", "denied", "expired", "login required",
        '"status":"error"', '"success":false', '"ok":false',
    ]

    def __init__(self, piimasker=None):
        self.masker = piimasker

    async def compare(self, data: ComparisonInput) -> ComparisonResult:
        score = 0.0
        signals = []
        
        # S1: Status Match
        if data.test_status == data.baseline_status:
            score += 0.15
            signals.append(f"[+0.15] status_match: Both returned {data.test_status}")
        
        # S2: Body Size Similarity
        b_len = len(data.baseline_body)
        t_len = len(data.test_body)
        if b_len > 0:
            diff_ratio = abs(t_len - b_len) / b_len
            if diff_ratio < 0.2:
                score += 0.10
                signals.append(f"[+0.10] body_size_similar: Size diff {diff_ratio:.1%}")
        
        # S3: JSON Structure Match
        struct_match, b_json, t_json = self._check_json_structure(data.baseline_body, data.test_body)
        if struct_match >= 0.8:
            score += 0.25
            signals.append(f"[+0.25] json_structure_match: Key structure {struct_match:.1%} match")
            
            # S6: Different Data (Value check)
            if self._has_different_values(b_json, t_json):
                score += 0.10
                signals.append("[+0.10] different_data: Values differ despite same structure")
        
        # S4: ID Reflection
        if self._check_id_reflection(data.test_body, data.test_id):
            score += 0.20
            signals.append(f"[+0.20] id_reflection: Test ID \"{data.test_id}\" found in response")
            
        # S5: Secret Detection
        secrets = await self._scan_for_secrets(data.test_body)
        if secrets:
            score += 0.20
            signals.append(f"[+0.20] secret_detected: Found {len(secrets)} secrets/PII")

        # N1: Error Body Detection
        if self._detect_error_body(data.test_body):
            score -= 0.40
            signals.append("[-0.40] error_body_detected: Response contains error keywords")
            
        # N2: Empty / Short Body
        if t_len < 20:
            score -= 0.30
            signals.append("[-0.30] empty_body: Response body is too short")
            
        # N3: Redirect
        if 300 <= data.test_status < 400:
            score -= 0.20
            signals.append(f"[-0.20] redirect_detected: Status {data.test_status}")

        # Final Score Normalize
        final_score = max(0.0, min(1.0, score))
        is_vuln = final_score >= 0.60
        
        # Severity Hint
        sev = Severity.MEDIUM
        if final_score >= 0.8:
            sev = Severity.HIGH
            if secrets:
                sev = Severity.CRITICAL
        
        report = self._format_diagnostic_report(data, final_score, signals, sev, is_vuln)
        
        return ComparisonResult(
            is_vulnerable=is_vuln,
            confidence=final_score,
            signals=signals,
            severity_hint=sev,
            report=report
        )

    def _check_json_structure(self, b_body: str, t_body: str) -> Tuple[float, Optional[Any], Optional[Any]]:
        try:
            b_json = json.loads(b_body)
            t_json = json.loads(t_body)
        except:
            return 0.0, None, None
            
        def get_keys(obj, prefix=""):
            keys = set()
            if isinstance(obj, dict):
                for k, v in obj.items():
                    full_key = f"{prefix}.{k}" if prefix else k
                    keys.add(full_key)
                    keys.update(get_keys(v, full_key))
            elif isinstance(obj, list) and obj:
                keys.update(get_keys(obj[0], prefix))
            return keys
            
        b_keys = get_keys(b_json)
        t_keys = get_keys(t_json)
        
        if not b_keys: return 0.0, b_json, t_json
        
        intersection = b_keys.intersection(t_keys)
        match_ratio = len(intersection) / len(b_keys)
        return match_ratio, b_json, t_json

    def _has_different_values(self, b_json: Any, t_json: Any) -> bool:
        # 構造を維持しつつ値が一つでも違えばTrue (簡易)
        return b_json != t_json

    def _check_id_reflection(self, body: str, test_id: str) -> bool:
        return test_id in body

    def _detect_error_body(self, body: str) -> bool:
        body_l = body.lower()
        return any(indicator in body_l for indicator in self.ERROR_INDICATORS)

    async def _scan_for_secrets(self, text: str) -> List[Dict[str, Any]]:
        try:
            from src.tools.custom.secret_finder import SecretFinderTool
            tool = SecretFinderTool()
            return await tool.scan_text(text)
        except:
            return []

    def _format_diagnostic_report(self, data, score, signals, sev, is_vuln) -> str:
        verdict = "LIKELY VULNERABLE (human review recommended)" if is_vuln else "NOT VULNERABLE"
        if score >= 0.8: verdict = "CONFIRMED VULNERABLE"
        
        b_snippet = data.baseline_body[:500] + ("..." if len(data.baseline_body) > 500 else "")
        t_snippet = data.test_body[:500] + ("..." if len(data.test_body) > 500 else "")
        
        if self.masker:
            b_snippet = self.masker.mask(b_snippet)
            t_snippet = self.masker.mask(t_snippet)
            
        report = f"""=== IDOR Diagnostic Report ===
Original ID: {data.original_id} → Test ID: {data.test_id}

--- Response Comparison ---
Baseline: Status {data.baseline_status} | Size {len(data.baseline_body)}
Test:     Status {data.test_status} | Size {len(data.test_body)}

--- Signal Analysis ---
"""
        report += "\n".join(signals)
        report += f"""

--- Confidence ---
Score: {score:.2f} / 1.00 → {sev.value} severity
Verdict: {verdict}

--- Response Snippets ---
Baseline:
{b_snippet}

Test:
{t_snippet}
"""
        return report
