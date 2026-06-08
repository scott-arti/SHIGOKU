"""
SessionAnalyzer - セッション管理の脆弱性を分析するクラス
"""

import hashlib
import logging
import re
from typing import List, Dict, Optional, Any

logger = logging.getLogger(__name__)

class SessionAnalyzer:
    """
    セッションID（Cookie）の予測可能性や脆弱性を分析する。
    """

    def __init__(self):
        self._collected_cookies: List[str] = []

    def analyze_randomness(self, cookie_values: List[str]) -> Dict[str, Any]:
        """
        収集したCookie値から予測可能性を判定する。
        """
        if len(cookie_values) < 2:
            return {
                "is_predictable": False,
                "reason": "not_enough_data",
                "vuln_type": None,
            }

        # 1. 完全一致（Session Fixationのリスク）
        if len(set(cookie_values)) == 1:
            return {
                "is_predictable": True, 
                "pattern": "static",
                "reason": "Cookies are static across multiple requests. Potential Session Fixation.",
                "vuln_type": "session_fixation",
            }

        # 2. タイムスタンプベースの単調増加（秒/ミリ秒）
        ts_candidates = [int(v) for v in cookie_values if v.isdigit() and len(v) in (10, 13)]
        if len(ts_candidates) >= 2:
            diffs = [ts_candidates[i+1] - ts_candidates[i] for i in range(len(ts_candidates)-1)]
            if all(d >= 0 for d in diffs) and max(diffs) <= 10000:
                return {
                    "is_predictable": True,
                    "pattern": "timestamp",
                    "reason": "Cookies appear to be timestamp-based sequential values.",
                    "vuln_type": "weak_session_id",
                }

        # 3. インクリメント（1ずつ増加）
        try:
            ints = [int(v) for v in cookie_values if v.isdigit()]
            if len(ints) >= 2:
                diffs = [ints[i+1] - ints[i] for i in range(len(ints)-1)]
                if all(d == 1 for d in diffs):
                    return {
                        "is_predictable": True,
                        "pattern": "increment",
                        "reason": f"Cookies are incrementing by 1 (last: {ints[-1]})",
                        "vuln_type": "weak_session_id",
                    }
        except ValueError:
            pass

        # 4. MD5されたインクリメント (DVWA Medium等)
        # MD5パターンかチェック (32文字の16進数)
        if all(re.match(r"^[a-f0-9]{32}$", v) for v in cookie_values):
            # MD5(整数) か確認
            possible_ints = []
            for v in cookie_values:
                found = False
                for i in range(0, 10000): # 簡易的なブルートフォース
                    if hashlib.md5(str(i).encode()).hexdigest() == v:
                        possible_ints.append(i)
                        found = True
                        break
                if not found:
                    break
            
            if len(possible_ints) == len(cookie_values):
                diffs = [possible_ints[i+1] - possible_ints[i] for i in range(len(possible_ints)-1)]
                if all(d == 1 for d in diffs):
                    return {
                        "is_predictable": True,
                        "pattern": "hashed_increment",
                        "reason": "Cookies are MD5 hashes of incrementing integers.",
                        "vuln_type": "weak_session_id",
                    }

        # 5. ベース64デコード後の解析
        # TODO: 実装

        return {
            "is_predictable": False,
            "vuln_type": None,
        }

    def extract_cookie_value(self, set_cookie_headers: List[str], cookie_name: str) -> Optional[str]:
        """
        Set-Cookieヘッダー群から指定Cookieの値を抽出する。
        """
        if not isinstance(set_cookie_headers, list) or not cookie_name:
            return None

        prefix = f"{cookie_name}="
        for header in set_cookie_headers:
            if not isinstance(header, str):
                continue
            parts = [part.strip() for part in header.split(";") if part.strip()]
            if not parts:
                continue
            if parts[0].startswith(prefix):
                return parts[0][len(prefix):]
        return None

    def infer_vuln_type(self, analysis: Dict[str, Any]) -> Optional[str]:
        """
        analyze_randomness の結果から脆弱性タイプを返す。
        """
        if not isinstance(analysis, dict):
            return None
        token = analysis.get("vuln_type")
        if isinstance(token, str) and token:
            return token

        if not analysis.get("is_predictable"):
            return None

        pattern = str(analysis.get("pattern", "") or "")
        if pattern == "static":
            return "session_fixation"
        if pattern in {"increment", "hashed_increment", "timestamp"}:
            return "weak_session_id"
        return "weak_session_id"

    def generate_bypass_payloads(self, cookie_name: str, last_value: str) -> List[Dict[str, str]]:
        """
        Cookieの改変ペイロードを生成する。
        """
        payloads = []
        
        # 1. インクリメントパターンなら次を予測
        if last_value.isdigit():
            next_val = str(int(last_value) + 1)
            payloads.append({cookie_name: next_val})
        
        # 2. 特権フラグ
        common_flags = ["admin", "role", "uid", "user_id", "superuser"]
        if cookie_name.lower() in common_flags:
            if last_value in ["0", "false", "no"]:
                payloads.append({cookie_name: "1"})
                payloads.append({cookie_name: "true"})
            if last_value == "user":
                payloads.append({cookie_name: "admin"})
        
        # 3. IDOR的な操作 (現在のIDが数字なら±1)
        if last_value.isdigit():
            val = int(last_value)
            payloads.append({cookie_name: str(val - 1)})
            payloads.append({cookie_name: str(val + 1)})

        return payloads


SessionTester = SessionAnalyzer
