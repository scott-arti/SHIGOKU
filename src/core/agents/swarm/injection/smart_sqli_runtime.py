#!/usr/bin/env python3
"""SQLi response classification, database detection, and evidence building helpers.

Extracted from SmartSQLiHunter to keep the facade lean.
All functions are pure helpers – no instance state, no service pattern.
"""

import re
from typing import Dict, Any, List


def detect_database_type(body: str) -> Dict[str, Any]:
    """Detect database type from response body error signatures.

    Returns:
        {"type": "mysql|postgresql|sqlite|mssql|oracle|unknown",
         "confidence": float, "patterns": list, "all_scores": dict}
    """
    body_lower = body.lower()
    db_signatures = {
        "mysql": {
            "patterns": [
                r"mysql_fetch_",
                r"mysqli_",
                r"#1064",
                r"#1062",
                r"#1146",
                r"#1054",
                r"#1366",
                r"#1292",
                r"you have an error in your sql syntax.*mysql",
                r"warning.*mysql",
            ],
            "keywords": ["mysql", "mariadb"],
        },
        "postgresql": {
            "patterns": [
                r"postgresql",
                r"pqerror",
                r"pg_query",
                r"pg_connect",
                r"psycopg2",
                r"psql",
                r"error.*postgresql",
                r"warning.*postgresql",
            ],
            "keywords": ["postgresql", "psycopg2"],
        },
        "sqlite": {
            "patterns": [
                r"sqlite3",
                r"sqlite_",
                r"sqliteexception",
                r"near\s+\w+:\s*syntax error",
                r"unrecognized token",
                r"incomplete input",
                r"misuse of aggregate",
            ],
            "keywords": ["sqlite", "sqlite3"],
        },
        "mssql": {
            "patterns": [
                r"microsoft sql",
                r"mssql",
                r"odbc.*sql server",
                r"sql server.*error",
                r"oledb",
                r"sqlcmd",
            ],
            "keywords": ["mssql", "sql server", "microsoft"],
        },
        "oracle": {
            "patterns": [
                r"ora-\d{4,5}",
                r"oracle",
                r"pl/sql",
                r"tns:",
                r"oraclerror",
                r"ora_",
            ],
            "keywords": ["oracle", "ora-"],
        },
    }

    scores = {db: 0 for db in db_signatures}
    matched_patterns = []

    for db_name, signatures in db_signatures.items():
        # パターンマッチング
        for pattern in signatures["patterns"]:
            if re.search(pattern, body_lower):
                scores[db_name] += 2
                matched_patterns.append(f"{db_name}:{pattern}")
        # キーワードマッチング
        for keyword in signatures["keywords"]:
            if keyword in body_lower:
                scores[db_name] += 1

    if not matched_patterns:
        return {"type": "unknown", "confidence": 0.0, "patterns": []}

    best_db = max(scores, key=scores.get)
    best_score = scores[best_db]
    total_score = sum(scores.values())

    confidence = min(1.0, best_score / max(total_score, 3))

    return {
        "type": best_db if best_score > 0 else "unknown",
        "confidence": round(confidence, 2),
        "patterns": matched_patterns,
        "all_scores": scores,
    }


def classify_sql_error(body: str) -> Dict[str, Any]:
    """Classify SQL error type from response body.

    Returns:
        {"type": "syntax|auth|schema|data|none", "severity": "high|medium|low|none",
         "details": str, "exploitable": bool}
    """
    body_lower = body.lower()

    # シンタックスエラーパターン
    syntax_patterns = [
        r"syntax error",
        r"unclosed quotation mark",
        r"unexpected token",
        r"unexpected end of statement",
        r"parse error",
        r"invalid syntax",
        r"near.*syntax error",
        r"missing.*in expression",
        r"missing.*at or near",
    ]

    # 認証/権限エラーパターン
    auth_patterns = [
        r"access denied",
        r"permission denied",
        r"insufficient privileges",
        r"not authorized",
        r"login failed",
        r"authentication failed",
        r"invalid user",
        r"wrong password",
    ]

    # スキーマ/テーブルエラーパターン
    schema_patterns = [
        r"table.*doesn't exist",
        r"table.*does not exist",
        r"unknown table",
        r"unknown column",
        r"column.*not found",
        r"no such table",
        r"no such column",
        r"invalid object name",
    ]

    # データ型エラーパターン
    data_patterns = [
        r"data type mismatch",
        r"invalid.*for type",
        r"incorrect.*value",
        r"out of range",
        r"overflow",
        r"truncated",
    ]

    for pattern in syntax_patterns:
        if re.search(pattern, body_lower):
            return {
                "type": "syntax",
                "severity": "high",
                "details": f"Syntax error detected: {pattern}",
                "exploitable": True,
            }

    for pattern in auth_patterns:
        if re.search(pattern, body_lower):
            return {
                "type": "auth",
                "severity": "medium",
                "details": f"Authentication/Permission error: {pattern}",
                "exploitable": False,
            }

    for pattern in schema_patterns:
        if re.search(pattern, body_lower):
            return {
                "type": "schema",
                "severity": "medium",
                "details": f"Schema error (information leakage): {pattern}",
                "exploitable": True,
            }

    for pattern in data_patterns:
        if re.search(pattern, body_lower):
            return {
                "type": "data",
                "severity": "low",
                "details": f"Data type error: {pattern}",
                "exploitable": True,
            }

    return {"type": "none", "severity": "none", "details": "", "exploitable": False}
