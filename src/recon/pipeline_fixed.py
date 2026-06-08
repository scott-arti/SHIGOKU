# xss_candidate エントリを追加するための修正用スニペット
# 1741-1752 行目を以下に置き換え:

            "redirect_param": {
                "agent": "InjectionManagerAgent",  # SSRF/Open Redirect も Injection の一種
                "action": "scan",
                "priority": 75,
                "name": "Open Redirect/SSRF Scan"
            },
            "xss_candidate": {
                "agent": "InjectionManagerAgent",  # XSS 専用スキャン
                "action": "scan",
                "priority": 82,
                "name": "XSS Injection Scan"
            },
            "upload": {
