"""
Intel Commands - 偵察・分析関連のCLIコマンド

偵察・分析コマンド:
- crawl: Caido経由クロール
- analyze: アプリ分析
- dns: DNS履歴取得
- takeover: サブドメインテイクオーバー
"""

import json
from src.commands import print_banner, print_header, print_step, print_result


def run_crawl(target: str, depth: str = "standard", output_json: bool = False):
    """
    Caido経由でgospider/katanaを実行
    """
    print_header("🕷️ CAIDO CRAWLER")
    
    try:
        from src.core.intel.caido_crawler import CaidoCrawler
    except ImportError as e:
        if output_json:
            print(json.dumps({"error": str(e)}))
        else:
            print_result(False, f"Import error: {e}")
        return
    
    crawler = CaidoCrawler()
    print_step("🔧", f"Proxy: {crawler.proxy}")
    print_step("🎯", f"Target: {target}")
    print_step("📊", f"Depth: {depth}")
    
    result = crawler.run_both(target, depth=depth)
    
    if output_json:
        print(json.dumps({
            "target": result.target,
            "urls": result.urls[:50],
            "js_files": result.js_files,
            "endpoints": result.endpoints,
            "total_urls": len(result.urls),
            "errors": result.errors,
        }, ensure_ascii=False, indent=2))
    else:
        print(crawler.get_summary(result))


def run_analyze(target: str, output_json: bool = False):
    """
    アプリの機能・分類・構成・脆弱性スコアを分析
    """
    print_header("📱 APP ANALYZER")
    
    try:
        from src.core.intel.app_analyzer import AppAnalyzer
        from src.core.intel.caido_crawler import CaidoCrawler
    except ImportError as e:
        if output_json:
            print(json.dumps({"error": str(e)}))
        else:
            print_result(False, f"Import error: {e}")
        return
    
    print_step("🕷️", "Running crawler first...")
    crawler = CaidoCrawler()
    crawl_result = crawler.run_both(target, depth="standard")
    
    print_step("🔍", "Analyzing app...")
    analyzer = AppAnalyzer()
    result = analyzer.analyze(target, crawl_result.urls)
    
    if output_json:
        print(json.dumps({
            "target": result.target,
            "app_type": result.app_type,
            "functions": result.functions,
            "vuln_score": result.vuln_score,
            "vuln_reasons": result.vuln_reasons,
            "architecture": result.architecture,
        }, ensure_ascii=False, indent=2))
    else:
        print(analyzer.format_report(result))


def run_dns_history(domain: str, output_json: bool = False):
    """
    DNS History Mode
    
    ドメインのDNS履歴を取得。
    """
    if not output_json:
        print_banner()
        print_header("🌐 DNS History")
    
    try:
        from src.core.intel.dns_history import DNSHistoryCollector
    except ImportError as e:
        if output_json:
            print(json.dumps({"error": str(e)}))
        else:
            print_result(False, f"Import error: {e}")
        return
    
    collector = DNSHistoryCollector()
    result = collector.collect(domain)
    
    if output_json:
        output = {
            "domain": result.domain,
            "historical_ips": result.historical_ips,
            "subdomains": result.subdomains_found,
            "records_count": len(result.records),
        }
        print(json.dumps(output, ensure_ascii=False, indent=2))
    else:
        print(f"  Domain: {result.domain}")
        print(f"  Historical IPs: {len(result.historical_ips)}")
        print(f"  Subdomains: {len(result.subdomains_found)}")
        print(f"  Records: {len(result.records)}")
        
        if result.historical_ips:
            print("\n  📍 Historical IPs:")
            for ip in result.historical_ips[:10]:
                print(f"     - {ip}")


def run_takeover_check(domain: str, output_json: bool = False):
    """
    Takeover Detection Mode (via Subzy)
    
    サブドメインテイクオーバー脆弱性をチェック。
    """
    if not output_json:
        print_banner()
        print_header("🎯 Takeover Detection (Subzy)")
    
    try:
        from src.tools.custom.subzy import SubzyTool
    except ImportError as e:
        if output_json:
            print(json.dumps({"error": str(e)}))
        else:
            print_result(False, f"Import error: {e}")
        return
    
    if not output_json:
        print_step("t", f"Target: {domain}")
        print_step("r", "Running subzy...")

    tool = SubzyTool()
    # コマンド実行 (subzyは標準出力に結果を出す)
    # output_jsonの場合はパースが理想だが、現状は生の出力を "output" キーに入れるか、
    # subzyがJSON出力をサポートしているか確認が必要。
    # ここではテキスト出力をそのまま返す。
    
    output = tool.run(
        target=domain,
        https=True,
        concurrency=20,
        verify_ssl=False
    )
    
    if output_json:
        # 簡易的なJSONラップ
        print(json.dumps({
            "target": domain,
            "raw_output": output,
            "note": "Subzy raw output. Parsing not implemented yet."
        }, ensure_ascii=False, indent=2))
    else:
        print(output)

