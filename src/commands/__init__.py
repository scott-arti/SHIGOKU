"""
Commands - 共通ヘルパー関数

CLI出力用のヘルパー関数群
"""


def print_banner():
    """SHIGOKUバナーを表示"""
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║         至   極    -    S  H  I  G  O  K  U                   ║
║                                                               ║
║            Autonomous Bug Bounty Hunter v1.0                  ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def print_header(title: str):
    """セクションヘッダーを表示"""
    print()
    print("═" * 60)
    print(f"  {title}")
    print("═" * 60)


def print_step(icon: str, message: str):
    """ステップメッセージを表示"""
    print(f"  {icon} {message}")


def print_result(success: bool, message: str):
    """結果メッセージを表示"""
    icon = "✅" if success else "❌"
    print(f"  {icon} {message}")


def print_finding(finding):
    """Finding情報を表示"""
    icon = finding.get_severity_icon()
    print(f"\n  {icon} {finding.title}")
    print(f"     └─ Type: {finding.vuln_type.value}")
    print(f"     └─ Target: {finding.target_url[:50]}...")
    print(f"     └─ Confidence: {finding.confidence * 100:.0f}%")
