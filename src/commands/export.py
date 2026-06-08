"""
Export Command
"""
import json
from src.commands import print_banner, print_header, print_step, print_result

def run_export(project_dir: str, export_format: str = "json", output_json: bool = False):
    """
    Export Findings Mode
    
    Findingsを各種形式でエクスポート。
    """
    if not output_json:
        print_banner()
        print_header("📤 Export Findings")
    
    try:
        from src.core.export.exporter import get_exporter
    except ImportError as e:
        if output_json:
            print(json.dumps({"error": str(e)}))
        else:
            print_result(False, f"Import error: {e}")
        return
    
    # プロジェクトディレクトリからfindingsを読み込み（デモ用）
    print_step("📁", f"Project: {project_dir}")
    print_step("📄", f"Format: {export_format}")
    
    # 実際の実装では findings を読み込む
    exporter = get_exporter(output_dir=project_dir)
    
    print_result(True, f"Exporter ready: {export_format}")
