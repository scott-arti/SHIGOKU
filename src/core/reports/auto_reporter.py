"""
Auto-Reporter: HackerOne形式報告書自動生成

Findingオブジェクトを受け取り、HackerOne/Bugcrowd形式の
Markdown報告書を自動生成する。

PAM連携: 重複チェック
RAG連携: 過去の類似レポートから修正推奨を取得

Phase 1拡張:
- JSON/PDFエクスポート機能
- FindingsRepositoryとの連携
- EventBus通知トリガー
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, TYPE_CHECKING, Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from src.core.models.finding import Finding, Severity, VulnType
from src.core.notifications.notifier import get_notifier
from src.config import settings
from src.core.reports.poc_generator import PoCGenerator

if TYPE_CHECKING:
    from src.core.agents.analysis.triage_simulator import TriageSimulator

logger = logging.getLogger(__name__)


class AutoReporter:
    """
    Findingから報告書を自動生成
    
    出力形式:
    - HackerOne Markdown
    - Bugcrowd Markdown（将来対応）
    - JSON（API投稿用）
    """
    
    # 深刻度 → CVSS目安
    SEVERITY_TO_CVSS = {
        Severity.CRITICAL: "9.0-10.0",
        Severity.HIGH: "7.0-8.9",
        Severity.MEDIUM: "4.0-6.9",
        Severity.LOW: "0.1-3.9",
        Severity.INFO: "0.0",
    }
    
    def __init__(self, pam=None, rag_switch=None, triage_simulator: Optional['TriageSimulator'] = None):
        self._pam = pam
        self._rag_switch = rag_switch
        self._triage_simulator = triage_simulator
        
        # Jinja2 Environment Setup (Template Safety)
        template_dir = Path(__file__).parent.parent.parent / "templates"
        self._template_env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(['html', 'xml'])
        )
    
    def generate_report(self, finding: Finding, format: str = "hackerone") -> str:
        """
        Findingから報告書を生成
        
        Args:
            finding: 発見した脆弱性
            format: 出力形式 ("hackerone", "bugcrowd", "json")
        
        Returns:
            Markdown形式の報告書
        """
        if format == "hackerone":
            return self._generate_hackerone_report(finding)
        elif format == "json":
            import json
            return json.dumps(finding.to_dict(), indent=2, ensure_ascii=False)
        else:
            return self._generate_hackerone_report(finding)
    
    def _prepare_template_context(self, finding: Finding) -> dict:
        """テンプレート用の共通コンテキストを準備"""
        vuln_info = settings.get_vuln_info(finding.vuln_type.value)
        remediation = self._get_remediation(finding)
        cvss_range = self.SEVERITY_TO_CVSS.get(finding.severity, "N/A")
        
        # PoC Commands
        poc_gen = PoCGenerator()
        curl_cmd = poc_gen.generate_curl(finding) if finding.evidence else ""
        httpie_cmd = poc_gen.generate_httpie(finding) if finding.evidence else ""
        python_cmd = poc_gen.generate_python_requests(finding) if finding.evidence else ""
        
        # Triage Result
        triage_result = None
        if self._triage_simulator:
            try:
                triage_result = self._triage_simulator.simulate(finding)
            except Exception as e:
                logger.warning(f"Triage simulation failed: {e}")

        # Severity Color for HTML
        severity_colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#28a745",
            "info": "#17a2b8",
        }
        severity_color = severity_colors.get(finding.severity.value, "#6c757d")

        return {
            "finding": finding,
            "vuln_info": vuln_info,
            "remediation": remediation,
            "cvss_range": cvss_range,
            "curl_cmd": curl_cmd,
            "httpie_cmd": httpie_cmd,
            "python_cmd": python_cmd,
            "triage_result": triage_result,
            "severity_color": severity_color,
            "now": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }

    def _get_remediation(self, finding: Finding) -> str:
        """修正案を取得 (Finding固有 > 脆弱性DB > デフォルト)"""
        # Findingモデルにはremediation属性がないため、additional_infoを確認するか、属性がある場合のみ取得
        if hasattr(finding, "remediation") and finding.remediation:
            return finding.remediation
            
        if finding.additional_info and isinstance(finding.additional_info, dict):
            if finding.additional_info.get("remediation"):
                return finding.additional_info["remediation"]
            
        vuln_info = settings.get_vuln_info(finding.vuln_type.value)
        if vuln_info.get("remediation"):
            return vuln_info["remediation"]
            
        return "詳細な調査を行い、適切な修正を適用してください。"

    def _generate_hackerone_report(self, finding: Finding) -> str:
        """HackerOne形式のMarkdown報告書を生成 (Jinja2)"""
        context = self._prepare_template_context(finding)
        template = self._template_env.get_template("report.md.j2")
        return template.render(context)

    def _generate_html_report(self, finding: Finding) -> str:
        """HTML報告書を生成 (Jinja2) - PDF変換用"""
        context = self._prepare_template_context(finding)
        template = self._template_env.get_template("report.html.j2")
        return template.render(context)

    def export_pdf(self, finding: Finding, output_path: Optional[str] = None) -> str:
        """
        FindingをPDFファイルにエクスポート
        
        Args:
            finding: エクスポートするFinding
            output_path: 出力先パス（Noneならreportsディレクトリ）
            
        Returns:
            保存したファイルパス
        """
        if output_path is None:
            output_dir = Path("reports")
            output_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = str(output_dir / f"{timestamp}_{finding.id}.pdf")
        
        # Generate HTML from Template
        html_content = self._generate_html_report(finding)
        
        try:
            from weasyprint import HTML
            HTML(string=html_content).write_pdf(output_path)
            logger.info("PDF export saved: %s", output_path)
        except ImportError:
            logger.error("weasyprint not installed. Install with: pip install weasyprint")
            raise
        except Exception as e:
            logger.error("Failed to generate PDF: %s", e)
            raise
        
        return output_path

    def save_report(self, finding: Finding, output_dir: str = "reports") -> str:
        """Markdownレポートをファイル保存してパスを返す"""
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_path = out_dir / f"{timestamp}_{finding.id}.md"

        report_md = self.generate_report(finding, format="hackerone")
        file_path.write_text(report_md, encoding="utf-8")
        logger.info("Markdown report saved: %s", file_path)
        return str(file_path)

    def export_json(self, finding: Finding, output_path: Optional[str] = None) -> str:
        """単一FindingをJSON保存してパスを返す"""
        if output_path is None:
            output_dir = Path("reports")
            output_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = str(output_dir / f"{timestamp}_{finding.id}.json")

        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(finding.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
        logger.info("JSON export saved: %s", out)
        return str(out)

    def export_batch(
        self, 
        findings: list[Finding], 
        output_dir: str = "reports",
        export_format: str = "json"
    ) -> list[str]:
        """
        複数のFindingsをバッチエクスポート
        
        Args:
            findings: エクスポートするFindingのリスト
            output_dir: 出力ディレクトリ
            export_format: 出力形式 ("json", "pdf", "markdown")
            
        Returns:
            保存したファイルパスのリスト
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        exported_files = []
        
        for finding in findings:
            try:
                if export_format == "json":
                    file_path = self.export_json(finding, None)
                elif export_format == "pdf":
                    file_path = self.export_pdf(finding, None)
                else:
                    file_path = self.save_report(finding, output_dir)
                
                exported_files.append(file_path)
            except Exception as e:
                logger.error("Failed to export finding %s: %s", finding.id, e)
        
        logger.info("Batch export complete: %d files", len(exported_files))
        return exported_files

    def save_to_db(self, finding: Finding) -> str:
        """
        FindingをDBに保存
        
        Args:
            finding: 保存するFinding
            
        Returns:
            保存されたFindingのID
        """
        from src.core.learning.findings_repository import get_findings_repository
        return get_findings_repository().save(finding)


# ===== Convenience Functions =====

_reporter_instance: Optional[AutoReporter] = None


def get_auto_reporter() -> AutoReporter:
    """AutoReporterのシングルトンインスタンスを取得"""
    global _reporter_instance
    if _reporter_instance is None:
        _reporter_instance = AutoReporter()
    return _reporter_instance


def generate_report_from_finding(finding: Finding) -> str:
    """Findingから報告書を生成（便利関数）"""
    reporter = get_auto_reporter()
    return reporter.generate_report(finding)


def export_findings_json(findings: list[Finding], output_path: str) -> str:
    """複数のFindingsをJSONファイルにエクスポート"""
    data = {
        "generated_at": datetime.now().isoformat(),
        "count": len(findings),
        "findings": [f.to_dict() for f in findings],
    }
    
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    
    return output_path
