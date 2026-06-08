"""
Finding Exporter

Finding一覧をJSON/CSV/PDF形式でエクスポート
"""

import json
import csv
import asyncio
from pathlib import Path
from typing import List, Optional, Dict
from datetime import datetime
import logging

from src.core.models.finding import Finding
from src.core.export.platform_sync import PlatformSyncClient, PlatformType


logger = logging.getLogger(__name__)


class FindingExporter:
    """Finding エクスポートクラス"""
    
    def __init__(self, output_dir: str = "exports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def export_json(self, findings: List[Finding], filename: str = None) -> Path:
        """
        JSON形式でエクスポート
        
        Args:
            findings: Finding一覧
            filename: 出力ファイル名（省略時は自動生成）
        
        Returns:
            出力ファイルパス
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"findings_{timestamp}.json"
        
        output_path = self.output_dir / filename
        
        # JSONデータ構築
        data = {
            "export_date": datetime.now().isoformat(),
            "total_findings": len(findings),
            "findings": [f.to_dict() for f in findings]
        }
        
        # 統計情報追加
        data["statistics"] = self._calculate_statistics(findings)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Exported {len(findings)} findings to JSON: {output_path}")
        return output_path
    
    def export_csv(self, findings: List[Finding], filename: str = None) -> Path:
        """
        CSV形式でエクスポート
        
        Args:
            findings: Finding一覧
            filename: 出力ファイル名（省略時は自動生成）
        
        Returns:
            出力ファイルパス
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"findings_{timestamp}.csv"
        
        output_path = self.output_dir / filename
        
        # CSVヘッダー
        headers = [
            "ID",
            "Title",
            "Severity",
            "Vulnerability Type",
            "Target URL",
            "Confidence (%)",
            "Discovered At",
            "Source Agent",
            "CWE ID",
            "CVSS Score",
            "Description",
        ]
        
        with open(output_path, 'w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            
            for finding in findings:
                row = [
                    finding.id,
                    finding.title,
                    finding.severity.value,
                    finding.vuln_type.value,
                    finding.target_url,
                    f"{finding.confidence * 100:.0f}",
                    finding.discovered_at.strftime("%Y-%m-%d %H:%M:%S"),
                    finding.source_agent,
                    finding.cwe_id or "",
                    finding.cvss_score or "",
                    finding.description,
                ]
                writer.writerow(row)
        
        logger.info(f"Exported {len(findings)} findings to CSV: {output_path}")
        return output_path
    
    def export_pdf(self, findings: List[Finding], filename: str = None) -> Path:
        """
        PDF形式でエクスポート（reportlab使用）
        
        Args:
            findings: Finding一覧
            filename: 出力ファイル名（省略時は自動生成）
        
        Returns:
            出力ファイルパス
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"findings_{timestamp}.pdf"
        
        output_path = self.output_dir / filename
        
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4, letter
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.lib.enums import TA_CENTER, TA_LEFT
            
            doc = SimpleDocTemplate(str(output_path), pagesize=A4)
            story = []
            styles = getSampleStyleSheet()
            
            # タイトル
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor=colors.HexColor('#1a1a1a'),
                spaceAfter=30,
                alignment=TA_CENTER
            )
            story.append(Paragraph("SHIGOKU Findings Report", title_style))
            story.append(Spacer(1, 0.2 * inch))
            
            # サマリー
            stats = self._calculate_statistics(findings)
            summary_data = [
                ["Total Findings", str(len(findings))],
                ["Critical", str(stats['severity']['critical'])],
                ["High", str(stats['severity']['high'])],
                ["Medium", str(stats['severity']['medium'])],
                ["Low", str(stats['severity']['low'])],
                ["Export Date", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            ]
            
            summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(summary_table)
            story.append(Spacer(1, 0.5 * inch))
            
            # Finding詳細
            for i, finding in enumerate(findings, 1):
                # セクションヘッダー
                severity_colors_map = {
                    "critical": colors.red,
                    "high": colors.orange,
                    "medium": colors.yellow,
                    "low": colors.green,
                    "info": colors.blue,
                }
                severity_color = severity_colors_map.get(finding.severity.value, colors.grey)
                
                header_style = ParagraphStyle(
                    f'FindingHeader{i}',
                    parent=styles['Heading2'],
                    fontSize=14,
                    textColor=severity_color,
                    spaceAfter=10
                )
                story.append(Paragraph(f"{i}. {finding.title}", header_style))
                
                # Finding詳細テーブル
                finding_data = [
                    ["Severity", finding.severity.value.upper()],
                    ["Type", finding.vuln_type.value],
                    ["Target", finding.target_url[:80]],
                    ["Confidence", f"{finding.confidence * 100:.0f}%"],
                    ["Discovered", finding.discovered_at.strftime("%Y-%m-%d %H:%M:%S")],
                ]
                
                if finding.cwe_id:
                    finding_data.append(["CWE", finding.cwe_id])
                if finding.cvss_score:
                    finding_data.append(["CVSS", str(finding.cvss_score)])
                
                finding_table = Table(finding_data, colWidths=[1.5*inch, 4*inch])
                finding_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ]))
                story.append(finding_table)
                story.append(Spacer(1, 0.1 * inch))
                
                # 説明
                desc_style = ParagraphStyle(
                    f'Description{i}',
                    parent=styles['BodyText'],
                    fontSize=10,
                    spaceAfter=10
                )
                story.append(Paragraph(f"<b>Description:</b> {finding.description}", desc_style))
                
                # ページ区切り（最後以外）
                if i < len(findings):
                    story.append(Spacer(1, 0.3 * inch))
            
            # PDF生成
            doc.build(story)
            logger.info(f"Exported {len(findings)} findings to PDF: {output_path}")
            return output_path
            
        except ImportError:
            logger.error("reportlab not installed. Run: pip install reportlab")
            raise
        except Exception as e:
            logger.error(f"Failed to export PDF: {e}")
            raise
    
    def export_markdown(self, findings: List[Finding], filename: str = None) -> Path:
        """
        Markdown形式でエクスポート
        
        Args:
            findings: Finding一覧
            filename: 出力ファイル名（省略時は自動生成）
        
        Returns:
            出力ファイルパス
        """
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"findings_{timestamp}.md"
        
        output_path = self.output_dir / filename
        
        lines = []
        lines.append("# SHIGOKU Findings Report")
        lines.append("")
        lines.append(f"**Export Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"**Total Findings:** {len(findings)}")
        lines.append("")
        
        # 統計
        stats = self._calculate_statistics(findings)
        lines.append("## Summary")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for severity, count in stats['severity'].items():
            lines.append(f"| {severity.capitalize()} | {count} |")
        lines.append("")
        
        # Finding一覧
        lines.append("## Findings")
        lines.append("")
        
        for i, finding in enumerate(findings, 1):
            icon = finding.get_severity_icon()
            lines.append(f"### {i}. {icon} {finding.title}")
            lines.append("")
            lines.append(f"- **Severity:** {finding.severity.value.upper()}")
            lines.append(f"- **Type:** {finding.vuln_type.value}")
            lines.append(f"- **Target:** {finding.target_url}")
            lines.append(f"- **Confidence:** {finding.confidence * 100:.0f}%")
            lines.append(f"- **Discovered:** {finding.discovered_at.strftime('%Y-%m-%d %H:%M:%S')}")
            if finding.cwe_id:
                lines.append(f"- **CWE:** {finding.cwe_id}")
            if finding.cvss_score:
                lines.append(f"- **CVSS:** {finding.cvss_score}")
            lines.append("")
            lines.append(f"**Description:** {finding.description}")
            lines.append("")
            lines.append("---")
            lines.append("")
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines))
        
        logger.info(f"Exported {len(findings)} findings to Markdown: {output_path}")
        return output_path
    
    def _calculate_statistics(self, findings: List[Finding]) -> dict:
        """統計情報を計算"""
        stats = {
            "severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
            "vulnerability_types": {},
        }
        
        for finding in findings:
            # 深刻度
            severity_key = finding.severity.value
            if severity_key in stats["severity"]:
                stats["severity"][severity_key] += 1
            
            # 脆弱性タイプ
            vuln_type = finding.vuln_type.value
            stats["vulnerability_types"][vuln_type] = stats["vulnerability_types"].get(vuln_type, 0) + 1
        
        return stats

    async def sync_to_platform(self, findings: List[Finding], platform: PlatformType, program_id: str) -> Dict[str, str]:
        """
        Findingsを外部バウンティプラットフォームへオンライン同期する
        
        Args:
            findings: 同期するFindingリスト
            platform: HackerOne または Bugcrowd
            program_id: プラットフォームのプログラムID
            
        Returns:
            { "finding_id": "report/submission_id" } のマッピング結果
        """
        client = PlatformSyncClient(platform=platform)
        if not client.is_configured():
            logger.warning(f"PlatformSyncClient is not configured for {platform.value}. Sync aborted.")
            return {}
            
        results = {}
        for finding in findings:
            report_id = await client.sync_finding(finding, program_id)
            if report_id:
                results[finding.id] = report_id
                
        logger.info(f"Successfully synced {len(results)}/{len(findings)} findings to {platform.value}.")
        return results


# シングルトンインスタンス
_exporter_instance = None


def get_exporter(output_dir: str = "exports") -> FindingExporter:
    """FindingExporterのシングルトンインスタンスを取得"""
    global _exporter_instance
    if _exporter_instance is None:
        _exporter_instance = FindingExporter(output_dir)
    return _exporter_instance
