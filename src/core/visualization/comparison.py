"""
Comparison Tool

スキャン結果の差分検出・比較
"""

import json
from pathlib import Path
from typing import List, Dict, Set, Tuple
from datetime import datetime

from src.core.models.finding import Finding, Severity


class ScanComparison:
    """スキャン比較結果"""
    
    def __init__(self):
        self.new_findings: List[Finding] = []
        self.fixed_findings: List[Finding] = []
        self.common_findings: List[Finding] = []
        self.severity_changes: List[Tuple[Finding, Severity, Severity]] = []
    
    def summary(self) -> Dict[str, int]:
        """サマリー情報"""
        return {
            "new": len(self.new_findings),
            "fixed": len(self.fixed_findings),
            "unchanged": len(self.common_findings),
            "severity_changed": len(self.severity_changes)
        }


class ScanComparator:
    """スキャン比較クラス"""
    
    def __init__(self):
        pass
    
    def compare(
        self,
        baseline_findings: List[Finding],
        current_findings: List[Finding]
    ) -> ScanComparison:
        """
        2つのスキャン結果を比較
        
        Args:
            baseline_findings: 基準となるスキャン結果
            current_findings: 比較対象のスキャン結果
        
        Returns:
            比較結果
        """
        result = ScanComparison()
        
        # Finding IDのセットを作成
        baseline_ids = {self._get_finding_key(f): f for f in baseline_findings}
        current_ids = {self._get_finding_key(f): f for f in current_findings}
        
        baseline_keys = set(baseline_ids.keys())
        current_keys = set(current_ids.keys())
        
        # 新規Finding
        new_keys = current_keys - baseline_keys
        result.new_findings = [current_ids[k] for k in new_keys]
        
        # 修正されたFinding
        fixed_keys = baseline_keys - current_keys
        result.fixed_findings = [baseline_ids[k] for k in fixed_keys]
        
        # 共通Finding
        common_keys = baseline_keys & current_keys
        result.common_findings = [current_ids[k] for k in common_keys]
        
        # 深刻度変更チェック
        for key in common_keys:
            baseline_finding = baseline_ids[key]
            current_finding = current_ids[key]
            
            if baseline_finding.severity != current_finding.severity:
                result.severity_changes.append((
                    current_finding,
                    baseline_finding.severity,
                    current_finding.severity
                ))
        
        return result
    
    def _get_finding_key(self, finding: Finding) -> str:
        """
        Findingの一意キーを生成
        
        URL + 脆弱性タイプで識別
        """
        return f"{finding.target_url}|{finding.vuln_type.value}"
    
    def generate_report(
        self,
        comparison: ScanComparison,
        baseline_date: str,
        current_date: str
    ) -> str:
        """
        比較レポートをMarkdown形式で生成
        
        Args:
            comparison: 比較結果
            baseline_date: 基準スキャン日時
            current_date: 比較スキャン日時
        
        Returns:
            Markdownレポート
        """
        lines = []
        lines.append("# 📊 Scan Comparison Report")
        lines.append("")
        lines.append(f"**Baseline Scan:** {baseline_date}")
        lines.append(f"**Current Scan:** {current_date}")
        lines.append(f"**Report Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")
        
        # サマリー
        summary = comparison.summary()
        lines.append("## Summary")
        lines.append("")
        lines.append("| Metric | Count |")
        lines.append("|--------|-------|")
        lines.append(f"| 🆕 New Findings | {summary['new']} |")
        lines.append(f"| ✅ Fixed | {summary['fixed']} |")
        lines.append(f"| ➡️ Unchanged | {summary['unchanged']} |")
        lines.append(f"| ⚠️ Severity Changed | {summary['severity_changed']} |")
        lines.append("")
        
        # 新規Finding
        if comparison.new_findings:
            lines.append("## 🆕 New Findings")
            lines.append("")
            for finding in comparison.new_findings:
                icon = finding.get_severity_icon()
                lines.append(f"### {icon} {finding.title}")
                lines.append(f"- **Severity:** {finding.severity.value.upper()}")
                lines.append(f"- **Type:** {finding.vuln_type.value}")
                lines.append(f"- **Target:** {finding.target_url}")
                lines.append("")
        
        # 修正されたFinding
        if comparison.fixed_findings:
            lines.append("## ✅ Fixed Findings")
            lines.append("")
            for finding in comparison.fixed_findings:
                lines.append(f"### {finding.title}")
                lines.append(f"- **Was:** {finding.severity.value.upper()}")
                lines.append(f"- **Type:** {finding.vuln_type.value}")
                lines.append(f"- **Target:** {finding.target_url}")
                lines.append("")
        
        # 深刻度変更
        if comparison.severity_changes:
            lines.append("## ⚠️ Severity Changes")
            lines.append("")
            for finding, old_sev, new_sev in comparison.severity_changes:
                lines.append(f"### {finding.title}")
                lines.append(f"- **Change:** {old_sev.value.upper()} → {new_sev.value.upper()}")
                lines.append(f"- **Target:** {finding.target_url}")
                lines.append("")
        
        return "\n".join(lines)
    
    def save_comparison(
        self,
        comparison: ScanComparison,
        output_dir: Path,
        baseline_date: str,
        current_date: str
    ) -> Path:
        """比較レポートを保存"""
        report = self.generate_report(comparison, baseline_date, current_date)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_comparison_{timestamp}.md"
        output_path = output_dir / filename
        
        output_path.write_text(report, encoding='utf-8')
        return output_path


def compare_scans(
    baseline_findings: List[Finding],
    current_findings: List[Finding]
) -> ScanComparison:
    """スキャン比較（便利関数）"""
    comparator = ScanComparator()
    return comparator.compare(baseline_findings, current_findings)
