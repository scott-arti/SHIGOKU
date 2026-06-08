"""
PoC Generator

Finding情報から再現用コマンド（curl/httpie）を自動生成
"""

import json
from typing import Optional
from src.core.models.finding import Finding, Evidence


class PoCGenerator:
    """PoC再現コマンド生成"""
    
    def generate_curl(self, finding: Finding) -> str:
        """
        curl コマンドを生成
        
        Args:
            finding: Finding情報
        
        Returns:
            curl コマンド文字列
        """
        if not finding.evidence:
            return "# No evidence available for PoC generation"
        
        evidence = finding.evidence
        lines = []
        
        # コメント
        lines.append(f"# PoC for: {finding.title}")
        lines.append(f"# Target: {finding.target_url}")
        lines.append(f"# Vulnerability: {finding.vuln_type.value}")
        lines.append("")
        
        # curl コマンド構築
        cmd_parts = ["curl"]
        
        # メソッド
        if evidence.request_method and evidence.request_method != "GET":
            cmd_parts.append(f"-X {evidence.request_method}")
        
        # ヘッダー
        if evidence.request_headers:
            for key, value in evidence.request_headers.items():
                # 機密情報を含む可能性のあるヘッダーは注意喚起
                if key.lower() in ["authorization", "cookie"]:
                    cmd_parts.append(f"-H '{key}: [REDACTED - SET YOUR TOKEN]'")
                else:
                    cmd_parts.append(f"-H '{key}: {value}'")
        
        # ボディ
        if evidence.request_body:
            # JSONの場合は整形
            try:
                body_obj = json.loads(evidence.request_body)
                body_str = json.dumps(body_obj, ensure_ascii=False)
                cmd_parts.append(f"-d '{body_str}'")
            except json.JSONDecodeError:
                cmd_parts.append(f"-d '{evidence.request_body}'")
        
        # オプション
        cmd_parts.append("-v")  # Verbose
        cmd_parts.append("-s")  # Silent
        cmd_parts.append("-S")  # Show error
        
        # URL（最後）
        url = evidence.request_url or finding.target_url
        cmd_parts.append(f"'{url}'")
        
        # 整形（改行して読みやすく）
        if len(cmd_parts) > 5:
            formatted_cmd = " \\\n  ".join(cmd_parts)
        else:
            formatted_cmd = " ".join(cmd_parts)
        
        lines.append(formatted_cmd)
        
        # レスポンス情報
        if evidence.response_status:
            lines.append("")
            lines.append(f"# Expected Response: {evidence.response_status}")
            if evidence.response_body:
                lines.append(f"# Response Body: {evidence.response_body[:100]}...")
        
        return "\n".join(lines)
    
    def generate_httpie(self, finding: Finding) -> str:
        """
        httpie コマンドを生成
        
        Args:
            finding: Finding情報
        
        Returns:
            httpie コマンド文字列
        """
        if not finding.evidence:
            return "# No evidence available for PoC generation"
        
        evidence = finding.evidence
        lines = []
        
        # コメント
        lines.append(f"# PoC for: {finding.title}")
        lines.append(f"# Target: {finding.target_url}")
        lines.append(f"# Vulnerability: {finding.vuln_type.value}")
        lines.append("")
        
        # httpie コマンド構築
        cmd_parts = ["http"]
        
        # メソッド + URL
        method = evidence.request_method or "GET"
        url = evidence.request_url or finding.target_url
        cmd_parts.append(f"{method}")
        cmd_parts.append(f"'{url}'")
        
        # ヘッダー
        if evidence.request_headers:
            for key, value in evidence.request_headers.items():
                if key.lower() in ["authorization", "cookie"]:
                    cmd_parts.append(f"{key}:'[REDACTED - SET YOUR TOKEN]'")
                else:
                    cmd_parts.append(f"{key}:'{value}'")
        
        # ボディ（JSON）
        if evidence.request_body:
            try:
                body_obj = json.loads(evidence.request_body)
                # httpieはJSON形式でキー=値を指定
                for key, value in body_obj.items():
                    if isinstance(value, str):
                        cmd_parts.append(f"{key}='{value}'")
                    else:
                        cmd_parts.append(f"{key}:={json.dumps(value)}")
            except json.JSONDecodeError:
                # JSON以外はそのまま
                cmd_parts.append(f"--raw '{evidence.request_body}'")
        
        # オプション
        cmd_parts.append("--verbose")
        cmd_parts.append("--print=HhBb")  # Headers + Body
        
        # 整形
        if len(cmd_parts) > 5:
            formatted_cmd = " \\\n  ".join(cmd_parts)
        else:
            formatted_cmd = " ".join(cmd_parts)
        
        lines.append(formatted_cmd)
        
        # レスポンス情報
        if evidence.response_status:
            lines.append("")
            lines.append(f"# Expected Response: {evidence.response_status}")
        
        return "\n".join(lines)
    
    def generate_python_requests(self, finding: Finding) -> str:
        """
        Python requests コードを生成
        
        Args:
            finding: Finding情報
        
        Returns:
            Python コード文字列
        """
        if not finding.evidence:
            return "# No evidence available for PoC generation"
        
        evidence = finding.evidence
        lines = []
        
        # ヘッダー
        lines.append("import requests")
        lines.append("")
        lines.append(f"# PoC for: {finding.title}")
        lines.append(f"# Vulnerability: {finding.vuln_type.value}")
        lines.append("")
        
        # URL
        url = evidence.request_url or finding.target_url
        lines.append(f"url = '{url}'")
        
        # ヘッダー
        if evidence.request_headers:
            lines.append("headers = {")
            for key, value in evidence.request_headers.items():
                if key.lower() in ["authorization", "cookie"]:
                    lines.append(f"    '{key}': '[REDACTED - SET YOUR TOKEN]',")
                else:
                    lines.append(f"    '{key}': '{value}',")
            lines.append("}")
        else:
            lines.append("headers = {}")
        
        # ボディ
        if evidence.request_body:
            try:
                body_obj = json.loads(evidence.request_body)
                body_str = json.dumps(body_obj, indent=4)
                lines.append(f"data = {body_str}")
            except json.JSONDecodeError:
                lines.append(f"data = '''{evidence.request_body}'''")
        
        # リクエスト実行
        lines.append("")
        method = (evidence.request_method or "GET").lower()
        
        if evidence.request_body:
            lines.append(f"response = requests.{method}(url, headers=headers, data=data)")
        else:
            lines.append(f"response = requests.{method}(url, headers=headers)")
        
        lines.append("")
        lines.append("print(f'Status: {response.status_code}')")
        lines.append("print(f'Response: {response.text[:500]}')")
        
        # 期待値
        if evidence.response_status:
            lines.append("")
            lines.append(f"# Expected Status: {evidence.response_status}")
        
        return "\n".join(lines)
    
    def copy_to_clipboard(self, command: str) -> bool:
        """
        クリップボードにコピー
        
        Args:
            command: コピーするコマンド
        
        Returns:
            成功: True
        """
        try:
            import pyperclip
            pyperclip.copy(command)
            return True
        except ImportError:
            print("pyperclip not installed. Run: pip install pyperclip")
            return False
        except Exception as e:
            print(f"Failed to copy to clipboard: {e}")
            return False
