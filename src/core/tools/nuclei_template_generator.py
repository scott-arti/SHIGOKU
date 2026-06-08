"""
Nuclei Template Generator

脆弱性発見時に動的にNucleiテンプレートをYAML形式で生成。
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime
import yaml
import re
import logging

logger = logging.getLogger(__name__)


@dataclass
class NucleiTemplate:
    """Nucleiテンプレート"""
    id: str
    name: str
    severity: str
    yaml_content: str
    file_path: Optional[Path] = None


class NucleiTemplateGenerator:
    """
    Nucleiテンプレート動的生成器
    
    発見した脆弱性からNucleiテンプレートを自動生成し、
    同様の脆弱性を他のターゲットでも検出可能にする。
    """
    
    # 脆弱性タイプからテンプレートカテゴリへのマッピング
    VULN_TYPE_MAP = {
        "sql_injection": "sqli",
        "sqli": "sqli",
        "xss": "xss",
        "cross_site_scripting": "xss",
        "ssrf": "ssrf",
        "lfi": "lfi",
        "local_file_inclusion": "lfi",
        "rce": "rce",
        "remote_code_execution": "rce",
        "open_redirect": "redirect",
        "idor": "idor",
        "jwt": "jwt",
        "cors": "cors",
        "crlf": "crlf",
    }
    
    # 脆弱性タイプごとのデフォルトマッチャー
    DEFAULT_MATCHERS = {
        "sqli": {
            "type": "word",
            "words": ["syntax error", "mysql", "ORA-", "PostgreSQL", "SQLite"],
            "condition": "or"
        },
        "xss": {
            "type": "word",
            "words": ["<script>alert", "onerror=", "javascript:"]
        },
        "lfi": {
            "type": "regex",
            "regex": ["root:.*:0:0:", "\\[boot loader\\]", "\\[extensions\\]"]
        },
        "ssrf": {
            "type": "word",
            "words": ["AWS", "metadata", "169.254.169.254"]
        },
    }
    
    def __init__(self, templates_dir: str = None):
        self.templates_dir = Path(templates_dir) if templates_dir else Path("./nuclei-templates/custom")
        self.templates_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_template(self, finding) -> NucleiTemplate:
        """
        FindingからNucleiテンプレートを生成
        
        Args:
            finding: Finding オブジェクト
        
        Returns:
            NucleiTemplate
        """
        # 基本情報抽出
        title = getattr(finding, 'title', 'Custom Vulnerability')
        vuln_type = self._detect_vuln_type(finding)
        severity = getattr(finding, 'severity', 'medium').lower()
        url = getattr(finding, 'url', '')
        evidence = getattr(finding, 'evidence', {}) or {}
        
        # テンプレートID生成
        template_id = self._generate_id(title, vuln_type)
        
        # テンプレート構築
        template_dict = self._build_template(
            template_id=template_id,
            name=title,
            severity=severity,
            vuln_type=vuln_type,
            url=url,
            evidence=evidence,
            finding=finding
        )
        
        # YAML変換
        yaml_content = yaml.dump(template_dict, allow_unicode=True, default_flow_style=False, sort_keys=False)
        
        return NucleiTemplate(
            id=template_id,
            name=title,
            severity=severity,
            yaml_content=yaml_content
        )
    
    def _detect_vuln_type(self, finding) -> str:
        """脆弱性タイプを検出"""
        vuln_type = getattr(finding, 'vulnerability_type', '')
        if vuln_type:
            vuln_type_lower = vuln_type.lower().replace(' ', '_').replace('-', '_')
            return self.VULN_TYPE_MAP.get(vuln_type_lower, "generic")
        
        # タイトルから推測
        title = getattr(finding, 'title', '').lower()
        for keyword, category in self.VULN_TYPE_MAP.items():
            if keyword in title:
                return category
        
        return "generic"
    
    def _generate_id(self, title: str, vuln_type: str) -> str:
        """テンプレートID生成"""
        # タイトルを正規化
        normalized = re.sub(r'[^a-zA-Z0-9\s]', '', title.lower())
        words = normalized.split()[:4]  # 最初の4語
        slug = '-'.join(words) if words else 'custom'
        
        return f"shigoku-{vuln_type}-{slug}"
    
    def _build_template(
        self,
        template_id: str,
        name: str,
        severity: str,
        vuln_type: str,
        url: str,
        evidence: dict,
        finding
    ) -> dict:
        """テンプレート辞書を構築"""
        # info セクション
        template = {
            "id": template_id,
            "info": {
                "name": name,
                "author": "shigoku",
                "severity": severity,
                "description": getattr(finding, 'description', '')[:500],
                "tags": [vuln_type, "shigoku", "auto-generated"],
                "metadata": {
                    "generated_at": datetime.now().isoformat(),
                    "original_url": url
                }
            }
        }
        
        # requests セクション
        request = self._build_request(url, evidence, vuln_type)
        template["http"] = [request]
        
        return template
    
    def _build_request(self, url: str, evidence: dict, vuln_type: str) -> dict:
        """HTTPリクエストセクションを構築"""
        request = {}
        
        # URLからパス抽出
        path = "/"
        if url:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            path = parsed.path or "/"
            if parsed.query:
                path += f"?{parsed.query}"
        
        # メソッドとパス
        method = evidence.get('method', 'GET') if isinstance(evidence, dict) else 'GET'
        request["method"] = method
        request["path"] = [f"{{{{BaseURL}}}}{path}"]
        
        # ヘッダー
        headers = evidence.get('headers', {}) if isinstance(evidence, dict) else {}
        if headers:
            request["headers"] = headers
        
        # ボディ（POSTの場合）
        body = evidence.get('body', '') if isinstance(evidence, dict) else ''
        if body and method in ['POST', 'PUT', 'PATCH']:
            request["body"] = body
        
        # マッチャー
        request["matchers"] = self._create_matchers(vuln_type, evidence)
        request["matchers-condition"] = "and"
        
        return request
    
    def _create_matchers(self, vuln_type: str, evidence: dict) -> List[dict]:
        """マッチャーを生成"""
        matchers = []
        
        # ステータスコードマッチャー
        matchers.append({
            "type": "status",
            "status": [200, 201, 301, 302]
        })
        
        # 脆弱性タイプ固有のマッチャー
        if vuln_type in self.DEFAULT_MATCHERS:
            matchers.append(self.DEFAULT_MATCHERS[vuln_type])
        else:
            # レスポンスから特徴的な文字列を抽出
            response = evidence.get('response', '') if isinstance(evidence, dict) else ''
            if response and len(response) > 10:
                # 最初の特徴的な文字列を使用
                sample = response[:100].strip()
                if sample:
                    matchers.append({
                        "type": "word",
                        "words": [sample[:50]],
                        "part": "body"
                    })
        
        return matchers
    
    def save_template(self, template: NucleiTemplate, subdir: str = None) -> Path:
        """テンプレートをファイルに保存"""
        save_dir = self.templates_dir
        if subdir:
            save_dir = save_dir / subdir
            save_dir.mkdir(parents=True, exist_ok=True)
        
        filename = f"{template.id}.yaml"
        file_path = save_dir / filename
        
        file_path.write_text(template.yaml_content, encoding='utf-8')
        template.file_path = file_path
        
        logger.info("Saved Nuclei template: %s", file_path)
        return file_path
    
    def generate_and_save(self, finding, subdir: str = None) -> NucleiTemplate:
        """テンプレート生成と保存を一括実行"""
        template = self.generate_template(finding)
        self.save_template(template, subdir)
        return template


def create_nuclei_template_generator(templates_dir: str = None) -> NucleiTemplateGenerator:
    """ヘルパー関数"""
    return NucleiTemplateGenerator(templates_dir)
