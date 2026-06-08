"""
Fingerprinter: 技術スタック特定モジュール

HTTPレスポンス（ヘッダー、HTML）を解析し、
サーバー、フレームワーク、CMS、JSライブラリなどの技術スタックを特定する。
"""

import logging
import re
from dataclasses import dataclass
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)


@dataclass
class TechInfo:
    """特定された技術情報"""
    name: str
    category: str  # Server, Framework, CMS, Lang, Frontend, etc.
    version: Optional[str] = None
    confidence: float = 1.0


class Fingerprinter:
    """
    技術スタック識別クラス
    """
    
    # 技術シグネチャ定義
    # 各カテゴリごとにリストを持つ。
    # - headers: {Key: Regex Pattern}
    # - html: Regex Pattern
    SIGNATURES = {
        "WordPress": {
            "category": "CMS",
            "html": [r'content="WordPress', r'/wp-content/', r'/wp-includes/'],
            "headers": {"X-Powered-By": r"WordPress"}
        },
        "Drupal": {
            "category": "CMS",
            "html": [r'Drupal', r'jQuery.extend\(Drupal'],
            "headers": {"X-Generator": r"Drupal"}
        },
        "Joomla": {
            "category": "CMS",
            "html": [r'content="Joomla'],
            "headers": {}
        },
        "Laravel": {
            "category": "Framework",
            "html": [],
            "headers": {"Set-Cookie": r"laravel_session"}
        },
        "Django": {
            "category": "Framework",
            "html": [],
            "headers": {"Set-Cookie": r"csrftoken"}
        },
        "Rails": {
            "category": "Framework",
            "html": [r'content="authenticity_token"'],
            "headers": {"X-Powered-By": r"Phusion Passenger", "Set-Cookie": r"_session_id"}
        },
        "Express": {
            "category": "Framework",
            "html": [],
            "headers": {"X-Powered-By": r"Express"}
        },
        "Flask": {
            "category": "Framework",
            "html": [],
            "headers": {"Server": r"Werkzeug"}
        },
        "React": {
            "category": "Frontend",
            "html": [r'react-root', r'data-reactroot', r'_react', r'react.production.min.js'],
            "headers": {}
        },
        "Vue": {
            "category": "Frontend",
            "html": [r'data-v-', r'vue.min.js', r'__vue__'],
            "headers": {}
        },
        "Next.js": {
            "category": "Framework",
            "html": [r'__NEXT_DATA__', r'/_next/'],
            "headers": {"X-Powered-By": r"Next.js"}
        },
        "Nginx": {
            "category": "Server",
            "html": [],
            "headers": {"Server": r"nginx"}
        },
        "Apache": {
            "category": "Server",
            "html": [],
            "headers": {"Server": r"Apache"}
        },
        "PHP": {
            "category": "Lang",
            "html": [],
            "headers": {"X-Powered-By": r"PHP", "Set-Cookie": r"PHPSESSID"}
        },
        "Java": {
            "category": "Lang",
            "html": [],
            "headers": {"Set-Cookie": r"JSESSIONID"}
        },
        "ASP.NET": {
            "category": "Lang",
            "html": [r'__VIEWSTATE'],
            "headers": {"Set-Cookie": r"ASP.NET_SessionId", "X-Powered-By": r"ASP.NET"}
        },
        # テンプレートエンジン
        "Jinja2": {
            "category": "TemplateEngine",
            "html": [r'jinja', r'jinja2'],
            "headers": {},
            "lang": "Python"
        },
        "Thymeleaf": {
            "category": "TemplateEngine",
            "html": [r'th:', r'th:text', r'th:each', r'thymeleaf'],
            "headers": {},
            "lang": "Java"
        },
        "Twig": {
            "category": "TemplateEngine",
            "html": [r'twig'],
            "headers": {},
            "lang": "PHP"
        },
        "Freemarker": {
            "category": "TemplateEngine",
            "html": [r'freemarker', r'<#', r'<@'],
            "headers": {},
            "lang": "Java"
        },
        "Smarty": {
            "category": "TemplateEngine",
            "html": [r'smarty', r'\{literal\}'],
            "headers": {},
            "lang": "PHP"
        },
        "Velocity": {
            "category": "TemplateEngine",
            "html": [r'velocity', r'#set\s*\(', r'\$\{[a-z]'],
            "headers": {},
            "lang": "Java"
        },
        "ERB": {
            "category": "TemplateEngine",
            "html": [r'<%=', r'<%-'],
            "headers": {},
            "lang": "Ruby"
        },
        "Blade": {
            "category": "TemplateEngine",
            "html": [r'@extends', r'@section', r'@yield'],
            "headers": {},
            "lang": "PHP"
        },
        "Mako": {
            "category": "TemplateEngine",
            "html": [r'mako', r'<%def', r'<%block'],
            "headers": {},
            "lang": "Python"
        },
        "Handlebars": {
            "category": "TemplateEngine",
            "html": [r'handlebars', r'\{\{#each', r'\{\{#if'],
            "headers": {},
            "lang": "JavaScript"
        },
        "Mustache": {
            "category": "TemplateEngine",
            "html": [r'mustache'],
            "headers": {},
            "lang": "JavaScript"
        },
        "Pebble": {
            "category": "TemplateEngine",
            "html": [r'pebble'],
            "headers": {},
            "lang": "Java"
        },
    }
    
    # フレームワーク → テンプレートエンジン推測マッピング
    FRAMEWORK_TO_ENGINE: Dict[str, List[str]] = {
        "Django": ["Jinja2"],
        "Flask": ["Jinja2"],
        "Rails": ["ERB"],
        "Laravel": ["Blade"],
        "Express": ["Handlebars", "Mustache"],
        "Next.js": ["Handlebars", "Mustache"],
    }
    
    # 言語 → テンプレートエンジン推測マッピング
    LANG_TO_ENGINE: Dict[str, List[str]] = {
        "Python": ["Jinja2", "Mako"],
        "Java": ["Thymeleaf", "Freemarker", "Velocity", "Pebble"],
        "PHP": ["Twig", "Smarty", "Blade"],
        "Ruby": ["ERB"],
    }

    def __init__(self):
        # パターンをコンパイルしてキャッシュしても良いが、
        # ここではシンプルに都度マッチングまたは文字列検索を行う
        pass

    def identify(self, html_content: str, headers: Dict[str, str]) -> List[TechInfo]:
        """
        技術情報を特定する
        
        Args:
            html_content: レスポンスボディ (テキスト)
            headers: レスポンスヘッダー
            
        Returns:
            List[TechInfo]
        """
        detected = []
        html_lower = html_content.lower() if html_content else ""
        
        # ヘッダーのキーを小文字化して扱いやすくする
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        for name, sig in self.SIGNATURES.items():
            category = sig["category"]
            found = False
            version = None # バージョン抽出は今回はスキップ（正規表現グループ化が必要）

            # 1. ヘッダーチェック
            sig_headers = sig.get("headers", {})
            for h_key, h_pattern in sig_headers.items():
                target_val = headers_lower.get(h_key.lower())
                if target_val:
                    if re.search(h_pattern, target_val, re.IGNORECASE):
                        found = True
                        break # 1つでもマッチすればOK

            # 2. HTMLチェック (ヘッダーで見つかってなければ)
            if not found:
                sig_html = sig.get("html", [])
                for pattern in sig_html:
                    if re.search(pattern, html_lower, re.IGNORECASE): # HTML全体に対するRegexは重いが、今回は許容
                        found = True
                        break
            
            if found:
                detected.append(TechInfo(name=name, category=category, version=version))
        
        return detected

    def get_template_engines(self, detected: Optional[List[TechInfo]] = None) -> List[str]:
        """
        テンプレートエンジンを推測
        
        検出された技術情報から、使用されている可能性のあるテンプレートエンジンを返す。
        直接検出されたエンジン + フレームワーク/言語からの推測を含む。
        
        Args:
            detected: 検出済みの技術情報リスト（Noneなら空リスト扱い）
        
        Returns:
            テンプレートエンジン名のリスト（小文字）
        
        Example:
            >>> fp = Fingerprinter()
            >>> tech = [TechInfo(name="Django", category="Framework")]
            >>> fp.get_template_engines(tech)
            ['jinja2']
        """
        if detected is None:
            detected = []
        
        engines = set()
        
        for tech in detected:
            name = tech.name
            category = tech.category
            
            # 直接テンプレートエンジンとして検出されている場合
            if category == "TemplateEngine":
                engines.add(name.lower())
            
            # フレームワークから推測
            if name in self.FRAMEWORK_TO_ENGINE:
                for engine in self.FRAMEWORK_TO_ENGINE[name]:
                    engines.add(engine.lower())
            
            # 言語から推測
            if name in self.LANG_TO_ENGINE:
                for engine in self.LANG_TO_ENGINE[name]:
                    engines.add(engine.lower())
        
        return list(engines)
