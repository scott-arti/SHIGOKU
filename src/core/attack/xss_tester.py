"""
XSS Tester - XSS反射型テスター（安全版）

非破壊的な反射検出のみ
"""

import logging
import html
from typing import List, Dict, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class XSSResult:
    """XSS検出結果"""
    url: str
    parameter: str
    payload: str
    reflected: bool = False
    context: str = ""  # html/attribute/javascript/url
    escaped: bool = True
    severity: str = "medium"
    evidence: str = ""


class XSSTester:
    """
    XSS反射型テスター（安全版）
    
    機能:
    - 反射検出（ペイロード実行なし）
    - コンテキスト判定
    - エスケープ有無判定
    
    ⚠️ 注意: 反射検出のみ、実際のXSS実行は行わない
    """
    
    # 安全な検出用マーカー（実行されないが反射を確認可能）
    DETECTION_MARKERS = [
        "shigoku1337test",
        "xsstest7331probe",
        "<shigoku>",
        "\"shigoku'test",
        "'shigoku\"test",
    ]
    
    # コンテキスト判定用ペイロード
    CONTEXT_PAYLOADS = {
        "html": [
            "<shigoku>test</shigoku>",
            "<img shigoku>",
        ],
        "attribute": [
            '"shigoku"',
            "'shigoku'",
            '" shigoku="',
        ],
        "javascript": [
            "';shigoku//",
            "\";shigoku//",
            "</script>shigoku",
        ],
        "url": [
            "javascript:shigoku",
            "data:shigoku",
        ],
    }
    
    def __init__(self):
        self.results: List[XSSResult] = []
    
    def test(
        self,
        url: str,
        parameters: List[str]
    ) -> List[XSSResult]:
        """
        XSS反射テスト
        
        Args:
            url: テスト対象URL
            parameters: テスト対象パラメータ
        """
        results = []
        
        for param in parameters:
            # まずマーカーで反射確認
            for marker in self.DETECTION_MARKERS:
                result = self._test_reflection(url, param, marker)
                if result and result.reflected:
                    results.append(result)
                    self.results.append(result)
                    break  # 反射確認できたら次のパラメータへ
        
        return results
    
    def _test_reflection(
        self,
        url: str,
        parameter: str,
        marker: str
    ) -> Optional[XSSResult]:
        """
        反射テスト（プレースホルダー）
        """
        logger.info("Testing XSS reflection: %s=%s on %s", parameter, marker, url)
        
        # プレースホルダー
        # response = requests.get(url, params={parameter: marker})
        # if marker in response.text:
        #     context = self._detect_context(response.text, marker)
        #     escaped = self._is_escaped(response.text, marker)
        #     return XSSResult(
        #         url=url,
        #         parameter=parameter,
        #         payload=marker,
        #         reflected=True,
        #         context=context,
        #         escaped=escaped,
        #     )
        
        return None
    
    def _detect_context(self, html_content: str, marker: str) -> str:
        """
        反射コンテキスト判定
        
        Returns:
            html/attribute/javascript/url
        """
        # マーカーの前後を分析
        idx = html_content.find(marker)
        if idx == -1:
            return "unknown"
        
        before = html_content[max(0, idx-50):idx]
        
        # JavaScript内
        if "<script" in before.lower() and "</script>" not in before.lower():
            return "javascript"
        
        # 属性値内
        if '="' in before or "='" in before:
            return "attribute"
        
        # URL内
        if "href=" in before or "src=" in before:
            return "url"
        
        return "html"
    
    def _is_escaped(self, html_content: str, marker: str) -> bool:
        """エスケープされているか判定"""
        # HTMLエンティティ化されているか
        escaped_marker = html.escape(marker)
        if escaped_marker != marker and escaped_marker in html_content:
            return True
        return False
    
    def get_vulnerable(self) -> List[XSSResult]:
        """脆弱と判定されたもの（反射あり＆エスケープなし）"""
        return [r for r in self.results if r.reflected and not r.escaped]
    
    def get_reflected(self) -> List[XSSResult]:
        """反射が確認されたもの全て"""
        return [r for r in self.results if r.reflected]
    
    def get_summary(self) -> Dict:
        """サマリー"""
        by_context = {}
        for r in self.results:
            if r.reflected:
                by_context.setdefault(r.context, 0)
                by_context[r.context] += 1
        
        return {
            "total_tests": len(self.results),
            "reflected": len(self.get_reflected()),
            "vulnerable": len(self.get_vulnerable()),
            "by_context": by_context,
        }
    
    def get_summary_for_ai(self) -> str:
        """AI向けサマリー"""
        summary = self.get_summary()
        return (
            f"XSS Test: {summary['total_tests']} tests\n"
            f"Reflected: {summary['reflected']}\n"
            f"Vulnerable (unescaped): {summary['vulnerable']}\n"
            f"Contexts: {summary['by_context']}"
        )


def create_xss_tester() -> XSSTester:
    """XSSTester作成ヘルパー"""
    return XSSTester()
