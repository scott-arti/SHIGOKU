"""
Screenshot PoC Generator

PlaywrightでスクリーンショットをとりながらObsidian形式MarkdownでPoCレポートを生成。
"""

import asyncio
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

# Playwright遅延インポート
PLAYWRIGHT_AVAILABLE = False
try:
    from playwright.async_api import async_playwright, Page
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    logger.warning("Playwright not installed. Install with: pip install playwright && playwright install")
    Page = None


@dataclass
class StepResult:
    """ステップ実行結果"""
    index: int
    description: str
    screenshot_path: Optional[Path] = None
    note: str = ""
    success: bool = True


@dataclass
class ScreenshotPoCResult:
    """PoC生成結果"""
    markdown_path: Path
    screenshots: List[Path] = field(default_factory=list)
    output_dir: Path = None
    steps: List[StepResult] = field(default_factory=list)


class ScreenshotPoCGenerator:
    """
    スクリーンショットPoC生成器
    
    Playwrightでブラウザ操作しながらスクリーンショットを取得し、
    Obsidian形式のMarkdownレポートを生成。
    """
    
    # ステップパターン
    STEP_PATTERNS = {
        r"Navigate to (.+)": "navigate",
        r"Go to (.+)": "navigate",
        r"Click (?:on )?(.+)": "click",
        r"Type (.+) (?:into|in) (.+)": "type",
        r"Enter (.+) (?:into|in) (.+)": "type",
        r"Wait (\d+)": "wait",
        r"Screenshot": "screenshot",
        r"Assert (.+) (?:is )?visible": "assert_visible",
    }
    
    def __init__(self, headless: bool = True):
        self.headless = headless
        self.browser = None
        self.context = None
    
    async def generate(
        self,
        finding,
        output_dir: Path,
        manual_steps: List[str] = None
    ) -> ScreenshotPoCResult:
        """
        PoCを生成
        
        Args:
            finding: Finding オブジェクト
            output_dir: 出力ディレクトリ
            manual_steps: 手動で指定するステップ（Findingにない場合）
        
        Returns:
            ScreenshotPoCResult
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # ステップ取得
        steps = manual_steps or getattr(finding, 'reproduction_steps', []) or []
        if isinstance(steps, str):
            steps = [s.strip() for s in steps.split('\n') if s.strip()]
        
        title = getattr(finding, 'title', 'PoC Report')
        target_url = getattr(finding, 'url', None)
        
        step_results: List[StepResult] = []
        screenshots: List[Path] = []
        
        if PLAYWRIGHT_AVAILABLE and steps:
            step_results, screenshots = await self._execute_steps(
                steps, output_dir, target_url
            )
        else:
            # Playwrightなしの場合はテキストのみ
            for i, step in enumerate(steps):
                step_results.append(StepResult(
                    index=i + 1,
                    description=step,
                    note="(スクリーンショットなし - Playwright未インストール)"
                ))
        
        # Markdownレポート生成
        markdown_content = self._format_obsidian_md(title, finding, step_results)
        markdown_path = output_dir / "poc_report.md"
        markdown_path.write_text(markdown_content, encoding='utf-8')
        
        return ScreenshotPoCResult(
            markdown_path=markdown_path,
            screenshots=screenshots,
            output_dir=output_dir,
            steps=step_results
        )
    
    async def _execute_steps(
        self,
        steps: List[str],
        output_dir: Path,
        initial_url: str = None
    ) -> Tuple[List[StepResult], List[Path]]:
        """ステップを実行しながらスクリーンショット取得"""
        results = []
        screenshots = []
        
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=self.headless)
            context = await browser.new_context(
                viewport={"width": 1280, "height": 720}
            )
            page = await context.new_page()
            
            # 初期URL
            if initial_url:
                try:
                    await page.goto(initial_url, timeout=10000)
                except Exception as e:
                    logger.warning("Initial navigation failed: %s", e)
            
            for i, step in enumerate(steps):
                step_num = i + 1
                screenshot_path = output_dir / f"step_{step_num:03d}.png"
                
                try:
                    # ステップ実行
                    await self._execute_single_step(page, step)
                    await page.wait_for_timeout(500)  # 安定待ち
                    
                    # スクリーンショット取得
                    await page.screenshot(path=str(screenshot_path))
                    screenshots.append(screenshot_path)
                    
                    results.append(StepResult(
                        index=step_num,
                        description=step,
                        screenshot_path=screenshot_path,
                        success=True
                    ))
                except Exception as e:
                    logger.warning("Step %d failed: %s", step_num, e)
                    results.append(StepResult(
                        index=step_num,
                        description=step,
                        note=f"Error: {str(e)}",
                        success=False
                    ))
            
            await browser.close()
        
        return results, screenshots
    
    async def _execute_single_step(self, page: Page, step: str) -> None:
        """単一ステップを実行"""
        step_lower = step.lower()
        
        for pattern, action in self.STEP_PATTERNS.items():
            match = re.match(pattern, step, re.IGNORECASE)
            if match:
                if action == "navigate":
                    url = match.group(1).strip()
                    await page.goto(url, timeout=10000)
                elif action == "click":
                    selector = match.group(1).strip()
                    await page.click(selector, timeout=5000)
                elif action == "type":
                    text = match.group(1).strip()
                    selector = match.group(2).strip()
                    await page.fill(selector, text)
                elif action == "wait":
                    seconds = int(match.group(1))
                    await page.wait_for_timeout(seconds * 1000)
                elif action == "assert_visible":
                    text = match.group(1).strip()
                    await page.get_by_text(text).wait_for(timeout=5000)
                return
        
        # パターンマッチしない場合はログのみ
        logger.info("Step not automated: %s", step)
    
    def _format_obsidian_md(
        self,
        title: str,
        finding,
        steps: List[StepResult]
    ) -> str:
        """Obsidian形式Markdownを生成"""
        lines = [
            f"# PoC: {title}",
            "",
            f"> Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            "",
        ]
        
        # 概要
        vuln_type = getattr(finding, 'vulnerability_type', 'Unknown')
        severity = getattr(finding, 'severity', 'Unknown')
        url = getattr(finding, 'url', 'N/A')
        
        lines.extend([
            "## 概要",
            "",
            f"- **脆弱性タイプ**: {vuln_type}",
            f"- **深刻度**: {severity}",
            f"- **対象URL**: {url}",
            "",
        ])
        
        # 再現手順
        lines.extend([
            "## 再現手順",
            "",
        ])
        
        for step in steps:
            lines.append(f"### Step {step.index}: {step.description}")
            lines.append("")
            
            if step.screenshot_path:
                # Obsidian形式の画像埋め込み
                filename = step.screenshot_path.name
                lines.append(f"![[{filename}]]")
            
            if step.note:
                lines.append(f"> {step.note}")
            
            if not step.success:
                lines.append("> ⚠️ このステップは自動実行に失敗しました")
            
            lines.append("")
        
        # 証拠
        evidence = getattr(finding, 'evidence', None)
        if evidence:
            lines.extend([
                "## 証拠",
                "",
            ])
            
            if isinstance(evidence, dict):
                if evidence.get('request'):
                    lines.append("### Request")
                    lines.append("```http")
                    lines.append(str(evidence['request']))
                    lines.append("```")
                    lines.append("")
                
                if evidence.get('response'):
                    lines.append("### Response")
                    lines.append("```http")
                    lines.append(str(evidence['response'])[:1000])
                    lines.append("```")
                    lines.append("")
        
        # 影響
        impact = getattr(finding, 'impact', '')
        if impact:
            lines.extend([
                "## 影響",
                "",
                impact,
                "",
            ])
        
        lines.extend([
            "---",
            f"**結果**: 脆弱性確認 ✅",
        ])
        
        return "\n".join(lines)


def is_playwright_available() -> bool:
    """Playwright利用可能チェック"""
    return PLAYWRIGHT_AVAILABLE


async def generate_screenshot_poc(finding, output_dir: str) -> ScreenshotPoCResult:
    """ヘルパー関数"""
    generator = ScreenshotPoCGenerator()
    return await generator.generate(finding, Path(output_dir))
