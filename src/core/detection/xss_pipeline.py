"""
XSS Detection Pipeline - Phase X-3 (X3-4)
DOM XSS自動検証フロー: DOMXSSDetector (X1-3) + BrowserPoolXSSVerifier (X3-2) の統合

設計方針:
- 静的解析 → DalFox動的スキャン → Browser Pool発火確認 の3段階パイプライン
- 各段階で confidence を積み上げ、最終的な Finding を生成
- Browser Pool なしでも動作（graceful degradation）
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from src.core.detection.dom_xss_detector import DOMXSSDetector, DOMXSSFinding
from src.core.detection.browser_pool import BrowserPool, BrowserPoolXSSVerifier, XSSVerificationResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pipeline Result
# ---------------------------------------------------------------------------

@dataclass
class XSSPipelineResult:
    """3段階パイプライン全体の検出結果"""
    target: str
    total_findings: int = 0
    confirmed_findings: List[Dict[str, Any]] = field(default_factory=list)
    candidate_findings: List[Dict[str, Any]] = field(default_factory=list)
    pipeline_metrics: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "total_findings": self.total_findings,
            "confirmed_findings": self.confirmed_findings,
            "candidate_findings": self.candidate_findings,
            "pipeline_metrics": self.pipeline_metrics,
        }


# ---------------------------------------------------------------------------
# XSS Detection Pipeline
# ---------------------------------------------------------------------------

class XSSDetectionPipeline:
    """
    DOM XSS 完全自動検出パイプライン（X3-4）

    Stage 1: DOMXSSCandidateAnalyzer  - 静的解析で候補特定（X1-3）
    Stage 2: DalFox                   - 動的スキャン（X1-3）
    Stage 3: BrowserPoolXSSVerifier   - ブラウザ発火確認（X3-2）

    Architecture:
        URL
         │
         ▼
    ┌──────────────┐
    │ Stage 1      │ URLパターン解析・高リスクパラメータ特定
    │ Static Scan  │
    └──────┬───────┘
           │ candidates
           ▼
    ┌──────────────┐
    │ Stage 2      │ DalFox ブラウザ内蔵スキャン
    │ DalFox Scan  │
    └──────┬───────┘
           │ raw findings (confidence 0.7-0.9)
           ▼
    ┌──────────────┐
    │ Stage 3      │ Browser Pool で発火確認
    │ Browser Verify│ → confirmed (confidence 0.95)
    └──────┬───────┘
           │
           ▼
       XSSPipelineResult
    """

    def __init__(
        self,
        browser_pool: Optional[BrowserPool] = None,
        enable_browser_verify: bool = True,
    ) -> None:
        self._dom_detector = DOMXSSDetector()
        self._verifier = BrowserPoolXSSVerifier(pool=browser_pool)
        self._enable_browser_verify = enable_browser_verify

    async def run(
        self,
        target_url: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> XSSPipelineResult:
        """
        パイプライン全体を実行

        Args:
            target_url: スキャン対象URL
            options: スキャンオプション
                - max_verify_tasks: Stage3の最大並列数（デフォルト10）
                - dalfox_timeout: DalFoxタイムアウト秒（デフォルト120）
                - browser_dialog_timeout: ダイアログ待機秒（デフォルト3.0）

        Returns:
            XSSPipelineResult: パイプライン全体の結果
        """
        opts = options or {}
        result = XSSPipelineResult(target=target_url)
        metrics: Dict[str, Any] = {}

        logger.info("[XSSPipeline] Starting pipeline for: %s", target_url)

        # ── Stage 1: Static candidates ──────────────────────────────────────
        logger.info("[XSSPipeline] Stage 1: Static analysis")
        static_candidates = await self._dom_detector.run_static_only(target_url)
        metrics["static_candidates_count"] = len(static_candidates)

        # ── Stage 2: Dynamic scan (DalFox) ──────────────────────────────────
        logger.info("[XSSPipeline] Stage 2: DalFox dynamic scan")
        dalfox_findings: List[DOMXSSFinding] = []
        metrics["dalfox_error_count"] = 0
        metrics["dalfox_timeout_count"] = 0
        try:
            dalfox_findings = await self._dom_detector.run_dynamic_only(
                target_url,
                {
                    "timeout_seconds": opts.get("dalfox_timeout", 120),
                    "max_candidates": opts.get("max_candidates", 10),
                    "static_candidates": static_candidates,
                },
            )
        except TimeoutError:
            metrics["dalfox_error_count"] = 1
            metrics["dalfox_timeout_count"] = 1
            dalfox_findings = []
        except Exception:
            metrics["dalfox_error_count"] = 1
            dalfox_findings = []

        metrics["dynamic_findings_count"] = len(dalfox_findings)

        dom_findings = self._merge_findings(static_candidates, dalfox_findings)
        metrics["stage1_2_findings"] = len(dom_findings)
        logger.info("[XSSPipeline] Stage 1+2: %d merged candidate(s)", len(dom_findings))

        if not dom_findings:
            metrics["candidate_findings_count"] = 0
            result.pipeline_metrics = metrics
            return result

        # ── Stage 3: Browser Pool 発火確認 ───────────────────────────────
        if self._enable_browser_verify:
            logger.info("[XSSPipeline] Stage 3: Browser Pool verification")
            findings_for_verify = dom_findings
            static_verify_cap = opts.get("max_static_candidates_for_verify")
            if (
                isinstance(static_verify_cap, int)
                and static_verify_cap >= 0
                and not dalfox_findings
            ):
                findings_for_verify = dom_findings[:static_verify_cap]
            confirmed, candidates = await self._verify_with_pool(
                findings_for_verify,
                max_tasks=opts.get("max_verify_tasks", 10),
                dialog_timeout=opts.get("browser_dialog_timeout", 3.0),
            )
            metrics["stage3_confirmed"] = len(confirmed)
            metrics["stage3_candidates"] = len(candidates)
        else:
            # Browser verify 無効時はすべて candidates 扱い
            confirmed = []
            candidates = [f.to_dict() for f in dom_findings]
            metrics["stage3_confirmed"] = 0
            metrics["stage3_candidates"] = len(candidates)

        result.confirmed_findings = confirmed
        result.candidate_findings = candidates
        metrics["candidate_findings_count"] = len(candidates)
        result.total_findings = len(confirmed) + len(candidates)
        result.pipeline_metrics = metrics

        logger.info(
            "[XSSPipeline] Complete. confirmed=%d candidates=%d",
            len(confirmed), len(candidates),
        )
        return result

    async def _verify_with_pool(
        self,
        findings: List[DOMXSSFinding],
        *,
        max_tasks: int,
        dialog_timeout: float,
    ) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """
        DalFox findings を Browser Pool で発火確認。

        Returns:
            (confirmed_findings, candidate_findings)
        """
        # 検証タスクを生成（max_tasks 件に絞る）
        verify_tasks = [
            {
                "url": f.url,
                "parameter": f.parameter,
                "payload": f.payload,
                "_finding": f,
            }
            for f in findings[:max_tasks]
            if f.url and f.parameter and f.payload
        ]

        if not verify_tasks:
            return [], [f.to_dict() for f in findings]

        # BrowserPoolXSSVerifier で並列確認
        verification_results: List[XSSVerificationResult] = (
            await self._verifier.verify_batch(
                [{"url": t["url"], "parameter": t["parameter"], "payload": t["payload"]}
                 for t in verify_tasks],
                dialog_timeout=dialog_timeout,
            )
        )

        confirmed: List[Dict[str, Any]] = []
        candidates: List[Dict[str, Any]] = []

        for task, vr in zip(verify_tasks, verification_results):
            finding_dict = task["_finding"].to_dict()
            finding_dict["browser_verified"] = vr.executed
            finding_dict["verification_evidence"] = vr.evidence

            if vr.executed:
                finding_dict["confidence"] = 0.95
                confirmed.append(finding_dict)
            else:
                candidates.append(finding_dict)

        # 検証タスク外の findings は candidates に追加
        extra = [f.to_dict() for f in findings[max_tasks:]]
        candidates.extend(extra)

        return confirmed, candidates

    def _merge_findings(
        self,
        static_candidates: List[DOMXSSFinding],
        dalfox_findings: List[DOMXSSFinding],
    ) -> List[DOMXSSFinding]:
        """URLキーで統合。重複時はDalFox結果を優先。"""
        by_url: Dict[str, DOMXSSFinding] = {}
        for finding in static_candidates:
            key = finding.url or finding.target
            if key:
                by_url[key] = finding
        for finding in dalfox_findings:
            key = finding.url or finding.target
            if key:
                by_url[key] = finding
        return list(by_url.values())

    async def close(self) -> None:
        """リソース解放"""
        await self._verifier.close()
