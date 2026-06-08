"""
MigrationValidator: 新基盤内の実行経路等価性を検証するユーティリティ

Phase E-2向けに、一致率だけでなくFN/FPを分離して判定する。
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class ComparisonResult:
    tool_name: str
    baseline_result: Any
    candidate_result: Any
    match_rate: float
    false_negative_rate: float
    false_positive_rate: float
    time_old_ms: float
    time_new_ms: float
    time_diff_percent: float
    passed: bool
    details: List[str]


class MigrationValidator:
    """新旧実装の機能等価性を検証する。"""

    def __init__(self):
        self.threshold_match_rate = 0.95
        self.threshold_fn_rate = 0.05
        self.threshold_fp_rate = 0.10
        self.threshold_time_diff = 0.10

    async def compare_nuclei(
        self,
        target: str,
        tags: Optional[List[str]] = None,
        severity: str = "info",
    ) -> ComparisonResult:
        details: List[str] = []

        time_old_start = time.time()
        try:
            from src.core.adapters.external.nuclei_adapter import NucleiAdapter
            from src.core.adapters.external.base_external_adapter import ToolInput

            adapter = NucleiAdapter()
            baseline_obj = await adapter.run_with_validation(
                ToolInput(
                    target=target,
                    options={
                        "tags": ",".join(tags) if tags else "cve",
                        "severity": severity,
                    },
                ),
            )
            baseline_result = baseline_obj.data if baseline_obj.status.value == "success" else []
        except Exception as e:
            return ComparisonResult(
                tool_name="nuclei",
                baseline_result=None,
                candidate_result=None,
                match_rate=0.0,
                false_negative_rate=1.0,
                false_positive_rate=1.0,
                time_old_ms=0,
                time_new_ms=0,
                time_diff_percent=0,
                passed=False,
                details=[f"Baseline実行失敗(Adapter direct): {e}"],
            )
        time_old_ms = (time.time() - time_old_start) * 1000

        time_new_start = time.time()
        try:
            from src.core.adapters.external.nuclei_adapter import NucleiAdapter
            from src.core.adapters.external.base_external_adapter import ToolInput
            from src.core.adapters.external.external_tool_executor import get_global_executor

            executor = get_global_executor()

            candidate_obj = await executor.execute(
                adapter,
                ToolInput(
                    target=target,
                    options={
                        "tags": ",".join(tags) if tags else "cve",
                        "severity": severity,
                    },
                ),
            )
            candidate_result = candidate_obj.data if candidate_obj.status.value == "success" else []
        except Exception as e:
            return ComparisonResult(
                tool_name="nuclei",
                baseline_result=baseline_result,
                candidate_result=None,
                match_rate=0.0,
                false_negative_rate=1.0,
                false_positive_rate=1.0,
                time_old_ms=time_old_ms,
                time_new_ms=0,
                time_diff_percent=0,
                passed=False,
                details=[f"Candidate実行失敗(Adapter+Executor): {e}"],
            )
        time_new_ms = (time.time() - time_new_start) * 1000

        match_rate, fn_rate, fp_rate = self.compare_nuclei_results(baseline_result, candidate_result)
        time_diff_percent = ((time_new_ms - time_old_ms) / max(time_old_ms, 1)) * 100

        passed = True
        if match_rate < self.threshold_match_rate:
            passed = False
            details.append(f"一致率不足: {match_rate:.1%} < {self.threshold_match_rate:.0%}")
        if fn_rate > self.threshold_fn_rate:
            passed = False
            details.append(f"FN率超過: {fn_rate:.1%} > {self.threshold_fn_rate:.0%}")
        if fp_rate > self.threshold_fp_rate:
            passed = False
            details.append(f"FP率超過: {fp_rate:.1%} > {self.threshold_fp_rate:.0%}")
        # 性能ゲートは「劣化」を検知するためのもの。
        # 新実装が高速化しているケースはFailにしない。
        if time_diff_percent > self.threshold_time_diff * 100:
            passed = False
            details.append(
                f"パフォーマンス劣化超過: {time_diff_percent:+.1f}% (閾値+{self.threshold_time_diff*100:.0f}%以内)"
            )

        if not details:
            details.append(
                f"検証合格: 一致率{match_rate:.1%}, FN率{fn_rate:.1%}, FP率{fp_rate:.1%}, 時間差{time_diff_percent:+.1f}%"
            )

        return ComparisonResult(
            tool_name="nuclei",
            baseline_result=baseline_result,
            candidate_result=candidate_result,
            match_rate=match_rate,
            false_negative_rate=fn_rate,
            false_positive_rate=fp_rate,
            time_old_ms=time_old_ms,
            time_new_ms=time_new_ms,
            time_diff_percent=time_diff_percent,
            passed=passed,
            details=details,
        )

    @staticmethod
    def compare_nuclei_results(old_result: List[Dict], new_result: List[Dict]) -> Tuple[float, float, float]:
        """Nuclei結果を比較して一致率/FN率/FP率を返す。"""
        if not old_result and not new_result:
            return 1.0, 0.0, 0.0
        if not old_result or not new_result:
            if old_result:
                return 0.0, 1.0, 0.0
            return 0.0, 0.0, 1.0

        old_ids = {r.get("template_id", "") for r in old_result}
        new_ids = {r.get("template_id", "") for r in new_result}
        if not old_ids or not new_ids:
            if old_ids:
                return 0.0, 1.0, 0.0
            return 0.0, 0.0, 1.0

        intersection = len(old_ids & new_ids)
        union = len(old_ids | new_ids)
        match_rate = intersection / union if union > 0 else 0.0
        fn_rate = len(old_ids - new_ids) / max(len(old_ids), 1)
        fp_rate = len(new_ids - old_ids) / max(len(new_ids), 1)
        return match_rate, fn_rate, fp_rate

    async def validate_all(self, targets: List[str], verbose: bool = False) -> Dict[str, List[ComparisonResult]]:
        results: Dict[str, Any] = {"nuclei": [], "passed": 0, "failed": 0}
        for target in targets:
            result = await self.compare_nuclei(target)
            results["nuclei"].append(result)
            if result.passed:
                results["passed"] += 1
            else:
                results["failed"] += 1
            if verbose:
                print(f"\n[{target}]")
                print(f"  Match Rate: {result.match_rate:.1%}")
                print(f"  FN Rate: {result.false_negative_rate:.1%}")
                print(f"  FP Rate: {result.false_positive_rate:.1%}")
                print(f"  Time Diff: {result.time_diff_percent:+.1f}%")
                print(f"  Status: {'✅ PASS' if result.passed else '❌ FAIL'}")
                for detail in result.details:
                    print(f"    - {detail}")
        return results

    def generate_report(self, results: Dict) -> str:
        lines = [
            "# Phase E-2 Migration Validation Report",
            "",
            "## Summary",
            "",
            f"- **Total Tests**: {results['passed'] + results['failed']}",
            f"- **Passed**: {results['passed']}",
            f"- **Failed**: {results['failed']}",
            f"- **Pass Rate**: {results['passed'] / max(results['passed'] + results['failed'], 1):.1%}",
            "",
            "## Details",
            "",
        ]
        for tool_name, tool_results in results.items():
            if tool_name in ["passed", "failed"]:
                continue
            lines.append(f"### {tool_name.upper()}")
            lines.append("")
            for i, result in enumerate(tool_results, 1):
                status = "✅ PASS" if result.passed else "❌ FAIL"
                lines.append(f"#### Test {i}: {result.tool_name}")
                lines.append(f"- **Status**: {status}")
                lines.append(f"- **Match Rate**: {result.match_rate:.1%}")
                lines.append(f"- **False Negative Rate**: {result.false_negative_rate:.1%}")
                lines.append(f"- **False Positive Rate**: {result.false_positive_rate:.1%}")
                lines.append(f"- **Old Time**: {result.time_old_ms:.0f}ms")
                lines.append(f"- **New Time**: {result.time_new_ms:.0f}ms")
                lines.append(f"- **Time Diff**: {result.time_diff_percent:+.1f}%")
                lines.append("")
                lines.append("**Details**:")
                for detail in result.details:
                    lines.append(f"- {detail}")
                lines.append("")
        return "\n".join(lines)


if __name__ == "__main__":
    import asyncio

    async def main():
        validator = MigrationValidator()
        test_targets = ["https://httpbin.org"]
        print("=" * 60)
        print("Phase E-2 Migration Validation")
        print("=" * 60)
        results = await validator.validate_all(test_targets, verbose=True)
        print("\n" + "=" * 60)
        print(f"Results: {results['passed']} passed, {results['failed']} failed")
        print("=" * 60)
        report = validator.generate_report(results)
        with open("migration_validation_report.md", "w") as f:
            f.write(report)
        print("\nReport saved to: migration_validation_report.md")

    asyncio.run(main())
