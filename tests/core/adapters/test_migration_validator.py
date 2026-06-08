"""
互換エントリポイント: MigrationValidator 実行ラッパー

本体は `src/core/adapters/external/migration_validator.py` に配置。
このファイルは既存ドキュメントや運用手順の互換性維持のために残す。
"""

from src.core.adapters.external.migration_validator import ComparisonResult, MigrationValidator

__all__ = ["ComparisonResult", "MigrationValidator"]


def test_compare_nuclei_results_perfect_match():
    old_result = [{"template_id": "t1"}, {"template_id": "t2"}]
    new_result = [{"template_id": "t1"}, {"template_id": "t2"}]
    match, fn_rate, fp_rate = MigrationValidator.compare_nuclei_results(old_result, new_result)
    assert match == 1.0
    assert fn_rate == 0.0
    assert fp_rate == 0.0


def test_generate_report_uses_new_baseline_candidate_schema():
    validator = MigrationValidator()
    result = ComparisonResult(
        tool_name="nuclei",
        baseline_result=[],
        candidate_result=[],
        match_rate=1.0,
        false_negative_rate=0.0,
        false_positive_rate=0.0,
        time_old_ms=10.0,
        time_new_ms=9.0,
        time_diff_percent=-10.0,
        passed=True,
        details=["ok"],
    )
    report = validator.generate_report({"nuclei": [result], "passed": 1, "failed": 0})
    assert "Phase E-2 Migration Validation Report" in report
    assert "Match Rate" in report


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
