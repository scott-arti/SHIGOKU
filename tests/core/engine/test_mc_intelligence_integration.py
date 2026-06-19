import pytest
import asyncio
import time
from unittest.mock import MagicMock, patch, AsyncMock
from src.core.engine.master_conductor import MasterConductor
from src.core.agents.swarm.base import Task
from src.core.engine.master_conductor import TaskState
from src.core.models.finding import Finding, VulnType, Severity
from src.core.intelligence import (
    ActionRiskProfile, RiskAssessment, RiskLevel,
    ErrorRecord, RootCauseAnalysis, ErrorCategory,
    ExecutionRecord, ExecutionOutcome, ReflectionInsight,
    BoostEvent, BoostTrigger
)

@pytest.fixture
def mock_mc():
    with patch("src.core.engine.master_conductor_facade.get_findings_repository"), \
         patch("src.core.engine.master_conductor_facade.AsyncDatabaseWriter"), \
         patch("src.core.engine.master_conductor_facade.AgentFactory"), \
         patch("src.core.engine.master_conductor_facade.SmartScheduler"), \
         patch("src.core.engine.master_conductor_facade.KnowledgeGraph"), \
         patch("src.core.engine.master_conductor_facade.get_event_bus") as mock_get_event_bus, \
         patch("src.core.engine.master_conductor_facade.get_phase_gate"), \
         patch("src.core.engine.master_conductor_facade.get_notifier"):
        
        mock_get_event_bus.return_value.start = AsyncMock()
        mc = MasterConductor()
        # Mock Intelligence Modules
        mc.risk_predictor = MagicMock()
        mc.self_reflection = MagicMock()
        mc.error_analyzer = MagicMock()
        mc.priority_booster = MagicMock()
        
        # Mock components to avoid side effects
        mc.orchestrator = MagicMock()
        mc.task_queue = MagicMock()
        mc.optimizer = MagicMock()
        mc.optimizer.should_review.return_value = False
        mc.resource_manager = MagicMock()
        mc.resource_manager.get_suggested_concurrency.return_value = 5
        mc.writer = MagicMock()
        
        # Simple mock for async runners - just return values
        mc._run_async_safe = MagicMock()
        mc._run_safe = MagicMock()
        
        return mc

class TestMCIntelligenceIntegration:

    def test_infer_and_emit_attack_chain_emits_once_per_chain_key(self, mock_mc):
        class _FakeChain:
            def __init__(self):
                self.chain_key = "upload_to_rce:file_upload+os_command_injection"

            def to_finding(self):
                return Finding(
                    vuln_type=VulnType.OTHER,
                    severity=Severity.CRITICAL,
                    title="Attack Chain: Upload to RCE",
                    description="upload + command injection chain",
                    target_url="https://example.com/upload",
                    tags=["attack_chain"],
                    additional_info={"is_attack_chain": True},
                )

        base_finding = Finding(
            vuln_type=VulnType.FILE_UPLOAD,
            severity=Severity.HIGH,
            title="Unrestricted file upload",
            description="file upload accepts executable payload",
            target_url="https://example.com/upload",
        )

        mock_mc.chain_builder = MagicMock()
        mock_mc.chain_builder.analyze.return_value = [_FakeChain()]
        mock_mc.handle_finding = MagicMock()

        mock_mc._infer_and_emit_attack_chains(base_finding)
        mock_mc._infer_and_emit_attack_chains(base_finding)

        assert mock_mc.chain_builder.analyze.call_count == 2
        mock_mc.handle_finding.assert_called_once()
        emitted = mock_mc.handle_finding.call_args.args[0]
        assert "attack_chain" in emitted.tags
        assert emitted.additional_info.get("is_attack_chain") is True

    def test_infer_and_emit_attack_chain_tracks_state_version_in_trigger(self, mock_mc):
        class _FakeChain:
            def __init__(self):
                self.chain_key = "upload_to_rce:file_upload+os_command_injection"

            def to_finding(self):
                return Finding(
                    vuln_type=VulnType.OTHER,
                    severity=Severity.CRITICAL,
                    title="Attack Chain: Upload to RCE",
                    description="upload + command injection chain",
                    target_url="https://example.com/upload",
                    tags=["attack_chain"],
                    additional_info={"is_attack_chain": True},
                )

        base_finding = Finding(
            vuln_type=VulnType.FILE_UPLOAD,
            severity=Severity.HIGH,
            title="Unrestricted file upload",
            description="file upload accepts executable payload",
            target_url="https://example.com/upload",
        )

        mock_mc.chain_builder = MagicMock()
        mock_mc.chain_builder.analyze.return_value = [_FakeChain()]
        mock_mc.handle_finding = MagicMock()
        mock_mc.trigger_chain_evaluation = MagicMock(
            side_effect=["actionable_gate", "draft_refresh", "actionable_gate", "noop"]
        )

        mock_mc._infer_and_emit_attack_chains(base_finding)
        mock_mc._infer_and_emit_attack_chains(base_finding)

        assert mock_mc.trigger_chain_evaluation.call_args_list[1].kwargs == {
            "chain_key": "upload_to_rce:file_upload+os_command_injection",
            "state_version": 1,
        }
        assert mock_mc.trigger_chain_evaluation.call_args_list[3].kwargs == {
            "chain_key": "upload_to_rce:file_upload+os_command_injection",
            "state_version": 2,
        }
        mock_mc.handle_finding.assert_called_once()

    def test_infer_and_emit_attack_chain_runs_pre_action_gate_shadow_without_changing_output(self, mock_mc):
        class _FakeChain:
            def __init__(self):
                self.chain_key = "upload_to_rce:file_upload+os_command_injection"

            def to_finding(self):
                return Finding(
                    vuln_type=VulnType.OTHER,
                    severity=Severity.CRITICAL,
                    title="Attack Chain: Upload to RCE",
                    description="upload + command injection chain",
                    target_url="https://example.com/upload",
                    tags=["attack_chain"],
                    additional_info={"is_attack_chain": True},
                )

        base_finding = Finding(
            vuln_type=VulnType.FILE_UPLOAD,
            severity=Severity.HIGH,
            title="Unrestricted file upload",
            description="file upload accepts executable payload",
            target_url="https://example.com/upload",
        )

        mock_mc.chain_builder = MagicMock()
        mock_mc.chain_builder.analyze.return_value = [_FakeChain()]
        mock_mc.handle_finding = MagicMock()
        mock_mc.run_pre_action_gate_shadow = MagicMock(return_value={"trigger_action": "actionable_gate"})

        mock_mc._infer_and_emit_attack_chains(base_finding)

        mock_mc.run_pre_action_gate_shadow.assert_called_once()
        shadow_args = mock_mc.run_pre_action_gate_shadow.call_args.args[0]
        assert shadow_args == [base_finding]
        mock_mc.handle_finding.assert_called_once()

    def test_temporal_chain_audit_record_includes_demotion_context(self):
        conductor = MasterConductor.__new__(MasterConductor)

        class _StubAuditLogger:
            def __init__(self) -> None:
                self.events = []

            def log(self, event):
                self.events.append(event)

        class _StubDecisionTracer:
            def trace(self, **kwargs):
                return type("Trace", (), {"decision_id": "dec_temporal_001"})()

        conductor.audit_logger = _StubAuditLogger()
        conductor.decision_tracer = _StubDecisionTracer()

        record = conductor.emit_chain_audit_record(
            chain={
                "chain_key": "temporal-chain-1",
                "rule_id": "temporal_ato_chain",
                "state": "blocked",
                "previous_state": "actionable",
                "finding_id": "finding-001",
                "excluded_reasons": ["temporal:epoch_mismatch"],
                "session_generation": 8,
                "token_epoch": "epoch-8",
                "csrf_epoch": "epoch-9",
            },
            audit_context={
                "scope_basis": "program_scope_tag",
                "input_fingerprint": "fp-temporal-001",
                "override": False,
                "stop_reason": "temporal:epoch_mismatch",
            },
        )

        assert record["final_state"] == "blocked"
        assert conductor.audit_logger.events
        details = conductor.audit_logger.events[0].details
        assert details.get("reason_code") == "temporal:epoch_mismatch"
        assert details.get("finding_id") == "finding-001"
        assert details.get("previous_state") == "actionable"
        assert details.get("final_state") == "blocked"
        assert details.get("session_generation") == 8
        assert details.get("token_epoch") == "epoch-8"
        assert details.get("csrf_epoch") == "epoch-9"

    def test_pre_action_gate_shadow_reports_temporal_demotion_metrics(self):
        class _TemporalBuilder:
            def analyze_hybrid(self, findings, runtime_context):
                return {
                    "heuristic_chains": [],
                    "draft_candidates": [
                        {
                            "state": "draft",
                            "excluded_reasons": ["temporal:metadata_missing"],
                            "decision_trace": {"feasibility": {"verdict": "draft"}},
                        },
                        {
                            "state": "blocked",
                            "excluded_reasons": ["temporal:epoch_mismatch"],
                            "decision_trace": {"feasibility": {"verdict": "blocked"}},
                        },
                    ],
                    "ai_candidates": [],
                    "proposal_skip_reason": None,
                }

        mc = MasterConductor.__new__(MasterConductor)
        mc.chain_builder = _TemporalBuilder()
        mc._chain_shadow_reports = []

        report = mc.run_pre_action_gate_shadow(
            [
                Finding(
                    vuln_type=VulnType.XSS,
                    severity=Severity.HIGH,
                    title="Temporal test finding",
                    description="Temporal test finding",
                    target_url="https://example.com/account",
                )
            ],
            runtime_context={
                "mode": "shadow",
                "missing_temporal_metadata_threshold": 0.25,
            },
        )

        assert report.get("draft_demotion_count") == 1
        assert report.get("blocked_demotion_count") == 1
        assert report.get("missing_temporal_metadata_ratio") == pytest.approx(0.5)
        assert report.get("missing_temporal_metadata_threshold_exceeded") is True
        assert report.get("temporal_reason_counts", {}).get("temporal:metadata_missing") == 1
        assert report.get("temporal_reason_counts", {}).get("temporal:epoch_mismatch") == 1

    def test_trigger_chain_evaluation_rejects_stale_state_versions(self):
        conductor = MasterConductor.__new__(MasterConductor)

        first = conductor.trigger_chain_evaluation(
            "finding_added",
            chain_key="temporal-chain-1",
            state_version=2,
        )
        stale = conductor.trigger_chain_evaluation(
            "finding_added",
            chain_key="temporal-chain-1",
            state_version=1,
        )

        assert first == "draft_refresh"
        assert stale == "noop"

    def test_task_prioritizer_selects_and_removes_from_queue(self, mock_mc):
        t1 = Task(id="t1", name="low", agent_type="recon")
        t2 = Task(id="t2", name="high", agent_type="injection")

        mock_prioritizer = MagicMock()
        mock_prioritizer.select_task.return_value = t2

        mock_mc.task_queue.get_all.return_value = [t1, t2]
        mock_mc.task_queue.remove_by_id.return_value = True
        mock_mc.task_prioritizer = mock_prioritizer

        selected = mock_mc._select_next_task_from_queue()

        assert selected.id == "t2"
        mock_prioritizer.select_task.assert_called_once_with([t1, t2])
        mock_mc.task_queue.remove_by_id.assert_called_once_with("t2")

    def test_task_prioritizer_fallbacks_to_pop_on_error(self, mock_mc):
        fallback_task = Task(id="fallback", name="fallback", agent_type="recon")
        mock_prioritizer = MagicMock()
        mock_prioritizer.select_task.side_effect = RuntimeError("boom")

        mock_mc.task_queue.get_all.return_value = [fallback_task]
        mock_mc.task_queue.pop.return_value = fallback_task
        mock_mc.task_prioritizer = mock_prioritizer

        selected = mock_mc._select_next_task_from_queue()

        assert selected.id == "fallback"
        mock_mc.task_queue.pop.assert_called_once()

    def test_risk_predictor_block(self, mock_mc):
        """テスト1: RiskPredictor が CRITICAL リスクのタスクをブロックすることを検証"""
        task = Task(id="t1", name="exploit", agent_type="exploit")
        
        # RiskPredictor がブロックする設定
        mock_mc.risk_predictor.assess.return_value = RiskAssessment(
            risk_level=RiskLevel.CRITICAL,
            risk_score=0.9,
            detection_probability=0.8,
            recommended_delay=0
        )
        
        result = mock_mc._execute_single_task_full_flow(task)
        
        assert result["success"] is False
        assert "Blocked by RiskPredictor" in result["error"]
        assert task.state == TaskState.FAILED
        mock_mc.risk_predictor.assess.assert_called_once()

    def test_error_analyzer_retry_and_wait(self, mock_mc):
        """テスト2: ErrorAnalyzer が 429 を検知して待機時間を推奨することを検証"""
        task = Task(id="t2", name="scan", agent_type="scanner")
        
        # Dispatch 戻り値を直接設定
        mock_mc._run_async_safe.return_value = {
            "success": False, 
            "error": "429 Too Many Requests", 
            "data": {"status_code": 429}
        }
        mock_mc.replan = MagicMock(return_value=[])
        
        # RiskPredictor はパスさせる
        mock_mc.risk_predictor.assess.return_value = RiskAssessment(
            risk_level=RiskLevel.LOW,
            risk_score=0.1,
            detection_probability=0.1,
            recommended_delay=0
        )
        
        # ErrorAnalyzer の戻り値設定
        mock_analysis = RootCauseAnalysis(
            category=ErrorCategory.RATE_LIMITED,
            likely_cause="Rate limited",
            confidence=0.9,
            mitigation="Wait",
            retry_recommended=True,
            wait_seconds=0.1
        )
        mock_mc.error_analyzer.analyze.return_value = mock_analysis
        
        with patch("time.sleep") as mock_sleep:
            mock_mc._execute_single_task_full_flow(task)
            
            # 待機が適用されたか (HOOK 3 の直後)
            mock_sleep.assert_any_call(0.1)
            mock_mc.error_analyzer.analyze.assert_called_once()
            mock_mc.replan.assert_called_once()
            args, kwargs = mock_mc.replan.call_args
            assert kwargs.get("root_cause") == mock_analysis

    def test_self_reflection_periodic_insight(self, mock_mc):
        """テスト3: 定期省察が実行されることを検証"""
        mock_task = Task(id="t_ref", name="t_ref")
        mock_mc.task_prioritizer = None
        mock_mc.task_queue.peek.return_value = mock_task
        mock_mc.task_queue.empty.side_effect = [False, False, True]
        mock_mc.task_queue.is_empty.side_effect = [False, True, True]
        mock_mc.task_queue.pop.return_value = mock_task
        
        from src.core.engine.parallel_orchestrator import TaskResult
        mock_mc.orchestrator.execute_parallel.return_value = [
            TaskResult(task_id="t_ref", success=True, result={"success": True})
        ]
        mock_mc._run_async_safe.return_value = mock_mc.orchestrator.execute_parallel.return_value
        
        # インサイト設定
        mock_mc.self_reflection.reflect.return_value = [
            ReflectionInsight(insight="Pattern detected", suggested_action="None", confidence=0.8, actionable=True, category="improvement")
        ]
        
        with patch("src.core.engine.master_conductor_facade.settings") as mock_settings:
            mock_settings.reflection_interval = 1
            
            # 2回ループさせる設定
            mock_mc.execute_with_replan(max_tasks=2)
            
            mock_mc.self_reflection.reflect.assert_called()

    def test_priority_booster_auto_boost(self, mock_mc):
        """テスト4: PriorityBooster による優先度調整を検証"""
        task = Task(id="t4", name="crawl", agent_type="discovery")
        mock_mc._run_async_safe.return_value = {
            "success": True, 
            "output": "Found admin panel",
            "findings": []
        }
        
        mock_mc.risk_predictor.assess.return_value = RiskAssessment(risk_level=RiskLevel.LOW, risk_score=0.1, detection_probability=0.1, recommended_delay=0)
        
        mock_event = BoostEvent(
            trigger=BoostTrigger.HIGH_VALUE_ASSET,
            target="admin",
            boost_amount=0.3,
            reason="Admin found",
            related_tasks=["task_auth"]
        )
        mock_mc.priority_booster.auto_detect_boost.return_value = mock_event
        mock_mc.task_queue.get_pending_task_ids.return_value = ["task_auth"]
        
        mock_mc._execute_single_task_full_flow(task)
        
        mock_mc.priority_booster.boost_on_discovery.assert_called_once()
        mock_mc.task_queue.boost_priority.assert_called()

    def test_intelligence_failure_graceful_degradation(self, mock_mc):
        """テスト5: Intelligence が失敗してもタスク実行が成功することを検証"""
        task = Task(id="t5", name="recon", agent_type="recon")
        mock_mc._run_async_safe.return_value = {"success": True}
        
        # Exception throwing
        mock_mc.risk_predictor.assess.side_effect = Exception("Intelligence Error")
        
        # 実行
        result = mock_mc._execute_single_task_full_flow(task)
        
        assert result["success"] is True
        assert task.state == TaskState.SUCCESS
