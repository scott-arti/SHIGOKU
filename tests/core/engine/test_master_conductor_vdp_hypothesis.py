"""
SGK-2026-0420: MasterConductor VDP integration tests.

Covers the VDP hypothesis generation hook and its MasterConductor wiring:
- direct hook invocation (``_generate_vdp_hypotheses``) with
  record_only / shadow modes,
- state replacement on repeated runs (success → empty / all-rejected /
  exception),
- unavailable-observation-source recording for empty signal bundles,
- the REAL production recon connection point (``_dispatch`` with a
  recon_master task) followed by ``async_save_session`` and the M0 gate,
- zero network / zero LLM calls and unchanged task queue / findings.

All tests use ``object.__new__(MasterConductor)`` to remain compatible
with existing ``__new__``-based test suites.
"""
from __future__ import annotations

import time
import socket
from types import SimpleNamespace

import pytest

from src.core.engine.master_conductor import MasterConductor
from src.core.engine.master_conductor_session_service import (
    build_async_session_payload,
    inject_vdp_section_to_session_payload,
)
from src.core.engine.vdp_m0_gate import VdpM0ContractGate, M0GateResult
from src.core.models.vdp_contract import HypothesisRecord, EvidenceVerdictV1
from src.core.domain.model.task import Task
from src.core.engine.phase_gate import Phase


def _new_mc(**overrides) -> MasterConductor:
    """Build a minimal MC with ``__new__`` (existing test pattern)."""
    mc = object.__new__(MasterConductor)
    mc.project_manager = SimpleNamespace(
        project_dir="/tmp/shigoku-vdp-integ-test",
        save_session=_async_noop,
    )
    mc.task_queue = []
    mc.completed_tasks = []
    mc.pending_hitl = []
    mc._vdp_state = {
        "vdp_active": False,
        "hypotheses": [],
        "attempts": [],
        "evidence_records": [],
        "verdicts": [],
        "next_actions": [],
        "budget_snapshot": {},
        "run_health": {},
    }
    mc._current_session = SimpleNamespace(session_id="test-int")
    mc.run_ledger_recorder = SimpleNamespace(
        prepare_for_session=lambda spool_dir=None: {},
        run_id="test-run",
    )
    mc.decision_tracer = None
    mc.execution_log = SimpleNamespace(to_list=lambda: [])
    mc.context = SimpleNamespace(
        _total_attempts=0, _successful_attempts=0,
        bypass_methods=[], discovered_assets=[],
        target_info={"start_time": time.time()},
    )
    mc._ensure_task_reason_code = lambda task: None
    mc._evaluate_vuln_family_coverage = lambda: {}
    mc._evaluate_intervention_scenario_coverage = lambda: {}
    for key, value in overrides.items():
        setattr(mc, key, value)
    return mc


async def _async_noop(*args, **kwargs):
    pass


def _make_signal_bundle() -> dict:
    """Minimal recon signal bundle with one endpoint."""
    return {
        "_endpoint_signals": [
            {
                "signal_id": "test-uuid:tagged_auth:https://example.com/api",
                "entity_type": "endpoint",
                "url": "https://example.com/api/login",
                "method": "POST",
                "primary_label": "login",
                "candidate_labels": ["auth"],
                "confidence": 0.95,
                "source_observations": ["recon"],
                "auth_required": True,
                "auth_context": {"authorization": "Bearer test-token"},
                "subdomain_context": None,
                "interaction_kind": "static",
                "lineage": "tagged_auth",
                "params": [{"name": "username", "location": "form"}],
                "status": "active",
                "seen_count": 1,
                "created_at": "2026-08-02T12:00:00Z",
            }
        ]
    }


# ============================================================================
# Integration tests
# ============================================================================


class TestVdpHookOffMode:
    """vdp.mode=off → hook returns immediately, no state changes."""

    def test_off_mode_no_vdp_activation(self, monkeypatch):
        from types import SimpleNamespace as SN
        mc = _new_mc()
        mc._vdp_mode = SN(mode='off', label_leakage_denylist=[])

        mc._generate_vdp_hypotheses({'_signal_bundle': _make_signal_bundle()})

        assert mc._vdp_state['vdp_active'] is False
        assert mc._vdp_state['hypotheses'] == []
        assert mc.task_queue == []

    def test_off_mode_task_queue_unchanged(self, monkeypatch):
        from types import SimpleNamespace as SN
        mc = _new_mc()
        mc._vdp_mode = SN(mode='off', label_leakage_denylist=[])
        original_queue_len = len(list(mc.task_queue))

        mc._generate_vdp_hypotheses({'_signal_bundle': _make_signal_bundle()})

        assert len(list(mc.task_queue)) == original_queue_len

    def test_off_mode_no_shadow_decisions(self, monkeypatch):
        from types import SimpleNamespace as SN
        mc = _new_mc()
        mc._vdp_mode = SN(mode='off', label_leakage_denylist=[])

        mc._generate_vdp_hypotheses({'_signal_bundle': _make_signal_bundle()})

        assert not hasattr(mc, '_shadow_decisions')


class TestVdpHookRecordOnly:
    """vdp.mode=record_only → hypotheses stored, queue untouched."""

    def test_hypotheses_generated(self, monkeypatch):
        from types import SimpleNamespace as SN
        mc = _new_mc()
        mc._vdp_mode = SN(mode='record_only', label_leakage_denylist=[])

        mc._generate_vdp_hypotheses({'_signal_bundle': _make_signal_bundle()})

        assert mc._vdp_state['vdp_active'] is True
        assert len(mc._vdp_state['hypotheses']) > 0

    def test_hypothesis_has_required_fields(self, monkeypatch):
        from types import SimpleNamespace as SN
        mc = _new_mc()
        mc._vdp_mode = SN(mode='record_only', label_leakage_denylist=[])

        mc._generate_vdp_hypotheses({'_signal_bundle': _make_signal_bundle()})

        hyp_dict = mc._vdp_state['hypotheses'][0]
        assert hyp_dict.get('hypothesis_id') is not None
        assert hyp_dict.get('capability') is not None
        assert hyp_dict.get('dedup_key') is not None
        assert hyp_dict.get('generator_version') is not None

    def test_no_verdicts_in_record_only(self, monkeypatch):
        from types import SimpleNamespace as SN
        mc = _new_mc()
        mc._vdp_mode = SN(mode='record_only', label_leakage_denylist=[])

        mc._generate_vdp_hypotheses({'_signal_bundle': _make_signal_bundle()})

        assert mc._vdp_state.get('verdicts', []) == []
        assert mc._vdp_state.get('next_actions', []) == []

    def test_task_queue_unchanged(self, monkeypatch):
        from types import SimpleNamespace as SN
        mc = _new_mc()
        mc._vdp_mode = SN(mode='record_only', label_leakage_denylist=[])
        original_queue_len = 0

        mc._generate_vdp_hypotheses({'_signal_bundle': _make_signal_bundle()})

        assert len(list(mc.task_queue)) == original_queue_len

    def test_empty_signal_bundle_degrades_gracefully(self, monkeypatch):
        from types import SimpleNamespace as SN
        mc = _new_mc()
        mc._vdp_mode = SN(mode='record_only', label_leakage_denylist=[])

        mc._generate_vdp_hypotheses({'_signal_bundle': {}})

        assert mc._vdp_state['vdp_active'] is False
        assert mc._vdp_state['hypotheses'] == []


class TestVdpHookShadowMode:
    """vdp.mode=shadow → hypotheses + candidate verdicts stored."""

    def test_verdicts_and_next_actions_stored(self, monkeypatch):
        from types import SimpleNamespace as SN
        mc = _new_mc()
        mc._vdp_mode = SN(mode='shadow', label_leakage_denylist=[])

        mc._generate_vdp_hypotheses({'_signal_bundle': _make_signal_bundle()})

        assert mc._vdp_state['vdp_active'] is True
        assert len(mc._vdp_state['hypotheses']) > 0
        assert len(mc._vdp_state['verdicts']) > 0
        assert len(mc._vdp_state['next_actions']) > 0

    def test_verdict_is_candidate_not_confirmed(self, monkeypatch):
        from types import SimpleNamespace as SN
        mc = _new_mc()
        mc._vdp_mode = SN(mode='shadow', label_leakage_denylist=[])

        mc._generate_vdp_hypotheses({'_signal_bundle': _make_signal_bundle()})

        for verdict in mc._vdp_state['verdicts']:
            assert verdict['status'] == 'candidate'

    def test_task_queue_unchanged(self, monkeypatch):
        from types import SimpleNamespace as SN
        mc = _new_mc()
        mc._vdp_mode = SN(mode='shadow', label_leakage_denylist=[])

        mc._generate_vdp_hypotheses({'_signal_bundle': _make_signal_bundle()})

        assert len(list(mc.task_queue)) == 0


class TestM0GateIntegration:
    """M0 gate passes/fails correctly with VDP state."""

    def test_m0_passes_with_valid_hypotheses(self, monkeypatch):
        from types import SimpleNamespace as SN
        mc = _new_mc()
        mc._vdp_mode = SN(mode='record_only', label_leakage_denylist=[])

        mc._generate_vdp_hypotheses({'_signal_bundle': _make_signal_bundle()})
        assert mc._vdp_state['vdp_active'] is True

        timestamp = time.time()
        payload = build_async_session_payload(
            task_queue=mc.task_queue, completed_tasks=mc.completed_tasks,
            context=mc.context, pending_hitl=mc.pending_hitl,
            coverage_gate={}, scenario_coverage={},
            timestamp=timestamp, default_start_time=timestamp - 3600.0,
        )
        injected = inject_vdp_section_to_session_payload(payload, mc._vdp_state)
        result = VdpM0ContractGate().validate(injected)
        assert result.passed, f"M0 gate failed: {result.detail}"

    def test_m0_passes_with_zero_hypotheses_inactive(self, monkeypatch):
        """vdp_active=False + 0 hypotheses → M0 gate passes (clean session)."""
        mc = _new_mc()
        mc._vdp_state['vdp_active'] = False
        mc._vdp_state['hypotheses'] = []

        timestamp = time.time()
        payload = build_async_session_payload(
            task_queue=[], completed_tasks=[], context=mc.context,
            pending_hitl=[], coverage_gate={}, scenario_coverage={},
            timestamp=timestamp, default_start_time=timestamp - 3600.0,
        )
        injected = inject_vdp_section_to_session_payload(payload, mc._vdp_state)
        result = VdpM0ContractGate().validate(injected)
        assert result.passed


class TestNoNetworkIO:
    """VDP hook must cause zero network I/O."""

    def test_vdp_hook_zero_network(self, monkeypatch):
        from types import SimpleNamespace as SN
        call_count = [0]
        original_connect = socket.socket.connect

        def counting_connect(self_conn, *args, **kwargs):
            call_count[0] += 1
            return original_connect(self_conn, *args, **kwargs)

        monkeypatch.setattr(socket.socket, "connect", counting_connect)

        mc = _new_mc()
        mc._vdp_mode = SN(mode='shadow', label_leakage_denylist=[])

        mc._generate_vdp_hypotheses({'_signal_bundle': _make_signal_bundle()})

        assert call_count[0] == 0, (
            f"VDP hook caused {call_count[0]} socket connections, expected 0"
        )


class TestNoLLMCalls:
    """VDP hook must not invoke LLMClient."""

    def test_vdp_hook_zero_llm_calls(self, monkeypatch):
        from types import SimpleNamespace as SN
        # Patch LLMClient to raise if instantiated
        import src.core.models.llm as llm_module
        original_init = llm_module.LLMClient.__init__

        def forbid_init(self_llm, *args, **kwargs):
            raise RuntimeError("LLMClient was instantiated during VDP hook")

        monkeypatch.setattr(llm_module.LLMClient, "__init__", forbid_init)

        mc = _new_mc()
        mc._vdp_mode = SN(mode='shadow', label_leakage_denylist=[])

        # Must not raise
        mc._generate_vdp_hypotheses({'_signal_bundle': _make_signal_bundle()})

        # Restore
        monkeypatch.undo()
        # Verify hypotheses were still generated
        assert len(mc._vdp_state['hypotheses']) > 0


class TestIdempotency:
    """Same hook called twice → no duplicate records, same output."""

    def test_same_hook_twice_no_duplicates(self, monkeypatch):
        from types import SimpleNamespace as SN
        mc = _new_mc()
        mc._vdp_mode = SN(mode='record_only', label_leakage_denylist=[])

        mc._generate_vdp_hypotheses({'_signal_bundle': _make_signal_bundle()})
        count1 = len(mc._vdp_state['hypotheses'])

        # Run again with same input — should not append duplicates
        mc._generate_vdp_hypotheses({'_signal_bundle': _make_signal_bundle()})
        count2 = len(mc._vdp_state['hypotheses'])

        assert count2 == count1, "Duplicate hypotheses should not be appended"

    def test_deterministic_across_runs(self, monkeypatch):
        from types import SimpleNamespace as SN
        mc1 = _new_mc()
        mc1._vdp_mode = SN(mode='record_only', label_leakage_denylist=[])
        mc1._generate_vdp_hypotheses({'_signal_bundle': _make_signal_bundle()})

        mc2 = _new_mc()
        mc2._vdp_mode = SN(mode='record_only', label_leakage_denylist=[])
        mc2._generate_vdp_hypotheses({'_signal_bundle': _make_signal_bundle()})

        ids1 = [h['hypothesis_id'] for h in mc1._vdp_state['hypotheses']]
        ids2 = [h['hypothesis_id'] for h in mc2._vdp_state['hypotheses']]
        assert ids1 == ids2, "Deterministic IDs must match across independent MC instances"


class TestMcNewCompatibility:
    """MC.__new__ tests must continue to work (hasattr guards)."""

    def test_hasattr_guards_prevent_attribute_error(self):
        """Lazy-init attributes must not raise on __new__-constructed MC."""
        mc = _new_mc()
        # Access VDP-related attributes — must not raise
        assert hasattr(mc, '_vdp_state')
        # _vdp_mode and _shadow_decisions are lazy-init;
        # they must not cause AttributeError on direct access by other MC code
        mc._ensure_vdp_mode_loaded()
        # after _ensure_vdp_mode_loaded, _vdp_mode is set (may be SimpleNamespace)
        assert mc._vdp_mode is not None
        assert mc._vdp_mode.mode == 'off'  # default from fallback


class TestVdpStateReplacement:
    """I-03: every non-off run replaces VDP state; stale records never survive."""

    @staticmethod
    def _assert_m0_passes(mc):
        timestamp = time.time()
        payload = build_async_session_payload(
            task_queue=mc.task_queue, completed_tasks=mc.completed_tasks,
            context=mc.context, pending_hitl=mc.pending_hitl,
            coverage_gate={}, scenario_coverage={},
            timestamp=timestamp, default_start_time=timestamp - 3600.0,
        )
        injected = inject_vdp_section_to_session_payload(payload, mc._vdp_state)
        result = VdpM0ContractGate().validate(injected)
        assert result.passed, f"M0 gate failed after state replacement: {result.detail}"

    def test_success_then_empty_replaces_state(self):
        from types import SimpleNamespace as SN
        mc = _new_mc()
        mc._vdp_mode = SN(mode='record_only', label_leakage_denylist=[])
        mc._generate_vdp_hypotheses({'_signal_bundle': _make_signal_bundle()})
        assert mc._vdp_state['vdp_active'] is True
        assert len(mc._vdp_state['hypotheses']) > 0
        self._assert_m0_passes(mc)

        # Second run with EMPTY bundle — previous records must be REPLACED.
        mc._generate_vdp_hypotheses({'_signal_bundle': {}})
        assert mc._vdp_state['vdp_active'] is False
        assert mc._vdp_state['hypotheses'] == []
        assert mc._vdp_state['verdicts'] == []
        assert mc._vdp_state['next_actions'] == []
        self._assert_m0_passes(mc)

    def test_success_then_all_rejected_replaces_state(self):
        from types import SimpleNamespace as SN
        mc = _new_mc()
        mc._vdp_mode = SN(mode='record_only', label_leakage_denylist=[])
        mc._generate_vdp_hypotheses({'_signal_bundle': _make_signal_bundle()})
        assert mc._vdp_state['vdp_active'] is True

        # Second run where every observation is rejected (leakage) → REPLACE.
        leak_bundle = {
            '_endpoint_signals': [
                {
                    'signal_id': 'x:y:https://example.com',
                    'entity_type': 'endpoint',
                    'url': 'https://example.com/flag{leak}',
                    'method': 'GET',
                    'primary_label': 'flag{leak}',
                    'candidate_labels': ['flag{leak}'],
                    'auth_context': {},
                    'params': [],
                }
            ]
        }
        mc._generate_vdp_hypotheses({'_signal_bundle': leak_bundle})
        assert mc._vdp_state['vdp_active'] is False
        assert mc._vdp_state['hypotheses'] == []
        self._assert_m0_passes(mc)

    def test_success_then_exception_replaces_state(self, monkeypatch):
        from types import SimpleNamespace as SN
        import src.core.engine.vdp_hypothesis_generator as gen_mod
        mc = _new_mc()
        mc._vdp_mode = SN(mode='record_only', label_leakage_denylist=[])
        mc._generate_vdp_hypotheses({'_signal_bundle': _make_signal_bundle()})
        assert mc._vdp_state['vdp_active'] is True

        # Third run: generator raises → hook must swallow, reset state, continue.
        def _boom(*args, **kwargs):
            raise RuntimeError('injected failure')

        monkeypatch.setattr(gen_mod, 'generate_hypotheses', _boom)
        mc._generate_vdp_hypotheses({'_signal_bundle': _make_signal_bundle()})
        monkeypatch.undo()

        assert mc._vdp_state['vdp_active'] is False
        assert mc._vdp_state['hypotheses'] == []
        assert mc._vdp_state['verdicts'] == []
        assert mc._vdp_state['next_actions'] == []
        # degraded reason must be recorded in decision trace
        assert hasattr(mc, '_shadow_decisions')
        reasons = [d for d in mc._shadow_decisions if d.get('scope') == 'vdp_hypothesis_generation']
        assert any('generator_exception' in str(d.get('reason', '')) for d in reasons)
        self._assert_m0_passes(mc)


class TestRealSavePathIntegration:
    """I-08: real hook → real async_save_session() → M0 gate on the SAVED payload."""

    async def test_hook_then_real_save_then_m0(self, tmp_path):
        from types import SimpleNamespace as SN
        from src.core.engine.vdp_m0_gate import VdpM0ContractGate
        import asyncio

        saved_payload = {}
        captured = {}

        async def _capture_save(payload, filename=None):
            captured['payload'] = payload
            captured['filename'] = filename

        mc = _new_mc()
        mc.project_manager = SN(
            project_dir=str(tmp_path),
            save_session=_capture_save,
        )
        mc._vdp_mode = SN(mode='record_only', label_leakage_denylist=[])

        # 1. Run the real hook.
        mc._generate_vdp_hypotheses({'_signal_bundle': _make_signal_bundle()})
        assert mc._vdp_state['vdp_active'] is True
        assert len(mc._vdp_state['hypotheses']) > 0

        # 2. Save through the REAL async_save_session path (M0 gate inside).
        await mc.async_save_session('real_save_test.json')

        # 3. Verify the save actually happened and M0 passes on the saved payload.
        assert 'payload' in captured, 'project_manager.save_session was not called'
        saved = captured['payload']
        vdp_section = saved.get('vdp_contract', {})
        assert vdp_section.get('vdp_active') is True
        assert len(vdp_section.get('hypotheses', [])) > 0
        result = VdpM0ContractGate().validate(saved)
        assert result.passed, f"M0 gate failed on saved session: {result.detail}"
        assert captured['filename'] == 'real_save_test.json'

    async def test_real_save_after_empty_replacement_passes_m0(self, tmp_path):
        """After success→empty replacement, the real save must also pass M0."""
        from types import SimpleNamespace as SN
        from src.core.engine.vdp_m0_gate import VdpM0ContractGate

        captured = {}

        async def _capture_save(payload, filename=None):
            captured['payload'] = payload

        mc = _new_mc()
        mc.project_manager = SN(project_dir=str(tmp_path), save_session=_capture_save)
        mc._vdp_mode = SN(mode='record_only', label_leakage_denylist=[])

        mc._generate_vdp_hypotheses({'_signal_bundle': _make_signal_bundle()})
        mc._generate_vdp_hypotheses({'_signal_bundle': {}})

        await mc.async_save_session('empty_save_test.json')

        saved = captured.get('payload', {})
        vdp_section = saved.get('vdp_contract', {})
        assert vdp_section.get('vdp_active') is False
        assert vdp_section.get('hypotheses') == []
        result = VdpM0ContractGate().validate(saved)
        assert result.passed, f"M0 gate failed on empty-replaced session: {result.detail}"

    async def test_real_save_zero_network_and_llm(self, tmp_path, monkeypatch):
        """Real save path must cause zero network and zero LLM calls."""
        from types import SimpleNamespace as SN
        from src.core.engine.vdp_m0_gate import VdpM0ContractGate

        captured = {}

        async def _capture_save(payload, filename=None):
            captured['payload'] = payload

        socket_call_count = [0]
        original_connect = socket.socket.connect

        def counting_connect(self_conn, *args, **kwargs):
            socket_call_count[0] += 1
            return original_connect(self_conn, *args, **kwargs)

        monkeypatch.setattr(socket.socket, "connect", counting_connect)

        import src.core.models.llm as llm_module

        def forbid_init(self_llm, *args, **kwargs):
            raise RuntimeError("LLMClient instantiated during real save path")

        monkeypatch.setattr(llm_module.LLMClient, "__init__", forbid_init)

        mc = _new_mc()
        mc.project_manager = SN(project_dir=str(tmp_path), save_session=_capture_save)
        mc._vdp_mode = SN(mode='record_only', label_leakage_denylist=[])

        mc._generate_vdp_hypotheses({'_signal_bundle': _make_signal_bundle()})
        await mc.async_save_session('no_network_test.json')

        monkeypatch.undo()
        assert socket_call_count[0] == 0, f"Real save path opened {socket_call_count[0]} sockets"
        result = VdpM0ContractGate().validate(captured['payload'])
        assert result.passed


class TestUnavailableSourceRecording:
    """I-03b: 観測0件（空signal bundle / 空_endpoint_signals）でも
    未接続観測源のunavailable記録をdecision traceへ保存する。

    SGK-2026-0421: form源は既存signal bundleの location=="form" から
    接続済みのため、unavailable inventoryは6源（crawler/javascript/
    api_schema/graphql/browser_traffic/proxy_history）となる。"""

    @staticmethod
    def _assert_m0_passes(mc):
        timestamp = time.time()
        payload = build_async_session_payload(
            task_queue=mc.task_queue, completed_tasks=mc.completed_tasks,
            context=mc.context, pending_hitl=mc.pending_hitl,
            coverage_gate={}, scenario_coverage={},
            timestamp=timestamp, default_start_time=timestamp - 3600.0,
        )
        injected = inject_vdp_section_to_session_payload(payload, mc._vdp_state)
        result = VdpM0ContractGate().validate(injected)
        assert result.passed, f"M0 gate failed: {result.detail}"

    @staticmethod
    def _assert_7_sources_recorded(mc, expected_degraded_reason):
        assert hasattr(mc, '_shadow_decisions')
        traces = [d for d in mc._shadow_decisions if d.get('scope') == 'vdp_observation_sources']
        assert traces, "vdp_observation_sources trace missing"
        sources = traces[-1].get('sources_unavailable', [])
        assert len(sources) == 6, f"expected 6 sources, got {len(sources)}"
        expected_reasons = {
            "crawler": "producer_requires_new_crawl",
            "javascript": "producer_requires_new_crawl",
            "api_schema": "producer_not_found",
            "graphql": "producer_not_found",
            "browser_traffic": "no_passive_artifact",
            "proxy_history": "no_passive_artifact",
        }
        for src in sources:
            assert src['status'] == 'unavailable', src
            assert src['reason'] == expected_reasons[src['source']], src
            assert src['tracking_task'] == 'SGK-2026-0423', src
        degraded = [d for d in mc._shadow_decisions if d.get('scope') == 'vdp_hypothesis_generation']
        assert degraded, "degraded trace missing"
        assert any(expected_degraded_reason in str(d.get('reason', '')) for d in degraded)

    def test_empty_signal_bundle_records_unavailable(self):
        from types import SimpleNamespace as SN
        mc = _new_mc()
        mc._vdp_mode = SN(mode='record_only', label_leakage_denylist=[])
        mc._generate_vdp_hypotheses({'_signal_bundle': {}})
        self._assert_7_sources_recorded(mc, 'no_signal_bundle')
        assert mc._vdp_state['vdp_active'] is False
        assert mc._vdp_state['run_health'] == {}
        assert mc._vdp_state['hypotheses'] == []
        self._assert_m0_passes(mc)

    def test_missing_signal_bundle_key_records_unavailable(self):
        from types import SimpleNamespace as SN
        mc = _new_mc()
        mc._vdp_mode = SN(mode='record_only', label_leakage_denylist=[])
        mc._generate_vdp_hypotheses({})
        self._assert_7_sources_recorded(mc, 'no_signal_bundle')
        assert mc._vdp_state['vdp_active'] is False
        assert mc._vdp_state['run_health'] == {}
        self._assert_m0_passes(mc)

    def test_empty_endpoint_signals_records_unavailable(self):
        from types import SimpleNamespace as SN
        mc = _new_mc()
        mc._vdp_mode = SN(mode='record_only', label_leakage_denylist=[])
        mc._generate_vdp_hypotheses({'_signal_bundle': {'_endpoint_signals': []}})
        self._assert_7_sources_recorded(mc, 'no_observations')
        assert mc._vdp_state['vdp_active'] is False
        assert mc._vdp_state['run_health'] == {}
        assert mc._vdp_state['hypotheses'] == []
        self._assert_m0_passes(mc)


class TestRealDispatchConnection:
    """I-08: 実際のrun接続点（_dispatch + recon_master task）→ 本番hook →
    async_save_session → M0 gate を一本で検証する。"""

    def _make_recon_task(self, target: str = "https://example.com") -> Task:
        return Task(
            id="recon-dispatch-1",
            name="recon",
            agent_type="recon_master",
            action="recon",
            phase=Phase.RECON,
            params={"target": target},
            target=target,
        )

    async def _dispatch_recon(self, mc, monkeypatch, fake_state):
        import src.recon.pipeline as recon_pipeline_module
        from types import SimpleNamespace as SN

        async def _fake_run(self_pl, target, start_step=1, end_step=8):
            return fake_state

        monkeypatch.setattr(recon_pipeline_module.ReconPipeline, "run", _fake_run)
        task = self._make_recon_task()
        return await mc._dispatch(task)

    async def test_recon_dispatch_invokes_production_hook_and_saves(self, tmp_path, monkeypatch):
        from types import SimpleNamespace as SN
        from unittest.mock import AsyncMock

        captured = {}

        async def _capture_save(payload, filename=None):
            captured['payload'] = payload
            captured['filename'] = filename

        mc = _new_mc()
        mc.project_manager = SN(project_dir=str(tmp_path), save_session=_capture_save)
        # mode: vulntest にすることで bugbounty bundle gate / ctf filter を回避
        mc.context.target_info = {
            "target": "https://example.com",
            "in_scope_domains": ["example.com"],
            "mode": "vulntest",
            "start_time": time.time(),
        }
        mc.workspace = None
        mc.accumulated_context = None
        mc.llm_client = None
        mc.network_client = None
        mc._import_recon_bundle = None
        mc._import_recon_dir = None
        mc._vdp_mode = SN(mode='record_only', label_leakage_denylist=[])

        def _locked_can_create(*args, **kwargs):
            return (False, "test-locked")

        mc.phase_gate = SN(
            add_asset=lambda *a, **k: None,
            add_tech=lambda *a, **k: None,
            set_classified_files=lambda *a, **k: None,
            unlock=lambda *a, **k: None,
            can_create_task=_locked_can_create,
        )

        # worker factory: recon_master 用workerは無いため None を返す stub
        monkeypatch.setattr(
            "src.core.swarm.worker.factory.get_worker_factory",
            lambda *a, **k: SN(create_worker=lambda agent_type: None),
        )

        # 本番hookをspy（mockしない）
        hook_calls = []
        real_hook = mc._generate_vdp_hypotheses

        def _spy_hook(merged_results, **kwargs):
            hook_calls.append(kwargs)
            return real_hook(merged_results, **kwargs)

        mc._generate_vdp_hypotheses = _spy_hook

        # network / LLM カウント
        socket_count = [0]
        original_connect = socket.socket.connect

        def _counting_connect(self_conn, *args, **kwargs):
            socket_count[0] += 1
            return original_connect(self_conn, *args, **kwargs)

        monkeypatch.setattr(socket.socket, "connect", _counting_connect)
        import src.core.models.llm as llm_module

        def _forbid_init(self_llm, *args, **kwargs):
            raise RuntimeError("LLMClient instantiated during recon dispatch")

        monkeypatch.setattr(llm_module.LLMClient, "__init__", _forbid_init)

        # recon 実行結果（fake state）だけをmock
        fake_state = SN(
            live_subs=[],
            tech_stack=[],
            results={"_signal_bundle": _make_signal_bundle()},
            current_step=8,
            screenshots_count=0,
        )

        queue_before = list(mc.task_queue)
        findings_before = list(mc.completed_tasks)

        result = await self._dispatch_recon(mc, monkeypatch, fake_state)

        assert result.get("success") is True, result
        assert len(hook_calls) == 1, f"production hook must be called exactly once, got {len(hook_calls)}"
        scope_snapshot = hook_calls[0].get("scope_definition")
        assert scope_snapshot is not None
        assert scope_snapshot.in_scope_domains == ["example.com"]
        assert mc._vdp_state['vdp_active'] is True
        assert len(mc._vdp_state['hypotheses']) > 0

        # 実際のasync_save_session()を通す（本番hook実行後に保存）
        await mc.async_save_session('recon_dispatch_save.json')

        assert 'payload' in captured, "project_manager.save_session was not called"
        saved = captured['payload']
        vdp_section = saved.get('vdp_contract', {})
        assert vdp_section.get('vdp_active') is True
        assert len(vdp_section.get('hypotheses', [])) > 0
        result_gate = VdpM0ContractGate().validate(saved)
        assert result_gate.passed, f"M0 gate failed on saved session: {result_gate.detail}"
        assert captured.get('filename') == 'recon_dispatch_save.json'

        # task queue / finding / network / LLM 不変
        assert list(mc.task_queue) == queue_before
        assert list(mc.completed_tasks) == findings_before
        assert socket_count[0] == 0, f"recon dispatch opened {socket_count[0]} sockets"
