from src.config import settings
from src.core.domain.model.task import Task
from src.core.engine.intervention_policy import InterventionPolicy


def _new_task(
    *,
    name: str,
    action: str = "scan",
    agent_type: str = "InjectionSwarm",
    params: dict | None = None,
    tags: list[str] | None = None,
) -> Task:
    return Task(
        id="task_policy_test",
        name=name,
        action=action,
        agent_type=agent_type,
        params=params or {},
        tags=tags or [],
    )


def test_intervention_policy_routes_oob_to_human_preferred() -> None:
    policy = InterventionPolicy(settings.get_intervention_scenarios())
    task = _new_task(name="Password Reset via email verification and reset token flow")

    decision = policy.decide(task)

    assert decision["route"] == "human_preferred"
    assert decision["scenario_id"] == "scn_08_oob_external_channel_flow"


def test_intervention_policy_routes_idor_to_shigoku_only() -> None:
    policy = InterventionPolicy(settings.get_intervention_scenarios())
    task = _new_task(
        name="IDOR object-level authorization check",
        params={"category": "id_param", "authz_probe": "id tampering"},
        tags=["idor_candidate"],
    )

    decision = policy.decide(task)

    assert decision["route"] == "shigoku_only"


def test_intervention_policy_routes_jwt_to_hitl() -> None:
    policy = InterventionPolicy(settings.get_intervention_scenarios())
    task = _new_task(name="JWT alg:none algorithm confusion probe")

    decision = policy.decide(task)

    assert decision["route"] == "shigoku_hitl"
    assert decision["scenario_id"] == "scn_07_token_trust_boundary"


def test_intervention_policy_explicit_requires_human_input_wins() -> None:
    policy = InterventionPolicy(settings.get_intervention_scenarios())
    task = _new_task(
        name="Any task",
        params={"requires_human_input": True, "category": "id_param"},
    )

    decision = policy.decide(task)

    assert decision["route"] == "human_preferred"
    assert decision["scenario_id"] == "explicit_requires_human_input"


def test_intervention_policy_routes_scn11_to_hitl_with_moderate_friction() -> None:
    policy = InterventionPolicy(settings.get_intervention_scenarios())
    task = _new_task(
        name="API chaining attack chain privilege escalation chain validation",
        params={"category": "api_candidate"},
        tags=["api_chaining"],
    )

    decision = policy.decide(task)

    assert decision["scenario_id"] == "scn_11_multi_vector_chain"
    assert decision["route"] == "shigoku_hitl"
    assert decision.get("route_decision_basis") == "high_friction_router"
    assert int(decision.get("friction_score", -1)) >= 0


def test_intervention_policy_routes_scn08_to_human_with_high_friction() -> None:
    policy = InterventionPolicy(settings.get_intervention_scenarios())
    task = _new_task(
        name="Password reset email verification mailbox out-of-band confirmation code workflow abuse",
        params={"category": "auth"},
        tags=["oob", "password-reset"],
    )

    decision = policy.decide(task)

    assert decision["scenario_id"] == "scn_08_oob_external_channel_flow"
    assert decision["route"] == "human_preferred"
    assert decision.get("route_decision_basis") == "high_friction_router"
    assert int(decision.get("friction_score", 0)) >= 7
