from src.main import _normalize_scenario_id_for_report


def test_normalize_scenario_for_report_maps_injection_category_to_scn03() -> None:
    scenario_id, route, source = _normalize_scenario_id_for_report(
        task={},
        params={"category": "api_data"},
        scenario_id="",
        route="",
    )

    assert scenario_id == "scn_03_injection_input_tampering"
    assert route == "shigoku_hitl"
    assert source == "normalized_category_alias"


def test_normalize_scenario_for_report_maps_data_exposure_category_to_scn06() -> None:
    scenario_id, route, source = _normalize_scenario_id_for_report(
        task={},
        params={"category": "meta_observability"},
        scenario_id="",
        route="",
    )

    assert scenario_id == "scn_06_data_exposure_diff"
    assert route == "shigoku_hitl"
    assert source == "normalized_category_alias"


def test_normalize_scenario_for_report_maps_admin_category_to_scn01() -> None:
    scenario_id, route, source = _normalize_scenario_id_for_report(
        task={},
        params={"category": "admin"},
        scenario_id="",
        route="",
    )

    assert scenario_id == "scn_01_idor_bola_object_access"
    assert route == "shigoku_hitl"
    assert source == "normalized_category_alias"
