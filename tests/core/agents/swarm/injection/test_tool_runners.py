from src.core.agents.swarm.injection.manager_internal.tool_runners import build_hunter_task


class TestBuildHunterTask:
    """build_hunter_task 共通 boilerplate の単体テスト。"""

    @staticmethod
    def _make_normalize():
        def _fn(params, kwargs):
            result = dict(params or {})
            result.update(kwargs)
            return result
        return _fn

    @staticmethod
    def _make_resolve(default_mode="phase1"):
        def _fn(params, mode):
            return params.get("detection_mode", mode)
        return _fn

    def test_basic_task_construction(self) -> None:
        task, detection_mode = build_hunter_task(
            url="http://example.com/page?id=1",
            specialist_key="sqli",
            task_name="SQLi Check",
            tags=["sqli"],
            params={"id": "1"},
            kwargs={"method": "POST", "auth_headers": {"X-Auth": "test"}},
            current_context={"auth_headers": {}, "params": {"cookies": "sess=abc"}},
            phase2_detection_mode="phase2",
            normalize_tool_supplied_params=self._make_normalize(),
            resolve_detection_mode=self._make_resolve(),
        )

        assert task.name == "SQLi Check"
        assert "sqli" in task.tags
        assert task.params["method"] == "POST"
        assert task.params["_auth"]["auth_headers"] == {"X-Auth": "test"}
        assert task.params["_auth"]["cookies"] == "sess=abc"
        assert detection_mode == "phase2"

    def test_default_method_is_get(self) -> None:
        task, _ = build_hunter_task(
            url="http://example.com/page?id=1",
            specialist_key="xss",
            task_name="XSS Check",
            tags=["xss"],
            params={"id": "1"},
            kwargs={},
            current_context={"auth_headers": {}, "params": {}},
            phase2_detection_mode="phase1",
            normalize_tool_supplied_params=lambda p, k: {"id": "1"},
            resolve_detection_mode=lambda p, d: "phase1",
        )

        assert task.params["method"] == "GET"

    def test_auth_headers_fallback_to_context(self) -> None:
        task, _ = build_hunter_task(
            url="http://example.com/page",
            specialist_key="lfi",
            task_name="LFI Check",
            tags=["lfi"],
            params={},
            kwargs={},
            current_context={"auth_headers": {"Authorization": "Bearer ctx"}, "params": {}},
            phase2_detection_mode="phase1",
            normalize_tool_supplied_params=lambda p, k: {},
            resolve_detection_mode=lambda p, d: "phase1",
        )

        assert task.params["_auth"]["auth_headers"] == {"Authorization": "Bearer ctx"}

    def test_cookies_from_context_params(self) -> None:
        task, _ = build_hunter_task(
            url="http://example.com/page",
            specialist_key="redirect",
            task_name="Redirect Check",
            tags=["redirect"],
            params={},
            kwargs={},
            current_context={"auth_headers": {}, "params": {"cookies": "sess=ctx123"}},
            phase2_detection_mode="phase1",
            normalize_tool_supplied_params=lambda p, k: {},
            resolve_detection_mode=lambda p, d: "phase1",
        )

        assert task.params["_auth"]["cookies"] == "sess=ctx123"

    def test_kwargs_cookies_override_context(self) -> None:
        task, _ = build_hunter_task(
            url="http://example.com/page",
            specialist_key="sqli",
            task_name="SQLi Check",
            tags=["sqli"],
            params={},
            kwargs={"cookies": "sess=override"},
            current_context={"auth_headers": {}, "params": {"cookies": "sess=ctx123"}},
            phase2_detection_mode="phase1",
            normalize_tool_supplied_params=lambda p, k: {},
            resolve_detection_mode=lambda p, d: "phase1",
        )

        assert task.params["_auth"]["cookies"] == "sess=override"

    def test_method_in_params_not_overwritten(self) -> None:
        task, _ = build_hunter_task(
            url="http://example.com/page",
            specialist_key="cmd_ssrf",
            task_name="CMD SSRF Check",
            tags=["cmd_ssrf"],
            params=None,
            kwargs={"method": "GET"},
            current_context={"auth_headers": {}, "params": {}},
            phase2_detection_mode="phase1",
            normalize_tool_supplied_params=lambda p, k: {"method": "PUT", "id": "1"},
            resolve_detection_mode=lambda p, d: "phase1",
        )

        assert task.params["method"] == "PUT"

    def test_cookies_via_kwargs_only(self) -> None:
        task, _ = build_hunter_task(
            url="http://example.com/page",
            specialist_key="xss",
            task_name="XSS Check",
            tags=["xss"],
            params={},
            kwargs={"cookies": "direct=sess"},
            current_context={"auth_headers": {}, "params": {}},
            phase2_detection_mode="phase1",
            normalize_tool_supplied_params=lambda p, k: {},
            resolve_detection_mode=lambda p, d: "phase1",
        )

        assert task.params["_auth"]["cookies"] == "direct=sess"
