from src.core.agents.swarm.injection.manager_internal.api_probe_evidence import (
    clip_http_text,
    render_http_request,
    render_http_response,
)


def test_clip_http_text_truncates_with_marker_when_limit_exceeded():
    assert clip_http_text("abcdef", limit=4) == "abcd\n...[truncated]"


def test_render_http_request_serializes_headers_and_json_body():
    rendered = render_http_request(
        method="post",
        request_url="http://example.com/api/users",
        request_headers={"Authorization": "Bearer token", "Content-Type": "application/json"},
        request_payload={"role": "admin"},
    )

    assert rendered == "\n".join(
        [
            "POST http://example.com/api/users HTTP/1.1",
            "Authorization: Bearer token",
            "Content-Type: application/json",
            "",
            '{"role": "admin"}',
        ]
    )


def test_render_http_response_limits_body_and_keeps_status_line():
    rendered = render_http_response(
        status_code=201,
        response_headers={"Content-Type": "application/json"},
        response_body="0123456789",
    )

    assert rendered == "\n".join(
        [
            "HTTP/1.1 201",
            "Content-Type: application/json",
            "",
            "0123456789",
        ]
    )
