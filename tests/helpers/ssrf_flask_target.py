"""
SSRF Flask テストターゲット (port 15559)
"""

import threading
from flask import Flask, request, Response

FLASK_PORT = 15559


def make_ssrf_app() -> Flask:
    app = Flask(__name__)

    @app.route("/fetch")
    def vulnerable():
        target = request.args.get("url", "")
        if target:
            return Response(f"ami-id: i-1234567890abcdef0\nFetched from: {target}", status=200)
        return Response("no url", status=400)

    @app.route("/safe")
    def safe():
        return Response("safe", status=200)

    @app.route("/post", methods=["POST"])
    def post_vulnerable():
        target = request.form.get("url", "")
        if target:
            return Response(f"ami-id: i-1234567890abcdef0\nFetched from: {target}", status=200)
        return Response("no url", status=400)

    return app


def start_ssrf_server(port: int = FLASK_PORT) -> threading.Thread:
    app = make_ssrf_app()
    thread = threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=port, use_reloader=False),
        daemon=True,
    )
    thread.start()
    return thread


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else FLASK_PORT
    print(f"Starting SSRF Flask target on http://127.0.0.1:{port}")
    make_ssrf_app().run(host="127.0.0.1", port=port, use_reloader=False)
