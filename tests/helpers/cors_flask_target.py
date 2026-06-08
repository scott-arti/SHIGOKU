"""
CORS Flask テストターゲット (port 15556)

用途: CORSTester / SmartCORSHunter の L1/L2 テスト
エンドポイント:
  /reflect  - Origin を ACAO にそのまま反射（脆弱）
  /wildcard - ACAO = * のみ（脆弱）
  /wildcard_creds - ACAO = * + ACAC = true（脆弱、設定ミス）
  /null     - ACAO = null（脆弱）
  /safe     - ACAO なし（安全）
"""

import threading
from flask import Flask, request, Response


CORS_FLASK_PORT = 15556


def make_cors_app() -> Flask:
    app = Flask(__name__)
    app.config["TESTING"] = True

    @app.route("/reflect")
    def reflect():
        origin = request.headers.get("Origin", "")
        res = Response("ok", status=200)
        if origin:
            res.headers["Access-Control-Allow-Origin"] = origin
            res.headers["Access-Control-Allow-Credentials"] = "true"
        return res

    @app.route("/wildcard")
    def wildcard():
        res = Response("ok", status=200)
        res.headers["Access-Control-Allow-Origin"] = "*"
        return res

    @app.route("/wildcard_creds")
    def wildcard_creds():
        res = Response("ok", status=200)
        res.headers["Access-Control-Allow-Origin"] = "*"
        res.headers["Access-Control-Allow-Credentials"] = "true"
        return res

    @app.route("/null")
    def null_origin():
        res = Response("ok", status=200)
        res.headers["Access-Control-Allow-Origin"] = "null"
        return res

    @app.route("/safe")
    def safe():
        return Response("ok", status=200)

    return app


def start_cors_flask_server(port: int = CORS_FLASK_PORT) -> threading.Thread:
    app = make_cors_app()
    thread = threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=port, use_reloader=False),
        daemon=True,
    )
    thread.start()
    return thread


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else CORS_FLASK_PORT
    print(f"Starting CORS Flask target on http://127.0.0.1:{port}")
    make_cors_app().run(host="127.0.0.1", port=port, use_reloader=False)
