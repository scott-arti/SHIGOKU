"""
CRLF Flask テストターゲット (port 15557)

用途: CRLFTester / SmartCRLFHunter の L1/L2 テスト
エンドポイント:
  /redirect - url パラメータを Location に挿入（CRLF脆弱）
              "shigoku" が含まれる場合 X-Injected: shigoku を返す（B13修正）
  /safe     - パラメータを使わない安全なレスポンス
  /post     - POST body の redirect パラメータをエコーバック（将来拡張用）
"""

import threading
from flask import Flask, request, Response


FLASK_PORT = 15557


def make_crlf_app() -> Flask:
    app = Flask(__name__)

    @app.route("/redirect")
    def vulnerable():
        """
        url パラメータを Location ヘッダーに直接挿入（CRLF脆弱）。
        B13: Flask/Werkzeug が \\r\\n をサニタイズしても X-Injected で検出可能にする。
             "shigoku" マーカーがペイロードに含まれる場合、X-Injected: shigoku を返す。
        """
        url_param = request.args.get("url", "/")
        resp = Response("", status=302)
        resp.headers["Location"] = url_param
        if "shigoku" in url_param:
            resp.headers["X-Injected"] = "shigoku"
        return resp

    @app.route("/safe")
    def safe():
        return Response("safe", status=200)

    @app.route("/post", methods=["POST"])
    def post_vulnerable():
        """POST body の redirect パラメータをエコーバック（将来拡張用）"""
        redirect_val = request.form.get("redirect", "/")
        resp = Response("", status=302)
        resp.headers["Location"] = redirect_val
        return resp

    return app


def start_crlf_server(port: int = FLASK_PORT) -> threading.Thread:
    app = make_crlf_app()
    thread = threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=port, use_reloader=False),
        daemon=True,
    )
    thread.start()
    return thread


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else FLASK_PORT
    print(f"Starting CRLF Flask target on http://127.0.0.1:{port}")
    make_crlf_app().run(host="127.0.0.1", port=port, use_reloader=False)
