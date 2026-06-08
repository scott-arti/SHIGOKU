"""
SSTI 統合テスト用 Flask ターゲット

/greet   : Jinja2 SSTI 脆弱エンドポイント（autoescape=False, name を直接テンプレートに展開）
/safe    : SSTI のない安全なエンドポイント（f-string のみ）
/post    : POST body の name を Jinja2 に展開（POST SSTI テスト用）
"""

import threading

from flask import Flask, request
from jinja2 import Environment


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["TESTING"] = True

    @app.route("/greet")
    def greet():
        name = request.args.get("name", "World")
        env = Environment(autoescape=False)
        template = env.from_string(f"Hello {name}!")
        return template.render(), 200, {"Content-Type": "text/plain"}

    @app.route("/safe")
    def safe():
        name = request.args.get("name", "World")
        return f"Hello {name}!", 200, {"Content-Type": "text/plain"}

    @app.route("/post", methods=["POST"])
    def post_greet():
        name = request.form.get("name", "World")
        env = Environment(autoescape=False)
        template = env.from_string(f"Hello {name}!")
        return template.render(), 200, {"Content-Type": "text/plain"}

    return app


def start_server(port: int = 15555) -> tuple:
    """バックグラウンドスレッドで Flask を起動し (app, server_thread) を返す"""
    app = create_app()
    server_thread = threading.Thread(
        target=lambda: app.run(host="127.0.0.1", port=port, use_reloader=False),
        daemon=True,
    )
    server_thread.start()
    return app, server_thread


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=15555, debug=False)
