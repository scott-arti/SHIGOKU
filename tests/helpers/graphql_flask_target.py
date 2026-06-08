"""
GraphQL Flask Target for Integration Testing

Usage:
    python graphql_flask_target.py [port]
"""

from flask import Flask, request, jsonify
import json
import sys

FLASK_PORT = 15558

# Introspection enabled schema response
SCHEMA_RESPONSE = {
    "data": {
        "__schema": {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
            "types": [
                {
                    "kind": "OBJECT",
                    "name": "Query",
                    "fields": [
                        {"name": "getUser", "args": [{"name": "id"}]},
                        {"name": "getPassword", "description": "Sensitive field"},
                        {"name": "adminSecret", "description": "Admin only"},
                    ],
                },
                {
                    "kind": "OBJECT",
                    "name": "Mutation",
                    "fields": [
                        {"name": "deleteUser", "args": [{"name": "id"}]},
                        {"name": "updatePassword", "args": [{"name": "password"}]},
                    ],
                },
            ],
        }
    }
}

# Field suggestions response
SUGGESTIONS_RESPONSE = {
    "errors": [{
        "message": 'Cannot query field "thisFieldDoesNotExist12345" on type "Query". Did you mean "getUser" or "getPassword"?'
    }]
}

# Introspection disabled response
DISABLED_RESPONSE = {
    "errors": [{"message": "Introspection is disabled"}]
}


def create_app() -> Flask:
    app = Flask(__name__)

    @app.route("/graphql", methods=["POST", "GET"])
    def graphql_endpoint():
        """GraphQL endpoint with introspection enabled"""
        if request.method == "GET" and "query" in request.args:
            query = request.args.get("query", "")
            if "__schema" in query or "IntrospectionQuery" in query:
                return jsonify(SCHEMA_RESPONSE)
            return jsonify({"errors": [{"message": "Invalid query"}]}), 400

        if request.method == "POST":
            content_type = request.headers.get("Content-Type", "")
            
            # JSON request
            if "json" in content_type:
                data = request.get_json() or {}
                query = data.get("query", "")
                
                if "thisFieldDoesNotExist" in query:
                    return jsonify(SUGGESTIONS_RESPONSE)
                if "__schema" in query or "IntrospectionQuery" in query:
                    return jsonify(SCHEMA_RESPONSE)
                return jsonify({"errors": [{"message": "Invalid query"}]}), 400
            
            # Form-urlencoded request (bypass)
            if "form" in content_type:
                query = request.form.get("query", "")
                if "__schema" in query or "IntrospectionQuery" in query:
                    return jsonify(SCHEMA_RESPONSE)
                return jsonify({"errors": [{"message": "Invalid query"}]}), 400
        
        return jsonify({"errors": [{"message": "Invalid request"}]}), 400

    @app.route("/graphql-disabled", methods=["POST"])
    def graphql_disabled():
        """GraphQL endpoint with introspection disabled"""
        return jsonify(DISABLED_RESPONSE), 200

    @app.route("/graphql-ui")
    def graphql_ui():
        """GraphiQL UI endpoint"""
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>GraphiQL</title>
            <script src="https://unpkg.com/react@16/umd/react.production.min.js"></script>
        </head>
        <body>
            <div id="graphiql">GraphiQL Explorer</div>
            <script>var GRAPHQL_ENDPOINT = '/graphql';</script>
        </body>
        </html>
        """
        return html_content, 200, {"Content-Type": "text/html"}

    @app.route("/safe", methods=["POST"])
    def safe():
        """Non-GraphQL endpoint"""
        return jsonify({"message": "Not GraphQL"})

    return app


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else FLASK_PORT
    print(f"Starting GraphQL Flask target on http://127.0.0.1:{port}")
    app = create_app()
    app.run(host="127.0.0.1", port=port, use_reloader=False)
