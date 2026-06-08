"""
GraphQL Query Crafter - GraphQL脆弱性診断用クエリ生成

GraphQLエンドポイントに対して、
- Introspection Query
- Mutation列挙
- DoS攻撃用深層ネストクエリ
- バッチ処理攻撃
などのクエリを生成する。
"""

from typing import Dict, List, Any
import logging

class GraphQLCrafter:
    
    def get_introspection_query(self) -> str:
        """完全なスキーマ情報を取得するIntrospection Query"""
        return """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              ...FullType
            }
            directives {
              name
              description
              locations
              args {
                ...InputValue
              }
            }
          }
        }
        fragment FullType on __Type {
          kind
          name
          description
          fields(includeDeprecated: true) {
            name
            description
            args {
              ...InputValue
            }
            type {
              ...TypeRef
            }
            isDeprecated
            deprecationReason
          }
          inputFields {
            ...InputValue
          }
          interfaces {
            ...TypeRef
          }
          enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
          }
          possibleTypes {
            ...TypeRef
          }
        }
        fragment InputValue on __InputValue {
          name
          description
          type { ...TypeRef }
          defaultValue
        }
        fragment TypeRef on __Type {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                    ofType {
                      kind
                      name
                      ofType {
                        kind
                        name
                      }
                    }
                  }
                }
              }
            }
          }
        }
        """

    def generate_nested_query(self, field_name: str, depth: int = 10) -> str:
        """
        DoS攻撃検出用の深層ネストクエリを生成（循環参照を利用）
        例: owner { pets { owner { pets { ... } } } }
        """
        query = f"{field_name} {{"
        closing = "}"
        
        current = query
        for _ in range(depth - 1):
            current += f" {field_name} {{ "
            closing += "}"
            
        return f"query DeepNest {{ {current} id {closing} }}"

    def generate_batch_query(self, queries: List[str]) -> List[Dict]:
        """
        Array-based Batching攻撃用のJSONボディ生成
        """
        # 実際には [{"query": "..."}, {"query": "..."}] の形式
        return [{"query": q} for q in queries]

    def extract_id_bearing_operations(self, schema_json: Dict) -> List[Dict[str, Any]]:
        """
        Introspection結果から ID型 (または ID を含む) 引数を持つ操作を抽出。
        """
        id_ops = []
        try:
            schema = schema_json.get("data", {}).get("__schema", {})
            types = {t["name"]: t for t in schema.get("types", [])}
            
            # Query と Mutation の型名を取得
            query_type_name = schema.get("queryType", {}).get("name")
            mutation_type_name = schema.get("mutationType", {}).get("name")
            
            for type_name in [query_type_name, mutation_type_name]:
                if not type_name or type_name not in types:
                    continue
                
                for field in types[type_name].get("fields", []):
                    args = field.get("args", [])
                    # 引数に 'ID' 型が含まれているかチェック
                    has_id_arg = False
                    for arg in args:
                        # 型情報（NonNull や List に包まれている可能性があるため再帰的にチェックする必要があるが、
                        # ここでは簡略化して name または underlying 型名に ID が含まれるか確認）
                        arg_type_name = arg.get("type", {}).get("name") or ""
                        if arg_type_name == "ID" or "ID" in str(arg.get("type")):
                            has_id_arg = True
                            break
                    
                    if has_id_arg:
                        id_ops.append({
                            "name": field["name"],
                            "type": "query" if type_name == query_type_name else "mutation",
                            "args": args
                        })
        except Exception as e:
            logging.getLogger(__name__).debug("Failed to extract ID bearing operations: %s", e)
            
        return id_ops

    def generate_idor_queries(self, schema_json: Dict, target_id: str) -> List[Dict[str, Any]]:
        """
        IDORテスト用のクエリセットを生成。
        """
        ops = self.extract_id_bearing_operations(schema_json)
        test_queries = []
        
        for op in ops:
            op_name = op["name"]
            vars_def = []
            vars_vals = {}
            op_args = []
            
            for arg in op["args"]:
                arg_name = arg["name"]
                # ここでは単純化のため、全引数を変数として定義
                # 本来的には型マッピングが必要だが、IDORテスト用なので ID と ID 以外で分ける
                arg_type_raw = arg["type"]
                # 再帰的にスカラー型名を取得
                curr = arg_type_raw
                type_name = "String" # fallback
                while curr:
                    if curr.get("name"):
                        type_name = curr["name"]
                        break
                    curr = curr.get("ofType")
                
                vars_def.append(f"${arg_name}: {type_name}!") # 必須として扱う（仮）
                op_args.append(f"{arg_name}: ${arg_name}")
                
                if type_name == "ID" or "id" in arg_name.lower():
                    vars_vals[arg_name] = target_id
                else:
                    # ダミー値
                    vars_vals[arg_name] = "test"
            
            query = f"{op['type']} {op_name}Test({', '.join(vars_def)}) {{\n"
            query += f"  {op_name}({', '.join(op_args)}) {{\n"
            query += "    id\n" # 常に id は取得しようとする
            query += "  }\n"
            query += "}"
            
            test_queries.append({
                "operationName": f"{op_name}Test",
                "query": query,
                "variables": vars_vals
            })
            
        return test_queries
