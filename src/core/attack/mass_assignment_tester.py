"""
Mass Assignment Tester - マスアサインメント脆弱性検出

APIエンドポイントに対して、権限昇格や不正なプロパティ操作を狙った
パラメータを追加送信し、レスポンスの変化から脆弱性を検出する。

ターゲット例:
- role: admin
- is_admin: true
- id: 1
- balance: 999999
"""

import logging
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class ContentType(Enum):
    JSON = "json"
    FORM = "form"

@dataclass
class InjectionAttempt:
    param_name: str
    value: Any
    format: str # 'flat', 'nested_dot', 'nested_bracket'
    payload_sent: Any
    
@dataclass
class MassAssignmentResult:
    url: str
    vulnerable: bool
    evidence: str
    successful_injections: List[InjectionAttempt]

class MassAssignmentTester:
    """マスアサインメント脆弱性テスター"""

    # 注入を試みる危険なパラメータ候補
    DANGEROUS_PARAMS = [
        ("admin", True),
        ("is_admin", True),
        ("role", "admin"),
        ("roles", ["admin"]),
        ("superuser", True),
        ("privilege", "admin"),
        ("type", "admin"),
        ("group", "admin"),
        # ビジネスロジック系
        ("balance", 999999),
        ("credit", 999999),
        ("verified", True),
        ("premium", True),
        ("subscription", "pro"),
        # IDOR系（既存ID書き換えではなく新規プロパティとしてのID上書き狙い）
        ("id", 1),
        ("user_id", 1),
        ("account_id", 1),
    ]

    def __init__(self, client: Optional[Any] = None):
        from src.core.infra.network_client import AsyncNetworkClient
        self._client = client or AsyncNetworkClient()

    async def test(self, url: str, method: str, original_params: Dict[str, Any], auth_token: Optional[str] = None) -> List[Any]:
        """
        指定されたURLに対してマスアサインメントのテストを実行する。
        """
        results = []
        headers = {}
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        # ペイロード生成
        content_type = ContentType.JSON # Todo: logic to detect from method
        if method == "GET":
             return [] # GETでのマスアサインメントは一般的ではない
             
        attempts = self.generate_payloads(original_params, content_type)
        
        for attempt in attempts:
            try:
                # ペイロード送信
                if content_type == ContentType.JSON:
                    resp = await self._client.request(method, url, json=attempt.payload_sent, headers=headers)
                else:
                    resp = await self._client.request(method, url, data=attempt.payload_sent, headers=headers)
                
                # レスポンス解析
                is_vuln = self.analyze_response(original_params, resp.json, attempt)
                
                if is_vuln:
                    @dataclass
                    class FindingResult:
                        success: bool
                        description: str
                        injected_field: str
                        payload: Any
                        response_diff: Any
                    
                    results.append(FindingResult(
                        success=True,
                        description=f"Mass Assignment via property '{attempt.param_name}'",
                        injected_field=attempt.param_name,
                        payload=attempt.payload_sent,
                        response_diff=resp.json
                    ))
            except Exception as e:
                logger.error(f"Injected request failed for {attempt.param_name}: {e}")
                
        return results

    def generate_payloads(self, original_params: Dict[str, Any], content_type: ContentType = ContentType.JSON) -> List[InjectionAttempt]:
        """
        元のパラメータに対して、危険なパラメータを追加・変異させたペイロードリストを生成する
        """
        payloads = []
        
        # 1. フラットな追加 check
        for key, val in self.DANGEROUS_PARAMS:
            if key in original_params:
                continue # 既に存在する場合は値の書き換えになる（それはそれでテストすべきだが今回は追加攻撃にフォーカス）
            
            # JSONの場合
            if content_type == ContentType.JSON:
                new_params = original_params.copy()
                new_params[key] = val
                payloads.append(InjectionAttempt(
                    param_name=key,
                    value=val,
                    format="flat",
                    payload_sent=new_params
                ))
                
                # ネストされたオブジェクトがある場合、その中にも注入
                for k, v in original_params.items():
                    if isinstance(v, dict):
                        new_nested = original_params.copy()
                        new_nested_child = v.copy()
                        new_nested_child[key] = val
                        new_nested[k] = new_nested_child
                        payloads.append(InjectionAttempt(
                            param_name=f"{k}.{key}",
                            value=val,
                            format="nested_object",
                            payload_sent=new_nested
                        ))

            # Form形式の場合 (key=value, user.role=admin, user[role]=admin)
            else:
                # フラット
                new_params = original_params.copy()
                new_params[key] = val
                payloads.append(InjectionAttempt(key, val, "flat", new_params))
                
                # オブジェクト記法推測
                # 既存キーが "user[name]" のような形式なら "user[role]" を試す
                known_prefixes = set()
                for k in original_params.keys():
                    if "[" in k:
                        prefix = k.split("[")[0]
                        known_prefixes.add(prefix)
                    elif "." in k:
                        prefix = k.split(".")[0]
                        known_prefixes.add(prefix)
                
                for prefix in known_prefixes:
                    # Bracket notation
                    k_bracket = f"{prefix}[{key}]"
                    p_bracket = original_params.copy()
                    p_bracket[k_bracket] = val
                    payloads.append(InjectionAttempt(k_bracket, val, "nested_bracket", p_bracket))
                    
                    # Dot notation
                    k_dot = f"{prefix}.{key}"
                    p_dot = original_params.copy()
                    p_dot[k_dot] = val
                    payloads.append(InjectionAttempt(k_dot, val, "nested_dot", p_dot))

        return payloads

    def analyze_response(self, original_resp: Dict, injected_resp: Dict, attempt: InjectionAttempt) -> bool:
        """
        レスポンス比較による脆弱性判定（簡易版）
        
        判定基準:
        1. レスポンスに注入したパラメータがそのまま反映されている（Reflection）
           例: Userオブジェクトが返却され、そこに "role": "admin" が含まれている
        2. 権限エラーが消える、またはステータスが変わる（Blind）-> ここでは検知困難
        """
        # 単純なReflection check
        if isinstance(injected_resp, dict):
            # JSONレスポンス全体を文字列化して検索（乱暴だが効果的）
            import json
            resp_str = json.dumps(injected_resp)
            
            # 値が反映されているか
            # 注意: stringの "admin" は一般的すぎるので、キーとセットで確認したい
            
            # キーが存在するか再帰的にチェック
            if self._has_key_value(injected_resp, attempt.param_name, attempt.value):
                return True
                
        return False

    def _has_key_value(self, data: Any, target_key: str, target_val: Any) -> bool:
        """再帰的にキーと値のペアを探す"""
        if isinstance(data, dict):
            # target_keyが "user.role" のようなドット区切りの場合に対応が必要だが、
            # ここでは単純なキー名の一致を見る
            simple_key = target_key.split(".")[-1].split("[")[0].replace("]", "")
            
            if simple_key in data:
                # 値の比較（型緩め）
                if str(data[simple_key]) == str(target_val):
                    return True
            
            for v in data.values():
                if self._has_key_value(v, target_key, target_val):
                    return True
        elif isinstance(data, list):
            for item in data:
                if self._has_key_value(item, target_key, target_val):
                    return True
        return False

