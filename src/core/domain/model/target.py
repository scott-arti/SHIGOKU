from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
import ipaddress
from urllib.parse import urlparse
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class TargetType(Enum):
    WILDCARD_DOMAIN = auto()    # *.example.com
    SINGLE_URL_PUBLIC = auto()  # https://example.com (GAU有効)
    SINGLE_URL_INTERNAL = auto() # http://192.168.1.1, dvwa.local (GAU無効)
    LOCAL_FILE = auto()         # /tmp/ctf.zip (Static Analysis)
    LOCAL_DIR = auto()          # ./src/ (Source Code Audit)
    UNKNOWN = auto()            # Fallback

@dataclass
class TargetAsset:
    raw_input: str
    asset_type: TargetType
    priority: int = 1
    # メタデータ (CTFのフラグ形式や、BBの認証情報など)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @classmethod
    def from_input(cls, input_str: str, config: Dict[str, Any] = None) -> 'TargetAsset':
        """
        create() のエイリアス。テストや main.py での使用を容易にする。
        """
        return cls.create(input_str, config)

    @classmethod
    def create(cls, input_str: str, config: Dict[str, Any] = None) -> 'TargetAsset':
        """
        入力文字列を解析し、適切なTargetTypeを判定してインスタンス化するファクトリメソッド
        """
        asset_type = cls._classify(input_str)
        metadata = {}
        
        # CTFモードの場合、ConfigからFlag形式などを注入
        if config and config.get('mode') == 'CTF':
            metadata['flag_format'] = config.get('flag_format', 'CTF{.*}')
            
        return cls(raw_input=input_str, asset_type=asset_type, metadata=metadata)

    @staticmethod
    def _classify(s: str) -> TargetType:
        # パスかどうかを確認するために展開を試みる (副作用なし)
        # ただしネットワークパスではないことが前提
        if s.startswith("/") or s.startswith("./") or s.startswith("../"):
            path = Path(s)
            # 存在チェックは後回しにするか、ここでやるか。一旦静的判定。
            # ディレクトリっぽいかファイルっぽいか
            if s.endswith("/"):
                return TargetType.LOCAL_DIR
            return TargetType.LOCAL_FILE

        # ワイルドカード/ドメイン判定
        if s.startswith("*."):
            return TargetType.WILDCARD_DOMAIN

        # URL解析
        parsed = urlparse(s if "://" in s else f"http://{s}")
        hostname = parsed.hostname or s

        # Internal / Public 判定ロジック
        if TargetAsset._is_internal(hostname):
            return TargetType.SINGLE_URL_INTERNAL
        
        # パスやスキームがなく、ドメインっぽい場合はWildcard扱いも考慮
        # 例: example.com -> SINGLE_URL_PUBLIC (通常はこれを想定)
        # ただし "*.example.com" は上で弾いている
        
        return TargetType.SINGLE_URL_PUBLIC

    @staticmethod
    def _is_internal(hostname: str) -> bool:
        """
        プライベートIP、localhost、.localドメイン等を判定
        """
        if not hostname: return False
        if hostname.lower() in ["localhost", "dvwa.local"] or hostname.lower().endswith(".local"):
            return True
        try:
            # IPアドレスとして解析
            ip = ipaddress.ip_address(hostname)
            return ip.is_private or ip.is_loopback
        except ValueError:
            # IPアドレスではない場合はパブリックとみなす(DNS解決はここではしない)
            return False
