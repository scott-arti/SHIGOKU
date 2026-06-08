import re
import logging
from typing import List, Callable, Optional, Pattern

logger = logging.getLogger(__name__)

class FlagWatcher:
    """
    CTF Flag 監視システム
    
    あらゆる通信、ファイル、コマンド出力からフラグパターンを検知する。
    シングルトンパターンで実装し、エンジン全体で共有する。
    """
    _instance: Optional['FlagWatcher'] = None

    def __init__(self):
        if FlagWatcher._instance is not None:
            raise RuntimeError("This class is a singleton!")
        self.patterns: List[Pattern] = []
        self.callbacks: List[Callable[[str, str], None]] = []

    @classmethod
    def get_instance(cls) -> 'FlagWatcher':
        if cls._instance is None:
            cls._instance = FlagWatcher()
        return cls._instance

    def register_pattern(self, regex: str) -> None:
        """
        監視対象のフラグパターンを登録
        例: 'flag{.*}', 'CTF{.*}'
        """
        try:
            self.patterns.append(re.compile(regex, re.IGNORECASE))
            logger.info(f"[*] Registered flag pattern: {regex}")
        except re.error as e:
            logger.error(f"Invalid regex pattern: {regex} - {e}")

    def register_callback(self, callback: Callable[[str, str], None]) -> None:
        """
        フラグ発見時に呼び出されるコールバックを登録
        Args:
            callback: fn(flag_str, source_info)
        """
        self.callbacks.append(callback)

    def check(self, content: str, source: str = "unknown") -> None:
        """
        内容をスキャンし、フラグが含まれていれば登録されたコールバックを叩く
        """
        if not content or not isinstance(content, str):
            return

        for pattern in self.patterns:
            matches = pattern.findall(content)
            for flag in matches:
                # findallがグループを持つ場合、結果はタプルになる可能性があるため調整
                flag_str = flag if isinstance(flag, str) else str(flag)
                
                logger.warning(f"🚩 [!!!] FLAG FOUND in {source}: {flag_str} [!!!] 🚩")
                
                for cb in self.callbacks:
                    try:
                        cb(flag_str, source)
                    except Exception as e:
                        logger.error(f"Error in FlagWatcher callback: {e}")

    def clear(self) -> None:
        """状態のクリア (テスト用)"""
        self.patterns = []
        self.callbacks = []
