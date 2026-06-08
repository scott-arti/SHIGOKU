"""シンプルなトレーシング機能"""
import os
import time
from datetime import datetime
from typing import Optional

class Tracer:
    """実行トレーシング"""
    
    _enabled = os.getenv("SHIGOKU_TRACING", "false").lower() == "true"
    _indent_level = 0
    
    @classmethod
    def is_enabled(cls) -> bool:
        """トレーシングが有効か確認"""
        return cls._enabled
    
    @classmethod
    def enable(cls):
        """トレーシングを有効化"""
        cls._enabled = True
    
    @classmethod
    def disable(cls):
        """トレーシングを無効化"""
        cls._enabled = False
    
    @classmethod
    def log(cls, event: str, details: Optional[str] = None):
        """トレースログ出力（JSON形式）"""
        if not cls._enabled:
            return
        
        timestamp = datetime.now().isoformat()
        
        log_entry = {
            "timestamp": timestamp,
            "event": event,
            "details": details,
            "indent": cls._indent_level
        }
        
        # JSONで出力（構造化ログ）
        import json
        print(f"[TRACE] {json.dumps(log_entry, ensure_ascii=False)}")
    
    @classmethod
    def start_span(cls, name: str):
        """スパン開始（インデント追加）"""
        cls.log(f"→ {name}")
        cls._indent_level += 1
    
    @classmethod
    def end_span(cls, name: str):
        """スパン終了（インデント削除）"""
        cls._indent_level = max(0, cls._indent_level - 1)
        cls.log(f"← {name}")
    
    @classmethod
    def log_agent(cls, agent_name: str, action: str):
        """エージェントアクション"""
        cls.log("Agent", f"{agent_name} | {action}")
    
    @classmethod
    def log_tool(cls, tool_name: str, args: str = ""):
        """ツール呼び出し"""
        cls.log("Tool", f"{tool_name}({args})")
    
    @classmethod
    def log_handoff(cls, from_agent: str, to_agent: str):
        """ハンドオフ"""
        cls.log("Handoff", f"{from_agent} → {to_agent}")
    
    @classmethod
    def log_llm(cls, model: str, tokens: Optional[int] = None):
        """LLM呼び出し"""
        if tokens:
            cls.log("LLM", f"{model} ({tokens} tokens)")
        else:
            cls.log("LLM", model)


def trace_function(func):
    """関数トレーシングデコレータ"""
    def wrapper(*args, **kwargs):
        if Tracer.is_enabled():
            Tracer.start_span(func.__name__)
        try:
            result = func(*args, **kwargs)
            return result
        finally:
            if Tracer.is_enabled():
                Tracer.end_span(func.__name__)
    return wrapper
