from abc import ABC, abstractmethod
from typing import Dict, Any

class BaseTool(ABC):
    """すべてのツールの基底クラス"""
    name: str
    description: str
    
    @abstractmethod
    def to_schema(self) -> Dict[str, Any]:
        """
        OpenAI function callingフォーマットのスキーマを返す
        
        Returns:
            OpenAI function schema
        """
        pass
    
    @abstractmethod
    def run(self, **kwargs) -> Any:
        """
        ツールを実行
        
        Args:
            **kwargs: ツール固有の引数
            
        Returns:
            実行結果
        """
        pass
