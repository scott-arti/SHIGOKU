from typing import Dict, List, Type
from src.tools.base import BaseTool

class ToolRegistry:
    """ツールの動的登録・管理システム"""
    _tools: Dict[str, BaseTool] = {}
    
    @classmethod
    def register(cls, tool_class: Type[BaseTool]) -> Type[BaseTool]:
        """
        デコレータ：ツールクラスをレジストリに登録
        
        Usage:
            @ToolRegistry.register
            class MyTool(BaseTool):
                ...
        """
        instance = tool_class()
        cls._tools[instance.name] = instance
        return tool_class
    
    @classmethod
    def get(cls, name: str) -> BaseTool:
        """名前でツールを取得"""
        return cls._tools.get(name)
    
    @classmethod
    def get_all(cls) -> List[BaseTool]:
        """登録済みツールのリストを取得"""
        return list(cls._tools.values())
    
    @classmethod
    def list_tools(cls) -> List[tuple]:
        """ツール名と説明のリストを取得（CLI用）"""
        return [(name, tool.description) for name, tool in cls._tools.items()]

# Auto-load tool modules to populate registry
# These imports must be after ToolRegistry definition to avoid circular import issues
# when the submodules try to import ToolRegistry
try:
    import src.tools.builtin
    import src.tools.custom
except ImportError:
    pass
