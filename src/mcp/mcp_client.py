"""基本的なMCPクライアント（STDIO接続のみ）"""
import json
import subprocess
from typing import List, Dict, Any, Optional

class MCPClient:
    """Model Context Protocol クライアント（STDIO版）"""
    
    def __init__(self, command: List[str]):
        """
        MCPサーバーに接続
        
        Args:
            command: サーバー起動コマンド（例: ["python", "server.py"]）
        """
        self.command = command
        self.process: Optional[subprocess.Popen] = None
        self.tools: Dict[str, Dict] = {}
    
    def connect(self):
        """サーバープロセスを起動"""
        try:
            import os
            env = os.environ.copy()
            # GitHub Tokenがある場合は環境変数として渡す
            from src.config import settings
            if settings.github_token:
                env["GITHUB_TOKEN"] = settings.github_token
                env["GITHUB_PERSONAL_ACCESS_TOKEN"] = settings.github_token
                
            self.process = subprocess.Popen(
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                env=env
            )
            # ツール一覧を取得
            self._discover_tools()
        except Exception as e:
            raise ConnectionError(f"Failed to start MCP server: {e}") from e
    
    def _send_request(self, method: str, params: Dict = None) -> Dict:
        """MCPリクエスト送信"""
        if not self.process:
            raise RuntimeError("Not connected to MCP server")
        
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params or {}
        }
        
        try:
            # リクエスト送信
            request_str = json.dumps(request) + "\n"
            self.process.stdin.write(request_str)
            self.process.stdin.flush()
            
            # レスポンス受信
            response_str = self.process.stdout.readline()
            response = json.loads(response_str)
            
            if "error" in response:
                raise RuntimeError(f"MCP error: {response['error']}")
            
            return response.get("result", {})
        
        except Exception as e:
            raise RuntimeError(f"MCP communication error: {e}") from e
    
    def _discover_tools(self):
        """利用可能なツールを検出"""
        try:
            result = self._send_request("tools/list")
            tools_list = result.get("tools", [])
            
            for tool in tools_list:
                name = tool.get("name")
                if name:
                    self.tools[name] = tool
        
        except Exception as e:
            print(f"Warning: Failed to discover MCP tools: {e}")
    
    def list_tools(self) -> List[str]:
        """ツール名のリストを取得"""
        return list(self.tools.keys())
    
    def get_tool_schema(self, tool_name: str) -> Optional[Dict]:
        """ツールのスキーマを取得"""
        return self.tools.get(tool_name)
    
    def call_tool(self, tool_name: str, arguments: Dict) -> Any:
        """ツールを呼び出し"""
        if tool_name not in self.tools:
            raise ValueError(f"Tool '{tool_name}' not found")
        
        result = self._send_request("tools/call", {
            "name": tool_name,
            "arguments": arguments
        })
        
        return result.get("content", [])
    
    def disconnect(self):
        """接続を切断"""
        if self.process:
            self.process.terminate()
            self.process.wait(timeout=5)
            self.process = None


# グローバルMCPクライアントレジストリ
_mcp_clients: Dict[str, MCPClient] = {}

def add_mcp_server(name: str, command: List[str]) -> MCPClient:
    """MCPサーバーを追加"""
    client = MCPClient(command)
    client.connect()
    _mcp_clients[name] = client
    return client

def get_mcp_client(name: str) -> Optional[MCPClient]:
    """MCPクライアントを取得"""
    return _mcp_clients.get(name)

def list_mcp_clients() -> List[str]:
    """接続中のMCPクライアント一覧"""
    return list(_mcp_clients.keys())
