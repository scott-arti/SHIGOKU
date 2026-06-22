"""Execution Graph for tracking agent steps"""

from src.cli.messages import msg

class ExecutionGraph:
    """実行フローをASCII graphで可視化"""
    
    def __init__(self):
        self.steps = []
        self.current_step = 0
    
    def add_step(self, action: str, tool: str = None, result_preview: str = ""):
        """ステップを記録
        
        Args:
            action: アクション内容
            tool: 使用したツール名（オプション）
            result_preview: 結果のプレビュー（最初の50文字）
        """
        self.steps.append({
            "num": self.current_step,
            "action": action,
            "tool": tool,
            "result": result_preview[:50] if result_preview else ""
        })
        self.current_step += 1
    
    def render_ascii(self) -> str:
        """ASCII artでフローチャートを生成"""
        if not self.steps:
            return msg("graph.no_steps")
        
        lines = []
        lines.append("\n" + msg("graph.ascii_header") + "\n")
        
        for i, step in enumerate(self.steps):
            # ステップ番号とアクション
            lines.append("  " + msg("graph.step_line", i=i, action=step['action']))
            
            # ツールがあれば表示
            if step['tool']:
                lines.append("      " + msg("graph.tool_line", tool=step['tool']))
            
            # 結果プレビュー
            if step['result']:
                lines.append("      " + msg("graph.result_line", preview=step['result']))
            
            # 次のステップへの矢印（最後以外）
            if i < len(self.steps) - 1:
                lines.append("      " + msg("graph.connector"))
        
        return "\n".join(lines)
    
    def render_mermaid(self) -> str:
        """Mermaid形式のフローチャートを生成"""
        if not self.steps:
            return msg("graph.mermaid_empty")
        
        lines = ["```mermaid", "graph TD"]
        
        # Start node
        lines.append(f'  S0["Start"]')
        
        for i, step in enumerate(self.steps, 1):
            # Node definition
            action = step['action'].replace('"', '\\"')[:30]  # エスケープと長さ制限
            tool_info = f" ({step['tool']})" if step['tool'] else ""
            lines.append(f'  S{i}["{action}{tool_info}"]')
            
            # Edge
            lines.append(f"  S{i-1} --> S{i}")
        
        lines.append("```")
        return "\n".join(lines)
    
    def clear(self):
        """グラフをクリア"""
        self.steps = []
        self.current_step = 0
    
    def get_summary(self) -> str:
        """実行サマリーを取得"""
        if not self.steps:
            return msg("graph.no_steps_summary")
        
        tool_counts = {}
        for step in self.steps:
            if step['tool']:
                tool_counts[step['tool']] = tool_counts.get(step['tool'], 0) + 1
        
        tool_list = ", ".join([f"{tool}({count})" for tool, count in tool_counts.items()])
        return msg("graph.summary", steps=len(self.steps), tools=tool_list)
