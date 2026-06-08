"""Execution Graph for tracking agent steps"""

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
            return "[yellow]No execution steps recorded[/yellow]"
        
        lines = []
        lines.append("\n[bold cyan]Execution Flow:[/bold cyan]\n")
        
        for i, step in enumerate(self.steps):
            # ステップ番号とアクション
            lines.append(f"  [{i}] {step['action']}")
            
            # ツールがあれば表示
            if step['tool']:
                lines.append(f"      └─ Tool: [yellow]{step['tool']}[/yellow]")
            
            # 結果プレビュー
            if step['result']:
                lines.append(f"      └─ Result: [dim]{step['result']}...[/dim]")
            
            # 次のステップへの矢印（最後以外）
            if i < len(self.steps) - 1:
                lines.append("      ↓")
        
        return "\n".join(lines)
    
    def render_mermaid(self) -> str:
        """Mermaid形式のフローチャートを生成"""
        if not self.steps:
            return "```\ngraph TD\n  Start[No steps]\n```"
        
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
            return "No steps executed"
        
        tool_counts = {}
        for step in self.steps:
            if step['tool']:
                tool_counts[step['tool']] = tool_counts.get(step['tool'], 0) + 1
        
        summary = f"Total steps: {len(self.steps)}\n"
        if tool_counts:
            summary += "Tools used: " + ", ".join([f"{tool}({count})" for tool, count in tool_counts.items()])
        
        return summary
