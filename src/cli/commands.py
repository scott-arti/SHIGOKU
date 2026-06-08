"""CLIコマンドレジストリとコマンド実装"""
from typing import Dict, Callable, Any
import json

class CommandRegistry:
    """CLIコマンドの登録と管理"""
    _commands: Dict[str, Dict[str, Any]] = {}
    
    @classmethod
    def register(cls, name: str, description: str, usage: str = ""):
        """コマンド登録デコレータ"""
        def decorator(func: Callable):
            cls._commands[name] = {
                "func": func,
                "description": description,
                "usage": usage
            }
            return func
        return decorator
    
    @classmethod
    def get(cls, name: str) -> Callable:
        """コマンド関数を取得"""
        cmd = cls._commands.get(name)
        return cmd["func"] if cmd else None
    
    @classmethod
    def list_all(cls) -> Dict[str, Dict[str, Any]]:
        """全コマンドのリストを取得"""
        return cls._commands


@CommandRegistry.register("help", "Show available commands", "/help")
def cmd_help(cli):
    """ヘルプメッセージを表示"""
    cli.console.print("\n[bold cyan]Available Commands:[/bold cyan]")
    for name, info in CommandRegistry.list_all().items():
        usage = info.get("usage") or f"/{name}"
        cli.console.print(f"  [yellow]{usage:15}[/yellow] - {info['description']}")
    cli.console.print()


@CommandRegistry.register("tools", "List available tools", "/tools")
def cmd_tools(cli):
    """利用可能なツール一覧を表示"""
    cli.console.print("\n[bold cyan]Available Tools:[/bold cyan]")
    for tool in cli.runner.agent.tools:
        name = getattr(tool, "name", "unknown")
        desc = getattr(tool, "description", "No description")
        cli.console.print(f"  [yellow]{name:20}[/yellow] - {desc}")
    cli.console.print()


@CommandRegistry.register("history", "Show message history count", "/history")
def cmd_history(cli):
    """メッセージ履歴の数を表示"""
    count = len(cli.runner.agent.messages)
    cli.console.print(f"\n[cyan]Current message count:[/cyan] {count}")
    cli.console.print()


@CommandRegistry.register("model", "Change the LLM model", "/model <model_name>")
def cmd_model(cli, *args):
    """モデルを変更"""
    if not args:
        current = cli.runner.agent.model
        cli.console.print(f"\n[cyan]Current model:[/cyan] {current}")
        
        cli.console.print("\n[bold cyan]Recommended Models:[/bold cyan]")
        
        models = {
            "OpenAI": ["gpt-4o", "gpt-4-turbo", "gpt-3.5-turbo"],
            "Anthropic": ["claude-3-5-sonnet-20240620", "claude-3-opus-20240229"],
            "Local (Ollama)": ["ollama/llama3", "ollama/deepseek-coder", "ollama/mistral"],
            "DeepSeek": ["deepseek/deepseek-coder", "deepseek/deepseek-chat"]
        }
        
        for provider, model_list in models.items():
            cli.console.print(f"  [yellow]{provider}:[/yellow]")
            for m in model_list:
                marker = " [green]*[/green]" if m == current else ""
                cli.console.print(f"    - {m}{marker}")
        
        cli.console.print("\n[dim]Usage: /model <model_name>[/dim]")
        cli.console.print("[dim]Note: You can use any model supported by litellm.[/dim]")
        cli.console.print()
        return
    
    new_model = args[0]
    cli.runner.agent.model = new_model
    cli.runner.llm.model = new_model
    cli.console.print(f"\n[green]Model changed to:[/green] {new_model}")
    cli.console.print()


@CommandRegistry.register("agent", "Show current agent info", "/agent")
def cmd_agent(cli):
    """現在のエージェント情報を表示"""
    agent = cli.runner.agent
    cli.console.print(f"\n[bold cyan]Agent Information:[/bold cyan]")
    cli.console.print(f"  [yellow]Name:[/yellow] {agent.name}")
    cli.console.print(f"  [yellow]Model:[/yellow] {agent.model}")
    cli.console.print(f"  [yellow]Mode:[/yellow] {agent.mode}")  # モード追加
    cli.console.print(f"  [yellow]Tools:[/yellow] {len(agent.tools)}")
    cli.console.print(f"  [yellow]Messages:[/yellow] {len(agent.messages)}")
    cli.console.print()


@CommandRegistry.register("mode", "Switch agent mode", "/mode [redteam|webpentest|bugbounty|ctf|security]")
def cmd_mode(cli, *args):
    """エージェントモードを切り替え"""
    if not args:
        current = cli.runner.agent.mode
        cli.console.print(f"\n[cyan]Current mode:[/cyan] {current}")
        cli.console.print("\n[bold cyan]Available modes:[/bold cyan]")
        cli.console.print("  [yellow]redteam[/yellow]    - Red Team Operations (infrastructure penetration)")
        cli.console.print("  [yellow]webpentest[/yellow] - Web Application Pentesting (OWASP Top 10)")
        cli.console.print("  [yellow]bugbounty[/yellow]  - Bug Bounty Hunting (recon-focused)")
        cli.console.print("  [yellow]ctf[/yellow]        - CTF Challenge Solver (Crypto/Web/Pwn/Reversing)")
        cli.console.print("  [yellow]security[/yellow]   - General Security (default)")
        cli.console.print("\n[dim]Usage: /mode <mode_name>[/dim]")
        cli.console.print()
        return
    
    new_mode = args[0].lower()
    valid_modes = ["redteam", "webpentest", "bugbounty", "ctf", "security", "general"]
    
    if new_mode not in valid_modes:
        cli.console.print(f"\n[red]Invalid mode:[/red] {new_mode}")
        cli.console.print(f"[dim]Valid modes: {', '.join(valid_modes)}[/dim]")
        cli.console.print()
        return
    
    cli.runner.agent.switch_mode(new_mode)
    cli.console.print(f"\n[green]✓ Mode switched to:[/green] {new_mode}")
    
    # モードの説明を表示
    mode_desc = {
        "redteam": "Red Team mode: Infrastructure penetration testing",
        "webpentest": "Web Pentesting mode: OWASP Top 10 focused",
        "bugbounty": "Bug Bounty mode: Recon and high-impact vulnerabilities",
        "ctf": "CTF mode: Capture The Flag challenge solver",
        "security": "General Security mode: Balanced approach",
    }
    if new_mode in mode_desc:
        cli.console.print(f"[dim]{mode_desc[new_mode]}[/dim]")
    cli.console.print()


@CommandRegistry.register("graph", "Show execution graph", "/graph [ascii|mermaid]")
def cmd_graph(cli, *args):
    """実行グラフを表示"""
    if not hasattr(cli.runner, 'graph') or not cli.runner.graph:
        cli.console.print("\n[yellow]No execution graph available.[/yellow]")
        cli.console.print("[dim]Graph is automatically created during agent execution.[/dim]\n")
        return
    
    # 形式指定（デフォルトはascii）
    format_type = args[0].lower() if args else "ascii"
    
    if format_type == "mermaid":
        output = cli.runner.graph.render_mermaid()
        cli.console.print(output)
    else:
        output = cli.runner.graph.render_ascii()
        cli.console.print(output)
    
    # サマリー表示
    summary = cli.runner.graph.get_summary()
    cli.console.print(f"\n[dim]{summary}[/dim]\n")


@CommandRegistry.register("memory", "Manage session memory", "/memory [list|save|clear|stats]")
def cmd_memory(cli, *args):
    """セッションメモリ管理"""
    from src.core.memory import Memory
    
    memory = Memory()
    action = args[0].lower() if args else "list"
    
    if action == "save":
        # 現在のセッションを保存
        session_data = {
            "summary": " ".join(args[1:]) if len(args) > 1 else "Manual save",
            "agent": cli.runner.agent.name,
            "mode": cli.runner.agent.mode,
            "steps": len(cli.runner.agent.messages),
            "result": "Saved manually"
        }
        session_id = memory.save_session(session_data)
        cli.console.print(f"\n[green]✓ Session saved:[/green] ID {session_id}\n")
    
    elif action == "clear":
        memory.clear_all()
        cli.console.print("\n[green]✓ All memory cleared[/green]\n")
    
    elif action == "stats":
        stats = memory.get_stats()
        cli.console.print("\n[bold cyan]Memory Statistics:[/bold cyan]")
        cli.console.print(f"  Total sessions: {stats['total']}")
        if "by_mode" in stats:
            cli.console.print("  By mode:")
            for mode, count in stats["by_mode"].items():
                cli.console.print(f"    - {mode}: {count}")
        if "total_steps" in stats:
            cli.console.print(f"  Total steps: {stats['total_steps']}")
        cli.console.print()
    
    else:  # list
        sessions = memory.list_sessions()
        if not sessions:
            cli.console.print("\n[yellow]No saved sessions[/yellow]\n")
            return
        
        cli.console.print("\n[bold cyan]Saved Sessions:[/bold cyan]")
        for s in sessions:
            cli.console.print(
                f"  [yellow]ID:{s['id']:3}[/yellow] | "
                f"{s['summary'][:40]:40} | "
                f"Agent: {s['agent']:10} | "
                f"Mode: {s['mode']:10} | "
                f"Size: {s['size']:5} | "
                f"{s['created'][:10]}"
            )
        cli.console.print()


@CommandRegistry.register("agents", "List all registered agents", "/agents")
def cmd_agents(cli):
    """全エージェント一覧を表示"""
    from src.core.agent_registry import AgentRegistry
    
    agents = AgentRegistry.list_all()
    current = AgentRegistry.get_current()
    
    cli.console.print(f"\n[bold cyan]Registered Agents:[/bold cyan]")
    if not agents:
        cli.console.print("  [dim]No agents registered[/dim]")
    else:
        for name, agent in agents.items():
            marker = "→" if current and current.name == name else " "
            cli.console.print(f"  {marker} [yellow]{name:15}[/yellow] - {agent.model}")
    cli.console.print()


@CommandRegistry.register("compact", "Compact conversation history", "/compact")
def cmd_compact(cli):
    """コンテキストを圧縮（古いメッセージを要約）"""
    # シンプルな実装: 最初のシステムメッセージと最新N件のみ保持
    KEEP_RECENT = 10
    
    messages = cli.runner.agent.messages
    if len(messages) <= KEEP_RECENT + 1:
        cli.console.print("\n[yellow]History is already compact.[/yellow]\n")
        return
    
    # システムメッセージ + 最新のメッセージを保持
    system_msg = messages[0]
    recent_msgs = messages[-(KEEP_RECENT):]
    
    original_count = len(messages)
    cli.runner.agent.messages = [system_msg] + recent_msgs
    
    removed = original_count - len(cli.runner.agent.messages)
    cli.console.print(f"\n[green]Compacted:[/green] Removed {removed} old messages")
    cli.console.print(f"[cyan]Current count:[/cyan] {len(cli.runner.agent.messages)}\n")


@CommandRegistry.register("load", "Load JSONL conversation log", "/load <file_path>")
def cmd_load(cli, *args):
    """JSONLファイルから過去のログをロード（In-Context Learning）"""
    if not args:
        cli.console.print("\n[red]Error:[/red] Please specify a file path")
        cli.console.print("[dim]Usage: /load <file_path>[/dim]\n")
        return
    
    file_path = args[0]
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            loaded = 0
            for line in f:
                if line.strip():
                    msg = json.loads(line)
                    # システムメッセージは除外
                    if msg.get("role") != "system":
                        cli.runner.agent.messages.append(msg)
                        loaded += 1
        
        cli.console.print(f"\n[green]Loaded {loaded} messages from {file_path}[/green]\n")
    
    except FileNotFoundError:
        cli.console.print(f"\n[red]Error:[/red] File not found: {file_path}\n")
    except json.JSONDecodeError as e:
        cli.console.print(f"\n[red]Error:[/red] Invalid JSON in file: {e}\n")
    except Exception as e:
        cli.console.print(f"\n[red]Error:[/red] {e}\n")


@CommandRegistry.register("clear", "Clear conversation history", "/clear")
def cmd_clear(cli):
    """会話履歴をクリア（システムメッセージのみ残す）"""
    system_msg = cli.runner.agent.messages[0]
    cli.runner.agent.messages = [system_msg]
    cli.console.print("\n[green]Conversation history cleared.[/green]\n")


@CommandRegistry.register("mcp", "MCP server management", "/mcp <add|list> [args...]")
def cmd_mcp(cli, *args):
    """MCPサーバー管理"""
    if not args:
        cli.console.print("\n[red]Usage:[/red] /mcp <add|list> [args...]")
        cli.console.print("[dim]  /mcp add <command...>  - Add MCP server[/dim]")
        cli.console.print("[dim]  /mcp list             - List MCP servers[/dim]\n")
        return
    
    subcommand = args[0]
    
    if subcommand == "add":
        if len(args) < 2:
            cli.console.print("\n[red]Error:[/red] Please specify server command")
            cli.console.print("[dim]Example: /mcp add python mcp_server.py[/dim]\n")
            return
        
        try:
            from src.mcp.mcp_client import add_mcp_server
            
            command = list(args[1:])
            server_name = f"mcp_{len(command)}"  # 簡易的な名前
            
            cli.console.print(f"\n[cyan]Connecting to MCP server:[/cyan] {' '.join(command)}")
            client = add_mcp_server(server_name, command)
            
            tools = client.list_tools()
            cli.console.print(f"[green]✓ Connected![/green] Found {len(tools)} tools:")
            for tool in tools:
                cli.console.print(f"  - {tool}")
            cli.console.print()
        
        except Exception as e:
            cli.console.print(f"\n[red]Error:[/red] {e}\n")
    
    elif subcommand == "list":
        from src.mcp.mcp_client import list_mcp_clients, get_mcp_client
        
        clients = list_mcp_clients()
        cli.console.print(f"\n[bold cyan]MCP Servers:[/bold cyan]")
        if not clients:
            cli.console.print("  [dim]No MCP servers connected[/dim]")
        else:
            for name in clients:
                client = get_mcp_client(name)
                tools_count = len(client.list_tools()) if client else 0
                cli.console.print(f"  [yellow]{name:15}[/yellow] - {tools_count} tools")
        cli.console.print()
    
    else:
        cli.console.print(f"\n[red]Unknown subcommand:[/red] {subcommand}\n")


@CommandRegistry.register("rag", "Manage RAG knowledge base", "/rag <on|off|status>")
def cmd_rag(cli, *args):
    """RAGナレッジベースの動的切り替え"""
    from src.core.rag_module.rag import RAGSwitch
    
    # RAGSwitchシングルトン取得
    rag_switch = getattr(cli, '_rag_switch', None)
    if rag_switch is None:
        rag_switch = RAGSwitch()
        cli._rag_switch = rag_switch
    
    action = args[0].lower() if args else "status"
    
    if action == "on":
        rag_switch.toggle(True)
        cli.console.print("\n[green]✓ RAG enabled[/green]")
        cli.console.print("[dim]Knowledge base will be used for queries.[/dim]\n")
    
    elif action == "off":
        rag_switch.toggle(False)
        cli.console.print("\n[yellow]✓ RAG disabled[/yellow]")
        cli.console.print("[dim]Queries will not use knowledge base.[/dim]\n")
    
    elif action == "status":
        status = "enabled" if rag_switch.enabled else "disabled"
        color = "green" if rag_switch.enabled else "yellow"
        cli.console.print(f"\n[bold cyan]RAG Status:[/bold cyan]")
        cli.console.print(f"  State: [{color}]{status}[/{color}]")
        
        # インジェスター情報
        if rag_switch._ingester:
            cli.console.print(f"  Ingester: Active")
        else:
            cli.console.print(f"  Ingester: Not initialized")
        cli.console.print()
    
    else:
        cli.console.print(f"\n[red]Unknown action:[/red] {action}")
        cli.console.print("[dim]Usage: /rag <on|off|status>[/dim]\n")


@CommandRegistry.register("sessions", "List saved sessions", "/sessions")
def cmd_sessions(cli, *args):
    """保存されたセッション一覧を表示"""
    from pathlib import Path
    from src.core.session import SessionManager
    
    # SessionManagerインスタンス取得（プロジェクトディレクトリはカレント）
    project_dir = Path.cwd()
    session_manager = SessionManager(project_dir)
    
    sessions = session_manager.list_sessions()
    
    if not sessions:
        cli.console.print("\n[yellow]No saved sessions found.[/yellow]")
        cli.console.print("[dim]Sessions are created when running with MasterConductor.[/dim]\n")
        return
    
    cli.console.print("\n[bold cyan]Saved Sessions:[/bold cyan]")
    cli.console.print(f"{'ID':<20} {'Project':<25} {'Mode':<12} {'Progress':<10} {'Updated':<20}")
    cli.console.print("-" * 90)
    
    for s in sessions:
        progress = s.scan_progress.get("progress_percent", 0)
        progress_str = f"{progress:.0f}%" if progress else "N/A"
        updated = s.last_updated.strftime("%Y-%m-%d %H:%M") if s.last_updated else "Unknown"
        
        cli.console.print(
            f"[yellow]{s.session_id:<20}[/yellow] "
            f"{s.project_name[:24]:<25} "
            f"{s.mode:<12} "
            f"{progress_str:<10} "
            f"{updated:<20}"
        )
    
    cli.console.print()
    cli.console.print("[dim]Use /resume <session_id> to continue a session.[/dim]\n")


@CommandRegistry.register("resume", "Resume a saved session", "/resume <session_id>")
def cmd_resume(cli, *args):
    """保存されたセッションから再開"""
    from pathlib import Path
    from src.core.session import SessionManager
    from src.core.engine.master_conductor import MasterConductor
    
    if not args:
        cli.console.print("\n[red]Error:[/red] Please specify a session ID")
        cli.console.print("[dim]Usage: /resume <session_id>[/dim]")
        cli.console.print("[dim]Use /sessions to list available sessions.[/dim]\n")
        return
    
    session_id = args[0]
    
    # SessionManagerインスタンス取得
    project_dir = Path.cwd()
    session_manager = SessionManager(project_dir)
    
    # MasterConductorを作成してセッション復元
    conductor = MasterConductor(session_manager=session_manager)
    
    if conductor.resume_session(session_id):
        pending_count = len(conductor.task_queue)
        cli.console.print(f"\n[green]✓ Session resumed:[/green] {session_id}")
        cli.console.print(f"  [cyan]Pending tasks:[/cyan] {pending_count}")
        cli.console.print(f"  [cyan]Target:[/cyan] {conductor.context.target_info.get('target', 'Unknown')}")
        
        if pending_count > 0:
            cli.console.print("\n[yellow]Run 'continue' to execute remaining tasks.[/yellow]")
        else:
            cli.console.print("\n[dim]No pending tasks. Session was completed.[/dim]")
        
        # CLIにconductorを保存（後続の実行で使用）
        cli._conductor = conductor
        cli.console.print()
    else:
        cli.console.print(f"\n[red]Error:[/red] Failed to resume session '{session_id}'")
        cli.console.print("[dim]Use /sessions to list available sessions.[/dim]\n")


@CommandRegistry.register("dalfox", "Run DalFox XSS scanner", "/dalfox <target_url>")
def cmd_dalfox(cli, *args):
    """DalFox XSSスキャナーを実行（新外部ツール統合基盤）"""
    import asyncio
    from src.core.adapters.external.dalfox_adapter import DalFoxAdapter
    from src.core.adapters.external.base_external_adapter import ToolInput
    from src.core.adapters.external.external_tool_executor import get_global_executor
    
    if not args:
        cli.console.print("\n[red]Error:[/red] Please specify a target URL")
        cli.console.print("[dim]Usage: /dalfox <target_url>[/dim]")
        cli.console.print("[dim]Example: /dalfox https://example.com/search?q=test[/dim]\n")
        return
    
    target_url = args[0]
    
    # URL検証（簡易）
    if not target_url.startswith(('http://', 'https://')):
        cli.console.print(f"\n[red]Error:[/red] Invalid URL: {target_url}")
        cli.console.print("[dim]URL must start with http:// or https://[/dim]\n")
        return
    
    cli.console.print(f"\n[bold cyan]Running DalFox XSS Scanner[/bold cyan]")
    cli.console.print(f"  [yellow]Target:[/yellow] {target_url}")
    cli.console.print(f"  [dim]Using new external tool integration framework[/dim]\n")
    
    async def run_scan():
        adapter = DalFoxAdapter()
        executor = get_global_executor()
        
        # ヘルスチェック
        cli.console.print("[dim]Checking DalFox availability...[/dim]")
        is_healthy = await adapter.health_check()
        
        if not is_healthy:
            cli.console.print("\n[red]✗ DalFox is not available[/red]")
            cli.console.print("[dim]Binary may not be installed or configured.[/dim]\n")
            return None
        
        cli.console.print("[green]✓ DalFox is available[/green]\n")
        
        # 実行
        result = await executor.execute(
            adapter,
            ToolInput(target=target_url)
        )
        
        return result
    
    try:
        result = asyncio.run(run_scan())
        
        if result is None:
            return
        
        # 結果表示
        if result.status.value == "success":
            cli.console.print(f"[green]✓ Scan completed in {result.execution_time_ms:.0f}ms[/green]\n")
            
            if result.data and len(result.data) > 0:
                cli.console.print(f"[bold red]⚠ {len(result.data)} XSS vulnerability(s) found:[/bold red]\n")
                
                for i, finding in enumerate(result.data, 1):
                    severity = finding.get("severity", "Unknown")
                    param = finding.get("param", "Unknown")
                    evidence = finding.get("evidence", "")
                    
                    # 深刻度に応じた色分け
                    severity_color = {
                        "High": "red",
                        "Medium": "yellow",
                        "Low": "blue"
                    }.get(severity, "white")
                    
                    cli.console.print(f"  [{severity_color}]#{i} {severity} Severity[/{severity_color}]")
                    cli.console.print(f"    [cyan]Parameter:[/cyan] {param}")
                    if evidence:
                        cli.console.print(f"    [cyan]Evidence:[/cyan] {evidence}")
                    cli.console.print()
            else:
                cli.console.print("[green]✓ No XSS vulnerabilities found[/green]\n")
                
        elif result.status.value == "timeout":
            cli.console.print(f"\n[yellow]⚠ Scan timed out[/yellow]")
            cli.console.print("[dim]Consider increasing timeout or checking target responsiveness.[/dim]\n")
            
        else:
            cli.console.print(f"\n[red]✗ Scan failed[/red]")
            if result.error_message:
                cli.console.print(f"[red]Error:[/red] {result.error_message}")
            cli.console.print()
        
        # セマフォ統計情報表示（デバッグ用）
        executor = get_global_executor()
        stats = executor.get_semaphore_stats()
        if stats.get("enabled"):
            cli.console.print(f"[dim]Execution stats:[/dim]")
            cli.console.print(f"  [dim]- Total executed: {stats.get('total_executed', 0)}[/dim]")
            cli.console.print(f"  [dim]- Avg wait time: {stats.get('avg_waiting_time_ms', 0):.1f}ms[/dim]\n")
            
    except Exception as e:
        cli.console.print(f"\n[red]✗ Unexpected error:[/red] {str(e)}")
        cli.console.print("[dim]Check logs for details.[/dim]\n")


@CommandRegistry.register("nuclei", "Run Nuclei vulnerability scanner", "/nuclei <target_url> [options]")
def cmd_nuclei(cli, *args):
    """Nuclei脆弱性スキャナーを実行（新外部ツール統合基盤）"""
    import asyncio
    from src.core.adapters.external.nuclei_adapter import NucleiAdapter
    from src.core.adapters.external.base_external_adapter import ToolInput
    from src.core.adapters.external.external_tool_executor import get_global_executor
    
    if not args:
        cli.console.print("\n[red]Error:[/red] Please specify a target URL")
        cli.console.print("[dim]Usage: /nuclei <target_url> [tags=cve,auth] [severity=critical,high][/dim]")
        cli.console.print("[dim]Example: /nuclei https://example.com tags=cve severity=critical,high[/dim]\n")
        return
    
    target_url = args[0]
    
    # URL検証（簡易）
    if not target_url.startswith(('http://', 'https://')):
        cli.console.print(f"\n[red]Error:[/red] Invalid URL: {target_url}")
        cli.console.print("[dim]URL must start with http:// or https://[/dim]\n")
        return
    
    # オプション解析
    options = {}
    for arg in args[1:]:
        if '=' in arg:
            key, value = arg.split('=', 1)
            options[key] = value
    
    tags = options.get('tags', 'cve,auth,misconfig')
    severity = options.get('severity', 'critical,high,medium')
    
    cli.console.print(f"\n[bold cyan]Running Nuclei Vulnerability Scanner[/bold cyan]")
    cli.console.print(f"  [yellow]Target:[/yellow] {target_url}")
    cli.console.print(f"  [dim]Tags:[/dim] {tags}")
    cli.console.print(f"  [dim]Severity:[/dim] {severity}\n")
    
    async def run_scan():
        adapter = NucleiAdapter()
        executor = get_global_executor()
        
        # ヘルスチェック
        cli.console.print("[dim]Checking Nuclei availability...[/dim]")
        is_healthy = await adapter.health_check()
        
        if not is_healthy:
            cli.console.print("\n[red]✗ Nuclei is not available[/red]")
            cli.console.print("[dim]Binary may not be installed or configured.[/dim]\n")
            return None
        
        cli.console.print("[green]✓ Nuclei is available[/green]\n")
        
        # 実行
        result = await executor.execute(
            adapter,
            ToolInput(
                target=target_url,
                options={"tags": tags, "severity": severity}
            )
        )
        
        return result
    
    try:
        result = asyncio.run(run_scan())
        
        if result is None:
            return
        
        # 結果表示
        if result.status.value == "success":
            cli.console.print(f"[green]✓ Scan completed in {result.execution_time_ms:.0f}ms[/green]\n")
            
            if result.data and len(result.data) > 0:
                cli.console.print(f"[bold red]⚠ {len(result.data)} vulnerability(s) found:[/bold red]\n")
                
                for i, finding in enumerate(result.data, 1):
                    severity = finding.get("severity", "unknown")
                    template_id = finding.get("template_id", "Unknown")
                    template_name = finding.get("template_name", "Unknown")
                    matched_at = finding.get("matched_at", "")
                    
                    # 深刻度に応じた色分け
                    severity_color = {
                        "critical": "red",
                        "high": "yellow",
                        "medium": "blue",
                        "low": "white",
                        "info": "dim"
                    }.get(severity, "white")
                    
                    cli.console.print(f"  [{severity_color}]#{i} [{severity.upper()}] {template_id}[/{severity_color}]")
                    cli.console.print(f"    [cyan]Name:[/cyan] {template_name}")
                    cli.console.print(f"    [cyan]Location:[/cyan] {matched_at}")
                    cli.console.print()
            else:
                cli.console.print("[green]✓ No vulnerabilities found[/green]\n")
                
        elif result.status.value == "timeout":
            cli.console.print(f"\n[yellow]⚠ Scan timed out[/yellow]")
            cli.console.print("[dim]Consider increasing timeout or checking target responsiveness.[/dim]\n")
            
        else:
            cli.console.print(f"\n[red]✗ Scan failed[/red]")
            if result.error_message:
                cli.console.print(f"[red]Error:[/red] {result.error_message}")
            cli.console.print()
        
        # セマフォ統計情報表示（デバッグ用）
        executor = get_global_executor()
        stats = executor.get_semaphore_stats()
        if stats.get("enabled"):
            cli.console.print(f"[dim]Execution stats:[/dim]")
            cli.console.print(f"  [dim]- Total executed: {stats.get('total_executed', 0)}[/dim]")
            cli.console.print(f"  [dim]- Avg wait time: {stats.get('avg_waiting_time_ms', 0):.1f}ms[/dim]\n")
            
    except Exception as e:
        cli.console.print(f"\n[red]✗ Unexpected error:[/red] {str(e)}")
        cli.console.print("[dim]Check logs for details.[/dim]\n")


@CommandRegistry.register("external-tools", "List external tools status", "/external-tools")
def cmd_external_tools(cli):
    """外部ツールの状態を一覧表示"""
    import asyncio
    from src.core.adapters.external.dalfox_adapter import DalFoxAdapter
    from src.core.adapters.external.nuclei_adapter import NucleiAdapter
    from src.core.adapters.external.external_tool_executor import get_global_executor
    from src.core.adapters.external.binary_manager import BinaryManager
    
    cli.console.print("\n[bold cyan]External Tools Status[/bold cyan]\n")
    
    # エグゼキューター統計
    executor = get_global_executor()
    stats = executor.get_semaphore_stats()
    
    cli.console.print("[bold]Executor Status:[/bold]")
    if stats.get("enabled"):
        cli.console.print(f"  [green]✓[/green] Semaphore control enabled")
        cli.console.print(f"  [dim]- Max concurrent: {stats.get('max_concurrent')}[/dim]")
        cli.console.print(f"  [dim]- Available slots: {stats.get('available_slots')}[/dim]")
        cli.console.print(f"  [dim]- Total executed: {stats.get('total_executed', 0)}[/dim]")
        if stats.get('avg_waiting_time_ms', 0) > 0:
            cli.console.print(f"  [dim]- Avg wait time: {stats.get('avg_waiting_time_ms', 0):.1f}ms[/dim]")
    else:
        cli.console.print("  [yellow]⚠[/yellow] Semaphore control disabled (unlimited)")
    cli.console.print()
    
    # ツール別ヘルスチェック
    cli.console.print("[bold]Tool Health Checks:[/bold]")
    
    async def check_tools():
        # DalFox
        dalfox = DalFoxAdapter()
        dalfox_healthy = await dalfox.health_check()
        
        if dalfox_healthy:
            cli.console.print(f"  [green]✓ DalFox[/green] - Available")
        else:
            cli.console.print(f"  [red]✗ DalFox[/red] - Not available")
            cli.console.print(f"    [dim]Run with /dalfox to trigger binary installation[/dim]")
        
        # Nuclei
        nuclei = NucleiAdapter()
        nuclei_healthy = await nuclei.health_check()
        
        if nuclei_healthy:
            cli.console.print(f"  [green]✓ Nuclei[/green] - Available")
        else:
            cli.console.print(f"  [red]✗ Nuclei[/red] - Not available")
            cli.console.print(f"    [dim]Run with /nuclei to trigger binary installation[/dim]")
    
    try:
        asyncio.run(check_tools())
    except Exception as e:
        cli.console.print(f"  [red]Error checking tools:[/red] {e}")
    
    cli.console.print()

