"""CLIコマンドレジストリとコマンド実装"""
import asyncio
from typing import Dict, Callable, Any
import json

from src.cli.messages import msg
from src.core.preflight import (
    EntryGateFacade,
    PreflightContext,
    GatePolicy,
    PreflightFailure,
    PreflightResult,
    PreflightStatus,
)


def _parse_cookie_string(cookie_str: str) -> dict[str, str]:
    """Parse a cookie string like 'a=1; b=2' into a dict."""
    if not cookie_str:
        return {}
    cookies: dict[str, str] = {}
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" in part:
            key, _, value = part.partition("=")
            key = key.strip()
            value = value.strip()
            if key:
                cookies[key] = value
    return cookies


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
    cli.console.print(f"\n{msg('cmd.help.header')}")
    for name, info in CommandRegistry.list_all().items():
        usage = info.get("usage") or f"/{name}"
        cli.console.print(f"  {msg('cmd.help.usage', usage=usage, desc=info['description'])}")
    cli.console.print()


@CommandRegistry.register("tools", "List available tools", "/tools")
def cmd_tools(cli):
    """利用可能なツール一覧を表示"""
    cli.console.print(f"\n{msg('cmd.tools.header')}")
    for tool in cli.runner.agent.tools:
        name = getattr(tool, "name", "unknown")
        desc = getattr(tool, "description", "No description")
        cli.console.print(f"  {msg('cmd.tools.entry', name=name, desc=desc)}")
    cli.console.print()


@CommandRegistry.register("history", "Show message history count", "/history")
def cmd_history(cli):
    """メッセージ履歴の数を表示"""
    count = len(cli.runner.agent.messages)
    cli.console.print(f"\n{msg('cmd.history.count', count=count)}")
    cli.console.print()


@CommandRegistry.register("model", "Change the LLM model", "/model <model_name>")
def cmd_model(cli, *args):
    """モデルを変更"""
    if not args:
        current = cli.runner.agent.model
        cli.console.print(f"\n{msg('cmd.model.current', current=current)}")
        
        cli.console.print(f"\n{msg('cmd.model.recommended')}")
        
        models = {
            "OpenAI": ["gpt-4o", "gpt-4-turbo", "gpt-3.5-turbo"],
            "Anthropic": ["claude-3-5-sonnet-20240620", "claude-3-opus-20240229"],
            "DeepSeek": ["deepseek/deepseek-v4-flash", "deepseek/deepseek-coder", "deepseek/deepseek-chat"]
        }
        
        for provider, model_list in models.items():
            cli.console.print(f"  {msg('cmd.model.provider', provider=provider)}")
            for m in model_list:
                marker = " [green]*[/green]" if m == current else ""
                cli.console.print(f"    {msg('cmd.model.entry', model=m, marker=marker)}")
        
        cli.console.print(f"\n{msg('cmd.model.usage_hint')}")
        cli.console.print(msg('cmd.model.note'))
        cli.console.print()
        return
    
    new_model = args[0]
    cli.runner.agent.model = new_model
    cli.runner.llm.model = new_model
    cli.console.print(f"\n{msg('cmd.model.changed', model=new_model)}")
    cli.console.print()


@CommandRegistry.register("agent", "Show current agent info", "/agent")
def cmd_agent(cli):
    """現在のエージェント情報を表示"""
    agent = cli.runner.agent
    cli.console.print(f"\n{msg('cmd.agent.header')}")
    cli.console.print(f"  {msg('cmd.agent.name', name=agent.name)}")
    cli.console.print(f"  {msg('cmd.agent.model', model=agent.model)}")
    cli.console.print(f"  {msg('cmd.agent.mode', mode=agent.mode)}")
    cli.console.print(f"  {msg('cmd.agent.tools', tools=len(agent.tools))}")
    cli.console.print(f"  {msg('cmd.agent.messages', messages=len(agent.messages))}")
    cli.console.print()


@CommandRegistry.register("mode", "Switch agent mode", "/mode [redteam|webpentest|bugbounty|ctf|security]")
def cmd_mode(cli, *args):
    """エージェントモードを切り替え"""
    if not args:
        current = cli.runner.agent.mode
        cli.console.print(f"\n{msg('cmd.mode.current', current=current)}")
        cli.console.print(f"\n{msg('cmd.mode.available')}")
        cli.console.print(f"  {msg('cmd.mode.desc_redteam')}")
        cli.console.print(f"  {msg('cmd.mode.desc_webpentest')}")
        cli.console.print(f"  {msg('cmd.mode.desc_bugbounty')}")
        cli.console.print(f"  {msg('cmd.mode.desc_ctf')}")
        cli.console.print(f"  {msg('cmd.mode.desc_security')}")
        cli.console.print(f"\n{msg('cmd.mode.usage_hint')}")
        cli.console.print()
        return
    
    new_mode = args[0].lower()
    valid_modes = ["redteam", "webpentest", "bugbounty", "ctf", "security", "general"]
    
    if new_mode not in valid_modes:
        cli.console.print(f"\n{msg('cmd.mode.invalid', mode=new_mode)}")
        cli.console.print(msg('cmd.mode.valid_list', modes=', '.join(valid_modes)))
        cli.console.print()
        return
    
    cli.runner.agent.switch_mode(new_mode)
    cli.console.print(f"\n{msg('cmd.mode.switched', mode=new_mode)}")
    
    # モードの説明を表示
    mode_desc_keys = {
        "redteam": "cmd.mode.desc_redteam",
        "webpentest": "cmd.mode.desc_webpentest",
        "bugbounty": "cmd.mode.desc_bugbounty",
        "ctf": "cmd.mode.desc_ctf",
        "security": "cmd.mode.desc_security",
    }
    if new_mode in mode_desc_keys:
        cli.console.print(f"[dim]{msg(mode_desc_keys[new_mode])}[/dim]")
    cli.console.print()


@CommandRegistry.register("graph", "Show execution graph", "/graph [ascii|mermaid]")
def cmd_graph(cli, *args):
    """実行グラフを表示"""
    if not hasattr(cli.runner, 'graph') or not cli.runner.graph:
        cli.console.print(f"\n{msg('cmd.graph.no_graph')}")
        cli.console.print(f"{msg('cmd.graph.hint')}\n")
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
    cli.console.print(f"\n{msg('cmd.graph.summary', summary=summary)}\n")


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
        cli.console.print(f"\n{msg('cmd.memory.saved', session_id=session_id)}\n")
    
    elif action == "clear":
        memory.clear_all()
        cli.console.print(f"\n{msg('cmd.memory.cleared')}\n")
    
    elif action == "stats":
        stats = memory.get_stats()
        cli.console.print(f"\n[bold cyan]{msg('cmd.memory.stats_header')}[/bold cyan]")
        cli.console.print(f"  {msg('cmd.memory.stats_sessions', count=stats['total'])}")
        if "by_mode" in stats:
            cli.console.print("  By mode:")
            for mode, count in stats["by_mode"].items():
                cli.console.print(f"    - {mode}: {count}")
        if "total_steps" in stats:
            cli.console.print(f"  {msg('cmd.memory.stats_total_steps', steps=stats['total_steps'])}")
        cli.console.print()
    
    else:  # list
        sessions = memory.list_sessions()
        if not sessions:
            cli.console.print(f"\n{msg('cmd.memory.no_sessions')}\n")
            return
        
        cli.console.print(f"\n[bold cyan]{msg('cmd.memory.sessions_header')}[/bold cyan]")
        for s in sessions:
            row = msg('cmd.memory.session_row',
                      session_id=f"ID:{s['id']:3}",
                      summary=f"{s['summary'][:40]:40}",
                      agent=f"{s['agent']:10}",
                      mode=f"{s['mode']:10}",
                      size=f"{s['size']:5}",
                      created=s['created'][:10])
            cli.console.print(f"  {row}")
        cli.console.print()


@CommandRegistry.register("agents", "List all registered agents", "/agents")
def cmd_agents(cli):
    """全エージェント一覧を表示"""
    from src.core.agent_registry import AgentRegistry
    
    agents = AgentRegistry.list_all()
    current = AgentRegistry.get_current()
    
    cli.console.print(f"\n{msg('cmd.agents.header')}")
    if not agents:
        cli.console.print(f"  {msg('cmd.agents.none')}")
    else:
        for name, agent in agents.items():
            marker = "→" if current and current.name == name else " "
            cli.console.print(f"  {msg('cmd.agents.entry', marker=marker, name=name, model=agent.model)}")
    cli.console.print()


@CommandRegistry.register("compact", "Compact conversation history", "/compact")
def cmd_compact(cli):
    """コンテキストを圧縮（古いメッセージを要約）"""
    # シンプルな実装: 最初のシステムメッセージと最新N件のみ保持
    KEEP_RECENT = 10
    
    messages = cli.runner.agent.messages
    if len(messages) <= KEEP_RECENT + 1:
        cli.console.print(f"\n{msg('cmd.compact.already')}\n")
        return
    
    # システムメッセージ + 最新のメッセージを保持
    system_msg = messages[0]
    recent_msgs = messages[-(KEEP_RECENT):]
    
    original_count = len(messages)
    cli.runner.agent.messages = [system_msg] + recent_msgs
    
    removed = original_count - len(cli.runner.agent.messages)
    cli.console.print(f"\n{msg('cmd.compact.done', removed=removed)}")
    cli.console.print(f"{msg('cmd.compact.current', count=len(cli.runner.agent.messages))}\n")


@CommandRegistry.register("load", "Load JSONL conversation log", "/load <file_path>")
def cmd_load(cli, *args):
    """JSONLファイルから過去のログをロード（In-Context Learning）"""
    if not args:
        cli.console.print(f"\n{msg('cmd.load.no_path')}")
        cli.console.print(f"{msg('cmd.load.usage')}\n")
        return
    
    file_path = args[0]
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            loaded = 0
            for line in f:
                if line.strip():
                    msg_data = json.loads(line)
                    # システムメッセージは除外
                    if msg_data.get("role") != "system":
                        cli.runner.agent.messages.append(msg_data)
                        loaded += 1
        
        cli.console.print(f"\n{msg('cmd.load.success', count=loaded, path=file_path)}\n")
    
    except FileNotFoundError:
        cli.console.print(f"\n{msg('cmd.load.not_found', path=file_path)}\n")
    except json.JSONDecodeError as e:
        cli.console.print(f"\n{msg('cmd.load.invalid_json', error=str(e))}\n")
    except Exception as e:
        cli.console.print(f"\n{msg('cmd.load.error', error=str(e))}\n")


@CommandRegistry.register("clear", "Clear conversation history", "/clear")
def cmd_clear(cli):
    """会話履歴をクリア（システムメッセージのみ残す）"""
    system_msg = cli.runner.agent.messages[0]
    cli.runner.agent.messages = [system_msg]
    cli.console.print(f"\n{msg('cmd.clear.done')}\n")


@CommandRegistry.register("mcp", "MCP server management", "/mcp <add|list> [args...]")
def cmd_mcp(cli, *args):
    """MCPサーバー管理"""
    if not args:
        cli.console.print(f"\n{msg('cmd.mcp.usage')}")
        cli.console.print(msg('cmd.mcp.help_add'))
        cli.console.print(f"{msg('cmd.mcp.help_list')}\n")
        return
    
    subcommand = args[0]
    
    if subcommand == "add":
        if len(args) < 2:
            cli.console.print(f"\n{msg('cmd.mcp.no_command')}")
            cli.console.print(f"{msg('cmd.mcp.example')}\n")
            return
        
        try:
            from src.mcp.mcp_client import add_mcp_server
            
            command = list(args[1:])
            server_name = f"mcp_{len(command)}"  # 簡易的な名前
            
            cli.console.print(f"\n{msg('cmd.mcp.connecting', command=' '.join(command))}")
            client = add_mcp_server(server_name, command)
            
            tools = client.list_tools()
            cli.console.print(msg('cmd.mcp.connected', count=len(tools)))
            for tool in tools:
                cli.console.print(f"  {msg('cmd.mcp.tool_entry', tool=tool)}")
            cli.console.print()
        
        except Exception as e:
            cli.console.print(f"\n{msg('cmd.mcp.error', error=str(e))}\n")
    
    elif subcommand == "list":
        from src.mcp.mcp_client import list_mcp_clients, get_mcp_client
        
        clients = list_mcp_clients()
        cli.console.print(f"\n{msg('cmd.mcp.header')}")
        if not clients:
            cli.console.print(f"  {msg('cmd.mcp.none')}")
        else:
            for name in clients:
                client = get_mcp_client(name)
                tools_count = len(client.list_tools()) if client else 0
                cli.console.print(f"  {msg('cmd.mcp.entry', name=name, count=tools_count)}")
        cli.console.print()
    
    else:
        cli.console.print(f"\n{msg('cmd.mcp.unknown_subcommand', subcommand=subcommand)}\n")


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
        cli.console.print(f"\n{msg('cmd.rag.enabled')}")
        cli.console.print(f"{msg('cmd.rag.enabled_hint')}\n")
    
    elif action == "off":
        rag_switch.toggle(False)
        cli.console.print(f"\n{msg('cmd.rag.disabled')}")
        cli.console.print(f"{msg('cmd.rag.disabled_hint')}\n")
    
    elif action == "status":
        status = "enabled" if rag_switch.enabled else "disabled"
        color = "green" if rag_switch.enabled else "yellow"
        cli.console.print(f"\n[bold cyan]{msg('cmd.rag.status_header')}[/bold cyan]")
        cli.console.print(f"  State: [{color}]{status}[/{color}]")
        
        # インジェスター情報
        ingester_status = "Active" if rag_switch._ingester else "Not initialized"
        cli.console.print(f"  {msg('cmd.rag.ingester_status', status=ingester_status)}")
        cli.console.print()
    
    else:
        cli.console.print(f"\n{msg('cmd.rag.unknown_action', action=action)}")
        cli.console.print(f"{msg('cmd.rag.usage')}\n")


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
        cli.console.print(f"\n{msg('cmd.sessions.none')}")
        cli.console.print(f"{msg('cmd.sessions.hint')}\n")
        return
    
    cli.console.print(f"\n[bold cyan]{msg('cmd.sessions.header')}[/bold cyan]")
    cli.console.print(f"{msg('cmd.sessions.col_id'):<20} {msg('cmd.sessions.col_project'):<25} {msg('cmd.sessions.col_mode'):<12} {msg('cmd.sessions.col_progress'):<10} {msg('cmd.sessions.col_updated'):<20}")
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
    cli.console.print(f"{msg('cmd.sessions.resume_hint')}\n")


@CommandRegistry.register("resume", "Resume a saved session", "/resume <session_id>")
def cmd_resume(cli, *args):
    """保存されたセッションから再開"""
    from pathlib import Path
    from src.core.session import SessionManager
    from src.core.engine.master_conductor import MasterConductor
    
    if not args:
        cli.console.print(f"\n{msg('cmd.resume.no_id')}")
        cli.console.print(f"[dim]{msg('cmd.resume.usage')}[/dim]")
        cli.console.print(f"[dim]{msg('cmd.resume.list_hint')}[/dim]\n")
        return
    
    session_id = args[0]
    
    # SessionManagerインスタンス取得
    project_dir = Path.cwd()
    session_manager = SessionManager(project_dir)

    # Load session first to validate completeness
    saved_session = session_manager.load_session(session_id)

    # Fail-close: session must exist and have target_url
    if saved_session is None or not str(getattr(saved_session, "target_url", "") or "").strip():
        result = PreflightResult(
            status=PreflightStatus.FAIL,
            failures=[
                PreflightFailure(
                    reason_code="RESUME_CONTEXT_INCOMPLETE",
                    severity="critical",
                    category="session",
                    remediation=(
                        "The saved session has no target_url. "
                        "Provide a target with --target or use /sessions "
                        "to select a complete session."
                    ),
                )
            ],
        )
        for failure in result.failures:
            cli.console.print(f"[red][GATE] {failure.reason_code}: {failure.remediation}[/red]")
        cli.console.print("[red]Preflight entry gate failed — aborting resume.[/red]")
        return

    # Preflight gate check before resume — extract context from saved session
    try:
        resume_mode = str(getattr(saved_session, "mode", "") or "").strip() or "bugbounty"
        resume_target = str(getattr(saved_session, "target_url", "") or "").strip()
        session_metadata: dict = getattr(saved_session, "metadata", {}) or {}
        # Checkpoint saves cookies/auth in metadata["context"]
        ctx: dict = session_metadata.get("context", {}) or {}
        session_cookies = str(
            ctx.get("cookies", "")
            or session_metadata.get("cookies", "")
            or ""
        )
        session_bearer = str(
            ctx.get("bearer_token", "")
            or session_metadata.get("bearer_token", "")
            or ""
        )
        session_auth_headers: dict = (
            ctx.get("auth_headers", {})
            or session_metadata.get("auth_headers", {})
            or {}
        )
        session_goal = str(
            ctx.get("goal", "")
            or session_metadata.get("goal", "")
            or resume_mode
        ).strip() or "recon"
        session_profile = str(session_metadata.get("profile", "") or "").strip()

        gate_context = PreflightContext(
            target=resume_target,
            mode=resume_mode,
            goal=session_goal,
            profile=session_profile,
            cookies=_parse_cookie_string(session_cookies),
            bearer_token=session_bearer,
            auth_headers=session_auth_headers,
            resume_session_id=session_id,
            gate_policy=GatePolicy.STRICT_PROD,
        )
        result = asyncio.run(EntryGateFacade().run_once(gate_context))
        if result.failed:
            from src.core.preflight.reporter import format_failures_for_cli
            cli.console.print(format_failures_for_cli(result))
            return
    except ImportError:
        # reporter module not available, fallback to simple output
        result = asyncio.run(EntryGateFacade().run_once(
            PreflightContext(resume_session_id=session_id, gate_policy=GatePolicy.STRICT_PROD)
        ))
        if result.failed:
            for failure in result.failures:
                cli.console.print(f"[red][GATE] {failure.reason_code}: {failure.remediation}[/red]")
            cli.console.print("[red]Preflight entry gate failed — aborting resume.[/red]")
            return

    # MasterConductorを作成してセッション復元
    conductor = MasterConductor(session_manager=session_manager)
    
    if conductor.resume_session(session_id):
        pending_count = len(conductor.task_queue)
        cli.console.print(f"\n{msg('cmd.resume.success', session_id=session_id)}")
        cli.console.print(f"  {msg('cmd.resume.pending', count=pending_count)}")
        cli.console.print(f"  {msg('cmd.resume.target', target=conductor.context.target_info.get('target', 'Unknown'))}")
        
        if pending_count > 0:
            cli.console.print(f"\n{msg('cmd.resume.hint_continue')}")
        else:
            cli.console.print(f"\n{msg('cmd.resume.no_pending')}")
        
        # CLIにconductorを保存（後続の実行で使用）
        cli._conductor = conductor
        cli.console.print()
    else:
        cli.console.print(f"\n{msg('cmd.resume.failed', session_id=session_id)}")
        cli.console.print(f"[dim]{msg('cmd.resume.failed_hint')}[/dim]\n")


@CommandRegistry.register("dalfox", "Run DalFox XSS scanner", "/dalfox <target_url>")
def cmd_dalfox(cli, *args):
    """DalFox XSSスキャナーを実行（新外部ツール統合基盤）"""
    import asyncio
    from src.core.adapters.external.dalfox_adapter import DalFoxAdapter
    from src.core.adapters.external.base_external_adapter import ToolInput
    from src.core.adapters.external.external_tool_executor import get_global_executor
    
    if not args:
        cli.console.print(f"\n{msg('cmd.dalfox.no_url')}")
        cli.console.print(f"[dim]{msg('cmd.dalfox.usage')}[/dim]")
        cli.console.print(f"[dim]{msg('cmd.dalfox.example')}[/dim]\n")
        return
    
    target_url = args[0]
    
    # URL検証（簡易）
    if not target_url.startswith(('http://', 'https://')):
        cli.console.print(f"\n{msg('cmd.dalfox.invalid_url', url=target_url)}")
        cli.console.print(f"{msg('cmd.dalfox.url_hint')}\n")
        return
    
    cli.console.print(f"\n[bold cyan]{msg('cmd.dalfox.header')}[/bold cyan]")
    cli.console.print(f"  {msg('cmd.dalfox.target', target=target_url)}")
    cli.console.print(f"  [dim]{msg('cmd.dalfox.framework')}[/dim]\n")
    
    async def run_scan():
        adapter = DalFoxAdapter()
        executor = get_global_executor()
        
        # ヘルスチェック
        cli.console.print(msg('cmd.dalfox.checking'))
        is_healthy = await adapter.health_check()
        
        if not is_healthy:
            cli.console.print(f"\n{msg('cmd.dalfox.not_available')}")
            cli.console.print(f"{msg('cmd.dalfox.not_available_hint')}\n")
            return None
        
        cli.console.print(f"{msg('cmd.dalfox.available')}\n")
        
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
            cli.console.print(f"{msg('cmd.dalfox.completed', time=result.execution_time_ms)}\n")
            
            if result.data and len(result.data) > 0:
                cli.console.print(f"{msg('cmd.dalfox.vulns_found', count=len(result.data))}\n")
                
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
                cli.console.print(f"{msg('cmd.dalfox.no_vulns')}\n")
                
        elif result.status.value == "timeout":
            cli.console.print(f"\n{msg('cmd.dalfox.timeout')}")
            cli.console.print(f"{msg('cmd.dalfox.timeout_hint')}\n")
            
        else:
            cli.console.print(f"\n{msg('cmd.dalfox.failed')}")
            if result.error_message:
                cli.console.print(msg('cmd.dalfox.error', error=result.error_message))
            cli.console.print()
        
        # セマフォ統計情報表示（デバッグ用）
        executor = get_global_executor()
        stats = executor.get_semaphore_stats()
        if stats.get("enabled"):
            cli.console.print(f"[dim]{msg('cmd.dalfox.exec_stats')}[/dim]")
            cli.console.print(f"  [dim]{msg('cmd.dalfox.total_executed', count=stats.get('total_executed', 0))}[/dim]")
            cli.console.print(f"  [dim]{msg('cmd.dalfox.avg_wait', time=stats.get('avg_waiting_time_ms', 0))}[/dim]\n")
            
    except Exception as e:
        cli.console.print(f"\n{msg('cmd.dalfox.unexpected_error', error=str(e))}")
        cli.console.print(f"{msg('cmd.dalfox.check_logs')}\n")


@CommandRegistry.register("nuclei", "Run Nuclei vulnerability scanner", "/nuclei <target_url> [options]")
def cmd_nuclei(cli, *args):
    """Nuclei脆弱性スキャナーを実行（新外部ツール統合基盤）"""
    import asyncio
    from src.core.adapters.external.nuclei_adapter import NucleiAdapter
    from src.core.adapters.external.base_external_adapter import ToolInput
    from src.core.adapters.external.external_tool_executor import get_global_executor
    
    if not args:
        cli.console.print(f"\n{msg('cmd.nuclei.no_url')}")
        cli.console.print(f"[dim]{msg('cmd.nuclei.usage')}[/dim]")
        cli.console.print(f"[dim]{msg('cmd.nuclei.example')}[/dim]\n")
        return
    
    target_url = args[0]
    
    # URL検証（簡易）
    if not target_url.startswith(('http://', 'https://')):
        cli.console.print(f"\n{msg('cmd.nuclei.invalid_url', url=target_url)}")
        cli.console.print(f"{msg('cmd.nuclei.url_hint')}\n")
        return
    
    # オプション解析
    options = {}
    for arg in args[1:]:
        if '=' in arg:
            key, value = arg.split('=', 1)
            options[key] = value
    
    tags = options.get('tags', 'cve,auth,misconfig')
    severity = options.get('severity', 'critical,high,medium')
    
    cli.console.print(f"\n[bold cyan]{msg('cmd.nuclei.header')}[/bold cyan]")
    cli.console.print(f"  {msg('cmd.nuclei.target', target=target_url)}")
    cli.console.print(f"  [dim]{msg('cmd.nuclei.tags', tags=tags)}[/dim]")
    cli.console.print(f"  [dim]{msg('cmd.nuclei.severity', severity=severity)}[/dim]\n")
    
    async def run_scan():
        adapter = NucleiAdapter()
        executor = get_global_executor()
        
        # ヘルスチェック
        cli.console.print(msg('cmd.nuclei.checking'))
        is_healthy = await adapter.health_check()
        
        if not is_healthy:
            cli.console.print(f"\n{msg('cmd.nuclei.not_available')}")
            cli.console.print(f"{msg('cmd.nuclei.not_available_hint')}\n")
            return None
        
        cli.console.print(f"{msg('cmd.nuclei.available')}\n")
        
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
            cli.console.print(f"{msg('cmd.nuclei.completed', time=result.execution_time_ms)}\n")
            
            if result.data and len(result.data) > 0:
                cli.console.print(f"{msg('cmd.nuclei.vulns_found', count=len(result.data))}\n")
                
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
                cli.console.print(f"{msg('cmd.nuclei.no_vulns')}\n")
                
        elif result.status.value == "timeout":
            cli.console.print(f"\n{msg('cmd.nuclei.timeout')}")
            cli.console.print(f"{msg('cmd.nuclei.timeout_hint')}\n")
            
        else:
            cli.console.print(f"\n{msg('cmd.nuclei.failed')}")
            if result.error_message:
                cli.console.print(msg('cmd.nuclei.error', error=result.error_message))
            cli.console.print()
        
        # セマフォ統計情報表示（デバッグ用）
        executor = get_global_executor()
        stats = executor.get_semaphore_stats()
        if stats.get("enabled"):
            cli.console.print(f"[dim]{msg('cmd.nuclei.exec_stats')}[/dim]")
            cli.console.print(f"  [dim]{msg('cmd.nuclei.total_executed', count=stats.get('total_executed', 0))}[/dim]")
            cli.console.print(f"  [dim]{msg('cmd.nuclei.avg_wait', time=stats.get('avg_waiting_time_ms', 0))}[/dim]\n")
            
    except Exception as e:
        cli.console.print(f"\n{msg('cmd.nuclei.unexpected_error', error=str(e))}")
        cli.console.print(f"{msg('cmd.nuclei.check_logs')}\n")


@CommandRegistry.register("external-tools", "List external tools status", "/external-tools")
def cmd_external_tools(cli):
    """外部ツールの状態を一覧表示"""
    import asyncio
    from src.core.adapters.external.dalfox_adapter import DalFoxAdapter
    from src.core.adapters.external.nuclei_adapter import NucleiAdapter
    from src.core.adapters.external.external_tool_executor import get_global_executor
    from src.core.adapters.external.binary_manager import BinaryManager
    
    cli.console.print(f"\n{msg('cmd.external_tools.header')}\n")
    
    # エグゼキューター統計
    executor = get_global_executor()
    stats = executor.get_semaphore_stats()
    
    cli.console.print(msg('cmd.external_tools.executor_title'))
    if stats.get("enabled"):
        cli.console.print(f"  [green]✓[/green] {msg('cmd.external_tools.semaphore', status='有効')}")
        cli.console.print(f"  [dim]{msg('cmd.external_tools.max_concurrent', max_concurrent=stats.get('max_concurrent'))}[/dim]")
        cli.console.print(f"  [dim]{msg('cmd.external_tools.current_slots', slots=stats.get('available_slots'))}[/dim]")
        cli.console.print(f"  [dim]{msg('cmd.external_tools.total_executed', executed=stats.get('total_executed', 0))}[/dim]")
        if stats.get('avg_waiting_time_ms', 0) > 0:
            wait_ms = f"{stats.get('avg_waiting_time_ms', 0):.1f}ms"
            cli.console.print(f"  [dim]{msg('cmd.external_tools.waiting', waiting=wait_ms)}[/dim]")
    else:
        cli.console.print(f"  [yellow]⚠[/yellow] {msg('cmd.external_tools.semaphore', status='無効（無制限）')}")
    cli.console.print()
    
    # ツール別ヘルスチェック
    cli.console.print(msg('cmd.external_tools.health_title'))
    
    async def check_tools():
        # DalFox
        dalfox = DalFoxAdapter()
        dalfox_healthy = await dalfox.health_check()
        
        if dalfox_healthy:
            cli.console.print(f"  [green]✓ {msg('cmd.external_tools.health_tool', tool='DalFox', status='利用可能')}[/green]")
        else:
            cli.console.print(f"  [red]✗ {msg('cmd.external_tools.health_tool', tool='DalFox', status='利用不可')}[/red]")
            cli.console.print(f"    {msg('cmd.external_tools.health_hint')}")
        
        # Nuclei
        nuclei = NucleiAdapter()
        nuclei_healthy = await nuclei.health_check()
        
        if nuclei_healthy:
            cli.console.print(f"  [green]✓ {msg('cmd.external_tools.health_tool', tool='Nuclei', status='利用可能')}[/green]")
        else:
            cli.console.print(f"  [red]✗ {msg('cmd.external_tools.health_tool', tool='Nuclei', status='利用不可')}[/red]")
            cli.console.print(f"    {msg('cmd.external_tools.health_hint')}")
    
    try:
        asyncio.run(check_tools())
    except Exception as e:
        cli.console.print(msg('cmd.external_tools.error', error=str(e)))
    
    cli.console.print()

