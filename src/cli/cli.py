"""CLIメインインターフェース"""
import asyncio
import signal
import os
from rich.console import Console
from rich.panel import Panel
from rich.live import Live
from rich.spinner import Spinner
from src.core.engine.runner import Runner
from src.cli.commands import CommandRegistry
from src.cli.messages import msg

# readlineをインポート（入力履歴機能）
try:
    import readline
    READLINE_AVAILABLE = True
except ImportError:
    READLINE_AVAILABLE = False

class CLI:
    """[DEPRECATED] InteractiveBridgeに移行済み。このクラスは将来削除予定。"""
    
    def __init__(self, runner: Runner):
        self.runner = runner
        self.console = Console()
        self.running = True
        self.current_task = None
        
        # 入力履歴の設定
        if READLINE_AVAILABLE:
            self.history_file = os.path.expanduser("~/.cai_history")
            self._setup_readline()
    
    
    def _setup_readline(self):
        """readlineの設定"""
        # 履歴ファイルを読み込み
        try:
            readline.read_history_file(self.history_file)
        except FileNotFoundError:
            pass  # 初回起動時は履歴ファイルがない
        
        # 履歴の最大保存数
        readline.set_history_length(1000)
    
    def _save_history(self):
        """履歴をファイルに保存"""
        if READLINE_AVAILABLE:
            try:
                readline.write_history_file(self.history_file)
            except Exception:
                pass  # 保存に失敗しても無視
    
    def print_welcome(self):
        """ウェルカムメッセージ"""
        tool_names = [t.name for t in self.runner.agent.tools]
        welcome_text = msg("cli.welcome.body",
            title=msg("cli.welcome.header"),
            name=self.runner.agent.name,
            model=self.runner.agent.model,
            tool_list=', '.join(tool_names))
        panel = Panel(welcome_text, border_style="cyan")
        self.console.print(panel)
        self.console.print()
    
    def parse_command(self, user_input: str):
        """コマンドをパース"""
        if not user_input.startswith("/"):
            return None, None
        
        parts = user_input[1:].split()
        cmd_name = parts[0] if parts else ""
        args = parts[1:] if len(parts) > 1 else []
        
        return cmd_name, args
    
    async def execute_command(self, cmd_name: str, args: list):
        """コマンドを実行"""
        cmd_func = CommandRegistry.get(cmd_name)
        if cmd_func:
            cmd_func(self, *args)
        else:
            self.console.print(msg("cli.error.unknown_command", cmd=cmd_name))
            self.console.print(msg("cli.error.hint_help"))
    
    async def execute_agent_task(self, user_input: str):
        """エージェントタスクを実行"""
        self.runner.resume()  # 割り込みフラグをクリア
        
        with Live(Spinner("dots", text=msg("cli.processing")), console=self.console):
            try:
                # タスクを保存（Ctrl+Cで割り込めるように）
                self.current_task = asyncio.create_task(
                    self.runner.run(user_input)
                )
                response = await self.current_task
                
            except asyncio.CancelledError:
                response = msg("cli.cancelled")
            except Exception as e:
                response = f"Error: {e}"
            finally:
                self.current_task = None
        
        # 応答を表示
        self.console.print(msg("cli.response", response=response))
    
    async def repl(self):
        """非同期REPLループ"""
        # prompt_toolkitをインポート
        try:
            from prompt_toolkit import PromptSession
            from prompt_toolkit.key_binding import KeyBindings
            from prompt_toolkit.formatted_text import HTML
            from prompt_toolkit.styles import Style
            
            # キーバインディング設定
            bindings = KeyBindings()

            @bindings.add('c-enter')
            @bindings.add('escape', 'enter')  # Alt+Enter
            def _(event):
                """Ctrl+Enter または Alt+Enter で送信"""
                event.current_buffer.validate_and_handle()
                
            # プロンプトスタイル
            style = Style.from_dict({
                'prompt': '#0000ff bold',  # Blue bold
            })

            session = PromptSession(multiline=True, key_bindings=bindings)
            use_toolkit = True
        except ImportError:
            use_toolkit = False
            self.console.print(msg("cli.prompt_toolkit_missing"))
            session = None
            
        self.print_welcome()
        
        while self.running:
            try:
                # 入力を取得
                if use_toolkit:
                    # prompt_toolkitを使用 (multiline)
                    user_input = await asyncio.to_thread(
                        session.prompt, 
                        HTML('<prompt>[>] </prompt>'), 
                        style=style
                    )
                else:
                    # 標準inputを使用
                    user_input = await asyncio.to_thread(
                        input, 
                        "> "
                    )
                
                # 空入力はスキップ
                if not user_input.strip():
                    continue
                
                # 終了コマンド
                if user_input.lower() in ["exit", "quit"]:
                    break
                
                # コマンド処理
                cmd_name, args = self.parse_command(user_input)
                if cmd_name is not None:
                    await self.execute_command(cmd_name, args)
                else:
                    # エージェントタスク実行
                    await self.execute_agent_task(user_input)
            
            except KeyboardInterrupt:
                # Ctrl+Cで中断された場合（prompt_toolkit内）
                continue
            except EOFError:
                break
            except Exception as e:
                self.console.print(msg("cli.error.generic", error=str(e)))
    
    def run(self):
        """CLIを起動"""
        try:
            asyncio.run(self.repl())
        except KeyboardInterrupt:
            pass  # 正常終了
        finally:
            self._save_history()  # 履歴を保存
            self.console.print(msg("cli.goodbye"))
