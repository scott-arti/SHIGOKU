"""
Centralized Logger for SHIGOKU

プロジェクト全体で使用する統一ロギングシステム。
ログはカテゴリごとに分離して保存。

logs/
├── system/    # アプリケーションエラー
├── tasks/     # タスク遷移
├── tools/     # CLIツール全出力
├── findings/  # 発見ログ (JSONL)
└── debug/     # デバッグ情報
"""

import logging
import logging.handlers
import json
import queue
import asyncio
from pathlib import Path
import datetime
from typing import Optional, Any, Dict, List
from dataclasses import asdict
from rich.console import Console
from rich.theme import Theme
from rich.table import Table
from rich.tree import Tree
from rich.panel import Panel
from rich import box

# 相互参照を避けるための遅延インポート用
_async_writer = None


# ログディレクトリ
LOG_ROOT = Path(__file__).parent.parent.parent.parent / "logs"
LOG_CATEGORIES = ["system", "tasks", "tools", "findings", "debug"]


def _ensure_log_dirs() -> None:
    """ログディレクトリを作成"""
    for category in LOG_CATEGORIES:
        (LOG_ROOT / category).mkdir(parents=True, exist_ok=True)


def _get_log_path(category: str, target: str = "default") -> Path:
    """
    ログファイルパスを生成
    
    命名規則: YYYYMMDD_<category>_<target>.log
    """
    _ensure_log_dirs()
    date_str = datetime.datetime.now().strftime("%Y%m%d")
    safe_target = target.replace(".", "_").replace("/", "_")[:50]
    return LOG_ROOT / category / f"{date_str}_{category}_{safe_target}.log"


class ShigokuLogger:
    """SHIGOKU統一ロガー"""
    
    _instance: Optional["ShigokuLogger"] = None
    _initialized: bool = False  # クラス変数として宣言
    
    def __new__(cls) -> "ShigokuLogger":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        _ensure_log_dirs()
        self._que = queue.Queue(-1)  # 無制限キュー
        self._loggers: Dict[str, logging.Logger] = {}
        self._handlers: Dict[str, logging.Handler] = {}
        
        # Rich Console 設定
        self._custom_theme = Theme({
            "info": "cyan",
            "warning": "yellow",
            "error": "red bold",
            "success": "green bold",
            "thinking": "magenta",
            "recon": "blue",
            "finding": "red bold underline",
        })
        self.console = Console(theme=self._custom_theme)
        
        # コンソールハンドラ（INFO以上のみ）
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(logging.Formatter(
            "%(asctime)s | %(levelname)-7s | %(message)s",
            datefmt="%H:%M:%S"
        ))
        
        # キューハンドラの設定
        # 全カテゴリのログをこのキューに集約する
        self._queue_handler = logging.handlers.QueueHandler(self._que)
        
        for category in LOG_CATEGORIES:
            _logger = logging.getLogger(f"shigoku.{category}")
            _logger.setLevel(logging.DEBUG)
            _logger.addHandler(self._queue_handler)
            _logger.propagate = False  # 二重出力を防止
            self._loggers[category] = _logger
            
            # デフォルトのファイルターゲット用ハンドラ（Listenerに登録する用）
            self._handlers[category] = self._get_file_handler(category, "default")

        # Listenerの開始 (別スレッドでログを各ハンドラに分配)
        # 注意: ターゲット（ドメイン名）ごとにファイルを変える要件があるため、
        # Listener 側で動的に分配するか、主要なものだけ Listener で扱う。
        # ここでは基本ログを Listener で流す。
        self._listener = logging.handlers.QueueListener(
            self._que, 
            console_handler, 
            *[h for h in self._handlers.values()]
        )
        self._listener.start()
        
        self._initialized = True
    
    def _get_file_handler(self, category: str, target: str) -> logging.FileHandler:
        """ファイルハンドラを取得（日付ごとにローテーション）"""
        log_path = _get_log_path(category, target)
        handler = logging.FileHandler(log_path, encoding="utf-8")
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(logging.Formatter(
            "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"
        ))
        return handler
    
    def system(self, message: str, level: str = "info", target: str = "app") -> None:
        """システムログ（非同期）"""
        _logger = self._loggers["system"]
        # 特定ターゲットへのログ出力が必要な場合も、ここでは標準カテゴリに流す
        # (動的ハンドラ追加はボトルネックになるため、特別な理由がない限り一箇所に集約)
        getattr(_logger, level.lower())(f"[{target}] {message}")
        
        # EventBus連動 (Tier 7)
        if level.lower() in ["info", "warning", "error"]:
            try:
                from src.core.infra.event_bus import get_event_bus, Event, EventType
                eb = get_event_bus()
                eb.emit_sync(Event(
                    type=EventType.LOG_MESSAGE,
                    payload={"level": level.lower(), "message": message, "target": target},
                    source="ShigokuLogger"
                ))
            except ImportError:
                pass
            except Exception:
                pass
    
    def task(self, task_id: str, action: str, details: dict = None, target: str = "tasks") -> None:
        """タスク遷移ログ（非同期）"""
        _logger = self._loggers["tasks"]
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "task_id": task_id,
            "action": action,
            "details": details or {},
            "target": target
        }
        _logger.info(json.dumps(log_entry, ensure_ascii=False))
    
    def tool(self, tool_name: str, command: str, output: str, target: str = "tools") -> None:
        """CLIツール実行ログ（非同期）"""
        _logger = self._loggers["tools"]
        _logger.info(f"[{target}][{tool_name}] Command: {command}")
        # 出力が大きすぎる場合は省略
        if len(output) > 1000:
            _logger.debug(f"[{target}][{tool_name}] Output (truncated):\n{output[:1000]}...")
        else:
            _logger.debug(f"[{target}][{tool_name}] Output:\n{output}")
    
    def finding(self, finding: Any, target: str = "findings") -> None:
        """発見ログを非同期で保存（AsyncDatabaseWriterへの処理委譲）"""
        global _async_writer
        if _async_writer is None:
            try:
                from src.core.infra.async_writer import get_async_writer
                _async_writer = get_async_writer()
            except ImportError:
                pass

        # データの正規化
        if hasattr(finding, "to_dict"):
            data = finding.to_dict()
        elif hasattr(finding, "__dict__"):
            data = asdict(finding) if hasattr(finding, "__dataclass_fields__") else finding.__dict__
        else:
            data = {"finding": str(finding)}
        
        data["logged_at"] = datetime.datetime.now().isoformat()
        log_path = _get_log_path("findings", target).with_suffix(".jsonl")

        if _async_writer:
            # safe_run_async_forget を使用して、ループの有無を気にせず実行
            from src.core.utils.async_utils import safe_run_async_forget
            safe_run_async_forget(_async_writer.enqueue_jsonl(log_path, data))
        else:
            # フォールバック
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(data, ensure_ascii=False) + "\n")
    
    def debug(self, message: str, context: dict = None, target: str = "debug") -> None:
        """デバッグログ（非同期）"""
        _logger = self._loggers["debug"]
        if context:
            message = f"[{target}] {message} | Context: {json.dumps(context, ensure_ascii=False)}"
        else:
            message = f"[{target}] {message}"
        _logger.debug(message)
    
    def error(self, message: str, exc: Exception = None, target: str = "app") -> None:
        """エラーログ（システムカテゴリ）"""
        full_message = message
        if exc:
            full_message = f"{message} | Exception: {type(exc).__name__}: {exc}"
        self.system(full_message, level="error", target=target)
    
    def info(self, message: str, target: str = "app") -> None:
        """情報ログ（システムカテゴリ）"""
        self.system(message, level="info", target=target)
    
    def warning(self, message: str, target: str = "app") -> None:
        """警告ログ（システムカテゴリ）"""
        self.system(message, level="warning", target=target)

    # --- Rich Visual Methods ---

    def status(self, phase: str, message: str) -> None:
        """
        AIの状態を日本語アイコン付きで表示
        
        phase: recon, thinking, exploit, success, info, error
        """
        icons = {
            "recon": "🔍 [偵察]",
            "thinking": "🧠 [思考]",
            "exploit": "⚔️ [攻撃]",
            "success": "✅ [完了]",
            "info": "ℹ️ [情報]",
            "error": "❌ [エラー]",
            "finding": "🚨 [発見]"
        }
        icon = icons.get(phase, "🔹")
        style = phase if phase in self._custom_theme.styles else "white"
        
        # 標準ログにも記録
        self.system(f"{icon} {message}", level="info", target="rich")
        
        # コンソールへのリッチ出力
        self.console.print(f"[{style}]{icon} {message}[/{style}]")

    def show_tree(self, tree_data: Dict[str, Any], title: str = "Execution Tree") -> None:
        """
        実行のツリー構造を表示
        """
        tree = Tree(f"[bold blue]{title}[/bold blue]")
        
        def add_nodes(parent_tree: Tree, data: Any):
            if isinstance(data, dict):
                for key, value in data.items():
                    node = parent_tree.add(str(key))
                    add_nodes(node, value)
            elif isinstance(data, list):
                for item in data:
                    add_nodes(parent_tree, item)
            else:
                parent_tree.add(f"[cyan]{str(data)}[/cyan]")
        
        add_nodes(tree, tree_data)
        self.console.print(tree)

    def summary_table(self, title: str, columns: List[str], rows: List[List[Any]]) -> None:
        """
        結果をサマリー表として表示
        """
        table = Table(title=title, box=box.ROUNDED, header_style="bold magenta")
        
        for col in columns:
            table.add_column(col)
            
        for row in rows:
            formatted_row = [str(cell) for cell in row]
            table.add_row(*formatted_row)
            
        self.console.print(table)
        
    def show_panel(self, message: str, title: str = None, style: str = "info") -> None:
        """
        情報をパネルで囲んで強調表示
        """
        panel = Panel(message, title=title, style=style, border_style=style)
        self.console.print(panel)


# シングルトンインスタンス
logger = ShigokuLogger()


# 便利関数
def get_logger() -> ShigokuLogger:
    """ロガーインスタンスを取得"""
    return logger
