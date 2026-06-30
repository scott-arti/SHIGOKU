"""
外部ツール実行の共通基盤

DEV_MODE 対応でモック実行をサポートし、テスト容易性を確保する。
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class ToolNotFoundError(Exception):
    """必須ツールが見つからない場合の例外"""
    pass


class ToolRunner:
    """外部ツール実行ラッパー
    
    DEV_MODE (SHIGOKU_DEV_MODE=true) の場合はモック出力を返す。
    本番モードでは実際の外部ツールを subprocess で実行。
    """
    
    def __init__(
        self,
        dev_mode: bool | None = None,
        demo_provider: Any | None = None,
    ) -> None:
        """初期化
        
        Args:
            dev_mode: 開発モード（None の場合は環境変数から判定）
        """
        if dev_mode is None:
            dev_mode = os.getenv("SHIGOKU_DEV_MODE", "").lower() == "true"
        
        self.dev_mode = dev_mode
        self.demo_provider = demo_provider
        logger.info("ToolRunner initialized (DEV_MODE=%s)", self.dev_mode)

    def get_demo_provider(self) -> Any | None:
        """Return the active demo provider, creating the default one lazily."""
        if not self.dev_mode:
            return None

        if self.demo_provider is None:
            from src.recon.demo import ReconDemoProvider

            self.demo_provider = ReconDemoProvider()

        return self.demo_provider
    
    def check_tools(self, tools: list[str]) -> None:
        """必須ツールの存在確認
        
        Args:
            tools: チェックするツール名のリスト
        
        Raises:
            ToolNotFoundError: ツールが見つからない場合
        """
        demo_provider = self.get_demo_provider()
        if demo_provider is not None:
            logger.info("DEV_MODE: Skipping tool check for %s", ", ".join(tools))
            demo_provider.check_tools(tools)
            return
        
        missing = []
        for tool in tools:
            if not shutil.which(tool):
                missing.append(tool)
        
        if missing:
            msg = f"Required tools not found: {', '.join(missing)}\n"
            msg += "Please install them on your system.\n"
            msg += "If you are running in Docker, ensure these tools are installed inside the container.\n"
            msg += "Alternatively, set SHIGOKU_DEV_MODE=true to use mock outputs for testing."
            raise ToolNotFoundError(msg)
        
        logger.info("All required tools found: %s", ", ".join(tools))

    def is_tool_available(self, tool_name: str) -> bool:
        """ツールが利用可能か確認
        
        Args:
            tool_name: ツール名
            
        Returns:
            bool: 利用可能な場合 True
        """
        demo_provider = self.get_demo_provider()
        if demo_provider is not None:
            return demo_provider.is_tool_available(tool_name)
        return shutil.which(tool_name) is not None
    
    async def run(
        self,
        cmd: list[str],
        timeout: int,
        mock_output: str = "",
        cwd: Path | None = None,
    ) -> str:
        """外部ツールを実行
        
        Args:
            cmd: コマンドリスト (例: ["subfinder", "-d", "example.com"])
            timeout: タイムアウト秒数
            mock_output: DEV_MODE 時に返すモック出力 (空の場合はデフォルトを使用)
            cwd: 実行ディレクトリ
        
        Returns:
            stdout の出力文字列
        """
        cmd_str = " ".join(cmd)
        
        demo_provider = self.get_demo_provider()
        if demo_provider is not None:
            logger.info("DEV_MODE: Mocking command: %s", cmd_str)
            return demo_provider.get_command_output(cmd, mock_output)
        
        logger.info("Executing: %s (timeout=%ds)", cmd_str, timeout)
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(cwd) if cwd else None,
            )
            
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout,
            )
            
            stdout_str = stdout.decode("utf-8", errors="replace")
            stderr_str = stderr.decode("utf-8", errors="replace")
            
            if proc.returncode != 0:
                logger.warning(
                    "Command failed (exit=%d): %s\nStderr: %s",
                    proc.returncode,
                    cmd_str,
                    stderr_str[:500],  # 最初の500文字のみ
                )
            
            return stdout_str
        
        except FileNotFoundError as e:
            raise ToolNotFoundError(f"Tool not found: {cmd[0]}") from e
        
        except asyncio.TimeoutError:
            logger.error("Command timed out after %ds: %s", timeout, cmd_str)
            if proc:
                proc.kill()
                await proc.wait()
            raise
        
        except Exception as e:
            logger.error("Command execution failed: %s - %s", cmd_str, e)
            raise

    async def run_json(
        self,
        cmd: list[str],
        timeout: int,
        mock_output: str = "",
        cwd: Path | None = None,
    ) -> list[dict[str, Any]]:
        """JSON/JSONL 出力を返すツールを実行
        
        Args:
            cmd: コマンドリスト
            timeout: タイムアウト秒数
            mock_output: DEV_MODE 時のモック出力
            cwd: 実行ディレクトリ
        
        Returns:
            パースされた JSON オブジェクトのリスト
        """
        import json
        
        output = await self.run(cmd, timeout, mock_output, cwd)
        
        results = []
        for line in output.strip().split("\n"):
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError as e:
                logger.warning("Failed to parse JSON line: %s - %s", line[:100], e)
        
        return results
