"""
SandboxLinuxCmd: サンドボックス内でのLinuxコマンド実行

Docker隔離環境内でコマンドを実行し、
試行錯誤ループを安全に行う。

Phase 3機能: config/features.yaml でオン/オフ可能
"""
from __future__ import annotations

import logging
import subprocess
import time
from dataclasses import dataclass
from typing import Optional

from src.tools.base import BaseTool
from src.core.config.feature_config import get_feature_config

logger = logging.getLogger(__name__)


@dataclass
class SandboxResult:
    """サンドボックス実行結果"""
    success: bool
    output: str
    exit_code: int
    execution_time: float
    attempt: int


class SandboxLinuxCmd(BaseTool):
    """
    Docker隔離環境内でLinuxコマンドを実行するツール
    
    特徴:
    - ネットワーク隔離オプション
    - 読み取り専用ファイルシステムオプション
    - 試行回数制限
    - タイムアウト設定
    
    使用例:
        sandbox = SandboxLinuxCmd()
        result = sandbox.run("cat /etc/passwd", max_retries=3)
    """
    
    name = "sandbox_linux_cmd"
    description = "Execute Linux commands in isolated Docker sandbox environment"

    # デフォルトのDockerイメージ
    DEFAULT_IMAGE = "alpine:latest"
    
    def __init__(self):
        self.config = get_feature_config().phase3.sandbox
        self._attempt_count = 0

    def is_enabled(self) -> bool:
        """機能が有効かチェック"""
        return self.config.enabled

    def to_schema(self) -> dict:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "description": "Linux command to execute in sandbox"
                        },
                        "image": {
                            "type": "string",
                            "description": f"Docker image to use (default: {self.DEFAULT_IMAGE})"
                        },
                        "network_isolated": {
                            "type": "boolean",
                            "description": "Disable network access (default: true)"
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Command timeout in seconds"
                        }
                    },
                    "required": ["command"]
                }
            }
        }

    def run(
        self,
        command: str,
        image: Optional[str] = None,
        network_isolated: Optional[bool] = None,
        timeout: Optional[int] = None,
        max_retries: Optional[int] = None,
    ) -> str:
        """
        サンドボックス内でコマンドを実行
        
        Args:
            command: 実行するコマンド
            image: 使用するDockerイメージ
            network_isolated: ネットワーク隔離
            timeout: タイムアウト（秒）
            max_retries: 最大試行回数
            
        Returns:
            実行結果
        """
        if not self.is_enabled():
            return "Error: Sandbox feature is disabled. Enable in config/features.yaml"

        # デフォルト値
        image = image or self.DEFAULT_IMAGE
        network_isolated = network_isolated if network_isolated is not None else self.config.network_isolated
        timeout = timeout or self.config.timeout_seconds
        max_retries = max_retries or self.config.max_retries

        # 試行回数チェック
        if self._attempt_count >= max_retries:
            return f"Error: Maximum retry limit reached ({max_retries})"

        self._attempt_count += 1
        
        # Dockerコマンド構築
        docker_cmd = ["docker", "run", "--rm"]
        
        if network_isolated:
            docker_cmd.append("--network=none")
        
        # 読み取り専用ファイルシステム
        docker_cmd.append("--read-only")
        
        # 一時書き込み領域
        docker_cmd.extend(["--tmpfs", "/tmp:rw,noexec,nosuid,size=64m"])
        
        # リソース制限
        docker_cmd.extend([
            "--memory=256m",
            "--cpus=0.5",
            "--pids-limit=100",
        ])
        
        # イメージとコマンド
        docker_cmd.extend([image, "sh", "-c", command])
        
        start_time = time.time()
        
        try:
            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            
            execution_time = time.time() - start_time
            
            output = result.stdout
            if result.stderr:
                output += f"\n[STDERR]\n{result.stderr}"
            
            if result.returncode != 0:
                output += f"\n[EXIT CODE: {result.returncode}]"
            
            logger.info(
                "Sandbox command executed: attempt=%d, exit_code=%d, time=%.2fs",
                self._attempt_count,
                result.returncode,
                execution_time
            )
            
            return output

        except subprocess.TimeoutExpired:
            return f"Error: Command timed out after {timeout} seconds"
        except FileNotFoundError:
            return "Error: Docker not found. Please install Docker to use sandbox feature."
        except Exception as e:
            logger.error("Sandbox execution error: %s", e)
            return f"Error: {e}"

    def reset_attempts(self) -> None:
        """試行回数をリセット"""
        self._attempt_count = 0

    def get_attempt_count(self) -> int:
        """現在の試行回数を取得"""
        return self._attempt_count


# シングルトンインスタンス
_sandbox_instance: Optional[SandboxLinuxCmd] = None


def get_sandbox_cmd() -> SandboxLinuxCmd:
    """SandboxLinuxCmdのシングルトンインスタンスを取得"""
    global _sandbox_instance
    if _sandbox_instance is None:
        _sandbox_instance = SandboxLinuxCmd()
    return _sandbox_instance
