"""
Notifier: System-wide notification wrapper using projectdiscovery/notify.
"""
import logging
import shutil
import subprocess
from typing import Optional, Dict

from src.core.models.finding import Finding, Severity
from src.config import settings

logger = logging.getLogger(__name__)

from pathlib import Path

class Notifier:
    """
    Wrapper for projectdiscovery/notify tool.
    Sends notifications to configured providers (Discord, Slack, etc.) via CLI.
    """
    
    def __init__(self):
        self.notify_path = shutil.which("notify")
        self.config_path: Optional[str] = None
        
        # Check for config in common locations
        # 1. Standard config path (~/.config/notify/provider-config.yaml)
        # 2. Project config path (config/provider-config.yaml)
        # 3. Docker Project config path (/app/config/provider-config.yaml)
        possible_configs = [
            Path.home() / ".config/notify/provider-config.yaml",
            Path("config/provider-config.yaml"),
            Path("/app/config/provider-config.yaml")
        ]
        
        for p in possible_configs:
            if p.exists():
                self.config_path = str(p)
                break

        if not self.notify_path:
            logger.warning("'notify' tool not found in PATH. Notifications will be disabled.")
        elif not self.config_path:
            # Config missing is common in dev/test, just warn once
            logger.warning("Notify config not found (checked ~/.config/notify/provider-config.yaml etc). Notifications will be disabled.")

    def notify(self, message: str, provider: Optional[str] = None, bulk: bool = False) -> bool:
        """
        Send a raw text notification.
        
        Args:
            message: The message content to send.
            provider: Specific provider ID to use (optional). If None, uses all providers.
            bulk: Whether to send as bulk (one message) or line-by-line (default false, but for single msg it doesn't matter much).
                  The `notify` tool defaults to line-by-line. -bulk sends the whole input as one notification.
        
        Returns:
            bool: True if command execution was successful, False otherwise.
        """
        if not self.notify_path or not self.config_path:
            return False

        if not message:
            return False

        # Build command
        # echo "message" | notify -silent [-provider provider] [-bulk] [-config config]
        cmd = [self.notify_path, "-silent"]
        
        if self.config_path:
            cmd.extend(["-config", self.config_path])
        
        if provider:
            cmd.extend(["-provider", provider])
        
        if bulk:
            cmd.append("-bulk")

        try:
            # We pass message via stdin
            process = subprocess.run(
                cmd,
                input=message,
                capture_output=True,
                text=True,
                check=False
            )
            
            if process.returncode == 0:
                return True
            else:
                logger.warning("Notify command failed (non-fatal): %s", process.stderr)
                return False
                
        except Exception as e:
            logger.error("Error executing notify: %s", e)
            return False

    def notify_finding(self, finding: Finding) -> bool:
        """
        Format and send a notification for a security finding.
        
        Args:
            finding: The Finding object.
            
        Returns:
            bool: True if sent successfully.
        """
        if not self.notify_path:
            return False

        # Simple text formatting for broad compatibility
        icon = finding.get_severity_icon()
        severity_str = finding.severity.value.upper()
        
        message = (
            f"{icon} **[{severity_str}] {finding.title}**\n"
            f"Type: {finding.vuln_type.value}\n"
            f"Target: {finding.target_url}\n"
            f"Confidence: {int(finding.confidence * 100)}%\n"
            f"\n"
            f"{finding.description}\n"
            f"\n"
            f"Agent: {finding.source_agent}"
        )
        
        # CRITICALの場合はメンションを追加
        if finding.severity == Severity.CRITICAL and settings.notify_critical_mention:
            message = f"{settings.notify_critical_mention}\n{message}"
        
        # Use bulk to keep newlines intact
        return self.notify(message, bulk=True)

    def notify_event(
        self,
        event_type: str,
        target: str,
        details: Optional[Dict] = None,
    ) -> bool:
        """
        Phase 6.2: イベントタイプに応じた通知を送信
        
        Args:
            event_type: イベントタイプ文字列 (SCAN_STARTED, VULN_HUNTING, etc.)
            target: ターゲットURL
            details: 追加情報
            
        Returns:
            bool: True if sent successfully.
        """
        if not self.notify_path:
            return False
        
        # フィルタリング設定確認
        notify_level = getattr(settings, 'notify_level', 'found')
        
        # フィルタリングリスト
        if notify_level == 'critical':
            allowed = ['vuln_found']
        elif notify_level == 'found':
            allowed = ['vuln_found', 'vuln_not_found']
        else:  # 'all'
            allowed = ['scan_started', 'vuln_hunting', 'vuln_found', 'vuln_not_found', 'agent_dispatched']
        
        if event_type.lower() not in allowed:
            return False
        
        # イベントタイプに応じた絵文字とタイトル
        event_formats = {
            'scan_started': ('🚀', 'スキャン開始'),
            'vuln_hunting': ('🔍', '脆弱性探索中'),
            'vuln_found': ('🎯', '脆弱性発見'),
            'vuln_not_found': ('✅', '探索完了 (Not Found)'),
            'agent_dispatched': ('🤖', 'エージェント起動'),
        }
        
        icon, title = event_formats.get(event_type.lower(), ('📢', event_type))
        
        message = f"{icon} **{title}**\nTarget: {target}\n"
        
        if details:
            for key, value in details.items():
                message += f"- {key}: {value}\n"
        
        return self.notify(message, bulk=True)


    def notify_action_required(
        self,
        action_type: str,
        message: str,
        details: Optional[Dict] = None,
    ) -> bool:
        """
        ユーザーアクションを要求する通知を送信
        
        Args:
            action_type: アクションタイプ (IDOR_CROSS_TEST, MANUAL_REVIEW等)
            message: 表示メッセージ
            details: 追加情報
            
        Returns:
            bool: True if sent successfully.
        """
        if not self.notify_path:
            return False
        
        # フォーマット
        formatted = (
            f"🔔 **ACTION REQUIRED: {action_type}**\n"
            f"\n"
            f"{message}\n"
        )
        
        if details:
            formatted += "\n**Details:**\n"
            for key, value in details.items():
                formatted += f"- {key}: {value}\n"
        
        formatted += (
            "\n"
            "---\n"
            "Please complete the required action and re-run the command."
        )
        
        return self.notify(formatted, bulk=True)

# Singleton instance
_notifier_instance: Optional[Notifier] = None

def get_notifier() -> Notifier:
    """Get singleton Notifier instance."""
    global _notifier_instance
    if _notifier_instance is None:
        _notifier_instance = Notifier()
    return _notifier_instance
