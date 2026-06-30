"""
Notifier: System-wide notification wrapper using projectdiscovery/notify.
"""
import datetime
import json
import logging
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional, Dict, List

from src.core.models.finding import Finding, Severity
from src.core.config.settings import Settings, get_settings
from src.config import settings

logger = logging.getLogger(__name__)


class BodyBuildError(Exception):
    """Raised when JapaneseBodyBuilder fails to build notification body."""
    pass


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

        # Phase A (SGK-2026-0297): Operational protections
        self._load_operational_settings()

    def _load_operational_settings(self):
        """Reload operational settings from config (supports hot-reload)."""
        try:
            s = get_settings()
            fn = s.feature_notifications
            self.dry_run: bool = getattr(fn, 'notify_dry_run', False)
            self.kill_switch: bool = getattr(fn, 'notify_kill_switch', False)
            self.notify_timeout: float = getattr(fn, 'notify_timeout_seconds', 10.0)
            self.notify_retry_count: int = getattr(fn, 'notify_retry_count', 1)
            self.notify_retry_backoff: float = getattr(fn, 'notify_retry_backoff_seconds', 1.0)
            self.provider_allowlist: List[str] = getattr(fn, 'notify_provider_allowlist', []) or []
            self.max_body_length: int = getattr(fn, 'notify_max_body_length', 4000)
        except Exception:
            # Fallback defaults if settings unavailable
            self.dry_run = False
            self.kill_switch = False
            self.notify_timeout = 10.0
            self.notify_retry_count = 1
            self.notify_retry_backoff = 1.0
            self.provider_allowlist = []
            self.max_body_length = 4000

    def notify(self, message: str, provider: Optional[str] = None, bulk: bool = False) -> bool:
        """
        Send a raw text notification with operational protections.

        Protections (in order):
        1. Kill switch: block all sends
        2. Empty message: skip
        3. Dry-run: log what WOULD be sent, return True (simulated success)
        4. Missing CLI/config: log and skip (only when actually sending)
        5. Provider allowlist: only allowed providers (only when actually sending)
        6. Timeout: subprocess timeout
        7. Retry: retry on failure with backoff
        """
        # 1. Kill switch (blocks everything, including dry-run)
        if self.kill_switch:
            logger.info("Notification blocked: kill_switch active (message not sent)")
            return False

        # 2. Empty message
        if not message:
            return False

        # 3. Dry-run (succeeds regardless of CLI/config/allowlist state)
        if self.dry_run:
            logger.info("DRY-RUN: would send notification [provider=%s]: %s",
                       provider or "all", message[:200])
            return True  # Simulated success

        # 4. Missing CLI/config (only checked when actually sending)
        if not self.notify_path or not self.config_path:
            logger.debug("Notify CLI or config missing, skipping notification")
            return False

        # 5. Provider allowlist enforcement (only checked when actually sending)
        if self.provider_allowlist:
            if provider:
                if provider not in self.provider_allowlist:
                    logger.info("Provider '%s' not in allowlist, skipping notification", provider)
                    return False
            else:
                logger.warning(
                    "Provider allowlist is set (%s) but no specific provider given. "
                    "Refusing to broadcast to all providers. Specify a provider from the allowlist.",
                    self.provider_allowlist,
                )
                return False

        # 6. Build command with timeout
        cmd = [self.notify_path, "-silent"]
        if self.config_path:
            cmd.extend(["-config", self.config_path])
        if provider:
            cmd.extend(["-provider", provider])
        if bulk:
            cmd.append("-bulk")

        # 7. Retry loop
        last_error: Optional[str] = None
        for attempt in range(self.notify_retry_count + 1):
            try:
                process = subprocess.run(
                    cmd,
                    input=message,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=self.notify_timeout,
                )
                if process.returncode == 0:
                    return True
                last_error = process.stderr.strip() or f"exit code {process.returncode}"
                logger.warning("Notify attempt %d/%d failed: %s",
                             attempt + 1, self.notify_retry_count + 1, last_error)
            except subprocess.TimeoutExpired:
                last_error = f"timeout after {self.notify_timeout}s"
                logger.warning("Notify attempt %d/%d timed out after %.1fs",
                             attempt + 1, self.notify_retry_count + 1, self.notify_timeout)
            except Exception as e:
                last_error = str(e)
                logger.warning("Notify attempt %d/%d error: %s",
                             attempt + 1, self.notify_retry_count + 1, e)

            # Backoff before retry (not after last attempt)
            if attempt < self.notify_retry_count:
                time.sleep(self.notify_retry_backoff)

        logger.error("Notify failed after %d attempts: %s",
                    self.notify_retry_count + 1, last_error)
        return False

    def notify_finding(self, finding, run_id: str = "", source_component: str = "", ingress_path: str = "", provider: Optional[str] = None) -> bool:
        """
        Format and send a detailed Japanese notification for a security finding.

        Phase A (SGK-2026-0297): Uses JapaneseBodyBuilder for detailed body
        with all key fields and mandatory redaction.

        Args:
            finding: Finding object, FindingNotificationDTO, or dict.
            run_id: Run identifier for structured logging.
            source_component: Component that originated this notification.
            ingress_path: How the finding entered the notification system.

        Returns:
            bool: True if notification was processed (sent, dry-run, or logged).
                  False only when completely blocked (kill switch, no CLI).
        """
        # Reload settings (supports runtime changes)
        self._load_operational_settings()

        # Kill switch: block everything
        if self.kill_switch:
            logger.info("Notification blocked by kill_switch: %s",
                       getattr(finding, 'title', str(finding)[:100]))
            self._log_notification(finding, "", run_id, source_component, ingress_path, False)
            return False

        # If notify CLI is missing and NOT dry-run: log and skip
        if not self.notify_path and not self.dry_run:
            logger.info("Notify CLI not available, notification skipped: %s",
                       getattr(finding, 'title', str(finding)[:100]))
            self._log_notification(finding, "", run_id, source_component, ingress_path, False)
            return False

        # Build detailed Japanese body
        try:
            from src.core.notifications.body_builder import JapaneseBodyBuilder
            builder = JapaneseBodyBuilder(max_length=self.max_body_length)
            body = builder.build(finding)
        except BodyBuildError:
            raise
        except Exception as e:
            logger.error("Body build failed for finding: %s", e)
            raise BodyBuildError(f"Failed to build notification body: {e}") from e

        # CRITICAL severity: prepend mention if configured
        if hasattr(finding, 'severity'):
            sev = finding.severity
            if hasattr(sev, 'value'):
                sev = sev.value
            if str(sev).lower() == 'critical' and settings.notify_critical_mention:
                body = f"{settings.notify_critical_mention}\n{body}"
        elif isinstance(finding, dict):
            sev = finding.get('severity', '')
            if hasattr(sev, 'value'):
                sev = sev.value
            if str(sev).lower() == 'critical' and settings.notify_critical_mention:
                body = f"{settings.notify_critical_mention}\n{body}"

        # Send (with all operational protections in self.notify())
        success = self.notify(body, provider=provider, bulk=True)

        # Structured log entry with accurate delivery_status
        self._log_notification(finding, body, run_id, source_component, ingress_path, success)

        return success

    def _log_notification(self, finding, body: str, run_id: str,
                         source_component: str, ingress_path: str,
                         success: Optional[bool] = None) -> None:
        """
        Emit a structured log entry for this notification attempt.
        JSONL-compatible format. Does NOT log the full body (only first 200 chars).
        """
        try:
            d = {}
            if hasattr(finding, 'to_dict'):
                d = finding.to_dict()
            elif isinstance(finding, dict):
                d = finding

            entry = {
                "timestamp": datetime.datetime.now().isoformat(),
                "run_id": run_id or "unknown",
                "finding_id": d.get('finding_id', d.get('id', 'unknown')),
                "severity": d.get('severity', 'unknown'),
                "vuln_type": d.get('vuln_type', d.get('type', 'unknown')),
                "title": d.get('title', '')[:200],
                "source_component": source_component,
                "ingress_path": ingress_path,
                "delivery_status": self._compute_delivery_status(success),
                "body_length": len(body),
                "body_preview": body[:200],
                "dry_run": self.dry_run,
                "kill_switch": self.kill_switch,
                "notify_path_available": bool(self.notify_path),
            }
            logger.info("NOTIFICATION_EVENT %s", json.dumps(entry, ensure_ascii=False))
        except Exception as e:
            logger.debug("Failed to log notification entry: %s", e)

    def _compute_delivery_status(self, success: Optional[bool]) -> str:
        """Compute accurate delivery status based on operational state."""
        if self.kill_switch:
            return "blocked_kill_switch"
        if self.dry_run:
            return "dry_run"
        if success is True:
            return "sent"
        if success is False:
            return "failed"
        return "unknown"

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
