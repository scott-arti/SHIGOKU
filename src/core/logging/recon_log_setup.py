"""
Recon logger setup with Japanese localization and secret redaction (SGK-2026-0344).

Provides:

* ``JapaneseConsoleFormatter`` — console formatter that redacts secrets and
  translates high-frequency log messages to Japanese.
* ``FileLogFormatter`` — file formatter that redacts secrets but preserves
  English for searchability (includes logger name, level, paths, counts).
* ``setup_recon_logging()`` — idempotent setup that attaches both formatters
  (with attached ``RedactionFilter``) to the ``src.recon`` logger namespace.
"""

from __future__ import annotations

import logging
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from src.core.logging.log_redactor import LogRedactor


# ---------------------------------------------------------------------------
# Japanese translation mappings (regex-based, high-frequency logs only)
# ---------------------------------------------------------------------------

_JAPANESE_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # ── Tool execution ────────────────────────────────────────────────
    (
        re.compile(
            r"(^\d{2}:\d{2}:\d{2}\s+\|\s+\w+\s+\|\s+)"
            r"Executing:\s+(.+?)\s+\(timeout=(\d+)s\)$",
        ),
        r"\1実行中: \2 (timeout=\3s)",
    ),
    (
        re.compile(
            r"(^\d{2}:\d{2}:\d{2}\s+\|\s+\w+\s+\|\s+)"
            r"Command\s+failed\s+\(exit=(\d+)\):\s+(.+?)\\nStderr:\s+(.+)$",
        ),
        r"\1コマンド失敗 (exit=\2): \3\nStderr: \4",
    ),
    (
        re.compile(
            r"(^\d{2}:\d{2}:\d{2}\s+\|\s+\w+\s+\|\s+)"
            r"Command\s+timed\s+out\s+after\s+(\d+)s:\s+(.+)$",
        ),
        r"\1コマンドタイムアウト (\2s): \3",
    ),
    (
        re.compile(
            r"(^\d{2}:\d{2}:\d{2}\s+\|\s+\w+\s+\|\s+)"
            r"Command\s+execution\s+failed:\s+(.+)$",
        ),
        r"\1コマンド実行失敗: \2",
    ),
    # ── Steps ─────────────────────────────────────────────────────────
    (
        re.compile(
            r"(^\d{2}:\d{2}:\d{2}\s+\|\s+\w+\s+\|\s+)"
            r"\[Step\s+(\d+)[^\]]*\]\s+(.+?)\s+started$",
        ),
        r"\1[ステップ\2] \3 開始",
    ),
    (
        re.compile(
            r"(^\d{2}:\d{2}:\d{2}\s+\|\s+\w+\s+\|\s+)"
            r"\[Step\s+(\d+)[^\]]*\]\s+(.+?)\s+completed:\s?(.*)$",
        ),
        r"\1[ステップ\2] \3 完了: \4",
    ),
    # ── Tool results: found ───────────────────────────────────────────
    (
        re.compile(
            r"(^\d{2}:\d{2}:\d{2}\s+\|\s+\w+\s+\|\s+)"
            r"(\w+)\s+found\s+(\d+)\s+live\s+subdomains$",
        ),
        r"\1\2: \3 件のライブサブドメインを検出しました",
    ),
    (
        re.compile(
            r"(^\d{2}:\d{2}:\d{2}\s+\|\s+\w+\s+\|\s+)"
            r"(\w+)\s+found\s+(\d+)\s+subdomains(?:\s+\(total:\s+(\d+)\))?$",
        ),
        r"\1\2: \3 件のサブドメインを検出",
    ),
    (
        re.compile(
            r"(^\d{2}:\d{2}:\d{2}\s+\|\s+\w+\s+\|\s+)"
            r"(\w+)\s+found\s+(\d+)\s+historical\s+hosts$",
        ),
        r"\1\2: \3 件の履歴ホストを検出",
    ),
    (
        re.compile(
            r"(^\d{2}:\d{2}:\d{2}\s+\|\s+\w+\s+\|\s+)"
            r"(\w+)\s+found\s+(\d+)\s+unique\s+URLs",
        ),
        r"\1\2: \3 件のユニークURLを検出",
    ),
    # ── Tool results: not found ───────────────────────────────────────
    (
        re.compile(
            r"(^\d{2}:\d{2}:\d{2}\s+\|\s+\w+\s+\|\s+)"
            r"(\w+)\s+not\s+found,\s+skipping$",
        ),
        r"\1\2 が見つからないためスキップします",
    ),
    # ── Auth headers ──────────────────────────────────────────────────
    (
        re.compile(
            r"(^\d{2}:\d{2}:\d{2}\s+\|\s+\w+\s+\|\s+)"
            r"Katana\s+auth\s+headers\s+configured:",
        ),
        r"\1Katana 認証ヘッダーを構成しました",
    ),
    (
        re.compile(
            r"(^\d{2}:\d{2}:\d{2}\s+\|\s+\w+\s+\|\s+)"
            r"No\s+auth\s+headers\s+configured\s+for\s+Katana",
        ),
        r"\1Katana に認証ヘッダーは構成されていません",
    ),
    (
        re.compile(
            r"(^\d{2}:\d{2}:\d{2}\s+\|\s+\w+\s+\|\s+)"
            r"Injecting\s+(\d+)\s+auth\s+headers\s+into\s+(\w+)$",
        ),
        r"\1\3 に \2 件の認証ヘッダーを注入中",
    ),
    # ── Proxy ─────────────────────────────────────────────────────────
    (
        re.compile(
            r"(^\d{2}:\d{2}:\d{2}\s+\|\s+\w+\s+\|\s+)"
            r"Injecting\s+proxy\s+into\s+(\w+)\s+(?:probe:\s+)?(.+)$",
        ),
        r"\1プロキシ注入: \3 (\2)",
    ),
    # ── Recon lifecycle ───────────────────────────────────────────────
    (
        re.compile(
            r"(^\d{2}:\d{2}:\d{2}\s+\|\s+\w+\s+\|\s+)"
            r"Starting\s+Recon:\s+(.+)$",
        ),
        r"\1偵察開始: \2",
    ),
    (
        re.compile(
            r"(^\d{2}:\d{2}:\d{2}\s+\|\s+\w+\s+\|\s+)"
            r"ReconPipeline\s+initialized:\s+(.+)$",
        ),
        r"\1ReconPipeline 初期化: \2",
    ),
    # ── Saved ─────────────────────────────────────────────────────────
    (
        re.compile(
            r"(^\d{2}:\d{2}:\d{2}\s+\|\s+\w+\s+\|\s+)"
            r"Saved\s+(.+?):\s+(.+)$",
        ),
        r"\1保存: \3 (\2)",
    ),
    # ── Loaded ────────────────────────────────────────────────────────
    (
        re.compile(
            r"(^\d{2}:\d{2}:\d{2}\s+\|\s+\w+\s+\|\s+)"
            r"Loaded\s+(.+?)\s+from\s+(.+)$",
        ),
        r"\1ロード: \2 から \3",
    ),
    # ── State saved ──────────────────────────────────────────────────
    (
        re.compile(
            r"(^\d{2}:\d{2}:\d{2}\s+\|\s+\w+\s+\|\s+)"
            r"State\s+saved\s+\(atomic=(\w+)\):\s+(.+)$",
        ),
        r"\1状態保存 (atomic=\2): \3",
    ),
    # ── Running Katana ───────────────────────────────────────────────
    (
        re.compile(
            r"(^\d{2}:\d{2}:\d{2}\s+\|\s+\w+\s+\|\s+)"
            r"Running\s+Katana\s+on\s+(\d+)\s+targets\s+via\s+proxy\s+(.+?)\.\.\.$",
        ),
        r"\1Katana を \2 件のターゲットで実行中 (プロキシ: \3)...",
    ),
    # ── DNS resolution ───────────────────────────────────────────────
    (
        re.compile(
            r"(^\d{2}:\d{2}:\d{2}\s+\|\s+\w+\s+\|\s+)"
            r"DNS\s+resolution\s+completed:\s+(\d+)\s+subdomains$",
        ),
        r"\1DNS名前解決完了: \2 件のサブドメイン",
    ),
    # ── Known DEV_MODE messages (passthrough but keep dev mode visible) -
    # ── Total / counts ───────────────────────────────────────────────
    (
        re.compile(
            r"(^\d{2}:\d{2}:\d{2}\s+\|\s+\w+\s+\|\s+)"
            r"Total\s+(\d+)\s+URLs\s+ready\s+for\s+tagging$",
        ),
        r"\1合計 \2 件のURLがタグ付け準備完了",
    ),
    # ── WAF ──────────────────────────────────────────────────────────
    (
        re.compile(
            r"(^\d{2}:\d{2}:\d{2}\s+\|\s+\w+\s+\|\s+)"
            r"Detected\s+tech\s+stack:\s+(.+)$",
        ),
        r"\1検出された技術スタック: \2",
    ),
    # ── Playwright ───────────────────────────────────────────────────
    (
        re.compile(
            r"(^\d{2}:\d{2}:\d{2}\s+\|\s+\w+\s+\|\s+)"
            r"Playwright\s+seeds\s+selected:\s+(\d+)\s+target",
        ),
        r"\1Playwright シード選択: \2 件のターゲット",
    ),
    (
        re.compile(
            r"(^\d{2}:\d{2}:\d{2}\s+\|\s+\w+\s+\|\s+)"
            r"Playwright\s+dynamic\s+recon\s+found\s+(\d+)\s+endpoints$",
        ),
        r"\1Playwright 動的偵察: \2 件のエンドポイントを検出",
    ),
    # ── Caido ────────────────────────────────────────────────────────
    (
        re.compile(
            r"(^\d{2}:\d{2}:\d{2}\s+\|\s+\w+\s+\|\s+)"
            r"CaidoSitemapAgent\s+extracted\s+(\d+)\s+endpoints$",
        ),
        r"\1CaidoSitemapAgent: \2 件のエンドポイントを抽出",
    ),
    # ── Advanced fingerprinting ──────────────────────────────────────
    (
        re.compile(
            r"(^\d{2}:\d{2}:\d{2}\s+\|\s+\w+\s+\|\s+)"
            r"Advanced\s+fingerprinting\s+completed\s+for\s+(\d+)\s+sample\s+URLs$",
        ),
        r"\1高度フィンガープリント完了: \2 件のサンプルURL",
    ),
    # ── Parallel tasks ───────────────────────────────────────────────
    (
        re.compile(
            r"(^\d{2}:\d{2}:\d{2}\s+\|\s+\w+\s+\|\s+)"
            r"Starting\s+parallel\s+tasks\s+for\s+(\d+)\s+live\s+subdomains$",
        ),
        r"\1並列タスク開始: \2 件のライブサブドメイン",
    ),
    (
        re.compile(
            r"(^\d{2}:\d{2}:\d{2}\s+\|\s+\w+\s+\|\s+)"
            r"All\s+parallel\s+tasks\s+completed$",
        ),
        r"\1全並列タスク完了",
    ),
    # ── Failed to parse JSON ────────────────────────────────────────
    (
        re.compile(
            r"(^\d{2}:\d{2}:\d{2}\s+\|\s+\w+\s+\|\s+)"
            r"Failed\s+to\s+parse\s+JSON\s+line:\s+(.+?)\s+-\s+(.+)$",
        ),
        r"\1JSON行のパースに失敗: \2 - \3",
    ),
]


_JAPANESE_SIMPLE_REPLACEMENTS: list[tuple[str, str]] = [
    # ── Simple word-level replacements (apply after pattern matching) ─
    ("execution failed", "実行失敗"),
    ("timed out after", "タイムアウト:"),
    ("not reachable at", "到達不能:"),
    ("is reachable", "到達可能"),
    ("completed:", "完了:"),
    ("completed", "完了"),
    ("started", "開始"),
    ("failed:", "失敗:"),
    ("skipping", "スキップ"),
    ("saved:", "保存:"),
    ("loaded:", "ロード:"),
    ("detected:", "検出:"),
    ("configured", "構成済み"),
    ("injecting", "注入中"),
    ("running", "実行中"),
    ("executing", "実行中"),
    ("found ", "検出: "),
    ("not found", "未検出"),
    ("total", "合計"),
    ("hosts", "ホスト"),
    ("targets", "ターゲット"),
    ("target(s)", "ターゲット"),
    ("endpoints", "エンドポイント"),
    ("subdomains", "サブドメイン"),
    ("subdomain", "サブドメイン"),
    ("unique URLs", "ユニークURL"),
    ("live", "ライブ"),
    ("dead", "停止"),
    ("entries", "エントリ"),
    ("results", "結果"),
    ("categories", "カテゴリ"),
    ("category", "カテゴリ"),
    ("mode", "モード"),
    ("check", "チェック"),
    ("passed", "成功"),
    ("error", "エラー"),
    ("warning", "警告"),
    ("timeout", "タイムアウト"),
    ("via proxy", "プロキシ経由"),
    ("through proxy", "プロキシ経由"),
    ("using proxy", "プロキシ使用"),
    ("proxy", "プロキシ"),
]


def _translate_japanese(text: str) -> str:
    """Apply Japanese translation to *text* (already redacted).

    High-frequency log patterns are matched via regex and translated.
    Unknown messages are returned as-is (redacted English).
    """
    result = text

    # Phase 1: structured pattern replacements (ordered, first-match wins)
    for pattern, replacement in _JAPANESE_PATTERNS:
        if pattern.search(result):
            result = pattern.sub(replacement, result)
            break  # First match wins for structured patterns

    # Unknown messages are returned as-is (redacted English).
    # No word-level fallback — accidental partial translation is riskier
    # than leaving an unmatched message in English.

    return result


# ---------------------------------------------------------------------------
# JapaneseConsoleFormatter
# ---------------------------------------------------------------------------


class JapaneseConsoleFormatter(logging.Formatter):
    """Console formatter: redacts secrets, then translates to Japanese.

    Format: ``HH:MM:SS | LEVEL   | message`` (compact for CLI).
    Unknown messages remain in English (redacted only).
    """

    def __init__(self) -> None:
        super().__init__(
            fmt="%(asctime)s | %(levelname)-7s | %(message)s",
            datefmt="%H:%M:%S",
        )
        self._redactor = LogRedactor()

    def format(self, record: logging.LogRecord) -> str:
        # Redact record fields in-place (idempotent — safe for shared records)
        record.msg = self._redactor.redact(record.msg)
        if record.args:
            record.args = self._redactor.redact(record.args)

        # Get standard formatted line (with redacted message)
        formatted = super().format(record)

        # Apply Japanese translation to the full line
        return _translate_japanese(formatted)


# ---------------------------------------------------------------------------
# FileLogFormatter
# ---------------------------------------------------------------------------


class FileLogFormatter(logging.Formatter):
    """File formatter: redacts secrets, preserves English for searchability.

    Format: ``YYYY-MM-DD HH:MM:SS,mmm | LEVEL   | logger.name | message``
    """

    def __init__(self) -> None:
        super().__init__(
            fmt="%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        self._redactor = LogRedactor()

    def format(self, record: logging.LogRecord) -> str:
        # Redact record fields in-place (idempotent — safe for shared records)
        record.msg = self._redactor.redact(record.msg)
        if record.args:
            record.args = self._redactor.redact(record.args)

        return super().format(record)


# ---------------------------------------------------------------------------
# setup_recon_logging
# ---------------------------------------------------------------------------


def setup_recon_logging(
    log_dir: str | Path | None = None,
    *,
    console: bool = True,
    file: bool = True,
) -> None:
    """Configure handlers for the ``src.recon`` logger namespace.

    Adds a console handler (JapaneseConsoleFormatter) and a file handler
    (FileLogFormatter) to ``src.recon``.  Both handlers carry a
    ``RedactionFilter`` as belt-and-suspenders protection.

    Idempotent: calling multiple times does not add duplicate handlers.

    Args:
        log_dir: Directory for recon log files (default: ``logs/recon/``
                 relative to the current working directory).
        console: Attach console (stderr) handler.
        file: Attach file handler.
    """
    from src.core.logging.log_redactor import RedactionFilter

    recon_logger = logging.getLogger("src.recon")
    recon_logger.setLevel(logging.DEBUG)

    # Break propagation to root logger so we fully control the output
    # (the root logger may have been configured by tagging_filter's basicConfig)
    recon_logger.propagate = False

    # ── Determine log directory for file handler ─────────────────────
    if log_dir is None:
        log_dir = Path("logs") / "recon"
    elif isinstance(log_dir, str):
        log_dir = Path(log_dir)

    # ── Collect existing handler types for idempotency check ─────────
    existing_types: set[type] = {type(h) for h in recon_logger.handlers}

    # ── Console handler ──────────────────────────────────────────────
    if console and logging.StreamHandler not in existing_types:
        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(logging.INFO)
        stream_handler.setFormatter(JapaneseConsoleFormatter())
        stream_handler.addFilter(RedactionFilter("src.recon.console"))
        recon_logger.addHandler(stream_handler)

    # ── File handler ─────────────────────────────────────────────────
    if file and logging.FileHandler not in existing_types:
        log_dir.mkdir(parents=True, exist_ok=True)
        today = datetime.now().strftime("%Y%m%d")
        log_path = log_dir / f"{today}_recon.log"
        file_handler = logging.FileHandler(str(log_path), encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(FileLogFormatter())
        file_handler.addFilter(RedactionFilter("src.recon.file"))
        recon_logger.addHandler(file_handler)

    # ── Ensure child loggers have their own handler copies ───────────
    # Each child logger gets the same handlers so len(logger.handlers) > 0
    # works for both parent and child loggers.  Idempotency is per-logger.
    for child_name in (
        "src.recon.tool_runner",
        "src.recon.pipeline",
        "src.recon.parallel_tasks",
    ):
        child = logging.getLogger(child_name)
        child.setLevel(logging.DEBUG)
        child.propagate = False  # Prevent double-output via root logger

        child_existing: set[type] = {type(h) for h in child.handlers}

        if console and logging.StreamHandler not in child_existing:
            child_sh = logging.StreamHandler()
            child_sh.setLevel(logging.INFO)
            child_sh.setFormatter(JapaneseConsoleFormatter())
            child_sh.addFilter(RedactionFilter(f"{child_name}.console"))
            child.addHandler(child_sh)

        if file and logging.FileHandler not in child_existing:
            log_dir.mkdir(parents=True, exist_ok=True)
            today = datetime.now().strftime("%Y%m%d")
            log_path = log_dir / f"{today}_recon.log"
            # Share the same file handler across all child loggers
            # so logs go to one file (not one per logger)
            child_fh = logging.FileHandler(str(log_path), encoding="utf-8")
            child_fh.setLevel(logging.DEBUG)
            child_fh.setFormatter(FileLogFormatter())
            child_fh.addFilter(RedactionFilter(f"{child_name}.file"))
            child.addHandler(child_fh)
