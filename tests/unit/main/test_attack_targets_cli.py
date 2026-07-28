"""Tests for --attack-targets CLI argument and target-branch passthrough."""

import argparse
from pathlib import Path

from src.cli.messages import msg


def test_argparse_attack_targets_flag() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--attack-targets",
        metavar="FILE",
        help=msg("argparse.attack_targets.help"),
    )
    args = parser.parse_args(["--attack-targets", "/tmp/attack_targets.json"])
    assert args.attack_targets == "/tmp/attack_targets.json"


def test_attack_targets_help_key_exists() -> None:
    help_text = msg("argparse.attack_targets.help")
    assert isinstance(help_text, str)
    assert len(help_text) > 0
    assert not help_text.startswith("??"), (
        f"Message key 'argparse.attack_targets.help' not registered: got '{help_text}'"
    )


def test_target_branch_passes_attack_targets_to_interactive_bridge() -> None:
    main_path = Path(__file__).parent.parent.parent.parent / "src" / "main.py"
    source = main_path.read_text(encoding="utf-8")

    assert "attack_targets_file=args.attack_targets" in source, (
        "args.target code path does not pass attack_targets_file to start_interactive_session"
    )
