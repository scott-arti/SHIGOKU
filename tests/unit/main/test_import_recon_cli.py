"""Tests for --import-recon CLI argument and bridge integration."""

import argparse
import inspect
from pathlib import Path

from src.cli.messages import msg
from src.core.conductor.interactive_bridge import start_interactive_session


def test_argparse_import_recon_flag():
    """Parse ['--import-recon', '/tmp/recon'] and verify args.import_recon == '/tmp/recon'."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--import-recon",
        metavar="DIR",
        help=msg("argparse.import_recon.help"),
    )
    args = parser.parse_args(["--import-recon", "/tmp/recon"])
    assert args.import_recon == "/tmp/recon"


def test_help_key_exists():
    """Verify that msg('argparse.import_recon.help') returns a string not starting with '??'."""
    help_text = msg("argparse.import_recon.help")
    assert isinstance(help_text, str)
    assert len(help_text) > 0
    assert not help_text.startswith("??"), (
        f"Message key 'argparse.import_recon.help' not registered: got '{help_text}'"
    )


def test_bridge_accepts_import_recon_dir():
    """Verify start_interactive_session signature includes import_recon_dir parameter."""
    sig = inspect.signature(start_interactive_session)
    assert "import_recon_dir" in sig.parameters, (
        f"import_recon_dir not found in start_interactive_session signature. "
        f"Available parameters: {list(sig.parameters.keys())}"
    )
    # Verify default value is None
    param = sig.parameters["import_recon_dir"]
    assert param.default is None, (
        f"Expected import_recon_dir default to be None, got: {param.default!r}"
    )


def test_recon_with_import_recon_passes_through():
    """Regression: --recon example.com --import-recon /tmp/recon code path
    passes import_recon_dir to start_interactive_session.

    Verifies that the args.recon call site includes import_recon_dir kwarg.
    """
    # Read main.py source to verify the call at the args.recon code path
    main_path = Path(__file__).parent.parent.parent.parent / "src" / "main.py"
    source = main_path.read_text(encoding="utf-8")

    # Find the start_interactive_session call in the args.recon elif branch
    # It should appear after "elif args.recon:" and contain import_recon_dir
    recon_section = source.split("elif args.recon:")[1]
    if "elif" in recon_section:
        recon_section = recon_section.split("elif")[0]

    # Verify import_recon_dir=args.import_recon is in the call
    assert "import_recon_dir=args.import_recon" in recon_section, (
        "args.recon code path does not pass import_recon_dir to "
        "start_interactive_session"
    )
