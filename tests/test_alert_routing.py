"""Every `hermes send` subprocess must pass an explicit environment.

There are three independent fail-safe senders in this project (the guard, the
watchdog and the plugin), duplicated on purpose so each survives the others
being broken. When alert_profile shipped in v2.4.0 two of them were updated
and the third was not, so owner notifications kept arriving from the wrong
bot until someone noticed in a live chat.

This test scans the source instead of the behaviour: any `subprocess.run` that
invokes `hermes send` has to pass `env=`. A fourth sender added later fails
here rather than in production.
"""
import ast
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent

SENDER_FILES = [
    REPO_ROOT / "scripts" / "whatsapp_guard.py",
    REPO_ROOT / "scripts" / "whatsapp_gatekeeper_watchdog.py",
    REPO_ROOT / "plugins" / "whatsapp_guard" / "__init__.py",
]


def _send_calls(path: Path):
    """Yields every subprocess.run(...) node whose argv mentions `send`."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = getattr(func, "attr", None) or getattr(func, "id", None)
        if name != "run" or not node.args:
            continue
        argv = node.args[0]
        if not isinstance(argv, (ast.List, ast.Tuple)):
            continue
        literals = [e.value for e in argv.elts
                    if isinstance(e, ast.Constant) and isinstance(e.value, str)]
        if "send" in literals:
            yield node


@pytest.mark.parametrize("path", SENDER_FILES, ids=lambda p: p.name)
def test_hermes_send_passes_explicit_env(path):
    calls = list(_send_calls(path))
    assert calls, f"no `hermes send` subprocess call found in {path.name}"
    for call in calls:
        kwargs = {kw.arg for kw in call.keywords}
        assert "env" in kwargs, (
            f"{path.name}:{call.lineno} calls `hermes send` without env= — "
            "it will use whichever profile happens to be current instead of "
            "the one named by alert_profile"
        )


def test_every_sender_defines_its_own_alert_env():
    # Shared imports are deliberately avoided here: each fail-safe point must
    # work even if the other files are missing, so each defines its own helper.
    for path in SENDER_FILES:
        src = path.read_text(encoding="utf-8")
        assert "def alert_env(" in src or "def _alert_env(" in src, (
            f"{path.name} sends owner notifications but has no alert_env helper"
        )
