"""Shared pytest fixtures for the whatsapp_guard test suite.

scripts/whatsapp_guard.py resolves HERMES_HOME -- and every path derived
from it (STATE_DIR, CONFIG_PATH, SESSION_DIR, PEOPLE_DIR) -- exactly once,
as module-level constants, at import time. So HERMES_HOME has to point at
a throwaway sandbox BEFORE the module is first imported; the `wg` fixture
below does that once per test session and every test shares the resulting
sandbox. Tests avoid stepping on each other by using distinct, purpose-
named chat_ids rather than needing a fresh sandbox per test.

Nothing here touches real production state, makes a network call, or
calls an LLM/Telegram -- TELEGRAM_OWNER_CHAT_ID is explicitly left unset
so every alert path in whatsapp_guard.py silently no-ops, by design.
"""
import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"


@pytest.fixture(scope="session")
def wg(tmp_path_factory):
    sandbox = tmp_path_factory.mktemp("hermes_home")
    (sandbox / "whatsapp").mkdir(parents=True, exist_ok=True)
    os.environ["HERMES_HOME"] = str(sandbox)
    os.environ.pop("TELEGRAM_OWNER_CHAT_ID", None)
    sys.path.insert(0, str(SCRIPTS_DIR))
    import whatsapp_guard as module  # noqa: E402 (must import after HERMES_HOME is set)

    return module
