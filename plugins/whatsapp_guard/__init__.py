"""
WhatsApp Guard Plugin — code-level enforcement of WhatsApp conversation rules.

Registers as a `pre_gateway_dispatch` hook and runs AUTOMATICALLY for every
incoming message, BEFORE the agent.

Works INDEPENDENTLY of the agent — provides:
1. Delayed Gatekeeper Handover:
   - For DM messages, delays the assistant's automatic reply so the account
     owner gets a window to reply personally from their phone first.
   - If the owner replies (a `fromMe` message), the assistant never steps in.
   - If the owner doesn't reply within the configured window
     (gatekeeper_config.json), the watchdog takes over.
2. Hardening & limits (slash commands, 5-round cap, injection, wiki extraction).

Version: 2.0.0 (Modular Gatekeeper)
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import threading
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# ── Import whatsapp_guard from the scripts directory ─────────────────

_SCRIPTS_DIR = os.path.join(os.environ.get("HERMES_HOME", "/home/hermes/.hermes"), "scripts")
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

try:
    from whatsapp_guard import check_incoming, load_gatekeeper_config
    _GUARD_AVAILABLE = True
    logger.info("WhatsApp Guard plugin loaded — whatsapp_guard.py available")
except ImportError as e:
    _GUARD_AVAILABLE = False
    logger.warning("WhatsApp Guard plugin: could not import whatsapp_guard.py: %s", e)

_ALWAYS_HARD_BLOCK_ACTIONS = {"warn_no_commands", "handoff_to_telegram", "silent_block", "pending_owner_delay", "owner_activity"}


def _find_hermes_bin() -> str:
    for candidate in [
        os.environ.get("HERMES_BIN", ""),
        "/app/venv/bin/hermes",
        "/home/hermes/.hermes/hermes-agent/.venv/bin/hermes",
        "/usr/local/bin/hermes",
        "/usr/bin/hermes",
    ]:
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return "hermes"


_HERMES_BIN = _find_hermes_bin()

# Where to deliver the owner-facing alert notifications this plugin sends
# (see _send_telegram below). Set this to your own Hermes-reachable contact
# address — leaving it unset just disables the side-channel alert, the
# WhatsApp-side blocking/enforcement still works either way.
_TELEGRAM_OWNER_CHAT_ID = os.environ.get("TELEGRAM_OWNER_CHAT_ID", "")


# ── Platform detection ───────────────────────────────────────────────

def _is_whatsapp(event: Any) -> bool:
    """Checks whether the event came from the WhatsApp platform."""
    source = getattr(event, "source", None)
    if source is not None:
        platform = getattr(source, "platform", None)
        if platform is not None:
            platform_str = platform.value if hasattr(platform, "value") else str(platform)
            if "whatsapp" in platform_str.lower():
                return True
        cid = getattr(source, "chat_id", "") or ""
        if "@s.whatsapp.net" in cid or "@lid" in cid or "@g.us" in cid:
            return True
    return False


def _find_whatsapp_adapter(gateway: Any):
    """Finds the WhatsApp adapter in gateway.adapters."""
    adapters = getattr(gateway, "adapters", {}) or {}
    for name, adapter in adapters.items():
        if "whatsapp" in name.lower() and adapter is not None:
            return adapter
    return None


def _send_telegram(message: str) -> None:
    """Sends an owner-facing alert asynchronously in a daemon thread.

    No-ops (with a debug log) if TELEGRAM_OWNER_CHAT_ID isn't configured —
    swap this out for whatever notification channel your Hermes deployment
    actually has (Telegram is what the original deployment used).
    """
    if not message:
        return
    if not _TELEGRAM_OWNER_CHAT_ID:
        logger.debug("WhatsApp Guard: TELEGRAM_OWNER_CHAT_ID not set — skipping owner alert")
        return

    def _worker():
        try:
            subprocess.run(
                [_HERMES_BIN, "send", "--to", f"telegram:{_TELEGRAM_OWNER_CHAT_ID}", message],
                check=False,
                capture_output=True,
                timeout=10,
            )
        except Exception as e:
            logger.warning("WhatsApp Guard: Telegram send failed: %s", e)

    t = threading.Thread(target=_worker, daemon=True, name="whatsapp-guard-tg-notify")
    t.start()


# ── Hook callback ──────────────────────────────────────────────────────

def _pre_gateway_dispatch_handler(event: Any, gateway: Any = None, **kwargs: Any) -> Optional[Dict[str, Any]]:
    """pre_gateway_dispatch hook callback."""
    if not _GUARD_AVAILABLE:
        return None

    if not _is_whatsapp(event):
        return None

    source = getattr(event, "source", None)
    if source is None:
        return None

    chat_id = getattr(source, "chat_id", "") or ""
    text = getattr(event, "text", "") or ""
    contact_name = getattr(source, "user_name", "") or ""
    sender_id = getattr(source, "user_id_alt", None) or getattr(source, "user_id", "") or ""
    # The real signal is event.metadata["whatsapp_from_owner"] (set by
    # adapter.py when the bridge sends fromOwner:true) — MessageEvent has no
    # from_me field, the older reads below were always False. Left in as a
    # fallback in case a future Hermes version changes this.
    _metadata = getattr(event, "metadata", None) or {}
    is_from_me = bool(_metadata.get("whatsapp_from_owner")) or getattr(event, "from_me", False) or getattr(source, "from_me", False)

    try:
        result = check_incoming(
            chat_id=chat_id,
            text=text,
            contact_name=contact_name,
            sender_id=str(sender_id),
            from_me=bool(is_from_me),
        )
    except Exception as e:
        logger.warning("WhatsApp Guard: check_incoming raised %s — allowing through", e)
        return None

    decision = result.get("decision", "allow")
    if decision == "allow":
        logger.info("WhatsApp Guard: ALLOW chat=%s rounds=%s",
                     chat_id, result.get("state", {}).get("rounds_completed", "?"))
        return None

    reason = result.get("reason", "unknown")
    action = result.get("action", "")
    reply = result.get("reply")
    tg_notification = result.get("telegram_notification")

    # Waiting-for-owner mode (Delayed Gatekeeper) and owner-activity detection
    if action in ("pending_owner_delay", "owner_activity"):
        logger.info("WhatsApp Guard: %s chat=%s", action.upper(), chat_id)
        # Block the message from reaching the agent
        return {"action": "skip", "reason": reason}

    mode = os.environ.get("WHATSAPP_GUARD_MODE", "block").strip().lower()
    if mode == "warn" and action not in _ALWAYS_HARD_BLOCK_ACTIONS:
        logger.info("WhatsApp Guard: WARN-ONLY chat=%s reason=%s (mode=warn, allowing through)",
                     chat_id, reason)
        warn_msg = (
            f"🔍 [WARN-ONLY] A pattern would have blocked a message from {contact_name or chat_id}, "
            f"but it was allowed through (WHATSAPP_GUARD_MODE=warn).\n"
            f"Reason: {reason}\nText: {text[:200]}"
        )
        _send_telegram(warn_msg)
        return None

    logger.info("WhatsApp Guard: BLOCK chat=%s reason=%s action=%s", chat_id, reason, action)

    # Send the block reply via the adapter, if one is available
    if reply:
        try:
            adapter = _find_whatsapp_adapter(gateway)
            if adapter is not None:
                import asyncio
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.create_task(adapter.send(chat_id, reply))
                else:
                    loop.run_until_complete(adapter.send(chat_id, reply))
        except Exception as e:
            logger.warning("WhatsApp Guard: failed to send reply to %s: %s", chat_id, e)

    if tg_notification:
        _send_telegram(tg_notification)

    return {"action": "skip", "reason": reason}


def register(ctx: Any) -> None:
    """Plugin entry point."""
    ctx.register_hook("pre_gateway_dispatch", _pre_gateway_dispatch_handler)
    logger.info("WhatsApp Guard plugin registered (v2.0.0) — pre_gateway_dispatch hook active")
