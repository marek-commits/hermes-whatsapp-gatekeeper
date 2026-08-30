#!/usr/bin/env python3
"""
WhatsApp Gatekeeper Watchdog
Part of the Hermes WhatsApp Gatekeeper system.

Periodically (via cron or a background loop) checks the state of incoming
conversations. If a contact has been waiting for the owner's reply longer
than the configured limit (e.g. 10 min in testing / 4h in production) and
the owner still hasn't replied, the watchdog:
1. Builds a natural, human-sounding message reflecting the topic the
   contact raised.
2. Sends it via the WhatsApp bridge.
3. Flips the conversation state to 'in_progress_assistant' and sets
   rounds_completed = 1.
4. Notifies the owner (Telegram, by default) that the assistant took over.

Runs its per-conversation read-modify-write under the same per-chat lock as
the gateway plugin (see scripts/whatsapp_guard.py's state_lock), so this
process and a live incoming message can never race on the same state file.

Version: 1.1.0 (hardened — locking + capped alerts)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List

HERMES_HOME = Path(os.environ.get("HERMES_HOME", "/home/hermes/.hermes"))
SCRIPTS_DIR = HERMES_HOME / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from whatsapp_guard import (
    STATE_DIR,
    load_state,
    save_state,
    load_gatekeeper_config,
    is_owner_timeout_expired,
    build_contextual_intro,
    lookup_person_profile,
    ASSISTANT_NAME,
    OWNER_NAME,
    state_lock,
)

BRIDGE_URL = os.environ.get("WHATSAPP_BRIDGE_URL", "http://localhost:3000")

# Same owner-alert channel as plugins/whatsapp_guard — see its __init__.py
# for notes on swapping this out for a different notification channel.
_TELEGRAM_OWNER_CHAT_ID = os.environ.get("TELEGRAM_OWNER_CHAT_ID", "")

# Telegram alert size caps (security review, medium finding): an unbounded
# alert — many short messages, or one very long one — could exceed
# Telegram's message-length limit and silently fail to deliver. Show only
# the last N messages, each truncated, and cap the combined summary length
# as a second line of defense.
MAX_PENDING_MSGS_IN_ALERT = 10
MAX_PENDING_SUMMARY_CHARS = 1500


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


HERMES_BIN = _find_hermes_bin()


def send_whatsapp_message(chat_id: str, message: str) -> bool:
    """Sends a message via the local Baileys WhatsApp bridge."""
    try:
        import urllib.request
        data = json.dumps({"chatId": chat_id, "message": message}).encode("utf-8")
        req = urllib.request.Request(
            f"{BRIDGE_URL}/send",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except Exception as e:
        print(f"[watchdog] Error sending WhatsApp message to {chat_id}: {e}", file=sys.stderr)
        return False


def notify_owner_telegram(message: str) -> None:
    """Sends an owner-facing notification (Telegram, by default).

    No-ops if TELEGRAM_OWNER_CHAT_ID isn't configured.
    """
    if not _TELEGRAM_OWNER_CHAT_ID:
        return
    try:
        result = subprocess.run(
            [HERMES_BIN, "send", "--to", f"telegram:{_TELEGRAM_OWNER_CHAT_ID}", message],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode != 0:
            print(f"[watchdog] Telegram delivery failed (code {result.returncode}): {result.stderr.strip()}", file=sys.stderr)
    except Exception as e:
        print(f"[watchdog] Error sending Telegram notification: {e}", file=sys.stderr)


def process_pending_conversations() -> int:
    """
    Walks all conversation state files and checks for an expired wait on
    the owner. Returns the number of conversations taken over.
    """
    config = load_gatekeeper_config()
    if not config.get("enabled", True):
        return 0

    timeout_minutes = float(config.get("owner_response_timeout_minutes", 10))
    handled_count = 0

    for state_file in STATE_DIR.glob("*.json"):
        if state_file.name == "index.json" or state_file.name.startswith("group_"):
            continue

        try:
            with open(state_file, "r", encoding="utf-8") as f:
                candidate = json.load(f)
            chat_id = candidate.get("chat_id", "")
        except Exception:
            continue
        if not chat_id:
            continue

        # The gateway plugin and this cron process both mutate the same
        # state file. Re-load it (not the copy read above, which was only
        # used to get chat_id) AFTER acquiring the lock, and hold the SAME
        # per-chat lock the gateway plugin uses for the entire takeover —
        # the timeout check, sending the takeover message, and persisting
        # the new state (security review, race-condition finding: without
        # this, the gateway could process the owner's reply in the exact
        # window between this process reading and writing the state file,
        # and the assistant would send its takeover message anyway, right
        # on top of a reply the owner just sent). Re-checking status after
        # the lock deliberately favors a concurrent owner reply: this
        # process waits for the lock, and once it gets it, re-verifies the
        # status is still pending_owner_reply — if the owner replied in the
        # meantime, the status will already have changed and the takeover
        # is skipped.
        with state_lock(chat_id):
            state = load_state(chat_id)
            if state.get("status") != "pending_owner_reply" or not is_owner_timeout_expired(state, timeout_minutes):
                continue

            contact_name = state.get("contact_name", "") or chat_id
            pending_msgs = state.get("pending_messages", [])
            recent_msgs = state.get("recent_messages", [])

            intro_text = build_contextual_intro(pending_msgs, contact_name, chat_id, recent_msgs)

            # Full name + phone from the optional people-profile lookup (for
            # the Telegram alert below). Falls back to contact_name / chat_id
            # if the contact isn't found.
            full_name, _about, _style, phone = lookup_person_profile(chat_id, contact_name)
            display_name = full_name or contact_name or chat_id
            phone_display = f"+{phone}" if phone else "unknown"

            print(f"[watchdog] Timeout {timeout_minutes}m expired for {contact_name} ({chat_id}). Handing over to {ASSISTANT_NAME}...")

            # 1. Send the WhatsApp takeover message
            success = send_whatsapp_message(chat_id, intro_text)
            if success:
                # 2. Update state
                now_iso = datetime.now(timezone.utc).isoformat()
                state["status"] = "in_progress_assistant"
                state["rounds_completed"] = 1
                state["waiting_since"] = None
                state["pending_messages"] = []
                state["last_message_at"] = now_iso
                state.setdefault("messages", []).append({
                    "round": 1,
                    "direction": "outgoing",
                    "text": intro_text,
                    "timestamp": now_iso,
                    "note": f"Gatekeeper auto-takeover after {timeout_minutes}m timeout",
                })
                save_state(chat_id, state)

                # 3. Notify the owner (headers in English; message content
                # stays in whatever language the conversation itself is in —
                # it isn't translated)
                hours_str = f"{int(timeout_minutes // 60)}h" if timeout_minutes >= 60 else f"{int(timeout_minutes)}m"
                _shown = pending_msgs[-MAX_PENDING_MSGS_IN_ALERT:]
                pending_summary = "\n".join(f"• {m[:300]}" for m in _shown) if _shown else "(no text)"
                if len(pending_summary) > MAX_PENDING_SUMMARY_CHARS:
                    pending_summary = pending_summary[:MAX_PENDING_SUMMARY_CHARS] + "\n… (truncated)"
                if len(pending_msgs) > MAX_PENDING_MSGS_IN_ALERT:
                    pending_summary = f"(last {MAX_PENDING_MSGS_IN_ALERT} of {len(pending_msgs)})\n" + pending_summary
                tg_alert = (
                    f"🤖 **{ASSISTANT_NAME} took over the WhatsApp conversation** (no reply from you for {hours_str})\n\n"
                    f"👤 **Contact:** {display_name} — {phone_display} (`{chat_id}`)\n\n"
                    f"📩 **Incoming messages:**\n{pending_summary}\n\n"
                    f"💬 **{ASSISTANT_NAME}'s reply:**\n\"{intro_text[:1000]}\"\n\n"
                    f"ℹ️ _Reply directly on WhatsApp any time to take back over — {ASSISTANT_NAME} yields immediately._"
                )
                notify_owner_telegram(tg_alert)
                handled_count += 1
            else:
                print(f"[watchdog] Failed to deliver WhatsApp intro to {chat_id}", file=sys.stderr)

    return handled_count


if __name__ == "__main__":
    count = process_pending_conversations()
    if count > 0:
        print(f"[watchdog] Handled {count} expired conversation(s).")
