#!/usr/bin/env python3
"""
WhatsApp Guard — code-level enforcement of WhatsApp conversation rules.
Part of the modular Hermes WhatsApp Gatekeeper system.

Works INDEPENDENTLY of the LLM agent. Provides:
1. Delayed Handover (waiting for the owner to reply):
   - For a DM, waits a configured amount of time (default 4h / 240 min) to give
     the account owner a window to reply personally from their phone.
   - If the owner replies (a `fromMe` message from a linked device), the
     assistant immediately backs off and does not step in / stops replying.
   - If the owner doesn't reply within the limit, the assistant takes over
     with a personalized, contextual opener generated via an LLM from the
     recent messages and the contact's profile (if one is configured).
2. Round counter (max 5 rounds in a DM / 10 rounds in a group).
3. Hardening & security filters (slash commands, prompt injection, wiki
   extraction, Telegram-injection attempts).

Version: 2.1.0 (Personalized Delayed Gatekeeper)
"""

from __future__ import annotations

import glob
import json
import os
import re
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, Dict, Any, Tuple, List

# ── Configuration and paths ───────────────────────────────────────────

HERMES_HOME = Path(os.environ.get("HERMES_HOME", "/home/hermes/.hermes"))
STATE_DIR = HERMES_HOME / "whatsapp" / "conversation-state"
STATE_DIR.mkdir(parents=True, exist_ok=True)

CONFIG_PATH = HERMES_HOME / "whatsapp" / "gatekeeper_config.json"
SESSION_DIR = HERMES_HOME / "whatsapp" / "session"

# Optional per-contact profile lookup: if you keep a notes/wiki file per
# contact (Markdown, with a YAML frontmatter phone field and a couple of
# named sections), point WHATSAPP_GUARD_PEOPLE_DIR at that folder and
# lookup_person_profile() will pull a short relationship/style blurb into
# the takeover message. Entirely optional — with no matching file, or the
# directory unset/empty, it just falls back to the bare contact name.
# The header/key names below must match whatever convention your own notes
# use; the defaults are just an example.
PEOPLE_DIR = Path(os.environ.get("WHATSAPP_GUARD_PEOPLE_DIR", str(HERMES_HOME / "whatsapp" / "people")))
PROFILE_PHONE_KEY = os.environ.get("WHATSAPP_GUARD_PROFILE_PHONE_KEY", "phone")
PROFILE_ABOUT_HEADER = os.environ.get("WHATSAPP_GUARD_PROFILE_ABOUT_HEADER", "## About")
PROFILE_STYLE_HEADER = os.environ.get("WHATSAPP_GUARD_PROFILE_STYLE_HEADER", "## Communication style")


def load_gatekeeper_config() -> Dict[str, Any]:
    """Loads configuration from gatekeeper_config.json, falling back to ENV and defaults."""
    defaults = {
        "enabled": True,
        "owner_response_timeout_minutes": 240,
        "default_production_timeout_minutes": 240,
        "max_rounds_dm": 5,
        "max_rounds_group": 10,
        "round_reset_hours": 4,
        "owner_whatsapp_id": "",
        "assistant_name": "the assistant",
        "owner_name": "the owner",
        # False = the assistant's automatic replies in group chats are
        # disabled (listen/log only). True = normal automatic replies in
        # groups. This is a fast kill-switch — edit gatekeeper_config.json
        # directly, no restart needed (check_incoming reads the config live
        # on every message).
        "group_auto_reply_enabled": True,
        # False = the assistant never creates wiki profiles for unknown/new people
        # encountered in group chats or added to the DM allowlist -- existing
        # profiles are still enriched normally. True = when the assistant first
        # sees an unmatched sender in a group (picked up by the nightly
        # profile-sync job) OR when a new number is added to the DM allowlist
        # that the assistant can talk to, it automatically creates a minimal stub
        # profile (bare facts only: name, phone, source, last message) in the
        # wiki people folder -- no LLM call involved. Flip and save -- takes
        # effect on the next nightly profile-sync run (not immediately, unlike
        # group_auto_reply_enabled).
        "remember_new_people_enabled": False,
    }
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                defaults.update(data)
        except Exception:
            pass

    # ENV variables take precedence when explicitly set
    if "WHATSAPP_OWNER_TIMEOUT_MINUTES" in os.environ:
        try:
            defaults["owner_response_timeout_minutes"] = int(os.environ["WHATSAPP_OWNER_TIMEOUT_MINUTES"])
        except ValueError:
            pass

    return defaults


CONFIG = load_gatekeeper_config()

MAX_ROUNDS = int(os.environ.get("WHATSAPP_GUARD_DM_ROUND_LIMIT", CONFIG.get("max_rounds_dm", 5)))
MAX_ROUNDS_GROUP = int(os.environ.get("WHATSAPP_GUARD_GROUP_ROUND_LIMIT", CONFIG.get("max_rounds_group", 10)))
ROUND_RESET_HOURS = float(CONFIG.get("round_reset_hours", 4))
OWNER_TIMEOUT_MINUTES = float(CONFIG.get("owner_response_timeout_minutes", 240))
ASSISTANT_NAME = str(CONFIG.get("assistant_name") or "the assistant")
OWNER_NAME = str(CONFIG.get("owner_name") or "the owner")

# Slash commands — starting with / or !
SLASH_PATTERN = re.compile(r'^[/!]\w+', re.IGNORECASE)

# Prompt-injection patterns. Includes both English and the original
# deployment's Slovak-language examples — add patterns matching whatever
# language(s) your own deployment is likely to be attacked in.
INJECTION_PATTERNS = [
    re.compile(r'ignore\s+(previous|prior|all|above)\s+instructions?', re.IGNORECASE),
    re.compile(r'act\s+as\s+(if|though|you)', re.IGNORECASE),
    re.compile(r'you\s+are\s+now\s+', re.IGNORECASE),
    re.compile(r'pretend\s+(that|you)', re.IGNORECASE),
    re.compile(r'forget\s+(your|all|previous)\s+rules?', re.IGNORECASE),
    re.compile(r'show\s+(me\s+)?(your|the)\s+(system\s+)?prompt', re.IGNORECASE),
    re.compile(r'what\s+are\s+your\s+(system\s+)?instructions', re.IGNORECASE),
    re.compile(r'developer\s+mode\s+(on|enabled)', re.IGNORECASE),
    re.compile(r'reveal\s+(your|the)\s+(system\s+)?prompt', re.IGNORECASE),
    re.compile(r'zmeň\s+(inštrukcie|pravidlá|správanie|nastavenie)', re.IGNORECASE),
    re.compile(r'zabudni\s+(inštrukcie|pravidlá|všetko|predchádzajúce)', re.IGNORECASE),
    re.compile(r'správaj\s+sa\s+ako', re.IGNORECASE),
    re.compile(r'ty\s+si\s+teraz', re.IGNORECASE),
    re.compile(r'prezraď\s+(systémový\s+)?prompt', re.IGNORECASE),
    re.compile(r'aké\s+máš\s+(inštrukcie|pravidlá|príkazy)', re.IGNORECASE),
]

# Wiki / private-data extraction patterns (same bilingual note as above).
WIKI_EXTRACTION_PATTERNS = [
    re.compile(r'čo\s+(o\s+mne|o\s+nás)\s+(vieš|máš|je\s+napísané)', re.IGNORECASE),
    re.compile(r'čo\s+vieš\s+o\s+', re.IGNORECASE),
    re.compile(r'aké\s+(mám|máme)\s+(poznámky|informácie|dáta)', re.IGNORECASE),
    re.compile(r'aký\s+(mám|máme)\s+(profil|záznam|súbor)', re.IGNORECASE),
    re.compile(r'ukáž\s+(mi\s+)?(môj|náš)\s+(profil|záznam|kartu)', re.IGNORECASE),
    re.compile(r'psycholog.*profil', re.IGNORECASE),
    re.compile(r'osobné\s+(údaje|informácie|dáta)', re.IGNORECASE),
    re.compile(r'wiki\s*(informácie|záznam|profil|obsah)', re.IGNORECASE),
    re.compile(r'obsidian', re.IGNORECASE),
    re.compile(r'interné\s+(poznámky|dokumenty|súbory)', re.IGNORECASE),
    re.compile(r'what\s+(do\s+you\s+)?know\s+about\s+(me|us)', re.IGNORECASE),
    re.compile(r'show\s+(me\s+)?my\s+(profile|file|record)', re.IGNORECASE),
    re.compile(r'internal\s+(notes|documents|files)', re.IGNORECASE),
]

# Telegram-injection patterns (same bilingual note as above).
TELEGRAM_INJECTION_PATTERNS = [
    re.compile(r'(napíš|pošli|odkáž|posli)\s+(to\s+)?(na|do)\s+(marekov\s+)?telegram', re.IGNORECASE),
    re.compile(r'telegram.*(správa|odkaz|notifikácia)', re.IGNORECASE),
    re.compile(r'prepošli\s+na\s+telegram', re.IGNORECASE),
    re.compile(r'(send|forward)\s+(this\s+)?to\s+(the\s+owner.?s\s+)?telegram', re.IGNORECASE),
]


# ── Contact / profile helper functions ────────────────────────────────

def clean_digits(s: Any) -> str:
    """Extracts only the digits from a string."""
    if not s:
        return ""
    return re.sub(r'\D', '', str(s))


def lookup_person_profile(chat_id: str, contact_name: str = "") -> Tuple[str, str, str, str]:
    """
    Looks up a contact in WHATSAPP_GUARD_PEOPLE_DIR/*.md by chat_id, phone
    number, or name. Returns: (name, about, communication_style, phone).

    "phone" is read from the file's YAML frontmatter (the
    PROFILE_PHONE_KEY field), NOT from the LID-reverse-mapping lookup
    below — that mapping is only used as a search key to find the right
    file, its value isn't a verified source for display.
    """
    phone = clean_digits(chat_id)
    if "lid" in chat_id.lower() or len(phone) > 13:
        # Resolve a LID to a phone number via the reverse mapping (search key only)
        lid_clean = chat_id.replace("@lid", "").replace("@s.whatsapp.net", "")
        for f in glob.glob(f"{SESSION_DIR}/lid-mapping-*_reverse.json"):
            if lid_clean in f:
                try:
                    with open(f, "r", encoding="utf-8") as fp:
                        phone = clean_digits(json.load(fp))
                except Exception:
                    pass

    found_profile: Optional[Tuple[str, str]] = None
    if PEOPLE_DIR.exists():
        for f in glob.glob(f"{PEOPLE_DIR}/*.md"):
            base = os.path.basename(f)
            if base.startswith("_") or base == "index.md":
                continue
            try:
                with open(f, "r", encoding="utf-8") as fp:
                    content = fp.read()
                    if phone and len(phone) >= 9 and phone in clean_digits(content):
                        found_profile = (f, content)
                        break
                    if contact_name and len(contact_name) >= 3:
                        # Token-based match (not a contiguous substring): a
                        # WhatsApp push-name is often "Last First" (e.g.
                        # "Doe John"), while notes/filenames tend to use the
                        # natural order "John Doe". Every word of the name
                        # must appear somewhere in the content or filename,
                        # regardless of order.
                        name_tokens = [t for t in re.findall(r"\w+", contact_name.lower()) if len(t) >= 2]
                        haystack = content.lower() + " " + base.lower()
                        if name_tokens and all(t in haystack for t in name_tokens):
                            found_profile = (f, content)
                            break
            except Exception:
                pass

    if found_profile:
        filepath, content = found_profile
        name = os.path.basename(filepath).replace(".md", "").replace("-", " ").title()
        about = ""
        comm_style = ""
        phone_field = ""
        m_fm = re.match(r'^---\n(.*?)\n---', content, re.DOTALL)
        if m_fm:
            m_tel = re.search(rf'^{re.escape(PROFILE_PHONE_KEY)}:\s*(.+)$', m_fm.group(1), re.MULTILINE)
            if m_tel:
                phone_field = m_tel.group(1).strip().strip("'\"")
        m_about = re.search(re.escape(PROFILE_ABOUT_HEADER) + r'\n(.*?)(?=\n## |\Z)', content, re.DOTALL)
        if m_about:
            about = m_about.group(1).strip()[:300]
        m_style = re.search(re.escape(PROFILE_STYLE_HEADER) + r'\n(.*?)(?=\n## |\Z)', content, re.DOTALL)
        if m_style:
            comm_style = m_style.group(1).strip()[:300]
        return name, about, comm_style, phone_field

    return contact_name or "Contact", "", "", ""


# ── State persistence ──────────────────────────────────────────────────

def _safe_filename(identifier: str) -> str:
    """Replaces filesystem-unsafe characters in a filename."""
    clean = re.sub(r'[/\\?%*:|"<>]', '_', identifier)
    return clean.strip()


def get_state_file(chat_id: str, sender_id: str = "") -> Path:
    """
    Returns the path to a conversation's state file.
    Per-sender for groups, per-chat for DMs.
    """
    if chat_id.endswith("@g.us") and sender_id and sender_id != chat_id:
        group_part = _safe_filename(chat_id.replace("@g.us", ""))
        sender_part = _safe_filename(sender_id.replace("@s.whatsapp.net", "").replace("@lid", ""))
        filename = f"group_{group_part}_user_{sender_part}.json"
    else:
        filename = f"{_safe_filename(chat_id)}.json"
    return STATE_DIR / filename


def load_state(chat_id: str, sender_id: str = "") -> Dict[str, Any]:
    """Loads conversation state from disk."""
    path = get_state_file(chat_id, sender_id)
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    is_group = chat_id.endswith("@g.us")
    return {
        "chat_id": chat_id,
        "sender_id": sender_id or chat_id,
        "rounds_completed": 0,
        "limit": MAX_ROUNDS_GROUP if is_group else MAX_ROUNDS,
        "limit_exceeded": False,
        "handoff_sent": False,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "last_message_at": datetime.now(timezone.utc).isoformat(),
        "last_topic": "",
        "messages": [],
        "status": "idle",  # "idle" | "pending_owner_reply" | "handled_by_owner" | "in_progress_assistant" | "completed"
        "waiting_since": None,
        "pending_messages": [],
        "recent_messages": [],
        "contact_name": "",
    }


def save_state(chat_id: str, state: Dict[str, Any], sender_id: str = "") -> None:
    """Saves conversation state to disk and updates the index."""
    path = get_state_file(chat_id, sender_id)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"[whatsapp_guard] Error saving state for {chat_id}: {e}", file=sys.stderr)

    _update_index(chat_id, state, sender_id)


def _update_index(chat_id: str, state: Dict[str, Any], sender_id: str = "") -> None:
    """Updates the central conversation index."""
    index_file = STATE_DIR / "index.json"
    index = {}
    if index_file.exists():
        try:
            with open(index_file, "r", encoding="utf-8") as f:
                index = json.load(f)
        except Exception:
            index = {}

    index["last_updated"] = datetime.now(timezone.utc).isoformat()
    updated = False
    for conv in index.get("conversations", []):
        if conv.get("chat_id") == chat_id and conv.get("sender_id", "") == (sender_id or chat_id):
            conv["rounds_completed"] = state.get("rounds_completed", 0)
            conv["last_message_at"] = state.get("last_message_at")
            conv["status"] = state.get("status", "active")
            conv["waiting_since"] = state.get("waiting_since")
            conv["contact_name"] = state.get("contact_name", "")
            updated = True
            break

    if not updated:
        index.setdefault("conversations", []).append({
            "chat_id": chat_id,
            "sender_id": sender_id,
            "contact_name": state.get("contact_name", ""),
            "rounds_completed": state.get("rounds_completed", 0),
            "last_message_at": state.get("last_message_at"),
            "status": state.get("status", "active"),
            "waiting_since": state.get("waiting_since"),
        })

    try:
        with open(index_file, "w", encoding="utf-8") as f:
            json.dump(index, f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def should_reset(state: Dict[str, Any]) -> bool:
    """Checks whether enough idle time has passed to reset the conversation."""
    last = state.get("last_message_at")
    if not last:
        return True
    try:
        last_dt = datetime.fromisoformat(last)
        if last_dt.tzinfo is None:
            last_dt = last_dt.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        gap = (now - last_dt).total_seconds() / 3600
        return gap >= ROUND_RESET_HOURS
    except (ValueError, TypeError):
        return False


def _append_recent_message(state: Dict[str, Any], speaker: str, text: str, cap: int = 12) -> None:
    """Appends a message to the conversation's rolling log (both sides:
    'contact'/'owner'), used as context by build_contextual_intro() so the
    takeover message can naturally continue the thread instead of asking a
    generic question. Keeps only the last `cap` messages."""
    if not text or not text.strip():
        return
    log = state.setdefault("recent_messages", [])
    log.append({
        "speaker": speaker,
        "text": text.strip()[:500],
        "at": datetime.now(timezone.utc).isoformat(),
    })
    if len(log) > cap:
        del log[: len(log) - cap]


# ── Owner activity & delayed handover logic ────────────────────────────

def record_owner_reply(chat_id: str, text: str = "") -> None:
    """
    Records that the owner personally stepped into the conversation / replied
    to the contact from their phone (fromMe: true). Immediately stops the
    assistant, resets the round counter, and flips state to 'handled_by_owner'.
    """
    state = load_state(chat_id)
    state["status"] = "handled_by_owner"
    state["waiting_since"] = None
    state["pending_messages"] = []
    state["rounds_completed"] = 0
    state["limit_exceeded"] = False
    state["handoff_sent"] = False
    state["messages"] = []
    state["last_message_at"] = datetime.now(timezone.utc).isoformat()
    if text:
        _append_recent_message(state, "owner", text)
    save_state(chat_id, state)


def is_owner_timeout_expired(state: Dict[str, Any], timeout_minutes: Optional[float] = None) -> bool:
    """Checks whether the wait for the owner's reply has timed out."""
    waiting_since = state.get("waiting_since")
    if not waiting_since or state.get("status") != "pending_owner_reply":
        return False
    try:
        w_dt = datetime.fromisoformat(waiting_since)
        if w_dt.tzinfo is None:
            w_dt = w_dt.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        limit = timeout_minutes if timeout_minutes is not None else OWNER_TIMEOUT_MINUTES
        return (now - w_dt).total_seconds() >= (limit * 60)
    except Exception:
        return False


def register_incoming_dm_for_delay(chat_id: str, text: str, contact_name: str = "") -> Dict[str, Any]:
    """
    Registers a new incoming DM into the waiting-for-owner mode. If a wait
    is already in progress, appends the text to pending_messages instead.
    """
    state = load_state(chat_id)
    now_iso = datetime.now(timezone.utc).isoformat()

    stale = should_reset(state)
    if stale or state.get("status") in ("idle", "handled_by_owner", "completed"):
        state["rounds_completed"] = 0
        state["limit_exceeded"] = False
        state["handoff_sent"] = False
        state["status"] = "pending_owner_reply"
        state["waiting_since"] = now_iso
        state["pending_messages"] = [text]
        state["started_at"] = now_iso
        state["messages"] = []
        if stale:
            # A genuinely new topic after a long pause (>= ROUND_RESET_HOURS)
            # — the old thread is no longer relevant context for the next
            # takeover message.
            state["recent_messages"] = []
    elif state.get("status") == "pending_owner_reply":
        state.setdefault("pending_messages", []).append(text)

    _append_recent_message(state, "contact", text)

    state["last_message_at"] = now_iso
    state["last_topic"] = text[:100]
    if contact_name:
        state["contact_name"] = contact_name

    save_state(chat_id, state)
    return state


_MOJIBAKE_BIGRAMS = ("Ã¡", "Ã©", "Ã­", "Ã³", "Ãº", "Ã½", "Ä", "Å¡", "Å¾", "Ä¾",
                     "Ã¤", "Ã´", "Å¥", "Åˆ", "Ä", "Ã„", "Å")


def _looks_mojibake(text: str) -> bool:
    """Detects the typical fingerprint of UTF-8 bytes misread as CP1252/
    Latin-1 (e.g. from a broken LLM/proxy response). A cheap safety check
    before sending anything out to WhatsApp."""
    if "�" in text:
        return True
    if any(0x80 <= ord(ch) <= 0x9F for ch in text):
        return True
    return any(bg in text for bg in _MOJIBAKE_BIGRAMS)


def build_contextual_intro(
    pending_messages: List[str],
    contact_name: str = "",
    chat_id: str = "",
    recent_messages: Optional[List[Dict[str, Any]]] = None,
) -> str:
    """
    Builds a natural, personal, contextual takeover message via an LLM.

    If `recent_messages` is available (the rolling log of both sides of the
    conversation, see _append_recent_message), the assistant gets the actual
    last stretch of the conversation and is instructed to CONTINUE it — not
    ask a generic "what do you need" question. Without it (older state files
    predating this feature, or a genuinely first contact), it falls back to
    the older mode of just listing the messages that arrived while waiting.
    """
    person_name, about, comm_style, _phone = lookup_person_profile(chat_id, contact_name)
    display_first_name = person_name.split()[0] if person_name else (contact_name or "there")

    # Prefer the real two-sided rolling log over the bare pending_messages
    # list (which is one-sided, contact-only).
    transcript_text = ""
    if recent_messages:
        lines = []
        for m in recent_messages[-10:]:
            who = OWNER_NAME if m.get("speaker") == "owner" else display_first_name
            t = (m.get("text") or "").strip()
            if t:
                lines.append(f"{who}: {t}")
        transcript_text = "\n".join(lines)

    if not transcript_text:
        msgs_text = "\n".join(f"- {m}" for m in pending_messages if m.strip())
        transcript_text = msgs_text or "(a short greeting / message)"

    # Try to generate a smart, contextual message via an LLM
    try:
        sys.path.insert(0, "/app/hermes-agent-src")
        from agent.auxiliary_client import call_llm

        system_prompt = (
            f"You are {ASSISTANT_NAME}, {OWNER_NAME}'s personal assistant and WhatsApp "
            f"gatekeeper.\n"
            f"{OWNER_NAME} hasn't replied to this contact for a while, so you're stepping "
            f"in now.\n"
            "You'll get the last stretch of the ACTUAL conversation between the owner and "
            "the contact (both sides, chronological). Your job: CONTINUE it exactly where "
            "it left off — as if you picked up the phone mid-conversation.\n\n"
            "STYLE RULES (HUMANIZER & ULTRA-BREVITY):\n"
            "1. Write like a busy person on their phone who's watching every word.\n"
            "2. No filler, no AI clichés, no politeness padding.\n"
            "3. Length: 1-2 short, punchy sentences.\n"
            f"4. Introduce yourself ONLY in the first sentence: 'Hi [Name], it's "
            f"{ASSISTANT_NAME} — {OWNER_NAME}'s assistant. {OWNER_NAME} is swamped, so "
            "I'm writing.' (match formal/informal tone to the contact's profile.)\n"
            "5. Immediately after, pick up directly on the LAST concrete point from the "
            "transcript (e.g. a scheduled meeting, an unanswered question, a plan to "
            "confirm) — NOT a generic 'what do you need' question.\n"
            "6. NEVER quote messages verbatim in quotation marks — paraphrase naturally.\n"
            "7. NO emoji.\n"
            "8. Return ONLY the message text, no prefixes or quotation marks."
        )

        user_prompt = (
            f"Contact: {person_name}\n"
            f"Relationship / profile: {about or 'Friend / business contact'}\n"
            f"Communication style: {comm_style or 'Informal'}\n\n"
            f"Last stretch of the conversation (chronological, both sides):\n{transcript_text}"
        )

        resp = call_llm(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            task="whatsapp_intro",
            timeout=15
        )
        if resp and resp.choices and resp.choices[0].message and resp.choices[0].message.content:
            raw_msg = resp.choices[0].message.content.strip()
            # Strip a leading assistant-name prefix or stray quote marks
            cleaned = re.sub(rf'^({re.escape(ASSISTANT_NAME)}:\s*|["\'])', '', raw_msg).rstrip('"\'')
            if cleaned and not _looks_mojibake(cleaned):
                return cleaned
            if cleaned:
                print(f"[whatsapp_guard] LLM intro rejected — mojibake detected, using rule-based fallback: {cleaned!r}", file=sys.stderr)
    except Exception as e:
        print(f"[whatsapp_guard] LLM intro generation fallback due to: {e}", file=sys.stderr)

    # Rule-based fallback (if the LLM call fails or times out)
    return (
        f"Hi {display_first_name}, it's {ASSISTANT_NAME} — {OWNER_NAME}'s assistant. "
        f"{OWNER_NAME} can't get to this right now, so I'm stepping in. Anything new on "
        f"your end, or what exactly do you need prepared so I can pass it along?"
    )


# ── Security pattern detection ─────────────────────────────────────────

def detect_slash_command(text: str) -> Optional[str]:
    """Detects a slash command."""
    match = SLASH_PATTERN.match(text.strip())
    if match:
        return match.group(0)
    return None


def detect_injection(text: str) -> Optional[str]:
    """Detects a prompt-injection attempt."""
    for pattern in INJECTION_PATTERNS:
        match = pattern.search(text)
        if match:
            return f"Injection pattern: {pattern.pattern[:60]}"
    return None


def detect_wiki_extraction(text: str) -> Optional[str]:
    """Detects an attempt to extract wiki / personal data."""
    for pattern in WIKI_EXTRACTION_PATTERNS:
        match = pattern.search(text)
        if match:
            return f"Wiki extraction pattern: {pattern.pattern[:60]}"
    return None


def detect_telegram_injection(text: str) -> Optional[str]:
    """Detects an attempt to manipulate Telegram notifications."""
    for pattern in TELEGRAM_INJECTION_PATTERNS:
        match = pattern.search(text)
        if match:
            return f"Telegram injection pattern: {pattern.pattern[:60]}"
    return None


# ── Main filter: check_incoming ─────────────────────────────────────────

def _check_incoming_core(
    chat_id: str,
    text: str,
    contact_name: str = "",
    sender_id: str = "",
    from_me: bool = False,
) -> Dict[str, Any]:
    """
    Main entry point for the pre_gateway_dispatch hook.
    Checks security, updates state, and drives the delayed-handover logic.
    """
    cfg = load_gatekeeper_config()
    is_group = chat_id.endswith("@g.us")

    # 1. The owner is writing from a linked device (fromMe: true) into a DM
    if from_me and not is_group:
        record_owner_reply(chat_id, text)
        return {
            "decision": "block",
            "reason": "Owner message recorded — assistant yields",
            "action": "owner_activity",
            "state": load_state(chat_id),
            "reply": None,
            "telegram_notification": None,
        }

    # 2. Hardening checks (slash commands, injection, wiki extraction)
    cmd = detect_slash_command(text)
    if cmd:
        return {
            "decision": "block",
            "reason": f"Slash command detected: {cmd}",
            "action": "warn_no_commands",
            "state": load_state(chat_id, sender_id),
            "reply": "That's an administrative command — not available via WhatsApp.",
            "telegram_notification": None,
        }

    inj = detect_injection(text)
    if inj:
        return {
            "decision": "block",
            "reason": inj,
            "action": "deflect_injection",
            "state": load_state(chat_id, sender_id),
            "reply": "Nice try. Let's get to the point — what do you actually need?",
            "telegram_notification": f"⚠️ Injection attempt from {contact_name or chat_id}:\n{text[:200]}",
        }

    wiki = detect_wiki_extraction(text)
    if wiki:
        return {
            "decision": "block",
            "reason": wiki,
            "action": "deflect_wiki_request",
            "state": load_state(chat_id, sender_id),
            "reply": "I only know what you've told me right here. What do you need?",
            "telegram_notification": None,
        }

    tg_inj = detect_telegram_injection(text)
    if tg_inj:
        return {
            "decision": "block",
            "reason": tg_inj,
            "action": "deflect_telegram_injection",
            "state": load_state(chat_id, sender_id),
            "reply": f"I handle things directly here on WhatsApp. If you want to leave "
                     f"something for {OWNER_NAME}, write it here and I'll pass it on.",
            "telegram_notification": None,
        }

    # 3. Round-limit check (if a conversation is already running with the assistant)
    state = load_state(chat_id, sender_id)
    if should_reset(state):
        state["rounds_completed"] = 0
        state["limit_exceeded"] = False
        state["handoff_sent"] = False
        state["status"] = "idle"
        save_state(chat_id, state, sender_id)

    round_limit = MAX_ROUNDS_GROUP if is_group else MAX_ROUNDS
    if state.get("rounds_completed", 0) >= round_limit:
        if not state.get("handoff_sent", False):
            state["limit_exceeded"] = True
            state["handoff_sent"] = True
            save_state(chat_id, state, sender_id)
            return {
                "decision": "block",
                "reason": f"Round limit reached ({round_limit})",
                "action": "handoff_to_telegram",
                "state": state,
                "reply": f"{OWNER_NAME} will take it from here. You'll hear back.",
                "telegram_notification": f"📞 WhatsApp conversation with {contact_name or chat_id} reached the {round_limit}-round limit.\nLast topic: {text[:100]}\nHanding the conversation back to you.",
            }
        else:
            return {
                "decision": "block",
                "reason": "Round limit already exceeded — silent",
                "action": "silent_block",
                "state": state,
                "reply": None,
                "telegram_notification": None,
            }

    # 4. Delayed handover for DM messages.
    # If enabled and the message is a DM and the conversation isn't already
    # in an active assistant-handled mode:
    if cfg.get("enabled", True) and not is_group:
        if state.get("status") in ("idle", "pending_owner_reply", "handled_by_owner"):
            # Register the message and delay the assistant's immediate reply
            state = register_incoming_dm_for_delay(chat_id, text, contact_name)
            return {
                "decision": "block",
                "reason": "Delaying for owner reply (Delayed Gatekeeper Mode)",
                "action": "pending_owner_delay",
                "state": state,
                "reply": None,
                "telegram_notification": None,
            }

    # 5. Standard direct reply (groups, or once the assistant has already taken over)
    state["rounds_completed"] = state.get("rounds_completed", 0) + 1
    state["status"] = "in_progress_assistant"
    state["last_message_at"] = datetime.now(timezone.utc).isoformat()
    state["last_topic"] = text[:100]
    _append_recent_message(state, "contact", text)
    save_state(chat_id, state, sender_id)

    return {
        "decision": "allow",
        "reason": "Normal message allowed",
        "action": "continue_conversation",
        "state": state,
        "reply": None,
        "telegram_notification": None,
    }


def check_incoming(
    chat_id: str,
    text: str,
    contact_name: str = "",
    sender_id: str = "",
    from_me: bool = False,
) -> Dict[str, Any]:
    """
    Public entry point for the pre_gateway_dispatch hook. Calls
    _check_incoming_core() for all security/state logic, then applies the
    group mute switch (a fast kill-switch via gatekeeper_config.json's
    "group_auto_reply_enabled").

    When group auto-reply is disabled:
    - a normal message that would otherwise get a reply (decision=allow) is
      silently blocked (no reply, no Telegram notification — just an
      ordinary group discussion).
    - security detections (slash/injection/wiki/telegram-injection) stay
      ACTIVE, and the Telegram alert about the attempt still goes out — only
      the reply into the group itself is suppressed (the assistant stays
      silent even when blocking).
    DM messages are entirely unaffected by this switch.
    """
    result = _check_incoming_core(chat_id, text, contact_name, sender_id, from_me)

    is_group = chat_id.endswith("@g.us")
    if not is_group:
        return result

    cfg = load_gatekeeper_config()
    if cfg.get("group_auto_reply_enabled", True):
        return result

    if result.get("decision") == "allow":
        return {
            "decision": "block",
            "reason": "Group auto-reply disabled (listen-only mode, gatekeeper_config.json)",
            "action": "group_listen_only",
            "state": result.get("state"),
            "reply": None,
            "telegram_notification": None,
        }

    if result.get("reply"):
        muted = dict(result)
        muted["reply"] = None
        return muted

    return result


if __name__ == "__main__":
    print(f"WhatsApp Guard v2.1.0 loaded.")
    print(f"Config: timeout={OWNER_TIMEOUT_MINUTES} min, max_dm={MAX_ROUNDS}, max_group={MAX_ROUNDS_GROUP}")
