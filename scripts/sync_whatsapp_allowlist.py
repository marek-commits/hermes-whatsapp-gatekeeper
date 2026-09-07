#!/usr/bin/env python3
"""Keep the WhatsApp DM allowlist in ONE place.

    config.yaml (allow_admin_from + allow_from)  --->  .env WHATSAPP_ALLOWED_USERS

WHY THIS EXISTS
---------------
The WhatsApp bridge reads its allowlist from the ``WHATSAPP_ALLOWED_USERS``
environment variable and *only* from there. ``allow_from`` in ``config.yaml``
never reaches it — the adapter passes just the ``WHATSAPP_*`` env vars down to
the bridge process. So editing ``allow_from`` alone looks like it worked and
silently changes nothing.

Worse, two env settings can make the config allowlist entirely decorative:

* ``WHATSAPP_ALLOW_ALL_USERS=true`` — the gateway's authorization check returns
  "allowed" before it ever looks at ``dm_policy`` / ``allow_from``.
* ``WHATSAPP_ALLOWED_USERS=*`` — the bridge lets everyone through.

And one non-obvious consequence: the bridge's owner-message gate matches the
*contact's* chat id against the same allowlist. A contact who is not on it
means the owner's own replies in that chat are dropped too, so the guard never
learns the owner took over. Removing someone from the allowlist to silence the
assistant therefore also disables owner-takeover detection for that chat.

USAGE
-----
    python3 sync_whatsapp_allowlist.py --profile mia --check
        Silent + exit 0 when the two agree. Exit 1 and a description otherwise
        (suitable for a cron watchdog).

    python3 sync_whatsapp_allowlist.py --profile mia --fix
        Rewrites WHATSAPP_ALLOWED_USERS from config.yaml (keeps a timestamped
        backup) and comments out WHATSAPP_ALLOW_ALL_USERS. Takes effect on the
        next gateway restart.

    python3 sync_whatsapp_allowlist.py --profile mia --show
        Prints both sides and the verdict.

``--profile default`` (or omitting it) targets HERMES_HOME itself; any other
name targets ``HERMES_HOME/profiles/<name>``.
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
from datetime import datetime
from pathlib import Path

import yaml

HERMES_HOME = Path(os.environ.get("HERMES_HOME", str(Path.home() / ".hermes")))


def profile_home(profile: str) -> Path:
    if profile in ("", "default"):
        return HERMES_HOME
    root = HERMES_HOME.parent if HERMES_HOME.parent.name == "profiles" else HERMES_HOME / "profiles"
    return root / profile


def normalize(value) -> str:
    """'+421 900 123' / '421900123@s.whatsapp.net' -> '421900123'."""
    return str(value).strip().lstrip("+").split("@")[0].replace(" ", "")


def expected_from_config(home: Path):
    cfg_path = home / "config.yaml"
    if not cfg_path.exists():
        return None, f"config.yaml not found: {cfg_path}"
    cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    whatsapp = ((cfg.get("platforms") or {}).get("whatsapp") or {})
    if not whatsapp:
        return None, "profile has no platforms.whatsapp section"
    extra = whatsapp.get("extra") or {}
    ordered, seen = [], set()
    for raw in list(extra.get("allow_admin_from") or []) + list(extra.get("allow_from") or []):
        value = normalize(raw)
        if value and value not in seen:
            seen.add(value)
            ordered.append(value)
    return ordered, None


def env_lines(home: Path):
    env_path = home / ".env"
    if not env_path.exists():
        return None, None
    return env_path, env_path.read_text(encoding="utf-8").splitlines()


def current_from_env(lines):
    """-> (numbers, allow_all_enabled, value_is_wildcard)."""
    users, allow_all, wildcard = [], False, False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("WHATSAPP_ALLOWED_USERS="):
            raw = stripped.split("=", 1)[1].strip()
            if raw == "*":
                wildcard = True
            users = [normalize(x) for x in raw.split(",") if normalize(x)]
        elif stripped.startswith("WHATSAPP_ALLOW_ALL_USERS="):
            allow_all = stripped.split("=", 1)[1].strip().lower() in {"true", "1", "yes"}
    return users, allow_all, wildcard


def report(expected, current, allow_all, wildcard) -> list:
    """Returns a list of problems; empty means the two sides agree."""
    problems = []
    if allow_all:
        problems.append(
            "WHATSAPP_ALLOW_ALL_USERS is on — authorization returns 'allowed' before it "
            "reaches dm_policy/allow_from, so the config allowlist is never evaluated"
        )
    if wildcard:
        problems.append(
            "WHATSAPP_ALLOWED_USERS='*' — the bridge lets everyone through and allow_from "
            "in config.yaml has no effect"
        )
    if not wildcard:
        missing = sorted(set(expected) - set(current))
        extra = sorted(set(current) - set(expected))
        if missing:
            problems.append(
                f"missing from .env ({len(missing)}): {', '.join(missing)} — these contacts are "
                f"allowed by config.yaml but the bridge drops them"
            )
        if extra:
            problems.append(
                f"extra in .env ({len(extra)}): {', '.join(extra)} — the bridge accepts these "
                f"even though config.yaml does not list them"
            )
    return problems


def write_env(env_path: Path, lines, expected):
    backup = env_path.parent / f".env.bak.{datetime.now():%Y%m%d_%H%M%S}"
    shutil.copy2(env_path, backup)
    joined = ",".join(expected)
    out, replaced = [], False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("WHATSAPP_ALLOWED_USERS="):
            out.append(f"WHATSAPP_ALLOWED_USERS={joined}")
            replaced = True
        elif stripped.startswith("WHATSAPP_ALLOW_ALL_USERS=") and not stripped.startswith("#"):
            out.append("# disabled by sync_whatsapp_allowlist.py: allow-all bypasses the "
                       "config.yaml allowlist")
            out.append("#" + line)
        else:
            out.append(line)
    if not replaced:
        out.append(f"WHATSAPP_ALLOWED_USERS={joined}")
    env_path.write_text("\n".join(out) + "\n", encoding="utf-8")
    return backup


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Sync the WhatsApp DM allowlist from config.yaml into .env")
    parser.add_argument("--profile", default="default")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="report drift only (silent when in sync)")
    mode.add_argument("--fix", action="store_true", help="rewrite .env from config.yaml")
    mode.add_argument("--show", action="store_true", help="print both sides")
    args = parser.parse_args()

    home = profile_home(args.profile)
    expected, err = expected_from_config(home)
    if err:
        print(f"[allowlist:{args.profile}] {err}")
        return 2
    env_path, lines = env_lines(home)
    if env_path is None:
        print(f"[allowlist:{args.profile}] no .env in {home}")
        return 2
    current, allow_all, wildcard = current_from_env(lines)
    problems = report(expected, current, allow_all, wildcard)

    if args.show:
        print(f"profile:      {args.profile}")
        print(f"config.yaml:  {len(expected)} number(s)")
        print(f".env:         {'*' if wildcard else f'{len(current)} number(s)'}")
        print(f"allow-all:    {allow_all}")
        print("verdict:      " + ("in sync" if not problems else "OUT OF SYNC"))
        for problem in problems:
            print(f"  - {problem}")
        return 0

    if args.check:
        if not problems:
            return 0
        print(f"WhatsApp allowlist ({args.profile}) is out of sync:")
        for problem in problems:
            print(f"  * {problem}")
        print(f"  Fix: sync_whatsapp_allowlist.py --profile {args.profile} --fix "
              f"(then restart the gateway)")
        return 1

    if not problems:
        print(f"[allowlist:{args.profile}] already in sync ({len(expected)} number(s))")
        return 0
    backup = write_env(env_path, lines, expected)
    print(f"[allowlist:{args.profile}] .env updated from config.yaml "
          f"({len(expected)} number(s), backup: {backup.name})")
    print("  Restart the gateway for the bridge to pick it up.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
