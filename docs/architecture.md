# Architecture

## The problem

Hermes Agent's `platform_toolsets` config lets you restrict which *tools* a
messaging channel can call, but that's where the built-in controls stop.
Nothing in Hermes itself:

- limits how long an unattended conversation on a messaging channel runs,
- distinguishes "the account owner is replying personally" from "the agent
  is replying," so a channel can't easily prioritize the human,
- filters prompt-injection, data-exfiltration, or admin-command attempts
  *before* the agent ever sees them,
- survives a `hermes update` if you fix any of the above by patching
  vendored source directly.

This project is a defense-in-depth stack that closes those gaps, built
incrementally over about a week of live, incident-driven hardening on a
production WhatsApp deployment.

## The incident that started it

A WhatsApp contact drove a conversation well past its intended round limit.
Two things went wrong at once: the round counter wasn't being enforced
anywhere the contact couldn't influence it, and a slash-command allowlist
gap meant the agent disclosed a list of admin-only commands to a non-admin
sender. Both were emergency-patched within the same day; everything else
here grew out of hardening those patches and closing adjacent gaps found
by testing.

## Design principle: enforcement lives in code, not in a prompt

The single biggest lesson from that incident and the weeks after: **a
round limit or a command lockdown that lives only in a skill/prompt is a
suggestion, not a control.** An LLM can be talked out of counting
correctly, especially by an adversarial sender who knows (or guesses) that
a counter exists. Every hard invariant in this project — the round cap,
the slash-command block, the owner-vs-assistant handover — is enforced in
plain Python in a `pre_gateway_dispatch` hook that runs *before* the agent
is ever invoked. The `whatsapp-conversation-rules` skill only shapes tone
and gives the LLM context; it is never trusted to enforce a limit.

## The layers

1. **Contact allowlist** (Hermes-native config) — who can reach the
   channel at all.
2. **Slash-command lockdown** (Hermes-native config:
   `allow_admin_from` / `group_allow_admin_from` /
   `user_allowed_commands: []`) — non-admins get no commands by config.
3. **`whatsapp-security-floor` plugin** — closes a gap *config alone can't
   close*: Hermes hardcodes `/help` and `/whoami` as always-reachable
   regardless of the config above (see
   `plugins/whatsapp-security-floor/__init__.py` for the exact mechanism
   and why it has to be a plugin rather than a source patch).
4. **Minimal toolset** (`platform_toolsets.whatsapp` in Hermes's own
   `config.yaml`) — the channel gets the smallest tool set that's useful
   (e.g. vision + text-to-speech), independent of what other channels are
   allowed.
5. **`whatsapp_guard` plugin** — the core of this repo. A
   `pre_gateway_dispatch` hook that runs the round counter, the
   delayed-handover state machine, and the injection/wiki/Telegram-
   extraction pattern detection, all before the agent runs. See
   `scripts/whatsapp_guard.py` for the implementation and
   `plugins/whatsapp_guard/__init__.py` for the hook wiring.
6. **Delayed Gatekeeper conversation mode** — optional, but the feature
   this project is named for: the owner is the primary responder for a
   configurable window; the assistant only takes over after a timeout of
   owner inactivity, then runs on its own limited round budget. See
   `scripts/whatsapp_gatekeeper_watchdog.py`.
7. **`whatsapp-conversation-rules` skill** — tone, brevity, and
   escalation guidance for the LLM once it *is* allowed to reply. Shapes
   behavior; enforces nothing (see the design principle above).
8. **Owner-alert side channel** (Telegram, by default) — every hard block
   and every takeover notifies the owner out-of-band, so the owner has
   visibility even while away from WhatsApp.
9. **Update-safe patching** — plugins under `HERMES_HOME/plugins` survive
   `hermes update` automatically; anything that had to touch vendored
   source is documented in `docs/update-integration.md` so it can be
   reapplied deliberately instead of silently vanishing.
10. **Independent monitoring** — the original deployment runs two
    unrelated periodic checks (a security-invariant verifier and a
    general health check) so a regression in any of the above is caught
    even if nobody's actively watching. Not included verbatim in this
    repo (they're deployment-specific), but worth building an equivalent
    for your own setup — see the Status note in the README.

## Known rough edges

- The in-progress conversation-state value is generically named
  `in_progress_assistant` in this repo; the original deployment used a
  value that baked in its own persona's name. Cosmetic, but worth knowing
  if you're diffing against an older deployment.
- The optional per-contact profile lookup (`lookup_person_profile` in
  `scripts/whatsapp_guard.py`) assumes a folder of Markdown notes with a
  particular frontmatter/heading convention. It's fully configurable via
  environment variables, but if you don't keep notes like that, the
  feature just degrades gracefully to using the bare contact name.
- Group-chat handling (per-sender round limits, the `group_auto_reply_enabled`
  kill-switch) has less live testing behind it than the DM path.
