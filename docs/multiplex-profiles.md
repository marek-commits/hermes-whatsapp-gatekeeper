# Running the gatekeeper under a dedicated profile

Hermes can run one gateway process that serves several profiles at once
(`gateway.multiplex_profiles: true`). Moving WhatsApp onto its own profile is a
good idea — the assistant that talks to your friends gets its own persona,
model, memory and a minimal toolset, while your main profile keeps your private
tools. But the move has sharp edges that fail *silently*. This page is the list
we paid for the hard way.

Every item below was observed on a live deployment, not inferred from the code.

---

## 1. `plugins/` and `scripts/` resolve per profile

A non-default profile looks for plugins in `<profile home>/plugins/` and for
cron `--script` targets in `<profile home>/scripts/` — **not** in the shared
`$HERMES_HOME/plugins` and `$HERMES_HOME/scripts`.

If the directory is missing, `plugins.enabled` in that profile's `config.yaml`
resolves to nothing. The gateway starts, WhatsApp connects, messages flow — and
the guard is simply not there. No error, no warning.

The symptom is the assistant behaving as if the gatekeeper did not exist: it
never yields when the owner takes over, never enforces the round limit, and the
security floor is gone too.

```bash
# What it looks like when it is broken
hermes profile use mia && hermes plugins list     # empty table

# Fix: point the profile at the shared directories
ln -sfn "$HERMES_HOME/plugins"  "$HERMES_HOME/profiles/mia/plugins"
ln -sfn "$HERMES_HOME/scripts"  "$HERMES_HOME/profiles/mia/scripts"
```

Verify in the gateway log — the guard registers **per profile**, and the
profile-scoped registration carries a home-hash suffix:

```
hermes_plugins.whatsapp_guard__home_1c8dbfae2c38: WhatsApp Guard plugin registered
    — pre_gateway_dispatch hook active
gateway.run: ✓ whatsapp connected (profile: mia)
```

The unsuffixed `hermes_plugins.whatsapp_guard` line is the *default* profile's
registration. Seeing only that one means the WhatsApp-owning profile has no
guard.

## 2. Guard state paths follow `HERMES_HOME`

`whatsapp_guard.py` derives `STATE_DIR`, `CONFIG_PATH` and `SESSION_DIR` from
`HERMES_HOME`. Under a profile they would point at
`<profile home>/whatsapp/...`, splitting conversation state, the gatekeeper
config and the LID→phone mappings away from the shared store.

Symlinking the whole directory keeps exactly one physical copy:

```bash
ln -sfn "$HERMES_HOME/whatsapp" "$HERMES_HOME/profiles/mia/whatsapp"
```

A useful canary: if `whatsapp/conversation-state/` has not been written for
days while messages are arriving, the guard is not running.

## 3. `.env` overrides `config.yaml`

This one has bitten us three times, on three different keys
(`WHATSAPP_ENABLED`, `WHATSAPP_REPLY_PREFIX`, `WHATSAPP_ALLOWED_USERS`).

Setting `platforms.whatsapp.enabled: false` in the default profile's
`config.yaml` does **not** disable WhatsApp there if `WHATSAPP_ENABLED=true` is
still in its `.env`. Whenever something ignores your config, check the `.env`
of that profile first.

## 4. Copying a `.env` between profiles breaks startup

A new profile is often seeded by copying the default profile's `.env`. If the
copy keeps `API_SERVER_KEY`, `WEBHOOK_ENABLED` or `WEBHOOK_PORT`, the whole
profile is skipped at startup:

```
WARNING gateway.run: Skipping secondary profile 'mia' due to port-binding config
  error: Profile 'mia' enables port-binding platform(s) api_server, webhook, but
  gateway.multiplex_profiles is on.
```

Only the default profile may own the shared HTTP listener. Remove those keys
from the secondary profile's `.env`.

A copied `TELEGRAM_BOT_TOKEN` is the same class of problem: two pollers on one
bot token produce Telegram 409 conflicts. Give each profile its own bot.

## 5. An `open` policy without an allow-all opt-in refuses to start

Tightening security can take the gateway *down*. Removing
`WHATSAPP_ALLOW_ALL_USERS` while a policy is still `open` fails the multiplex
config check:

```
ERROR gateway.run: Gateway multiplexer config error: Profile 'mia' enables whatsapp:
  open policy without allow-all opt-in. Enable GATEWAY_ALLOW_ALL_USERS or the platform
  allow-all flag for that profile, or change dm_policy/group_policy away from 'open'.
Gateway exiting cleanly
```

Note it applies to `group_policy` as well as `dm_policy` — ours had
`dm_policy: allowlist` and `group_policy: open`, which was enough to refuse the
start. Set both to `allowlist` (with `group_allow_from`) before dropping the
allow-all flag.

## 6. The allowlist lives in the env var, not in `config.yaml`

The bridge reads `WHATSAPP_ALLOWED_USERS` and nothing else — `allow_from` never
reaches it. Editing the config alone changes nothing, and an empty env var means
*nobody* is allowed, so removing the variable makes the assistant deaf.

`scripts/sync_whatsapp_allowlist.py` keeps the two in agreement; run it after
editing `config.yaml`, or from a daily healthcheck.

There is a second-order effect worth internalising: the bridge's owner-message
gate matches the *contact's* chat id against the same allowlist. Dropping a
contact from the allowlist to silence the assistant therefore also stops the
owner's own replies in that chat from reaching the guard, so owner-takeover
detection dies with it.

## 7. Under s6, `s6-svc -r` may leave the service down

Not gatekeeper-specific, but it will bite anyone automating a restart in the
official container image. After `s6-svc -r` we repeatedly observed:

```
down (exitcode 0) 17 seconds, normally up
```

and the gateway did not come back on its own. Any script that restarts the
gateway should follow with an explicit `-u`:

```bash
s6-svc -r /run/service/gateway-default; sleep 10; s6-svc -u /run/service/gateway-default
```

---

## Post-migration checklist

```bash
# 1. the guard is actually loaded for the profile that owns WhatsApp
hermes profile use <profile> && hermes plugins list

# 2. the platform is connected under the profile's own key
python3 -c "import json;print(json.load(open('$HERMES_HOME/gateway_state.json'))['platforms'])"
#   expect: 'mia:whatsapp': {'state': 'connected'}    (not a bare 'whatsapp')

# 3. the allowlist agrees with the config
python3 scripts/sync_whatsapp_allowlist.py --profile <profile> --show

# 4. the guard is writing state
ls -lt "$HERMES_HOME/whatsapp/conversation-state/" | head -3

# 5. alerts come from the right bot
#    set "alert_profile" in gatekeeper_config.json to the WhatsApp-owning profile
```

Points 1, 3 and 4 are exactly the checks worth putting in a daily job — each of
them corresponds to a failure we only noticed because a human happened to look.
