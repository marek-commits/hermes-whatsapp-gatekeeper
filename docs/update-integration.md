# Wiring this into your update pipeline

> This is a description of the *pattern* the original deployment uses, with
> a generic reusable script, not a copy of that deployment's actual update
> script (which is a much larger, deployment-specific file covering things
> unrelated to WhatsApp). Adapt the pattern to whatever update mechanism
> your own Hermes deployment uses.

## Why this matters at all

`hermes update` (or however your deployment refreshes the vendored Hermes
source) typically re-extracts vendored source from a fresh image or
release tarball. Anything you changed *inside* that vendored tree is
silently overwritten with zero warning. Two different strategies handle
that, depending on where a given piece of this project lives:

- **Plugins** (`plugins/whatsapp_guard`, `plugins/whatsapp-security-floor`)
  live under `HERMES_HOME/plugins`, which is your durable, non-vendored
  home directory. Updates never touch it. Nothing to reapply — this is
  the preferred approach for everything in this repo that *can* be a
  plugin.
- **Direct source patches** — if you ever end up patching vendored source
  directly (the original deployment briefly did, as a belt-and-suspenders
  measure alongside the `whatsapp-security-floor` plugin, before
  confirming the plugin alone was sufficient) — those get wiped on every
  update and must be **reapplied deliberately, as a scripted step in your
  update pipeline**, not by hand, or they will eventually be forgotten.

## The pattern

1. Write each patch as a small, **idempotent** shell function: check
   whether the patch is already applied (e.g. `grep` for a marker string)
   and skip if so, so re-running it is always safe.
2. Call each patch function from your update script, immediately after the
   step that refreshes vendored source and before the gateway restarts.
3. Log clearly which patches were (re)applied vs. already present, so a
   failed or skipped reapply is visible in the update's output, not silent.

```bash
# Example shape — adapt paths/markers to your own patch.
reapply_example_patch() {
  local target="/opt/hermes/some/vendored_file.py"
  local marker="# whatsapp-guard-patch-marker"

  if grep -q "$marker" "$target" 2>/dev/null; then
    echo "[reapply] example patch already present — skipping"
    return 0
  fi

  echo "[reapply] applying example patch to $target"
  # ... apply the patch (sed/patch/python -c, whatever fits) ...
  echo "$marker" >> "$target"
}

# Call this from your update script, after vendored source is refreshed:
reapply_example_patch
```

4. Prefer moving the patch into a plugin instead, whenever the thing
   you're patching has any kind of hook/extension point available (as
   `whatsapp-security-floor` does for its case — see
   `docs/architecture.md`). A direct source patch should be the fallback,
   not the default.

## Verifying it stuck

After any update, a quick smoke test is worth automating: confirm both
plugins still show up in your plugin listing, and that a synthetic
non-admin message still gets a slash command blocked. Silent regressions
here are exactly the failure mode this whole project exists to prevent.
