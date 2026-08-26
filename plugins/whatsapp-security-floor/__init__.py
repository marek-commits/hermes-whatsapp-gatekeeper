"""whatsapp-security-floor — local plugin.

Closes the built-in "help"/"whoami" always-allowed floor in
gateway.slash_access for non-admin users. Upstream hardcodes these two
commands as always reachable (see the docstring in gateway/slash_access.py)
so a fully locked-down user isn't left completely blind. This deployment
wants ZERO slash commands reachable by non-admin WhatsApp senders, no
exceptions — admins are completely unaffected, since is_admin() short-
circuits before this floor is ever consulted.

Why a plugin instead of patching gateway/slash_access.py directly: that
file lives under the vendored Hermes source tree, which the update
pipeline wholesale-replaces from a fresh image extract on every update
(confirmed by reading the update script) — a direct patch would be
silently wiped with zero warning. This plugin lives under
HERMES_HOME/plugins, which updates never touch, so the patch re-applies
itself automatically on every gateway start. In the original deployment a
direct source patch was ALSO kept in place (belt-and-suspenders) so that
if it ever gets wiped by an update, this plugin is already the sole
active mechanism, seamlessly. See docs/architecture.md for the full
incident writeup and docs/update-integration.md for the update-survival
pattern.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def _apply_patch() -> bool:
    try:
        import gateway.slash_access as _sa
    except ImportError:
        logger.warning(
            "whatsapp-security-floor: gateway.slash_access not importable — "
            "skipping (Hermes internals may have changed; check manually)"
        )
        return False

    before = _sa._ALWAYS_ALLOWED_FOR_USERS
    _sa._ALWAYS_ALLOWED_FOR_USERS = frozenset()
    if before:
        logger.info(
            "whatsapp-security-floor: closed always-allowed floor (%s -> frozenset())",
            sorted(before),
        )
    else:
        logger.debug("whatsapp-security-floor: floor already empty, no-op")
    return True


_apply_patch()


def register(ctx) -> None:
    """No runtime hooks needed — the patch above already ran at import time.

    register() must still exist so the plugin loader treats this as a
    well-formed plugin.
    """
    return None
