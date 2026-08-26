# Contributing

This project is in early, private development while it's being extracted from a live deployment and generalized. It isn't accepting external contributions yet — this file is a placeholder for when it opens up.

Once public, the expectations will be:

- Open an issue before a large PR, to agree on the approach first.
- Keep security-relevant changes (anything touching `whatsapp_guard` or `whatsapp-security-floor`) small and well-explained — this code runs in front of an untrusted input channel, before the agent itself ever sees the message.
- Favor plain, explicit code over cleverness. Security invariants (round limits, command lockdown) are enforced in code, not left to a prompt or skill to remember — see the README for why that distinction mattered in practice.
- Add or update tests for any change to `whatsapp_guard`'s dispatch logic.
