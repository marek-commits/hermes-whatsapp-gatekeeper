# Security Policy

This project exists specifically to reduce the attack surface of an AI agent exposed to an untrusted messaging channel — please report vulnerabilities responsibly rather than exploiting them.

## Reporting a vulnerability

Please do not open a public GitHub issue for a security vulnerability. Instead, use GitHub's private vulnerability reporting on this repository (Security tab → "Report a vulnerability"), or contact the maintainer directly.

Please include:

- A description of the vulnerability and its potential impact
- Steps to reproduce, or a proof of concept
- The version or commit you tested against

## Scope

**In scope:** the plugins, skills, and scripts in this repository (`whatsapp_guard`, `whatsapp-security-floor`, and the conversation-rules skill).

**Out of scope:** vulnerabilities in Hermes Agent itself (please report those [upstream](https://github.com/NousResearch/hermes-agent/security)), or in the Baileys library / WhatsApp's own protocol.

## Response

This is currently a solo-maintained project without a formal SLA. Reports will be acknowledged as soon as practical.
