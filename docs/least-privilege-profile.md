# The least-privilege profile: what the edge agent must NOT have

`docs/multiplex-profiles.md` covers the mechanics of moving WhatsApp onto its
own profile — the silent failure modes, the symlinks, the `.env` precedence.
This page covers the part that comes *after* the move works: deciding what that
profile is allowed to do at all.

The short version:

> **The agent that strangers can write to holds no tools. It holds a form.**

Everything below was deployed and observed on a live personal deployment. Where
something is a design decision rather than a measurement, it says so.

---

## 1. Why a separate profile is a security control, not a cosmetic one

A messaging gateway inverts the normal trust model. In a CLI or a private chat,
every token in the context window came from the operator. On a WhatsApp line,
most of it came from *somebody else* — and that somebody can write anything,
including a sentence shaped like an instruction from the operator.

Once you accept that, the question stops being "how do I stop the model being
fooled" and becomes "what is the blast radius when it is". A dedicated profile
is how you make that radius small:

| | Main profile | Edge profile |
|---|---|---|
| Who writes into the context | operator only | anyone on the allowlist |
| Tools | whatever the operator needs | as close to none as the job allows |
| Model | the expensive one | a fast, cheap one is usually enough |
| Memory / wiki / calendar | yes | **no** |

Prompt-injection defences (see the regex floor in `whatsapp_guard`) are worth
having, but they are a filter, not a boundary. The boundary is the toolset.

---

## 2. What to disable, and the one that surprises people

```yaml
# <edge profile>/config.yaml
agent:
  disabled_toolsets:
    - terminal          # obvious
    - file              # obvious
    - code_execution    # obvious
    - browser
    - computer_use
    - kanban
    - moa
    - cronjob           # the one people forget
```

`cronjob` belongs on that list and it is the one that gets missed, because it
does not look like a dangerous tool. It is a scheduler. But a scheduler is:

* **persistence** — an instruction that survives the conversation that created it,
* **an outbound channel** — cron delivery reaches platforms the agent itself cannot,
* **deferred execution** — it runs when nobody is watching the transcript.

On the deployment this project came from, the edge agent had no way to send a
message on the operator's instruction (see §3), so it improvised: it created a
cron job. The message arrived — with a `Cronjob Response: <job name>` header
and a footer explaining how to cancel the job. Nothing was broken. The model
simply used the only outbound path it had.

**That is the real lesson, and it generalises:** a capability you remove without
replacing does not produce refusal. It produces improvisation. Audit what the
agent actually does, not only what it is forbidden from doing.

---

## 3. Outbound messaging: upstream says no, on purpose

Hermes deliberately does not expose an agent-callable `send_message`. From
`toolsets.py`:

> *"agents do NOT get an agent-callable `send_message` tool — outbound platform
> messaging is handled outside the agent loop (cron delivery, the gateway kanban
> notifier, and the `hermes send` CLI), not by the model deciding to send on its
> own."*

That is a good default and you should think hard before changing it. If you do
need the operator to be able to say "reply to X for me" from another channel,
narrow the door instead of removing it:

* one platform only — not a generic sender;
* recipient must already be on the allowlist, or an allowed group;
* rate limits, both global (per hour) and per recipient (minimum gap);
* a length cap;
* every send **and every refusal** written to an append-only log;
* optionally mirror each send to the operator so nothing leaves silently.

A tool with those constraints is a door with a lock. `send_message` is a missing
wall.

---

## 4. Requests from third parties: the form, not the instruction

The interesting case is when a *contact* asks for something that touches the
operator's world — "remind him about our meeting on Monday", "put me in his
calendar".

The edge agent must not do it. It must also not throw it away. The pattern that
resolves this has three properties:

**(a) The request is a form with fixed fields, not free text.**

```
kind:     reminder | meeting | question | other
subject:  one sentence, the agent's own words
when:     ISO timestamp or a weekday+time; EMPTY if ambiguous
verbatim: what the contact actually wrote
contact:  identifier from the chat context
```

Note what this excludes *by construction*: there is no field in which "send
money" or "delete that file" can be expressed. Restricting the vocabulary is
stronger than validating the content.

**(b) The decision is code, not a prompt.**

A scheduled job reads the queue and decides. The model's only role was filling
in the form. This matters because a prompt can be argued with and a branch
cannot:

```
contact not found in the contact store   -> nothing happens, operator informed
kind not in {reminder, meeting}          -> forwarded as a note, nothing happens
time unparseable / past / absurdly far   -> nothing happens, operator informed
contact flagged as allowed to schedule   -> action taken, operator informed
otherwise                                -> operator confirms with one word
```

**(c) Identity resolution is exact-match only.**

Resolve the contact by phone number or chat ID. **Never** fall back to matching
on name. An earlier release of this project (v2.3.3) fixed exactly that bug in a
different code path, where a name-token fallback attributed a reply to the wrong
person. In an authorisation path the same bug means one contact inherits
another's permissions.

**(d) "Important" is not the same as "allowed".**

If your contact store already has a VIP flag, do not reuse it for this. VIP
means *this person matters*. Scheduling permission means *this person may write
into my time* — which is a claim about trust in their phone, not about their
importance. Use a separate field, default it to off, and let the operator turn
it on one contact at a time.

---

## 5. Letting the edge agent ask a question — fast, and without tools

Blocking writes is easy. Blocking *reads* makes the assistant useless: "is he
free on Monday?" is a reasonable question and the answer lives in a calendar the
edge agent must not touch.

Hermes already has the channel for this. `hermes peer dm` is documented as *"the
cross-machine twin of `hermes -p <bot> chat`"*, and it works by calling the
target agent's `api_server` platform. If both agents run on the same host, you
can call that endpoint directly over loopback:

```
POST http://127.0.0.1:<api_server port>/v1/chat/completions
Authorization: Bearer <API_SERVER_KEY>
X-Hermes-Session-Id: <a fixed id of your choosing>
```

Three things are worth knowing before you build on it:

1. **`/v1/chat/completions` is stateless by default.** Without
   `X-Hermes-Session-Id` every call is a brand-new conversation — and a
   well-configured assistant will answer a new conversation with its greeting
   rather than your question. With a fixed id, history is loaded from
   `state.db` on every call and the two agents share one persistent thread.
2. **Session continuation requires the API key.** That is deliberate: it exposes
   conversation history, so it is gated on authentication.
3. **Frame the payload.** The privileged agent should be told, in the request
   itself, that the quoted text came from a third party and is data rather than
   an instruction — and what it may reveal. "Busy" is an answer; the name of the
   meeting is a leak.

Round-trip on the reference deployment: ~7 s with no tool use, ~74 s when the
privileged agent actually queried a calendar. Budget your timeout accordingly.

### The split that makes this safe

> **Reads are synchronous. Writes are queued and reviewed.**

Questions go straight through and come back in seconds, because a question
harms nobody. Anything that changes the operator's world goes into the queue
from §4. Two different channels, deliberately not interchangeable.

---

## 6. Audit logs are not conversation logs

Log enough to debug, and nothing that would embarrass anyone if the file leaked.
On the reference deployment the audit line keeps: event, request id, kind,
outcome, duration, and the *length* of any human text. It does not keep the
text, and identifiers are stored as a short hash so entries can still be
correlated ("same contact, third time today") without the log containing a phone
number.

The full text does exist — in the request queue, under a retention policy, where
it belongs.

---

## 7. Restarting: the gateway drains first

Operationally useful, and easy to misread as a fault: `s6-svc -r` (or any
restart signal) returns success but the PID does not change while an agent turn
is still running. The gateway reports `state: draining` with a non-zero
`active_agents` in its state file and exits once those finish.

Do not kill the process. Read the state file first.

---

## 8. Checklist

- [ ] Edge agent on its own profile, with `cronjob` in `disabled_toolsets`
- [ ] No memory, no wiki, no calendar, no file access on that profile
- [ ] Any outbound tool is single-platform, allowlisted, rate-limited, logged
- [ ] Third-party requests go through a fixed-field form, never free text
- [ ] The decision that follows the form is code, not a prompt
- [ ] Contact resolution is exact-match on an identifier; no name fallback
- [ ] Scheduling permission is its own field, defaulting to off
- [ ] Questions answered over a session-pinned loopback channel, with framing
- [ ] Audit log carries lengths and hashes, not text and numbers
