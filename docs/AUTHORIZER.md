# External authorizer: the contract

CrewCraft runs on its own built-in roles. An organization that already decides "who may do what" in another system can
point CrewCraft at an **external authorizer** instead (REQUIREMENTS.md section 4, integration points). This page is the
contract between a CrewCraft server and such a service, so either side can be built and tested without the other.
Task T600 implements CrewCraft's side of the decision rules (`crates/authz`); the HTTP transport follows in its own
task.

## Identity is not authorization

Identity answers "who is this?": a CrewCraft account, or a person signed in through an OpenID Connect provider.
Authorization answers "what may this person do here?". An authorizer never sees a password, a code or a token; it is
told an identity and answers with capabilities. Having an identity never grants entry by itself.

## Capabilities

| Capability | What it allows |
|---|---|
| `use` | Everything a member does: needed for every page and API. Without it, nothing else counts. |
| `moderate` | Delete other people's messages and read revisions (audited). |
| `respond` | Answer visitors in the visitor module. |
| `dispatch` | Assign visitor conversations to responders. |

Capability names an authorizer sends that CrewCraft does not know are ignored, so an authorizer can add new ones
without breaking older servers. An empty list, or a list without `use`, gives no access.

## The request

The CrewCraft server asks; clients never talk to the authorizer.

```http
POST {authorizer}/v1/authorize
Content-Type: application/json

{"api": 1, "purpose": "sign-in", "identity": {"issuer": "https://id.example.org", "subject": "248289761001",
 "email": "ana@example.org"}}
```

- `purpose` is `sign-in` (a person is signing in now) or `recheck` (a signed-in session is being confirmed).
- `identity.issuer` and `identity.subject` name the person as their identity provider does; for a built-in CrewCraft
  account the issuer is the CrewCraft server's own name. `email` is informational.
- The server authenticates itself to the authorizer as configured: a client certificate (preferred) or a bearer token.
  The authorizer must refuse any other caller.

## The answer

```json
{"api": 1, "decision": "allow", "capabilities": ["use", "moderate"], "revision": 1042, "recheck_after_seconds": 300}
```

```json
{"api": 1, "decision": "deny", "revision": 1043}
```

- `decision` is `allow` or `deny`.
- `revision` is a whole number the authorizer **increases every time this person's grants change**. CrewCraft uses it
  to tell a newer answer from an older one.
- `recheck_after_seconds` (optional) asks CrewCraft to check again sooner than its default; CrewCraft never waits longer
  than 600 seconds.
- Anything else counts as **no answer**, not as a denial: a status other than 200, a timeout, a body that does not
  parse, `api` other than 1, an unknown `decision`. CrewCraft then follows the outage rules below.

## How CrewCraft applies the answers

| Situation | What CrewCraft does |
|---|---|
| Sign-in | Needs a fresh `allow` with `use`. No grace: an authorizer that does not answer means no sign-in. |
| After a good answer | Checks again after 10 minutes (or `recheck_after_seconds`, if sooner). |
| After a failed check | Retries after 60 seconds. |
| Authorizer unreachable | Keeps the last good grant for at most **24 hours from when it was last confirmed**, then refuses. The visitor module keeps nothing: no answer means no access there. |
| `deny` | Refuses at once. The denial is stored on the server, survives restarts and outages, and is lifted only by a later `allow` with a **higher** `revision`. |
| An `allow` with a lower `revision` than one already seen | Ignored as stale, never as a reason to grant. |
| Storing the decision fails | If the decision cannot be written durably and read back unchanged, access is refused. |

## For implementers of an authorizer

- Answer quickly (CrewCraft gives up after a few seconds) and from one source of truth.
- Keep `revision` per person, increasing on every change (role, group, disablement), never reused or lowered.
- To end someone's access, answer `deny`: it takes effect at the next check (at most 10 minutes) and cannot be undone by
  a stale replica. Ending a session at once is a separate server action (sign-out is real, REQUIREMENTS.md section 4).
