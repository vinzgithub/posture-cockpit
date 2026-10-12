# Study: a remote Docker agent for internal audits

🇫🇷 [Version française](REMOTE_AGENT.fr.md)

Status: **study, not developed.** Version 0.2.0 prepares the ground without adding an agent; this document says why, how it could work and what it would cost.

## 1. The need

Today, an internal perimeter can only be scanned if the central instance **reaches the internal network itself**: it is installed there, or a route, a VPN or a firewall rule opens those networks to it. To audit several sites (head office, branches, a customer), one would need either one instance per site, or inbound flows to each of them from the central instance. Both are heavy, and the second widens the attack surface of the audited networks.

An **agent** is a small container placed in each internal network. It only scans, on the central instance's orders, and sends the results back. Flows go from the agent to the instance (outgoing for the audited network), never the other way.

```
  internal network A                       central instance
 ┌──────────────────────┐ outgoing HTTPS   ┌────────────────────────────┐
 │ agent  ── scans ───► │ ───────────────► │ agents API ─► scans, plan, │
 │ (local rule:         │ ◄─── jobs ────── │ PDF, history, audit        │
 │  networks of A)      │                  └────────────────────────────┘
 └──────────────────────┘
```

## 2. Why the current code lends itself to it

- The **engine is independent of the web** (`core/`): an agent can run `engine.scan` without a web server, as the command line already does.
- The **egress rule** is an object (`EgressPolicy`) applied by `LiveNetwork`: the agent builds its own from its own configuration.
- A **perimeter** is data (networks, DNS, ports, CA), not a server setting.
- **Results can be serialized**: `Finding.outcome_json()` and `Finding.from_stored()` already are the database format.
- The **scanner** picks the network according to the perimeter (`Scanner.network_for`): that is where the instance would decide to scan itself or to hand the job to an agent.

## 3. Proposed operation

1. **Enrolment.** An administrator creates an agent in the interface and gets a single-use token. The agent exchanges it for a key of its own (or a client certificate), stored hashed on the instance, revocable.
2. **Jobs.** The agent polls the instance regularly (long polling, outgoing HTTPS only): "any job for me?". A job = a domain, the perimeter id, the list of checks and a deadline.
3. **Scan.** The agent applies **its own egress rule**, defined locally (environment variables of its container). The central instance cannot widen it: if it asks for a domain that points outside the agent's networks, the checks are "not evaluated", exactly as today.
4. **Results.** The agent sends back the serialized `Finding`s, its version and that of each extension. The instance treats them as **untrusted input**: known check ids, valid statuses, bounded sizes, texts reduced to translation keys (as today), evidence limited in size.
5. **Traceability.** Every job handed out, accepted, finished or expired is written to the audit log, with the agent concerned.

## 4. Security

| Risk | Measure |
|---|---|
| The central instance is compromised and wants to use the agents to probe internal networks | The egress rule is local to the agent; checks stay passive; the agent runs no code it receives, only checks already installed |
| An agent is compromised and sends false results | Revocable key per agent; validated results; an agent's scans are marked as such in the PDF and the history |
| The enrolment token leaks | Single use, short lifetime, tied to a perimeter |
| Interception | HTTPS with verification of the instance's certificate (CA configurable on the agent), possibly mTLS |
| Exposure of the agent | No listening port; read-only container, no capabilities, unprivileged user (as the current image) |

## 5. Cost and difficulties

- **API and interface**: enrolment, list of agents, status (last contact, version), revocation; job queue with deadlines.
- **Version skew**: an agent older than the instance may not know a check; it must say so (check "not evaluated" on the instance) rather than fail.
- **Offline agents**: jobs expire; the interface says "waiting for the agent" instead of a false result.
- **Tests**: an agent and an instance in the tests, with the local servers already available (`tests/local_servers.py`).

Estimate: about the size of 0.2.0 (new `agent/` module, `api/v1/agents` routes, two tables, an administration page, documentation), without rewriting what exists.

## 6. Recommendation

**Do not develop it now.** The priority is consolidation: egress rule, scoring, accuracy of the checks. These foundations were also the prerequisites of an agent: they are in place. The agent becomes useful as soon as several internal networks must be audited from a single instance; until then, an instance installed inside the internal network, with a perimeter, covers the need.

Steps proposed when the time comes:

1. a `posture-cockpit scan --perimeter <file>` command producing the JSON of an internal scan (useful on its own, and the first piece of the agent);
2. importing that JSON into the instance (history, plan, PDF);
3. enrolment and the job queue.
