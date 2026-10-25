# Charter: `iam`

**It does this one thing:** Who exists, what groups they are in, and what they
are allowed to do — answerable **inside a SQL query**.

Concretely: principals, groups and `(issuer, subject)` mapping; IdP adapters
and provisioning; relation tuples with usersets and inheritance; registerable
resource kinds and containment paths; content markings and their enforcement
class; the authority/projection protocol.

**It must not contain a deny mechanism** — no classification, no clearance, no
deny tuple, no exclusion operator. A principal is refused by the absence of a
grant and by nothing else, and an absolute that must survive a future
administrator is a key the deployment does not hold, which is `escrow`. This
is the module's central anti-goal (design A3) and it inverted on 2026-10-23:
it used to read "a mandatory control that can be defeated".

**It must not contain:** Capability tokens (`captoken`). Key material
(`keyring`) or share custody (`escrow`). Tenant/pool routing and connection
handling (`tenancy`). Audit storage (`audit`). Any consumer's resource model —
those are *registered*, never built in. A third-party authorization engine:
`iam` owns its grants and closures in Postgres, because the filtered-read
answer has to be something the consumer applies inside its own query and an
engine that answers over its own store cannot produce one (design §10).

Refined 2026-10-25, when that answer was built: what `iam` returns is a typed
**residual**, not a fragment, and a per-backend renderer turns it into SQL.
The boundary moves accordingly — **a backend's query language belongs in a
renderer beside its adapter, never across the port.** SQL text across the port
would give every consumer a dependency on the string, so a second storage
backend becomes a breaking change for all of them rather than a new renderer
here. `iam` may hold a renderer per backend it supports; it may not hold a
consumer's query builder.

## Enforced boundary

`api.txt` is the public API as a golden file, diffed in CI, so growing the
surface takes a reviewed diff. The conformance suite is the adoption contract:
a consumer counts as adopted when the suite runs green in *its* CI against
*its* wiring.

A module is created when a **second** consumer needs it, not in anticipation.

## Adoption

| Consumer | State |
|---|---|
| cas | pending — grants become grants on containers, one per share rather than one per resource; its denials have no mechanism and need a per-denial decision (design §12). Its columnar case still has no answer: finding F4 is open, so nothing here restricts a field |
| kgs / cogos | pending — privacy by placement in its named-graph tree maps directly onto containers, and the rule it needs ("which graphs may this principal read") is a restrictive policy over the rendered residual. Its phase-0 dependency on the *full* projection protocol is not met: the change log and its cursor exist, and nothing is built on them |
| acre | pending — no code yet; adopts from birth |

## Design

`docs/superpowers/specs/2026-10-23-iam-design.md`
