# Charter: `iam`

**It does this one thing:** Who exists, what groups they are in, and what they
are allowed to do — answerable **inside a SQL query**.

Concretely: principals, groups and `(issuer, subject)` mapping; IdP adapters
and provisioning; relation tuples with usersets and inheritance;
classifications as mandatory controls; registerable resource kinds and
containment paths; the authority/projection protocol.

**It must not contain:** Capability tokens (`captoken`). Key material
(`keyring`) or share custody (`escrow`). Tenant/pool routing and connection
handling (`tenancy`). Audit storage (`audit`). Any consumer's resource model —
those are *registered*, never built in.

## Enforced boundary

`api.txt` is the public API as a golden file, diffed in CI, so growing the
surface takes a reviewed diff. The conformance suite is the adoption contract:
a consumer counts as adopted when the suite runs green in *its* CI against
*its* wiring.

A module is created when a **second** consumer needs it, not in anticipation.

## Adoption

| Consumer | State |
|---|---|
| cas | pending — grants become tuples, denials become classifications (design §12) |
| kgs | pending — phase 0 dependency |
| acre | pending — no code yet; adopts from birth |

## Design

`docs/superpowers/specs/2026-10-23-iam-design.md`
