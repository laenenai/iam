# Mandatory controls

The layer that says no, and keeps saying it. Design §7's tier 2 survives
"any grant, any owner, any project admin, any future discretionary rule,
and any forgotten exclusion". If you have a requirement that somebody must
never see something, this is the only place in `iam` where it can live.

## Why it is not a `deny` relation

Three independent reasons from design §7.2, each sufficient, and they are
worth knowing before you reach for the thing you expected to find.

Exclusion in a relationship model is **local to the permission it is
written in**. OpenFGA's `but not` and SpiceDB's `-` apply to one relation
definition. To make "never" mean never, the exclusion has to appear in
every permission on every resource type, and be remembered for every type
added later — N permissions by M dimensions, growing with the schema, where
one omission is a silent bypass rather than an error.

Exclusion is also the one operator that **does not flatten** into a
precomputed closure, so using it forfeits the projection design §9 needs
and with it the entire performance budget.

And Lakekeeper, the one mature open-source ReBAC-over-a-hierarchy
implementation, **has no deny at all**. Its `Managed Access` restricts who
may grant rather than denying access. The absence is not an oversight; it
is what the model is bad at.

So CI lints registered schemas and **rejects any exclusion operator**, with
an error naming the classification mechanism. If you write one, you will
find out immediately.

## The shape of the answer

Two objects and a set containment check. A **classification** is a label on
resources. A **clearance** is what a principal holds to satisfy one. The
gate passes when every classification on the resource is satisfied by the
principal:

```
classification  conflict:matter-1234        enforcement: policy
assigned to     matter:1234                  ← one assignment, covers everything inside

clearance group clearance:matter-1234-team   channel: classify-permission
members         user:anne                    ← admitted by a mandatory act, with a reason

tuple           matter:1234#viewer@group:all-timekeepers#member
                                             ← the firm-wide grant, untouched
```

Then:

```
Decide(p, action, r) = mandatory_gate(p, r) AND discretionary_allows(p, action, r)
```

Deny-wins is **structural** — a property of the conjunction, not a rule
anybody has to remember to write. And the gate is evaluated first, so a
principal who fails it never has the discretionary layer consulted: the
attempt is auditable without being informative.

Three properties of the mandatory layer that the scenarios here are built
around:

A clearance may be held by a principal or by a **clearance group**, and a
clearance group is a mandatory object. Its membership changes only through
the classify permission or an authoritative directory sync, it is audited,
and it can **never** be referenced in a tier-1 tuple. An ordinary team may
not hold a clearance. The two id types are not interconvertible in Go, and
the registry refuses the textual attack too.

Classifications **inherit through containment and through derivation**.
Mark a matter and every document inside it is covered. Derive an object
from classified inputs and it carries the union of their labels, with no
read boundary at which that stops — which is where this design departs from
Foundry on purpose.

A **newly provisioned principal holds no clearances**. JIT grants identity,
never clearance, and this is structural rather than remembered: every
clearance write demands a `MandatoryAct`, `Claims` carries neither an actor
nor a channel, and `MandatoryAct`'s fields are unexported, so the
provisioning path cannot construct the witness it would need.

## The scenarios

**M1, the ethical wall**, is the scenario that drove the design. The firm
has a firm-wide grant on everything so timekeepers can work; a conflicted
partner must never see one matter. Both are true at once. The partner holds
the grant and the grant is never consulted. The *managing* partner, who
owns the document outright, is denied too — that row is the design's
hardest claim.

**M2** is the same mechanism written positively: the matter is closed and a
named team is let in. This is the form that scales, because it cannot be
forgotten. Add a fifth timekeeper tomorrow and they are denied, with no
rule to write.

**M3, "everyone except Bob"**, is a clearance group that does not contain
Bob, on the `directory-sync` channel because the membership tracks
employment. Bob is in the ordinary group — he works there — and in no
clearance group, and the scenario asserts both facts against the real
registry. One object, not 1,999 individual grants.

**M4, the new joiner**, is the fail-closed rule as a Monday morning. His
claim-derived groups are real, joinable rows on day one, so he can do
unclassified work immediately; he sees nothing classified. The live claim
also tries the widest discretionary channel there is — the issuer asserting
the compartment's own name as a claim-derived group — and it produces an
ordinary group of that name, not a clearance.

**M5** is anti-goal A3 with the attack already carried out. Eve is not a
victim of a missing grant: she has been given everything. She owns the
document, holds the project-admin role, administers the group that holds
the firm-wide grant, has a direct viewer tuple, and the firm-wide grant
sits between the label and the document. Six grants, five of them hers to
make, and she is denied by a label for a reason the corpus names. The live
half applies every discretionary operation the registry exposes on her
behalf and asserts she still holds no clearance.

**M6** is the laundering attempt. A pipeline reads a privileged fact and
writes an observation into an unclassified matter with no label of its own.
The observation is privileged, because the label set is resolved as the
union over the derivation's inputs. Without that, the mandatory layer would
have a door in it marked "run a pipeline".

## Status

All six are **pending** on `Decide` and the classification store. Their
expectation tables are pinned against the corpus's reference procedure.
What runs live is the identity half, and it is the half that carries the A3
claims: M1, M3, M4 and M5 each enumerate every discretionary operation the
registry exposes against a target principal and assert the clearance set
is unchanged.

One thing this directory **cannot** yet claim, and it matters: the
mandatory *channel* itself is not permissioned. See
[U6](../UNEXPRESSIBLE.md). Every assertion here is that no *discretionary*
operation opens a gate, which is true and is narrower than it sounds.
