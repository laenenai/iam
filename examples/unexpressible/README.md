# What the design cannot express

Read [../UNEXPRESSIBLE.md](../UNEXPRESSIBLE.md) first. It is the prose
version: each use case, why the design cannot express it, which design §17
finding it maps to, and what supporting it would cost. This file is about
how the scenarios in this package work, and why they are tests rather than
a list of complaints.

## Each one demonstrates its gap

A scenario here must mark at least one expectation row **unreachable**,
naming why, and must carry a claim that **runs** and shows the refusal.
`Scenario.Validate` refuses one that does not, on the grounds that a
requirement declared impossible with nothing executable behind the
declaration is prose.

The five demonstrations available, and which scenario uses each:

| Claim | What it executes | Used by |
|---|---|---|
| `schema-rejected` | the design §13 schema lint refuses the fixture, and its reason names the classification mechanism | U1 |
| `absolute-has-no-lift` | every discretionary operation the registry exposes, applied against the real registry, leaves the principal with no clearance | U2 |
| `no-direct-path` | `DirectPath` returns `ErrNoDirectPath` because containment above the resource is a DAG | U3 |
| `row-enforceable` | `RowEnforceable` reports that an attribute-scoped label on a columnar kind cannot be enforced by the predicate design §9 compiles | U4 |
| `stable-under-write` | a resource's ancestry closure moves when an ordinary data write lands | U5 |
| `any-actor-may-classify` | an unprivileged principal constructs a mandatory act naming itself and the real registry accepts it | U6 |

## They are written to fail when the gap closes

This is the part worth getting right, and it is why these are scenarios
rather than a document. Each claim asserts the *current, broken* behaviour,
so the moment the design or the module changes:

`schema-rejected` fails if the lint starts accepting an exclusionary
relation — meaning either the lint has a hole or tier 1 has grown a form.
Both are findings and neither is a pass.

`row-enforceable` with `false` fails if F4 is resolved and attribute
scoping becomes enforceable, at which point U4 leaves this package.

`stable-under-write` with `false` fails if predicate-defined containment is
removed or constrained to immutable attributes.

`any-actor-may-classify` fails the moment a classify permission lands —
which is exactly what should happen, and at that point design §16 question
2 is answered and the §17 register loses an entry.

## Two pairs worth reading together

**U3 against [D7](../discretionary/).** The same requirement — find a deep
object without seeing its siblings — with one containment edge different.
D7's `path-count` claim asserts one path and its `visible-set` claim
compares the reachable set element by element; both pass. U3's
`path-count` asserts two, and `DirectPath` refuses. The difference is one
edge that KGS §9.3 requires.

**U2 against [M5](../mandatory/).** The identical live claim, applied to
the identical mechanism, with opposite meaning. In M5, "no discretionary
operation gives this principal a clearance" is the invariant the whole
module exists for. In U2 it is the bill for having taken §8.5's advice to
express a discretionary preference as a classification. The corpus uses two
differently-named claim kinds for one assertion precisely so that this
shows up in the test names.

**U6 undercuts every mandatory scenario a little**, and it should be read
after them. M1 through M5 assert that no *discretionary* operation opens a
gate, which is true and tested. U6 shows that the *mandatory channel* is
open to any principal who can call the registry, because who may classify
is still an open owner question. The type system makes a clearance write
impossible to perform accidentally; it does not make one impossible to
perform.
