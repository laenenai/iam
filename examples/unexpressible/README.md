# What the design cannot express

Read [../UNEXPRESSIBLE.md](../UNEXPRESSIBLE.md) first. It is the prose
version: each use case, why the design cannot express it, which design §17
finding it maps to, and what supporting it would cost. It also opens with
the thing that is *deliberately* unexpressible — an absolute enforced by
policy — which is not in this package because it is not a gap. This file is
about how the scenarios here work, and why they are tests rather than a
list of complaints.

## Each one demonstrates its gap

A scenario here must mark at least one expectation row **unreachable**,
naming why, and must carry a claim that **runs** and shows the refusal.
`Scenario.Validate` refuses one that does not, on the grounds that a
requirement declared impossible with nothing executable behind the
declaration is prose.

The four demonstrations available, and which scenario uses each:

| Claim | What it executes | Used by |
|---|---|---|
| `schema-rejected` | the design §13 schema lint refuses the fixture, and its reason names the open findings | U1 |
| `no-direct-path` | `DirectPath` returns `ErrNoDirectPath` because containment above the resource is a DAG | U3 |
| `attribute-enforceable` | `AttributeEnforceable` reports whether a restriction scoped to one attribute could be enforced by the fragment design §9 compiles — false for a column of a columnar kind | U1, U4 |
| `stable-under-write` | a resource's ancestry closure moves when an ordinary data write lands | U5 |

There were six demonstrations and six scenarios. Two of each went with the
deny mechanism: `absolute-has-no-lift`, which applied every discretionary
operation the registry exposed and showed the principal still held no
clearance, and `any-actor-may-classify`, which had an unprivileged
principal construct a mandatory act naming itself and watched the registry
accept it. `attribute-enforceable` is the old `row-enforceable` with its
label argument removed and a `Ref` in its place.

## They are written to fail when the gap closes

This is the part worth getting right, and it is why these are scenarios
rather than a document. Each claim asserts the *current, broken* behaviour,
so the moment the design or the module changes:

`schema-rejected` fails if the lint starts accepting an exclusionary or
attribute-conditioned relation — meaning either the lint has a hole or the
permitted subset has grown a form. Both are findings and neither is a pass.

`attribute-enforceable` with `false` fails if F4 is resolved and attribute
granularity becomes expressible, at which point U4 and U1 both leave this
package. They leave together now: the branch that used to distinguish them
was "express it as a classification scoped to the attribute", and that
branch is deleted.

`stable-under-write` with `false` fails if predicate-defined containment is
removed or constrained to immutable attributes.

**One hole, recorded rather than hidden.** The api.txt tripwire in
`scenario/pending.go` only fires for scenarios whose status is `pending`,
and everything here is `unexpressible`. So when `PermittedAttributes`
reaches the facade — the single remaining resolution for F4 and F7 — the
tripwire will not say so, and whoever lands it has to remember U1 and U4 by
hand. The capability constant `CapAttributePredicate` exists and names the
right thing; nothing pends on it.

## Two pairs worth reading together

**U3 against [D7](../discretionary/).** The same requirement — find a deep
object without seeing its siblings — with one containment edge different.
D7's `path-count` claim asserts one path and its `visible-set` claim
compares the reachable set element by element; both pass. U3's `path-count`
asserts two, and `DirectPath` refuses. The difference used to be one edge
that KGS §9.3 required.

> **It no longer requires it, as of 2026-10-24.** kgs was respecified onto a
> containment tree — one parent per graph, one graph per quad — so §17's F3
> is closed and `../UNEXPRESSIBLE.md` has moved U3's entry to "Resolved
> without being solved". **U3's scenario and its claims stay exactly as they
> are**, because both are still true statements about the fixture U3
> declares: containment above that fact really is a DAG and `DirectPath`
> really does refuse it. What changed is that no specified consumer asks for
> that shape, so the pair below reads as a record of a shape the design was
> asked to support and no longer is, rather than as a live gap. The
> follow-up that would make U3 a live scenario is named in
> `../UNEXPRESSIBLE.md`: `scenario.Visible` has to stop being built on
> `DirectPath` first.

Read U3 against [D8](../discretionary/) as well, which is newer and raises
the stakes. D8 is the legal ethical wall, and part of how it asserts that a
screened associate cannot learn the matter exists is a `visible-set` claim.
So "what does `visible_below` mean once containment is a DAG" was never only
a usability question about finding things — it was part of how a screen is
tested, which is why the pair is still worth reading now that the question
is dormant rather than open.

**U1 against U4.** They used to be cousins: one about the rule language
(there is no way to *write* "not salary") and the other about the compiled
fragment (there is no way to *enforce* it over a column). The design
already noted that F4 and F7 resolved to the same fork. With the
classification route deleted they are one fork with one option on it, and
the two scenarios now carry each other's contrast claim to make that
concrete: U1 asserts that a row-shaped kind *would* be enforceable if the
rule could be written, and U4 asserts that a columnar one would not be even
if it could.

**U2 and U6 are gone, and ../UNEXPRESSIBLE.md records why rather than
dropping them.** This file used to pair U2 with M5 — the identical live
claim, applied to the identical mechanism, with opposite meaning: in M5 "no
discretionary operation gives this principal a clearance" was the invariant
the whole module existed for, and in U2 it was the bill for having taken
§8.5's advice to express a discretionary preference as a classification.
Both halves of that pair are deleted. The pairing is still the clearest
statement of why the tier went, which is why it survives as prose in the
parent directory even though neither scenario does.
