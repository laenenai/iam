# What this design cannot express

Three use cases, each a real requirement from one of the three consumer
designs, that `iam` as designed cannot express. They are listed here
because a corpus whose value is that it all passes is worth much less than
one that precisely locates what does not work.

Each has a scenario in [unexpressible/](unexpressible/) that **demonstrates**
its gap rather than asserting it — the schema lint refusing the relation,
`DirectPath` refusing a DAG, `AttributeEnforceable` reporting that a column
cannot be hidden by a `WHERE` clause, an ancestry closure moving under an
ordinary data write. The harness refuses an unexpressible scenario that
carries no such claim. So if the design grows to cover one of these, the
corresponding claim starts failing and says so, and the scenario leaves
this file.

There were six, and the arithmetic is the record of three decisions, none of
which was "we built it":

- **Two left on 2026-10-23** with the deny mechanism, which was the
  mechanism they were about.
- **One left on 2026-10-24** — U3, the DAG — when the consumer whose data
  model required it was respecified onto a containment tree. Its
  requirement was withdrawn rather than met.

All three are at the bottom under **Resolved without being solved**, where
they are recorded rather than deleted, with the measurements that were in
flight for U3 when it went.

**There are still four scenarios in [unexpressible/](unexpressible/), and
that is not a miscount.** U3's scenario stays, carrying claims that are
still true of its own fixture, until a named follow-up rewrites
`scenario.Visible`; U3's entry says why. The corpus and this file disagree
about U3 on purpose and for a stated duration, which is better than one of
them being quietly wrong.

---

## First: the one thing that is deliberately unexpressible

This section is not a finding. It is the design, and it belongs at the top
of this file because a reader arriving here is usually looking for exactly
it.

**An absolute enforced by policy cannot be expressed, and will not be.**
"This principal may never see this, whatever anyone does later" has no
mechanism in `iam`. There is no deny, no classification, no clearance, no
exclusion operator, and no plan to add one. That is an anti-goal rather
than a gap, and the design document states it as one.

What replaces it, in two strengths that are honestly different:

- **"She may not see this"** → do not grant it. Default-deny is the only
  thing that refuses, so a resource nobody granted is a resource nobody
  reaches. It is liftable by anyone who may share, which for a private
  letter or a household invoice is the correct property and not a weakness.
  [D6](discretionary/) and [H1](household/) are this.
- **"Nobody may ever see this, whatever rule ever happens"** → `escrow`. A
  key the deployment does not hold survives the administrator, the
  operator, a subpoena, a stolen backup and every future policy change.
  `iam` records one field, the marking's enforcement class; `keyring` holds
  the wrapping and `escrow` holds the shares, the custodians, the ceremony
  and the dead-man's switch. [H4](household/) is this.

**The legal ethical wall is the case worth being explicit about**, because
it is the one the design was loudest about. CAS §9.3 wanted a conflict
screen "that no firm-wide grant may defeat", design §1 cited it as one of
two requirements this module exists for, and the corpus's old M5 — the
scenario the design called "the feature the whole module exists for" —
asserted it with a classification, a clearance group and an adversarial
suite.

It now has no policy mechanism of its own. [D8](discretionary/) is the
replacement: the firm-wide grant is written on the firm-wide container, the
matter is not inside it, nothing names the screened associate on the
matter, and nobody can navigate to a matter they are screened off. That is
sufficient for the everyday case and it is weaker in exactly one way,
stated plainly rather than buried: **it survives nobody.** Any principal
who may share the matter can share it with the screened associate tomorrow,
and no row in this module will object. A screen that must survive a future
administrator is content under a key the deployment does not hold.

The reason that is the right trade is that the old mechanism did not
deliver what it appeared to either. A classification was administered by
whoever held the classify permission, so it was only as absolute as that
administration — the corpus's old U6 demonstrated, against the real
registry, that *anybody* could perform the mandatory act. And routing
ordinary privacy through the same mechanism turned every household
preference into an absolute no owner could lift, which was the old U2. One
honest weak mechanism plus one honest absolute beats one mechanism that
read as absolute and was not.

---

## U1 — "May read `Person` entities but not `salary` facts"

**The use case.** An HR analyst may see the people in the graph and the
ordinary facts about them, and not their salaries. The HR director may see
both. KGS §9.3 lists this as one of its rule dimensions, in these words:
"a rule may name a type or predicate (may read `Person` entities but not
`salary` facts), which is what makes property-level security expressible."

**Why the design cannot express it.** The rule is two of §8.5's three
forbidden things at once. It is conditioned on an attribute of the resource
— the fact's predicate — and it is exclusionary in shape. There is no
relation definition that carries either. The scenario writes the rule the
way a consumer would want to declare it and the schema lint refuses the
whole fixture, so every row in its table is unanswerable: not denied, not
allowed, unreachable.

**This got strictly harder on 2026-10-23, and it is the only entry in this
file that did.** It used to have two candidate resolutions, and the cheap
one was the one §8.5 itself recommended: *express it as a classification
scoped to the salary attribute — see U2 for what that changes.* That
resolution no longer exists. The mechanism was deleted, not deprecated, so
there is nothing left to be redirected to.

What remains is one option: `Predicate` returns a permitted-attribute or
permitted-predicate set alongside its SQL fragment, and the **consumer**
applies the second part. That moves part of the trust boundary into
consumer code, where this module can neither enforce nor detect a consumer
that forgets, and it makes the §9.4 differential audit responsible for
consumer compliance and not only for projection divergence. The only
alternative is that kgs drops the dimension.

**Finding.** §17 F7 (ontology scope), now compounding F4. F7 used to read
"either kgs loses those dimensions or tier 1 gains a form"; the third
branch that existed in practice — use a classification — is gone, so the
register now records the discretionary-restriction form as permanently
refused and "kgs loses the dimension" as the definitive answer rather than
one of two.

**What supporting it would cost.** A form conditioned on resource
attributes costs §9's projection, and therefore A2: union, usersets and
inheritance precompute into a closure and a conditional expression does
not. An exclusion operator costs that and more, and is now refused on a
stronger ground than it used to be. The old argument was *locality* — in
OpenFGA's `but not` and SpiceDB's `-`, exclusion applies only to the
relation definition it is written in, so an absolute written there is
absolute only where somebody remembered it. That argument is sound and it
is narrower than it was made to carry: it is an objection to
relation-scoped exclusion specifically, and it was being used as an
argument for putting absolutes in another tier. There is no other tier.
Exclusion is now refused because the design has no deny mechanism at all.

One piece of the old supporting evidence should be discounted while
reading this. The previous version of this section said that Lakekeeper
having no deny mechanism "is the strongest available evidence that this is
what the model is bad at". Lakekeeper governs data-catalog hierarchies for
org-internal analytics: a domain with no per-resource owner asserting
privacy against a peer, and therefore no demand for the thing it does not
have. Its absence of deny is weak support for a conclusion about the
household case, and the conclusion rests on the two structural arguments
above instead.

---

## U3 — moved, 2026-10-24

**The requirement was withdrawn, so U3 is no longer a gap.** Its entry is at
the bottom of this file under "Resolved without being solved", with the
schema that withdrew it and the measurements that were in flight when it
happened. The scenario in [unexpressible/](unexpressible/) stays where it
is, and the entry explains why.

---

## U4 — An attribute-scoped restriction cannot hide a column

**Redirected on 2026-10-23.** As this entry used to be written it is moot.
It described design §8.3's offer of a classification "declared over a whole
resource, or over a named attribute or field of it", and its subject was
that the gate could answer "may she see `document:payroll.salary`"
correctly while `Predicate` could not express the answer. There is no
classification, so there is no attribute-scoped label to be unenforceable.

**The problem underneath it did not move, which is why this is redirected
and not deleted.** Design §9 compiles authorization into a `WHERE` fragment
the consumer joins, and a `WHERE` fragment hides rows and not columns. That
is a property of SQL and of the consumer's storage shape, and it was never
a property of which tier the restriction was written in. The scenario now
asks the same question with the label removed: given a resource whose
attributes are columns of one row, can the compiled fragment express a
restriction at attribute granularity?

**Why the design cannot express it.** It depends on the consumer's storage
shape, and the scenario carries both shapes side by side so the finding is
precise rather than general.

For kgs it is true and free. A fact carries one attribute, so hiding the
attribute is hiding the row, and a row is what a predicate can hide. KGS
§9.2 says so: "because facts carry attributes rather than entities carrying
columns, Palantir's object-level + property-level = cell-level security
falls out of the data model instead of needing a second mechanism." The
scenario's row-shaped claim passes.

For CAS it is not. A document's fields are columns of one row, so the
fragment lets the row through and something else has to hide the column. A
consumer that falls back to calling `Decide` per cell has abandoned §9 and
is post-filtering, which is KGS leak channel #6.

Nothing in the schema is wrong, so no lint catches this. It is caught by
asking what the compiled fragment can express, which is what
`AttributeEnforceable` does.

**Finding.** §17 F4, open. Note that F4 and U1's F7 are now a single fork
with a single option on it, rather than the same fork reached from two
directions: the branch that used to distinguish them — express it as a
classification — was available for F7 and is gone.

**What supporting it would cost.** Two options, and they are not variations
of each other.

`Predicate` returns a fragment *plus* a permitted-attribute set, and the
consumer applies the second part. Cheap to build, and it moves a piece of
the trust boundary into consumer code: the module could no longer claim
that nothing but a grant permits anything, because a consumer that forgets
to apply the attribute set is a disclosure this module can neither prevent
nor detect. If this is chosen, the §9.4 differential audit must cover
consumer compliance and not only projection divergence, which is a
substantially larger audit than the one designed.

Or this module becomes a query rewriter, parsing and rewriting SELECT lists
across three consumers' query builders. That keeps the trust boundary
intact and is a different module with a different charter. CHARTER.md's "it
must not contain" list has to grow a line either way.

There is a third, cheaper answer for CAS specifically: make sensitive
document fields their own addressable resources, so the columnar case
becomes a row case and an ordinary grant reaches it. It costs a schema
migration in CAS and a cardinality increase in its tables, and it needs no
new mechanism here. It is now the only resolution that keeps the trust
boundary where it is and asks nothing of this module, which makes it more
attractive than it was rather than less.

---

## U5 — A predicate-defined entity-set has no authorization event

**The use case.** "Eva can see all Belgian suppliers", as one rule that
stays correct as suppliers arrive. KGS §9.3 allows an entity-set to be
"definable either explicitly or by predicate."

**Why the design cannot express it safely.** An ordinary data write, made
by somebody holding no `grant` or `policy.set` permission, moves an
authorization answer. In the scenario, Pascal asserts `country = BE` on a
company in his own transaction and Eva can now read it. There is no
authorization operation to audit under §8.6, nothing to bump the deny
epoch, and — the part that matters most — the *restrictive* direction rides
the same path. A supplier leaving the set is a permission being removed by
a data write, and design §9.3's one rule is that "the restrictive change
propagates on the fast path; the permissive change may lag, and lagging
fails closed." Here both changes are the same event.

KGS §9.3 already prices half of this: such a set is materialized with a
declared staleness bound, and staleness fails closed. What is unpriced is
the restrictive direction and the closure maintenance.

This finding is **unaffected** by the removal of the deny mechanism, except
that one of its sentences got shorter: the old version listed `deny` and
`classify` among the permissions the data writer does not hold, and neither
permission exists any more. The problem was always that the writer holds
*no* authorization permission of any kind, and it still holds.

**Finding.** §17 F7's second dimension ("predicate-defined entity-sets:
authorization as a function of data"), compounding F3.

**Updated 2026-10-24: the mechanism this was about is gone, and the hazard
is not.** kgs's respecified containment
(`kgs/docs/epistemic_quad_store_spec.md`) has no entity-set at all, so there
is no predicate-defined entity-set and no specified consumer is currently
asking for one. §17's F7 records that as its second half closing by
withdrawal.

This entry **stays in the main list anyway**, and the reason is the
difference between U5 and U3. U3 was about a *closure shape* that only
existed because of a mechanism that no longer exists — remove the mechanism
and the finding has nothing to be about. U5 is about something more general:
any construction in which an ordinary data write moves an authorization
answer. "Eva can see all Belgian suppliers, as one rule that stays correct
as suppliers arrive" is a natural want that will be asked for again under a
different name, and the hazard will arrive with it unchanged. Retiring the
entry would mean re-deriving it then.

**What supporting it would cost.** Either every consumer fact write
synchronously re-evaluates every predicate-defined set that could reference
the row — which puts authorization maintenance on the hot write path at
fact cardinality, and §10 established that a grant and a consumer's write
cannot commit atomically in any deployment shape — or the restrictive
direction lags and a removed supplier stays visible for the staleness
window, which is a disclosure the design refuses to accept everywhere else.

~~The containment half additionally lands in F3~~ — it did, and F3 is closed,
so that compounding is gone. What it said still describes the shape: a
predicate-defined set is a container whose membership nobody wrote, so the
ancestry closure it participates in cannot be maintained from an
authorization event at all.

**The standing answer, which is now a derivation rather than a suggestion.**
The cheapest honest resolution is to permit predicate-defined sets only
where the predicate is over immutable or append-only attributes — and since
the deny mechanism was removed, that is forced rather than preferred.
With nothing to subtract, *adding* a containment edge can only ever add
access and *removing* one can only ever take it away. So a set whose
membership is append-only generates permissive changes exclusively, which
design §9.3 already permits to lag and to fail closed; a set whose
membership can shrink generates a revocation riding the permissive path,
which §9.3's one rule forbids. That is a property of the predicate and
nothing about the closure's shape repairs it, so it wants to be a lint on
the registered schema rather than a paragraph a reader is trusted to
remember.

**And the floor cost, measured** before the F3 spike was abandoned
(`spikes/2026-10-24-f3-dag-containment/predicate-sets.txt`; partial, like
everything in that directory). Fifty predicate-defined sets over 2,000,000
entities, each one a single equality on one indexed column — the cheapest
predicate there is — produced **5,000,000 membership edges**, implied
**84,625,000 rows** of fact-keyed ancestry closure, and took **23.3 s** for
one membership refresh. Every one of those is a lower bound on the
mechanism, not an estimate of it, because a real predicate is not one
indexed equality.

---

## Resolved without being solved

Three entries left this file's main list without anybody closing the gap.
They are recorded here rather than deleted, because a gap that disappears
because its *mechanism* disappeared, or because its *requirement* was
withdrawn, is a different event from a gap that was closed — and the
difference matters to anyone reading this file to decide what to build.

Two of the three went on 2026-10-23 with the deny mechanism. The third went
on 2026-10-24 and is a different event again, so it is labelled separately.

### U3 — the requirement was withdrawn, 2026-10-24

**Resolved by withdrawal, not by solution.** U3's subject was KGS §9.3's
entity-sets: "a named, graph-scoped grouping of entities with their own
rules, nestable — this is how 'my wife can see everything about the school
and the daughter, nothing about my business' is expressed once rather than
per fact." A fact then had an episode *and* zero or more entity-sets as
containers, and entity-sets nested, so a fact in two sets had three
containment paths. Two consequences: design §9.2's ancestry closure stopped
being a path and became a many-to-many relation at fact cardinality, and
§8.2's bottom-up navigational visibility, which grants list rights on an
object's ancestors "**and only on the direct path**", was restricting itself
to something that did not exist.

kgs was respecified on 2026-10-24. Its implementation target is now
`kgs/docs/epistemic_quad_store_spec.md`, and containment there is a strict
four-tier tree — UNIVERSE → WORLD → SCOPE → TOPIC (§2.1) — with
`named_graphs.parent_graph_id` holding one parent, `tenant_quads.graph_id`
one graph per quad, and `tenant_entities.home_graph_id` one graph per
entity (§4.2). Its own ancestry walk is `WITH RECURSIVE … UNION ALL` over
that single parent pointer (§4.3), which is only correct for a tree. There
is no entity-set table, explicit or predicate-defined; the words are absent
from the document.

So §17 F3 closed by its own **first** branch — "entity-sets stop being an
authorization container" — chosen in the consumer's design rather than here,
and this file's job was to say what that branch costs. It costs the use case
in U3's first paragraph: expressing "everything about the school, nothing
about my business" once rather than per fact. Under a tree it is expressed
by putting the school in its own SCOPE graph and granting that, which is
D1's shape rather than a new mechanism — and which means the grouping is now
a **partition** rather than an overlay. A fact about the daughter *and* the
business has to be filed in one of them.

**The scenario stays in [unexpressible/](unexpressible/), with
`StatusUnexpressible`, and that is deliberate.** It declares a DAG fixture
and asserts that `DirectPath` refuses on it, and both halves are still true:
the corpus is not wrong today, it is describing a shape no consumer
currently asks for. Moving it needs the oracle's `Visible` to stop calling
`DirectPath` and compute something else, which is implementation work with
its own design question, and doing it half-way would leave the corpus
asserting one thing and this file another. The follow-up is named rather than
done: **rewrite `scenario.Visible` to the grant-anchored definition below,
then move U3 to a live scenario.**

**What was in flight when the requirement went**, kept because it is the
part a future DAG consumer would otherwise have to rediscover. A spike was
measuring the three resolutions at kgs A2's scale and got through six of its
eight sections before it was abandoned
(`docs/superpowers/spikes/2026-10-24-f3-dag-containment.md`; the numbers are
partial and labelled as such). Two of the three resolutions were worse than
this entry said:

- The **union of every path** does reopen leak channel #1, and the size of
  the reopening is **2,356 containers made list-visible to a principal
  granted ten episodes — 1,000 facts of 10,000,000 — that it held no grant
  on and none below**, 2,354 of them entity-sets. This entry called it "a
  principal granted one deep fact can enumerate every entity-set it belongs
  to", which understated it: it enumerates the sets of every fact it can
  read, and their ancestors.
- The **intersection** was called "cheap and frequently empty". Measured, it
  was exactly `{tenant, graph}` — size 2, minimum 2, maximum 2 — for *every*
  resource with more than one path. Not frequently empty: always empty below
  the graph, so the reading names nothing at all rather than naming little.
- A **designated primary container** stays implementable and still means
  somebody designates it on every write. Used as a containment key it also
  silently pruned **87%** of one probe's authorized rows, which is a worse
  failure than the one this entry predicted.

And a fourth resolution that nobody had written down, which is the one to
start from if F3 reopens: **anchor the relation on the grant rather than on
the object.** A container is navigable by a principal iff it lies on a
containment path from one of that principal's own grants down to something
it may read — `{ c | ∃ readable o, ∃ g ∈ grants(p) : g ⊒ c ⊒ o }`. That is
well-defined for any number of paths, leaks nothing by construction because
it is a subset of what the principal's own grants already imply, and reduces
to "the direct path" when containment is a tree and the grant sits above the
path. It is also what `scenario.Visible` would have to compute.

**One thing not to take from this.** F3 is resolved for the consumers that
have been specified. It is not a result about authorization containment in
general. A future consumer whose resources belong to several containers
reopens F3 and reopens F1's condition (iii) with it, and `acre` — which
nobody has specified — is evidence in neither direction.

### The two that went with the deny mechanism, 2026-10-23

### U2 — "Use a classification" made a preference into an absolute

**Resolved by removal.** U2's subject was that answering a *discretionary*
requirement with a classification converted "don't show her the salary"
into an absolute of the same kind as a legal ethical wall, administered by
whoever held the classify permission, which the resource's owner could not
lift. There is no classification to answer with, so the gap has nothing
left to be a gap in.

It is worth recording that U2 is **why** the mechanism was removed rather
than a casualty of it. The diagnosis in the design document's no-deny
anti-goal is U2's observation generalized: the design anchored on "this
principal may never see this" — a rare case — and made it the template for
the common one, so every ordinary privacy preference arrived as an absolute
nobody could undo. U2's cost section said the honest short-term answer was
"to tell consumers that this requirement has no discretionary form". The
answer taken instead was to remove the form that made it mandatory.

What the requirement now does is land in U1, with the cheap resolution U2
was warning about no longer available. U1 is strictly harder for exactly
this reason.

### U6 — Nothing checked whether the actor on a mandatory act may classify

**Resolved by removal.** U6 showed, against the real registry, that an
ordinary associate could construct an `iam.MandatoryAct` naming herself,
add herself to a conflict screen's clearance group, and open the gate. The
registry enforced the *witness* — a channel, an actor, a reason and an
instant, with unexported fields so one could not be forged — and never the
actor's **authority**, because §16 question 2 (deployment-level security
admin, per-tenant security admin, or the resource owner at creation time)
was unanswered.

There are no mandatory acts, no clearance groups and no classify
permission, so there is nothing left to check. §17's F9 is closed by
deletion and §16 question 2 is moot, which the design document now says
explicitly, because §16.2 was F9's blocking input and the owner should see
it closed rather than wonder.

What U6 contributed before it went is worth keeping in view. It was the
only gap in this file found by writing the corpus rather than taken from
the existing findings register, and its point — that the mandatory channel
was administered by somebody, so an absolute administered through it was
only as absolute as that administration — is one of the two observations
the no-deny decision rests on. The other is U2's.

---

## What should change in the design document

All five items from the previous version of this section have been applied
or made moot. They are kept because the trail is the useful part.

1. **§8.2's "and only on the direct path" should be marked as
   unimplemented pending F3.** *Applied, then superseded on 2026-10-24.*
   §8.2 carried the caveat; F3 is now closed, so §8.2 says instead that the
   phrase is implementable **because every specified consumer's containment
   is a tree**, and carries that as a precondition rather than as a
   reassurance. §9.2's "its containment path", singular, got the same
   treatment. The asking and the answering are both recorded because the
   answer did not come from where this file expected it to.

2. **§17 should gain a finding for §16 question 2.** *Applied, then
   closed.* It became F9, and F9 is closed by deletion along with the
   mandatory channel it was about.

3. **§8.3's "scoped" bullet should name the storage-shape condition.**
   *Moot.* §8.3 is gone with the classification. The storage-shape
   condition it was about survives as F4 and as U4 above, which is where a
   reader now finds it.

4. **§8.5 should say what happens when the answer is "use a
   classification" but the requirement was discretionary.** *Resolved by
   removal.* "Use a classification" is not an answer the design gives any
   more, which is the strongest available form of saying what happens.

5. **F4 and F7 should be decided together.** *Still true, and now
   unavoidable.* They are one fork with one option on it. Deciding them
   separately is no longer possible, since the branch that distinguished
   them has been deleted.

One item this file asks for rather than applies:

6. **The per-episode grant cost should be registered, or deliberately not
   registered.** H1's fixture had to move its grant from the graph down to
   the episode, because privacy inside a shared container is now expressed
   by grant granularity rather than by a label. §9.2's closure budget is
   untouched — a per-episode grant still reaches every fact inside it at
   one tuple per hop — but the number of tuples a household carries is now
   a function of how much it ingests rather than of how many people live in
   it. That is a consequence of the no-deny decision rather than an
   argument against it, and it is not currently in §17.

   **Note for whoever picks this up**, added 2026-10-24: "episode" is kgs's
   old vocabulary. The respecified consumer has TOPIC graphs where it had
   episodes, and the grant granularity question survives the rename
   unchanged — the tuple count is still a function of how much a tenant
   ingests. Only the noun moved.

And two this file asks for because of U3's withdrawal:

7. **The single-path assumption should be enforced where it is made, not
   assumed where it is relied on.** *Asked, and **landed**.* The ask was
   that §8.4's schema registration reject a consumer declaring multi-path
   containment rather than silently handing it an ancestry closure sized by
   resource cardinality. It now does: a schema giving a container kind two
   or more containment parents is refused with
   `iam.ErrMultipleContainmentParents`, and the refusal carries F3's own
   measurement — 106,495,540 rows and 10.9 GB keyed on the resource against
   433,063 rows and 37 MB keyed on the container. The corpus's own check
   (`scenario.Paths`, `scenario.DirectPath`) is what
   `scenario.Realize` applies before it writes a single container, so a
   multi-path fixture is refused on the corpus's side too — which is why
   U3's scenario cannot reach the real module and says so when it runs.

8. **`scenario.Visible` should stop being built on `DirectPath`.** *Asked,
   not applied.* The oracle computes a principal's navigable set by taking
   each readable object's single containment path, so it cannot run at all
   on a multi-path fixture — which is exactly why U3's scenario stays an
   `unexpressible` one. The replacement is in U3's entry: anchor the
   relation on the grant rather than on the object. Doing it would let U3's
   scenario become live and let this file's count and the corpus's agree
   again, and it is implementation work with a design question in it rather
   than a documentation change, so it is named here instead of being done
   quietly.

And two this file did not expect, found by running the corpus against the
real module rather than against its own oracle. Neither is a requirement
the design cannot express, so neither is a scenario here; both are
`iam.Authorizer` being narrower than §8.2 as the corpus writes it, and
they are recorded here because this is where the module's gaps are kept.

9. **`iam.ContainerKind` could not declare a kind nested inside itself.**
   *Found 2026-10-25. **Resolved 2026-10-25**, by being built.* A kind
   declared at most one parent kind, was refused if it named itself as its
   parent, and two parent kinds were refused as finding F3's DAG. Together
   those meant a `folder` inside a `folder` with a `folder` at the root had
   no declaration at all — an ordinary Drive hierarchy, which is design
   goal 4's own example, and the shape of both D2 and D7 as well as of any
   consumer with user-created nesting.

   What closed it is `ContainerKind.Nestable`: recursion declared as a flag
   rather than as a self-reference. The syntax does not offer the choice
   on purpose, because `Parents: ["tenant", "folder"]` on kind `folder`
   reads equally as "in a tenant *or* in a folder" and "in a tenant *and*
   in a folder", and only the second is the DAG F3 refuses — so `Parents`
   stays the one kind above, `Nestable` is the recursion, and a kind
   naming itself in `Parents` is now refused with a message pointing at
   the flag. `AllowsRoot`, `AllowsParentKind` and `PermittedParentKinds`
   are what a caller reads instead of reasoning about the fields.

   It is recorded here rather than deleted because the route matters: the
   corpus found this by being run against the real module instead of
   against its own oracle, which is the whole argument for the
   differential in `scenario/harness.go`. `scenario.Realize` declared a
   container kind per containment depth to work around it for one commit;
   it now declares each fixture kind as itself, with `Nestable` read off
   the containment graph.

   Two shapes are still refused by the translation, and only one of them
   is a finding. Two *distinct* kinds above one kind is a kind-level DAG
   and `ErrMultipleContainmentParents` is the right answer to it. A kind
   that is both a root and declared inside another kind has no declaration
   either, since `AllowsRoot` is "declares no parent" — the containment is
   still a tree, so that is a real limit rather than F3, and no fixture
   here is that shape. Both are refused with `ErrNotTranslatable` and a
   message that says which of the two it is.

10. **`iam` inherits every permission down the whole container tree, where
    §8.2's form 3 is declared per relation.** *Found 2026-10-25. Not a
    gap: a decision, with its cost named in `internal/authz`'s package
    doc.* There is one containment closure and no per-permission
    inheritance, so a grant on a container reaches every descendant for
    every permission. The corpus's Drive schema says something narrower:
    `viewer` and `editor` inherit from the parent and `owner` does not, so
    a folder's owner is declared not to own the documents inside it.

    No expectation row in the corpus distinguishes the two, because no row
    asks a non-inheriting permission about a nested object — and that is
    luck rather than design, so it is guarded rather than relied on.
    `scenario.Realize`'s `checkInheritanceDeclared` refuses to report an
    allow that `iam`'s closure carried further than the fixture's schema
    says the relation travels: the first row that would distinguish the
    two models fails loudly, naming both of them, instead of quietly
    agreeing. A divergence between the model a consumer reads in a schema
    and the model the module evaluates is the most expensive kind of
    authorization bug there is, and the only acceptable version of
    "nothing exercises it yet" is one that fails the moment something
    does.
