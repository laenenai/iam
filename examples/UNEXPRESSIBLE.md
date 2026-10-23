# What this design cannot express

Four use cases, each a real requirement from one of the three consumer
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

There were six. Two left this file on 2026-10-23 and neither was solved:
see **Resolved by removal** at the bottom, which is where they are
recorded rather than deleted.

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

## U3 — Containment is a DAG, so "only the direct path" names nothing

**The use case.** KGS §9.3's entity-sets: "a named, graph-scoped grouping
of entities with their own rules, nestable — this is how 'my wife can see
everything about the school and the daughter, nothing about my business' is
expressed once rather than per fact." The household depends on this.

**Why the design cannot express it.** A fact then has an episode *and* zero
or more entity-sets as containers, and entity-sets nest, so a fact in two
sets has three containment paths. Two consequences. §9.2's ancestry closure
stops being a path and becomes a many-to-many relation at fact cardinality,
maintained on every write. And §8.2's bottom-up navigational visibility,
which grants list rights on an object's ancestors "**and only on the direct
path**", is restricting itself to something that does not exist.

Scenario D7 is the same situation with a tree: there the restriction is
exact, the visible set is compared element by element, and the claim
passes. U3 is D7 plus one containment edge that KGS §9.3 requires, and
`DirectPath` refuses. The decision itself is fine in both — F3 is not about
whether the answer can be computed, it is about the closure that implements
it and about navigation.

This finding is **unaffected** by the removal of the deny mechanism, with
one exception worth noting: navigational visibility now carries more weight
than it did. D8's conflict screen rests partly on a `visible-set` claim —
the screened associate must not learn that the matter exists — so "what
does `visible_below` mean in a DAG" is no longer only a usability question
about finding things. It is part of how a screen is asserted.

**Finding.** §17 F3, marked **blocking for §9.2**: "either kgs's
entity-sets stop being an authorization container, or the closure and
`visible_below` are redefined for multiple paths."

**What supporting it would cost.** Three resolutions, and the choice
changes the projection's shape rather than its tuning, which is why the
finding is blocking.

Entity-sets stop being an authorization container and become a query
convenience — removing a kgs capability the household scenario is written
around.

Or the ancestry closure becomes explicitly many-to-many, maintained on
every fact write at ten-million-row cardinality. That is the closure cost
A2's budget is written to catch, and the one place where this design's
load-bearing performance claim could quietly stop holding.

Or `visible_below` is redefined for multiple paths, which needs a decision
nobody has made. The union of every path means a principal granted one deep
fact can enumerate every entity-set it belongs to — leak channel #1
reopened from a new direction. The intersection is cheap and frequently
empty. A single designated primary container per object is implementable
and means somebody has to designate it on every write.

The corpus cannot choose for the owner. Until somebody does, "only on the
direct path" should not appear in the design as though it were
implementable — and the design now says so in §8.2, which is the one
change to the design document this scenario asked for.

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

**What supporting it would cost.** Either every consumer fact write
synchronously re-evaluates every predicate-defined set that could reference
the row — which puts authorization maintenance on the hot write path at
fact cardinality, and §10 established that a grant and a consumer's write
cannot commit atomically in any deployment shape — or the restrictive
direction lags and a removed supplier stays visible for the staleness
window, which is a disclosure the design refuses to accept everywhere else.

The containment half additionally lands in F3: a predicate-defined set is a
container whose membership nobody wrote, so the ancestry closure it
participates in cannot be maintained from an authorization event at all.

The cheapest honest resolution is to permit predicate-defined sets only
where the predicate is over immutable or append-only attributes, and to say
so in the design rather than discovering it per consumer.

---

## Resolved by removal, 2026-10-23

Two entries left this file when the deny mechanism was removed. Neither was
solved. They are recorded here rather than deleted, because a gap that
disappears because its mechanism disappeared is a different event from a
gap that was closed, and the difference matters to anyone reading this file
to decide what to build.

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
   unimplemented pending F3.** *Applied.* §8.2 carries the caveat and says
   not to build against the sentence until F3 is settled.

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

One new item, which this file asks for rather than applies:

6. **The per-episode grant cost should be registered, or deliberately not
   registered.** H1's fixture had to move its grant from the graph down to
   the episode, because privacy inside a shared container is now expressed
   by grant granularity rather than by a label. §9.2's closure budget is
   untouched — a per-episode grant still reaches every fact inside it at
   one tuple per hop — but the number of tuples a household carries is now
   a function of how much it ingests rather than of how many people live in
   it. That is a consequence of the no-deny decision rather than an
   argument against it, and it is not currently in §17.
