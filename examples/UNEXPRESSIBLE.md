# What this design cannot express

Six use cases, each a real requirement from one of the three consumer
designs, that `iam` as designed cannot express. They are listed here
because a corpus whose value is that it all passes is worth much less than
one that precisely locates what does not work.

Each has a scenario in [unexpressible/](unexpressible/) that **demonstrates**
its gap rather than asserting it — the schema lint refusing the relation,
`DirectPath` refusing a DAG, `RowEnforceable` reporting that a column
cannot be hidden by a `WHERE` clause, an ancestry closure moving under an
ordinary data write, an unprivileged principal successfully clearing
itself. The harness refuses an unexpressible scenario that carries no such
claim. So if the design grows to cover one of these, the corresponding
claim starts failing and says so, and the scenario leaves this file.

Before the list, the two sentences that explain why there is a list at all.
Design §8.5 permits union, usersets and tuple-to-userset inheritance and
nothing else, because that is exactly the subset that flattens into §9's
closures, and the projection is what buys the entire A2 performance
budget. Its own answer to a requirement outside the subset is "use a
classification, and if it is neither — that is a design conversation, not
a configuration change." Four of the six below are that conversation. Two
are cases where "use a classification" is available and quietly changes
what the requirement means.

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

**Finding.** §17 F7 (ontology scope). Marked open, with "either kgs loses
those dimensions or tier 1 gains a form. Do not add a form casually; §8.5's
restriction is what buys the projection."

**What supporting it would cost.** A tier-1 form conditioned on resource
attributes costs §9's projection, and therefore A2: union, usersets and
inheritance precompute into a closure and a conditional expression does
not. An exclusion operator costs that *and* the A3 invariant, because
exclusion in a relationship model is local to the permission it is written
in — to make a restriction absolute it must appear on every relation of
every resource kind and be remembered for every kind added later, N
permissions by M dimensions, growing with the schema, where one omission is
a silent bypass rather than an error. Lakekeeper, the one production
open-source ReBAC-over-a-hierarchy implementation, has no deny mechanism at
all, which is the strongest available evidence that this is what the model
is bad at.

The cheaper resolutions are both real and both have a price. kgs drops the
ontology-scope dimension and expresses the requirement as a classification
— see U2 for what that changes. Or `Predicate` grows a second return value,
a permitted-predicate set the consumer applies, which moves part of the A3
trust boundary into consumer code. That is the same choice F4 forces, and
the two should be decided together.

---

## U2 — "Use a classification" makes a preference into an absolute

**The use case.** U1's, taking §8.5 at its word and expressing it as a
classification. The first half works: the analyst is denied the salary, by
the gate, and nobody wrote an exclusion. The second half is the HR
director's entirely ordinary "actually, show her this one salary, she's
running the review."

**Why the design cannot express it.** A classification is mandatory. §8.3:
it "cannot be granted away, delegated, transferred with ownership, or
satisfied by any tier-1 relation", and "there is no API that grants a
clearance as a side effect of sharing". So the lift has no operation behind
it. The scenario writes the director's attempted lift as the most direct
grant the model has — a tuple naming the analyst on the fact itself — and
it changes nothing. What began as a discretionary preference about one
field is now an absolute of the same kind as a legal ethical wall,
administered by whoever holds the classify permission, and the resource's
owner cannot lift it.

This is worth stating plainly because it is the gap most likely to be
adopted by accident: the workaround's schema is perfectly legal and no lint
catches it. In scenario M5 the absence of a discretionary path is the
feature the whole module exists for. Here it is the bill.

**Finding.** §17 F7, second half: "a classification is mandatory and
non-delegable, so a discretionary 'don't show her the salary' becomes an
absolute no owner can lift."

**What supporting it would cost.** Nothing to build, which is the problem.
Supporting the requirement *as stated* needs one of three things. A third
tier-1 form — a scoped, delegable restriction — costing the projection, as
U1. Or a second rule shape in the mandatory layer: a named
`(principal, resource)` block or a lift, which §16 question 1 explicitly
assumes is not needed, and which would double the A3 adversarial suite
since every absolute would then have two ways to be satisfied instead of
one. Or accept the promotion and make it visible: a consumer-facing
distinction between a classification meaning "legally absolute" and one
meaning "hidden by preference", with different administration — which is
two mandatory layers wearing one name.

The honest short-term answer is to tell consumers that this requirement has
no discretionary form, and to make the API say so, rather than letting them
discover it after a classification is in place and a thousand resources
carry it.

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
implementable — that is the one change to the design document this scenario
asks for.

---

## U4 — An attribute-scoped classification cannot hide a column

**The use case.** Eva may read the payroll document and not its salary
column. Design §8.3 offers exactly this: a classification "may be declared
over a whole resource, or over a named attribute or field of it, which is
how property-level and cell-level security compose without a second
mechanism."

**Why the design cannot express it.** It depends on the consumer's storage
shape, and the scenario carries both shapes side by side so the finding is
precise rather than general.

For kgs it is true and free. A fact carries one attribute, so hiding the
attribute is hiding the row, and a row is what a predicate can hide. KGS
§9.2 says so: "because facts carry attributes rather than entities carrying
columns, Palantir's object-level + property-level = cell-level security
falls out of the data model instead of needing a second mechanism." The
scenario's row-shaped claim passes.

For CAS it is not. A document's fields are columns of one row, and §9
compiles authorization into a `WHERE` fragment the consumer joins into its
own statement — and a `WHERE` fragment hides rows, not columns. So the
decision procedure can answer "may she see `document:payroll.salary`"
correctly while `Predicate`, which is the surface carrying the traffic,
cannot express the answer at all. A consumer that falls back to calling
`Decide` per cell has abandoned §9 and is post-filtering, which is KGS leak
channel #6.

Nothing in the schema is wrong, so no lint catches this. It is caught by
asking what the compiled predicate can express.

**Finding.** §17 F4, marked open with "two different modules; pick one
before phase 1 fixes the API."

**What supporting it would cost.** Two options, and they are not variations
of each other.

`Predicate` returns a fragment *plus* a permitted-attribute set, and the
consumer applies the second part. Cheap to build, and it moves a piece of
the A3 trust boundary into consumer code: the module could no longer claim
that no sequence of operations opens a gate, because a consumer that
forgets to apply the attribute set is a disclosure this module can neither
prevent nor detect. If this is chosen, the §9.4 differential audit must
cover consumer compliance and not only projection divergence, which is a
substantially larger audit than the one designed.

Or this module becomes a query rewriter, parsing and rewriting SELECT lists
across three consumers' query builders. That keeps the trust boundary
intact and is a different module with a different charter. CHARTER.md's "it
must not contain" list has to grow a line either way.

There is a third, cheaper answer for CAS specifically: make sensitive
document fields their own addressable resources, so the columnar case
becomes a row case. It costs a schema migration in CAS and a cardinality
increase in its tables, and it needs no new mechanism here.

---

## U5 — A predicate-defined entity-set has no authorization event

**The use case.** "Eva can see all Belgian suppliers", as one rule that
stays correct as suppliers arrive. KGS §9.3 allows an entity-set to be
"definable either explicitly or by predicate."

**Why the design cannot express it safely.** An ordinary data write, made
by somebody holding no `grant`, `deny`, `policy.set` or `classify`
permission, moves an authorization answer. In the scenario, Pascal asserts
`country = BE` on a company in his own transaction and Eva can now read it.
There is no authorization operation to audit under §8.6, nothing to bump
the deny epoch, and — the part that matters most — the *restrictive*
direction rides the same path. A supplier leaving the set is a permission
being removed by a data write, and design §9.3's one rule is that "the
restrictive change propagates on the fast path; the permissive change may
lag, and lagging fails closed." Here both changes are the same event.

KGS §9.3 already prices half of this: such a set is materialized with a
declared staleness bound, and staleness fails closed. What is unpriced is
the restrictive direction and the closure maintenance.

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

## U6 — Nothing checks whether the actor on a mandatory act may classify

**The use case.** The one the whole module exists for: a conflict screen
that no sequence of operations can open. Scenario M5 asserts the
discretionary half at length — every grant, share, role assignment and
ownership transfer available, applied in combination, and the gate stays
shut. This scenario asks the other half.

**Why the design cannot express it.** Design §8.3 makes clearance-group
membership move only "through the classify permission or an authoritative
directory sync", and closes with "creating and assigning classifications is
itself permissioned and audited, and is not a power that ownership
confers". The registry enforces the *witness*: every clearance write
demands an `iam.MandatoryAct` carrying a channel, an actor, a reason and an
instant, and `MandatoryAct`'s fields are unexported so one cannot be
forged or constructed by the provisioning path. What nothing enforces is
the **actor's authority**, because §16 question 2 — deployment-level
security admin, per-tenant security admin, or the resource owner at
creation time — is unanswered.

So an ordinary associate can construct an act naming herself, add herself
to a conflict screen's clearance group, and the gate opens. The scenario
does exactly that, against the real registry, and the registry accepts it.

The type system's achievement here is real and narrower than it looks: it
makes a clearance write impossible to perform *accidentally* or as a side
effect of sharing, and it does not make one impossible to perform.

**Finding.** §16 question 2. **This one is not in the §17 register and it
should be** — it is the only gap found by writing this corpus rather than
taken from the existing findings, and it is the gap that most undercuts the
scenarios that pass.

**What supporting it would cost.** Small to build, and it needs the §16
decision first, which is why it is here rather than on a task list. The
three candidates have different costs. A deployment-level security admin is
one role and breaks the household case, where the owner reasonably
classifies their own invoice at creation. A per-tenant security admin fits
the legal case and needs the role to exist before the first classification
does. The resource owner at creation time with changes restricted
afterwards fits the household and reintroduces, for the creation window,
exactly the ownership-confers-classification power §8.3 forbids.

Whichever is chosen, the mechanism is the same shape: `MandatoryAct`'s
construction stops being free and starts requiring a checked capability,
which means `iam.NewMandatoryAct` loses its current signature, and the A3
adversarial suite gains the mandatory channel as an attack surface it does
not presently cover at all.

Until then, no scenario in this corpus may claim that a clearance cannot be
obtained — only that it cannot be obtained *discretionarily*, which is a
narrower and much weaker statement than the design reads as making.

---

## What should change in the design document

Recorded here rather than applied, per the instruction not to edit the
design. In priority order:

1. **§8.2's "and only on the direct path" should be marked as
   unimplemented pending F3**, not stated as a property of the design. U3
   shows there is no such path once entity-sets are containers, and the
   three ways to redefine it have materially different leak profiles.

2. **§17 should gain a finding for §16 question 2**, with the observation
   that the mandatory channel is currently open to any principal who can
   call the registry, and that the A3 adversarial suite does not cover it.
   Right now the design's strongest claim rests on an unimplemented
   permission.

3. **§8.3's "scoped" bullet should name the storage-shape condition** —
   attribute scoping is enforceable by §9's predicate where the attribute
   is a row and not where it is a column. As written it reads as a
   general capability, and F4 is a footnote rather than a caveat on the
   feature itself.

4. **§8.5 should say what happens when the answer is "use a
   classification" but the requirement was discretionary.** U2 is a
   foreseeable, silent, one-way promotion of a preference into an
   absolute, and the paragraph that recommends it does not mention it.

5. **F4 and F7 should be decided together.** Both resolve to the same
   fork — either `Predicate` returns a second, consumer-applied value, or
   this module grows into a query rewriter — and deciding them separately
   risks picking differently for columns and for predicates.
