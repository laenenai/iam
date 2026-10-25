# The household

This is the scenario the project exists for. KGS §1, in the owner's words:

> An invoice marked personal is ingested. His wife must not see the
> invoice, the supplier's name, the total, or the goods. When *she* uploads
> an invoice from the same supplier, the graph must silently resolve it to
> the same supplier — without revealing that a member of the household had
> already entered it. A school document from their daughter yields a school
> entity they can both access.

Three of those four sentences are about what must not be learned. The
fourth is about deduplication staying correct anyway. Most access-control
models can do either one.

## The shape of the answer

The thing to understand first is that **entity existence is derived, not
granted**. KGS §7.3: an entity exists for a principal if and only if that
principal can read at least one assertion that references it. There is no
entity ACL. That single decision is what makes the second and third
sentences compatible:

```
entity:acme                     ← one entity. Identity is shared, by referent
                                  binding, and is NOT an authorization object.
                                  That is what makes dedup safe.

fact:his-acme-supplier  ──mentions──> entity:acme     (carries personal:pascal)
fact:her-acme-supplier  ──mentions──> entity:acme     (carries personal:eva)

entity:acme exists for pascal   ← because he can read one of those facts
entity:acme exists for eva      ← because she can read the other one
neither can read the other's
```

Had existence been an ACL, that row would have had to choose between
resolving both invoices to one supplier and keeping the two of them apart.

The second thing **used to be** that the household's sharing was generous
and was not what decides. It is worth quoting what this file said, because
the sentence is now false and the reason is the whole of the no-deny
decision:

> The ordinary, correct state is one tuple,
> `graph:household#viewer@group:household#member`. Both of them read nearly
> everything through it. What keeps the invoice private is not a narrower
> share — it is a label: a `personal:pascal` classification on the episode,
> satisfied only by a clearance group the mandatory channel admitted him
> to.

There is no classification. So sharing *is* what decides, and the generous
graph-wide tuple had to go. Every episode now carries its own grant:

```
episode:grocery-receipt#viewer@group:household#member   ← shared
episode:invoice-acme#viewer@user:pascal                 ← his
```

The episode's grant reaches every fact inside it through containment, so
the invoice, the supplier name, the total and the goods are four separate
denials from one grant that was not written, and nobody enumerated
anything. That is the same answer the label gave, with one difference that
matters: he can add her to it this afternoon. A classification could not be
lifted by the resource's owner, which was the right property for a legal
ethical wall and the wrong one for a household invoice — and routing the
household through it was the diagnosis that removed the tier.

**What it costs, stated here because it is a real cost.** Privacy inside a
shared container is now expressed by grant *granularity*, so the household
writes one tuple per episode where it used to write one per graph. Design
§9.2's closure budget is untouched — a per-episode grant still reaches
every fact inside it at one tuple per hop, not one per fact — but the
number of tuples a household carries is now a function of how much it
ingests rather than of how many people live in it. This is also KGS §9.3's
own default for a new episode ("the ingesting principal alone"), so it is
not a shape kgs has to be talked into.

## The scenarios

**H1** is the first half. Four denials — the invoice, the supplier's name,
the total, the goods — each its own row, because in kgs they are separate
objects: an episode and three facts. Plus one allow, so the scenario is not
passing because nothing works: Eva reads the shared grocery receipt through
the household's own grant, written on that episode. And one claim: the ACME
entity exists for him and not for her.

**H2** is the hard sentence. Both invoices are in the fixture, each granted
to its owner, symmetrically — a household is not a hierarchy. Her facts are
hers, his are his, and the claim asserts the supplier entity exists for
*both* of them, through two disjoint sets of assertions. That also closes
leak channels #4 and #5: she cannot read his facts, so a proof count or a
"12 invoices from this supplier" facet computed over the authorized
evidence set cannot include them.

The old fixture needed two clearance groups and two labels for that
symmetry, and two absolutes neither of them could lift. Two per-episode
grants do the same job, because the property that makes dedup safe was
never the deny — it was derived existence.

**H3** keeps the household usable, and it is the one household scenario
that did not change at all. The school episode is granted to a
`group:household-parents` and the facts inherit it at one tuple per hop;
the school entity exists for both parents and for neither the daughter nor
the neighbour. **Read it next to H1**, because the pair locates precisely
what the mandatory tier was carrying: not sharing, not derived existence,
only the case where a container is shared and one thing inside it is not.
Note the daughter's denial too: giving her access is one more tuple
whenever the household decides to, which is now the shape of every denial
in the corpus.

**H4 is the will**, and it is the one scenario in the corpus where the
expectation table says **allow** and the content is still unreadable — and
now the only place in the whole design where anything is withheld from a
principal a grant reached. The requirement that created the cryptographic
tier:

> whatever rule ever happens my will document should always stay private
> except if I die and the lawyer gives the access key

Tiers 1 and 2 are enforced by policy, which means they are enforced by
whoever administers policy, and no access-control system can promise that
no future rule will grant access — rules are mutable and administrators
exist. So the will is not protected by a decision at all. It is encrypted
under a key the deployment does not hold, and this module's entire
responsibility is one field:

```
marking      will:pascal     enforcement: crypto     ← the whole of iam's part
assigned to  episode:will-2026                       ← and it seals the facts inside
```

He holds the grant on the will's episode, so the decision procedure has
nothing to object to, and he cannot read a byte of it.

Eva's denial changed, and the change is not cosmetic. It used to come from
the policy tier as well as from the key, "because the tiers compose rather
than compete and her denial should not depend on a key". There is no policy
tier to compose with, so she is denied by the ordinary mechanism: nobody
granted the will's episode to her. That is liftable by him, where before it
was not liftable even by him — and for a will that is the correct
direction. He should be able to show it to her; she should not be able to
decrypt it if he does not.

The notary holds an escrow share and no grant, which is the correct state
while the testator is alive: the key material and the policy are
independent, and neither alone opens the will.

Recording the enforcement class is what lets a consumer tell a user *why*
something is unreadable, and lets the API refuse a processing operation
with a typed error rather than failing obscurely later. `keyring` holds the
wrapping; `escrow` holds the shares, the custodians, the ceremony and the
dead-man's switch. None of that is in this module.

## Status

**H1, H2 and H3 are live.** Each fixture's identity layer is materialized
against a real registry, its episodes and facts become real containers, its
tuples become real grants, and every row of its expectation table is
answered by `iam.Decide` and by the corpus's reference procedure and the
two are diffed — same verdict, same reason, same grant responsible. The
sentence the project exists for is now a passing differential rather than a
pinned table: she reads her own ACME invoice, he reads his, neither reads
the other's, and one supplier entity exists for both of them through two
disjoint sets of assertions.

**H4 is pending on `MarkingStore`**, and its table is not what waits — the
table runs the full differential, including the row that matters most,
where `Decide` returns allow for the will. What waits is the other half of
the scenario. This module stores no marking and no enforcement class at
all, so `crypto-unreadable` is answered by the corpus over fixture data,
and a consumer cannot yet ask `iam` *why* content is unreadable. H4's whole
point is that an allow and a readable byte are different things; half of
that distinction is live and half of it is still the corpus's own.

The entity-existence claims and the marking resolution run against fixture
data in all four; the live claims run against the real registry.

**H3 should be read next to [U3](../UNEXPRESSIBLE.md).** The fixture here
keeps containment a tree: a fact's only container is its episode. KGS §9.3
wants more than that — "my wife can see everything about the school and the
daughter, nothing about my business" expressed once, as an entity-set — and
the moment an entity-set is also a container, a fact has several
containment paths and the design's "only the direct path" names none of
them.
