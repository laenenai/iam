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

The second thing is that **the household's sharing is generous and is not
what decides**. The ordinary, correct state is one tuple:

```
graph:household#viewer@group:household#member
```

Both of them read nearly everything through it. What keeps the invoice
private is not a narrower share — it is a label:

```
classification  personal:pascal              enforcement: policy
assigned to     episode:invoice-acme         ← one assignment

clearance group clearance:personal-pascal    channel: classify-permission
members         user:pascal
```

The episode's label reaches every fact inside it through containment, so
the invoice, the supplier name, the total and the goods are four separate
denials from one assignment and nobody enumerated anything. Design §16
question 1 records why this is a label rather than a named
`(principal, resource)` block: a label propagates through derivation and a
named pair would not.

## The scenarios

**H1** is the first half. Four denials — the invoice, the supplier's name,
the total, the goods — each its own row, because in kgs they are separate
objects: an episode and three facts. Plus one allow, so the scenario is not
passing because nothing works: Eva reads the shared grocery receipt through
the very same graph-wide grant that does not help her with the invoice.
And one claim: the ACME entity exists for him and not for her.

**H2** is the hard sentence. Both invoices are in the fixture, each
classified to its owner, symmetrically — a household is not a hierarchy.
Her facts are hers, his are his, and the claim asserts the supplier entity
exists for *both* of them, through two disjoint sets of assertions. That
also closes leak channels #4 and #5: she cannot read his facts, so a proof
count or a "12 invoices from this supplier" facet computed over the
authorized evidence set cannot include them.

**H3** keeps the household usable. Nothing is classified; the school
episode is granted to a `group:household-parents` and the facts inherit it
at one tuple per hop. The school entity exists for both parents and for
neither the daughter nor the neighbour. Note the daughter's denial: KGS
§9.3's default for a new episode's facts is the ingesting principal alone,
so giving her access is an explicit act and one more tuple whenever the
household decides to — deny-by-default is the right direction for a system
whose stated why is "reveal less".

**H4 is the will**, and it is the one scenario in the corpus where the
expectation table says **allow** and the content is still unreadable. The
requirement that created design §7.3's third tier:

> whatever rule ever happens my will document should always stay private
> except if I die and the lawyer gives the access key

Tiers 1 and 2 are enforced by policy, which means they are enforced by
whoever administers policy, and no access-control system can promise that
no future rule will grant access — rules are mutable and administrators
exist. So the will is not protected by a decision at all. It is encrypted
under a key the deployment does not hold, and this module's entire
responsibility is one field:

```
classification  will:pascal      enforcement: crypto     ← the whole of iam's part
```

He holds the clearance and the household grant, so the decision procedure
has nothing to object to, and he cannot read a byte of it. Eva is denied by
the policy tier as well, because the tiers compose rather than compete and
her denial should not depend on a key. The notary holds an escrow share and
no clearance, which is the correct state while the testator is alive: the
key material and the policy are independent, and neither alone opens the
will.

Recording the enforcement class is what lets a consumer tell a user *why*
something is unreadable, and lets the API refuse a processing operation
with a typed error rather than failing obscurely later. `keyring` holds the
wrapping; `escrow` holds the shares, the custodians, the ceremony and the
dead-man's switch. None of that is in this module.

## Status

All four are **pending** on `Decide`; H1, H2 and H4 additionally on the
classification store. The entity-existence claims, the label resolution,
the crypto-unreadability and the model-provider refusal all run today
against fixture data; the live claims run against the real registry.

**H3 should be read next to [U3](../UNEXPRESSIBLE.md).** The fixture here
keeps containment a tree: a fact's only container is its episode. KGS §9.3
wants more than that — "my wife can see everything about the school and the
daughter, nothing about my business" expressed once, as an entity-set — and
the moment an entity-set is also a container, a fact has several
containment paths and the design's "only the direct path" names none of
them.
