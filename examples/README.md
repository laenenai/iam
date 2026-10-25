# The `iam` use-case corpus

This directory answers one question for somebody building on `iam`: **can I
express the rule I need, and if so how?**

The corpus exists because writing real use cases is the cheapest way to
find out which ones the design's deliberately restricted schema can
express and which ones it cannot, and finding that out before two
consumers have built schemas on it is far cheaper than after. Four of the
eighteen scenarios here turned out to be in the second category, and they
are the most useful part of the directory. They are in
[UNEXPRESSIBLE.md](UNEXPRESSIBLE.md).

**Eleven of the eighteen now run against the real module end to end**, and
that changed what this directory is. `iam.Authorizer.Decide` exists —
containers, a containment tree, grants to principals and groups — so a
fixture's tuples become real grants and every row of its expectation table
is answered twice: once by `iam.Decide` and once by the corpus's own
reference procedure in `scenario/oracle.go`. The two answers are then
diffed: same verdict, same reason, same grant responsible. That diff is
design §9.4's differential authorization audit aimed one layer up, and it
is the most valuable assertion here. A disagreement is a finding, and the
failure message says which of the two matched the pinned row so the
finding has a direction.

`Predicate` is still unwritten in the shape finding F4 needs. `Filter`
exists and returns a typed residual that hides rows; it says nothing about
columns, and U1 and U4 are what that costs.

> **There is no deny mechanism, and that is the first thing to know before
> reading anything else here.** `iam` has two tiers: discretionary grants
> with default-deny, and content encrypted under a key the deployment does
> not hold (`escrow`). There is no classification, no clearance, no
> exclusion operator, and no plan to add one. "This principal may never see
> this" is expressed by never granting it; an absolute that must survive a
> future administrator is a key, not a policy row.
>
> The corpus had twenty-six scenarios and a `mandatory/` directory. Six of
> them went with the tier they tested, and the one that mattered most — the
> legal ethical wall, which the design called "the feature the whole module
> exists for" — is now [D8](discretionary/), where it is a grant nobody
> wrote. UNEXPRESSIBLE.md opens with where the absolute went, and records
> two of its own entries as resolved-by-removal rather than solved.

## How to run it

```
go test ./examples/...            # the whole corpus, no containers, no database
go test ./examples/ -run TestCorpus -v     # with each scenario's prose header printed
```

The corpus runs against the in-memory adapters by default. To run it
against Postgres, or against your own implementations, hand
`scenario.RunCorpus` a different factory — the same shape and the same
type `iamtest.RunAuthorizerSuite` takes:

```go
scenario.RunCorpus(t, examples.All(), func(t *testing.T) iamtest.Authority {
    reg := myRegistry(t)          // register setup/teardown with t.Cleanup in here
    return iamtest.Authority{Registry: reg, Authorizer: myAuthorizer(t, reg)}
})
```

One factory returns both halves because the authorizer composes the
registry rather than keeping its own copy of membership: a decision joins
live group membership, so two independently supplied halves would be two
different answers to the same question.

An `Authority` whose `Authorizer` is nil is legitimate rather than a
mistake — a consumer that has built the identity half and not the
authorization half still runs every fixture's identity layer and every
structural claim. What it loses is the differential, and any scenario
marked **live** says so by failing, because `live` is this corpus's claim
that the scenario runs against the real module.

That is the point of the corpus being data rather than test functions:
CHARTER.md makes "the suite runs green in *its* CI against *its* wiring"
the adoption test, and CAS's alpha builds its own authorization shaped as
this module's port. The corpus is the behavioural half of that yardstick.

## What a scenario is

Three parts, in this order of importance.

**A fixture.** Tenants, principals (users, services, agent runs), groups,
containers and their containment edges, relation tuples, and markings with
their enforcement class. All of it declarative. The identity half is
*materialized against a real registry* at the start of every scenario,
through the same calls a consumer makes — JIT provisioning from claims,
`EnsureGroup`, `AddGroupMember`, `DelegateAgentRun`, `Deprovision` — so
that part of every scenario is evidence about `iam` and not about this
directory.

A **marking** is the one label left, and it is not an authorization input.
It says what a resource's *content* is, so that a consumer can tell a user
why something is unreadable (enforcement class `crypto`, which is
`escrow`) and so that a consumer's egress gate knows what it is about to
send to a model provider (enforcement class `none`). `Decide` never reads
one. The value `none` is where the old `policy` enforcement class went,
which is the whole decision in one enum value: a label that refused a
principal access was a deny administered by policy.

**An expectation table.** Rows of `(principal, action, resource) → allow |
deny`, each naming the *reason*: which tuple granted it, or that nothing
did. The harness matches the reason as well as the verdict, because a
scenario that passes for the wrong reason is worse than one that fails — an
allow that should have arrived by inheriting a container and arrived
instead through a union on the object itself would satisfy a verdict-only
table while sending a consumer debugging it to the wrong row.

Every deny in the corpus is now `no-grant` or `principal-unusable`. There
used to be a third, `classification`, and its absence is the anti-goal as
an enumeration.

**A one-paragraph prose header** saying what real situation the scenario
models and which design sections govern it. It is printed when you run the
scenario with `-v`.

Plus **structural claims**, which are the part the decision API does not
answer at all: that a relation fits the permitted subset or is rejected by
the lint, that sharing a container cost one tuple per hop and not one per
object, that a resource has exactly one containment path, that a
restriction at attribute granularity is or is not enforceable by a row
predicate, that an ancestry closure does not move when an ordinary data
write lands, that a resource is unreadable because its marking is
crypto-enforced, that a principal navigates to exactly these objects and
no sibling. Every one of them is a pure function over fixture data or a
call against the live registry — and the four scenarios still marked
pending are pending on a *claim* of this kind rather than on a table.

Two claim kinds carry more weight than they did. `path-count` and
`visible-set` are now how a screen is *asserted* rather than merely
described: with no deny mechanism, D8's conflict screen rests on the matter
folder having exactly one containment path and on the screened associate
navigating to nothing, so an added containment edge or an added grant
breaks a claim instead of silently opening a wall.

## Pending, and why it cannot stay pending quietly

A scenario that still waits on something `iam` does not have is marked
**pending** on the capability it waits for. Everything it can run still
runs, and that is now more than it used to be: most pending tables are
answered by both evaluators and diffed, because whether a *table* can be
replayed against the real module is a mechanical property of the fixture
(the harness asks the translation what it could not write) rather than a
consequence of the status. What a pending scenario is missing is the half
of its claim about the design that no code here can carry yet — D7's
visible set, H4's crypto enforcement, D3's team holding a role.

Where a fixture does not reach the real module, its table is evaluated by
the reference decision procedure in `scenario/oracle.go`, which implements
§8.2's four permitted composition forms **and nothing else** — it refuses
anything outside §8.5's subset with `ErrUnexpressible`. That table being
green says the requirement is expressible and pins what the answer must
be; it does not say `iam` answers it.

Two things stop a pending scenario from staying pending forever, and
neither needs anybody to remember anything:

The **tripwire** reads `api.txt` and fails the corpus if a capability any
scenario is pending on has appeared where a consumer can reach it, naming
the scenarios that must now be wired to the real API. `api.txt` is
regenerated by a test that `mise test` already runs, so landing a
capability is enough to set it off.

It reads the facade's section **plus** the sections of the internal
packages the facade re-exports by alias, and the second half of that
sentence was bought at full price. The tripwire used to read the facade
alone, on the sound-sounding grounds that a capability has arrived when a
consumer can name it. `Decide` then arrived as a method on an aliased port
— the facade grew one `type Authorizer = authz.Authorizer` line and the
string `Decide(ctx` appeared only under `package authz //
internal/authz` — so a consumer could call `iam.Authorizer.Decide` while
fourteen pending scenarios stayed pending and nothing failed at all. The
rule was right about *when* a capability arrives and wrong about *where*
the arrival is written down. The cost of the wider scan is in
`scenario/pending.go`'s doc comment rather than hidden: a symbol in one of
those internal sections that the facade does not alias will trip the wire
early, which is the cheap direction to be wrong in.

The **ledger**, [pending.txt](pending.txt), is a committed golden file of
every scenario's status. Any change to the set of pending or unexpressible
scenarios is a reviewed diff. Regenerate it with
`go test ./examples/... -run TestLedger -update-ledger`.

The harness itself is tested, in `scenario/pending_test.go`: a tripwire
that could not detect a capability landing, or an "unexpressible" claim
with no executable demonstration behind it, would be worse than nothing.

## How do I express…

| I need to | Use | Scenario |
|---|---|---|
| share a folder so everything inside inherits | tuple-to-userset inheritance (`viewer from parent`), one tuple on the container | [D1](discretionary/) |
| do that several levels deep | the same thing; nothing changes | [D2](discretionary/) |
| give a team access | a userset subject, `folder:x#viewer@team:eng#member` | [D4](discretionary/) |
| add somebody to that team | one membership row; **no grant is rewritten** | [D4](discretionary/) |
| have roles without a permission per (role, kind) | a role is an *object* with an `assignee` relation | [D3](discretionary/) |
| share by link | a tuple whose subject is the capability token's bearer identity | [D5](discretionary/) |
| transfer ownership | a tuple write. It carries everything, because grants are all there is | [D6](discretionary/) |
| let somebody find a deep object without seeing its siblings | bottom-up navigational visibility, which works because containment is a tree — one parent per container. If yours is not, it does not work at all, and [U3](UNEXPRESSIBLE.md) says what to build instead | [D7](discretionary/) |
| keep one principal from seeing a resource | **do not grant it.** Default-deny is the only thing that refuses, and it is liftable by anyone who may share | [D6](discretionary/), [H1](household/) |
| run a legal conflict screen / ethical wall | the matter is not inside the firm-wide container and nothing names the screened principal on it. **It survives nobody** — for a screen that must survive a future administrator, `escrow` | [D8](discretionary/) |
| make a rule that no grant, owner or admin can defeat | **you cannot, by policy.** There is no deny mechanism. Encrypt it under a key the deployment does not hold | [UNEXPRESSIBLE.md](UNEXPRESSIBLE.md), [H4](household/) |
| restrict something to a named team | one grant naming the team, on the container it applies to | [D3](discretionary/), [D8](discretionary/) |
| say "everyone except Bob" | a group that does not contain Bob, and a grant naming that group | [D8](discretionary/) |
| keep one household member's records from another | a grant on the episode rather than on the graph. Privacy is grant granularity now, not a label | [H1](household/), [H2](household/) |
| dedup an entity across principals without leaking that it existed | nothing — entity existence is *derived* from the assertions each principal may read | [H2](household/) |
| make something unreadable whatever any future rule says | enforcement class `crypto`, which is `escrow`. `Decide` may still say allow | [H4](household/) |
| give an agent its own identity and audit trail | `DelegateAgentRun`. It inherits no group membership at all | [A1](agents/) |
| stop a pipeline laundering a marking by deriving | declare the derivation; the output carries the union of its inputs' markings | [A3](agents/) |
| keep a model provider away from privileged content | a marking allowlist at the provider port, failing closed with a typed error. It is an egress gate and never a deny | [A3](agents/) |
| say "may read `Person` but not `salary`" | **you cannot**, and this got *harder* — the old answer was "use a classification" | [U1](UNEXPRESSIBLE.md) |
| hide one *column* of a document | **you cannot** | [U4](UNEXPRESSIBLE.md) |
| define a group of resources by a predicate over data | **you can, and should not yet** | [U5](UNEXPRESSIBLE.md) |

## The scenarios

Status is exactly what the corpus can honestly say today. **live** means
every assertion in the scenario runs against the real module, its
expectation table included, answered by `iam.Decide` and diffed against
the reference oracle. **pending** means the scenario still waits on the
named capability for part of what it asserts — usually a claim rather than
a table, and the row below says which. **unexpressible** means the design
cannot express the use case; the scenario demonstrates that with code that
runs.

### Discretionary / sharing — [discretionary/](discretionary/README.md)

| | Scenario | Status |
|---|---|---|
| D1 | Google-Drive-style folder share, inheriting down at one tuple per hop | **live** |
| D2 | Several levels of nested containers, still one tuple | **live** |
| D3 | A workspace with roles, where adding a resource type adds no roles | pending: `NestedGroupMember` — five of six rows run; a *team* holding a role has no form |
| D4 | Grant to a team; a membership change takes effect with no re-grant | **live** |
| D5 | Link sharing: the subject is a capability token's bearer identity | **live** |
| D6 | Ownership transfer carries everything, because grants are all there is to carry | **live** |
| D7 | Bottom-up navigational visibility: the path to it, and only that path | pending: `VisibleBelow` — the table runs; the `visible-set` claim is the scenario |
| D8 | The legal ethical wall is a grant nobody wrote, and that is all it is now | pending: `VisibleBelow` — the table runs; "she cannot navigate to the matter" does not |

### The mandatory tier, and where its six scenarios went

There was a `mandatory/` directory with M1 through M6. It is deleted, and
the honest accounting is short:

| | Scenario | Where it went |
|---|---|---|
| M1 | The legal ethical wall: a firm-wide grant cannot defeat a conflict screen | → **D8**, as a grant nobody wrote. Weaker, and the weakness is stated |
| M2 | Need-to-know, the positive form: restrict a matter to a named team | → **D8**. "Written positively" is now the only way to write it |
| M3 | "Everyone except Bob", as a clearance group that does not contain Bob | → **D8**. A group that does not contain Bob is an ordinary group |
| M4 | A new joiner holds no clearances and sees nothing classified | **gone, and true by construction.** A new joiner holds no grants, which is the registry's fail-closed JIT rule and is tested in `iamtest` |
| M5 | A project admin, an owner and a group admin each attempt the gate; all fail | **gone with the gate.** The invariant it protected — no discretionary operation opens a mandatory gate — has no gate to protect |
| M6 | A pipeline cannot launder a classification by deriving | → **A3**, as a marking. Derivation still propagates the union; it gates egress rather than access |

### The household — [household/](household/README.md)

| | Scenario | Status |
|---|---|---|
| H1 | Pascal's personal invoice stays his because nobody granted it to her | **live** |
| H2 | She uploads an invoice from the same supplier and learns nothing about his | **live** |
| H3 | The daughter's school document yields an entity both parents can read | **live** |
| H4 | The will: `Decide` returns allow and the content is still unreadable | pending: `MarkingStore` — the allow is live; nothing stores the marking that makes it unreadable |

### Agents — [agents/](agents/README.md)

| | Scenario | Status |
|---|---|---|
| A1 | A user delegates to an agent run; the run is its own principal; deprovisioning cascades | **live** |
| A2 | The researcher: world-layer write, and no read permission on any private fact | **live** |
| A3 | Marking-aware model access: a provider not allowlisted for `privileged` never receives it | pending: `MarkingStore` — the table runs; the allowlist and leak channel #15 are the corpus's own |

### What the design cannot express — [UNEXPRESSIBLE.md](UNEXPRESSIBLE.md)

| | Scenario | Finding |
|---|---|---|
| U1 | "May read `Person` entities but not `salary` facts" cannot be written at all | §17 F7 + F4 — and **strictly harder than it was**: its cheap resolution was "use a classification" |
| U4 | An attribute-scoped restriction cannot be enforced by a row predicate, whatever tier it is written in | §17 F4 — **redirected**: the classification framing is moot, the `WHERE`-hides-rows problem is not |
| U5 | A predicate-defined entity-set makes authorization a function of data a later write changes | §17 F7, whose second dimension is now **closed by withdrawal** — the mechanism is gone from the consumer's spec. The entry stays, because the hazard belongs to any predicate-defined grouping and will be asked for again |
| ~~U3~~ | ~~Containment is a DAG once entity-sets exist, so "only the direct path" names nothing~~ | **resolved by withdrawal, 2026-10-24** — kgs was respecified onto a containment tree, so §17 F3 closed by its own first branch. Not solved: the requirement went. Its *scenario* is still in `unexpressible/` and UNEXPRESSIBLE.md says why |
| ~~U2~~ | ~~"Use a classification" turns "don't show her the salary" into an absolute nobody can lift~~ | **resolved by removal** — there is no classification to answer with. It is also *why* the mechanism went |
| ~~U6~~ | ~~Nothing checks whether the actor on a mandatory act may classify at all~~ | **resolved by removal** — there are no mandatory acts. §17 F9 closed, §16 Q2 moot |

## What actually runs today

Worth being precise, because the honest answer is narrower than the number
of green tests suggests.

**Running against the real `iam`, and passing:** every fixture's identity
layer, in all eighteen scenarios. JIT provisioning and its idempotence;
claim-derived group upsert, including the reconciliation that makes a
shrinking claim set remove memberships; locally-added membership surviving
that reconciliation; agent-run delegation as a first-class principal
inheriting no group membership; the deprovision cascade from a user to its
runs; and immediate, unconditional denial for a deprovisioned principal.
A1 is entirely this. D4, H1, H2, H4 and A2 each carry live claims that are
the identity half of their point.

**And now the grant layer too, in fifteen of the eighteen.** A fixture's
objects become real containers in a real containment tree, its tuples
become real grants to real principals and real groups, and every reachable
row of its expectation table is answered by `iam.Decide` as well as by the
corpus's reference procedure — and the two are diffed on the verdict, the
reason and which grant was responsible. Three fixtures do not reach the
module and the refusals are typed and printed: D3 has a set whose member
is a set, U3 has a fact with three containment paths, U5 has a containment
edge that is a predicate over data. The other fifteen all agreed with the
oracle on every row, first run, which is the strongest statement this
corpus has ever been able to make.

Two things that differential found are worth knowing even though no row
exposes them. `iam.ContainerKind` cannot declare a kind nested inside
itself, so a `folder` inside a `folder` with a `folder` at the root — D2
and D7, an ordinary Drive hierarchy — has no declaration; the translation
synthesizes a container kind per containment depth to get round it. And
`iam` inherits *every* permission down the whole container tree, where
§8.2's form 3 is declared per relation, so this corpus's `owner` is
declared not to reach the documents inside a folder and `iam` would let it.
No expectation row asks a non-inheriting permission about a nested object,
so nothing distinguishes the two today; `scenario/realapi.go` fails the row
that first does rather than leaving it to be discovered.

**Still the corpus's own, not `iam`'s:** every structural claim. Markings
and their enforcement class are not stored by this module at all, so
`crypto-unreadable`, `provider-refused` and `marking-set` are computed
over fixture data — which is why H4 and A3 are still pending. There is no
bottom-up navigational visibility, so `visible-set` is too, which is why
D7 and D8 are. Entity existence is derived by the corpus from the
assertions each principal may read, and that one is deliberate: KGS §7.3
derives it rather than storing it, and the derivation is a consumer's.

**Demonstrated as broken:** the four scenarios in `unexpressible/`, each by
a claim that runs. UNEXPRESSIBLE.md's main list is three of them: U3's
requirement was withdrawn on 2026-10-24 and its entry moved, while its
scenario stays and its claims still pass, because `DirectPath` does still
refuse the DAG the fixture declares. The mismatch is deliberate and
UNEXPRESSIBLE.md names the follow-up that ends it.

**Not covered, and not coverable here:** that a screen stays shut. D8
asserts that the matter has one containment path and that the screened
associate navigates to nothing, which catches a *structural* change to the
fixture. It cannot catch the thing that now opens a conflict screen, which
is somebody with sharing rights writing one more tuple. Nothing in this
module can catch that, which is the honest content of the no-deny
decision.

## Adding a scenario

Put it in the group package it belongs to, as a function returning a
`scenario.Scenario`, and add it to that package's `Scenarios()`. Then:

Write the prose header first. If you cannot say in one paragraph what real
situation it models and which design section governs it, the scenario is
probably two scenarios.

Name the reason in every expectation row. `Because` is compared exactly
against the tuple or label responsible, so a scenario cannot drift into
passing through a different grant than the one it documents.

Set the status honestly. **live** means every assertion in the scenario
runs against the real module — the table included, which is why a live
scenario keeps its table rather than losing it: the table is what the two
evaluators are diffed against each other on. `Validate` refuses a live
scenario that is pending on anything, and the harness fails a live
scenario whose fixture does not reach the real authorization layer, so the
label cannot be claimed without being earned. A scenario claiming the
design cannot do something must mark at least one row `Unreachable` and
carry a claim that demonstrates the gap; `Validate` refuses one that does
not, because a requirement declared impossible with nothing executable
behind it is prose.

If your scenario waits on something, make `PendingOn` name the thing it
actually waits on, and make sure a capability constant exists with a
tripwire needle that can detect the arrival. A capability nothing can ever
detect is worse than no constant, because it reads like a mechanism.

Do not reach for a deny. There is no `Reason` value for one, and if your
scenario needs a resource withheld from a principal the grants reach, the
answer is either that the fixture's grants are wrong or that the content
belongs under a `crypto` marking. If it is genuinely neither, that is a
design conversation and UNEXPRESSIBLE.md is where it goes.

Then regenerate the ledger: `go test ./examples/... -run TestLedger
-update-ledger`.
