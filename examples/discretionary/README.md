# Discretionary sharing

The everyday layer: the one people click. Somebody shares a folder, adds a
colleague to a team, sends a link, hands a project over. Design §7 calls it
the discretionary tier and the tier table says it "survives nothing in
particular" — it is shareable and revocable, and that is the whole point of
it. Everything here is governed by design §8.2, which permits exactly four
composition forms, and §8.5, which explains why four.

**It is also now the only policy layer there is.** This file used to say
"nothing in this directory can keep anybody out — if you are looking for
'this person must never see this', you want ../mandatory". That directory
is deleted. There is no deny mechanism, so what keeps people out is
default-deny: a resource nobody granted is a resource nobody reaches.

Two consequences for a reader arriving with a requirement:

- A restriction is a grant you do not write. That is liftable by anybody
  who may share, which for a private letter is correct and for a legal
  ethical wall is weaker than the design used to claim. **D8** is the wall,
  it lives in this directory now, and it says so.
- An absolute that must survive a future administrator is a key the
  deployment does not hold — `escrow`, and [H4](../household/) is what it
  looks like. Reaching for an exclusion operator here still gets your
  schema rejected, and the refusal now names `escrow` rather than a
  classification mechanism, because there is no classification mechanism to
  name.

## The four forms, and what each is for

These are all of them. A requirement that needs a fifth is a design
conversation, not a configuration change, and
[../UNEXPRESSIBLE.md](../UNEXPRESSIBLE.md) has the ones we have found.

**Direct** — a tuple naming a principal.

```
document:lunch-menu#viewer@user:anne
```

**Userset** — a tuple naming a *set* of principals. Teams, roles and groups
all work through this one mechanism; none of them needs a special case,
because resolving a userset is the same question one level down: does this
principal hold that relation on that object?

```
folder:eng-docs#viewer@team:eng#member
workspace:atlas#viewer@role:ws-reader#assignee
```

**Tuple-to-userset inheritance** — `viewer from parent`, declared on the
relation. One tuple on a container reaches every descendant, including the
ones added tomorrow.

```
folder:project-apollo#viewer@user:ben     ← the only tuple written
  folder:project-apollo contains document:brief, document:budget, …
  → ben may read all of them, through containment
```

**Union** — this relation holds if another relation on the same object
does. It is how `owner` confers `editor` and `editor` confers `viewer`
without three tuples per person.

## The shapes

**A folder share** (D1) is one tuple on the container plus
`InheritFromParent: ["viewer"]` on the contained kind. The number the
scenario asserts is that two tuples reach five objects; the implementation
that writes one row per object is the cross product design §9.2 forbids,
and anti-goal A2's closure budget exists to catch it.

**Nesting** (D2) needs nothing extra. A grant at the root of a four-level
hierarchy reaches the leaves, and a grant in the middle reaches down and
not up — nor sideways into a sibling.

**Roles** (D3) are objects, not a cross product. A role is parented to a
container and carries `assignee` and `ownership`:

```
role:ws-reader#assignee@user:frank          ← a role assignment
role:ws-reader#assignee@team:eng#member     ← a whole team can hold one
workspace:atlas#viewer@role:ws-reader#assignee   ← what the role means
```

The scenario's point is in two rows of its table that have the *same*
reason: a reader role reaches both `document:onboarding` and
`report:q3-usage`. `report` was added to the schema and no role was
touched. This is Lakekeeper's model and it is the answer to "roles and
teams without exponential complexity".

**A grant to a team** (D4) names the team and not its members, which is why
adding somebody is one membership row and rewrites no grant. That half runs
live against the real registry today: the scenario adds a new joiner
through `AddGroupMember` and asserts both that the membership the predicate
joins against changed and that the grant count did not.

**A share link** (D5) is a tuple whose subject is the capability token's
bearer identity. `captoken` mints and constrains it; this module stores the
relationship and does not interpret caveats. Note where the tuple goes — on
the document, not the folder — because the shape of the share is the shape
of the tuple, and inheritance goes down.

**An ownership transfer** (D6) is a tuple write, so it carries everything,
because grants are all there is to carry. That used to be half the story:
the folder also carried a classification, and the new owner of a classified
folder was an owner who could not read it — correct, and initially
surprising.

The document the previous owner keeps is now kept by being outside the
container he handed over, and the scenario asserts that with a
`path-count` claim rather than describing it. One added containment edge
from the transferred folder would move it, which is why the structural
fact is a claim and not a comment.

**Navigational visibility** (D7) is the one that is easy to get wrong. Eva
may read one document four levels down; she has to be able to find it, and
she must not learn that the folder beside it exists. The answer is bottom-up
inheritance as an explicit relation, and the scenario compares the visible
set element by element: the document and the three folders above it,
nothing else. Navigating to an ancestor is not reading it, and it is not
reading the ancestor's other children.

**Read D7 and then read [U3](../UNEXPRESSIBLE.md).** D7's claim passes
because its containment is a tree. Add one kgs entity-set as a second
container and `DirectPath` has nothing to return. "Only the direct path" is
exact in a tree and undefined in a DAG, and kgs needs the DAG. That
question matters more than it did: D8 uses `visible-set` as part of how a
screen is asserted, so what `visible_below` means in a DAG is no longer
only about finding things.

**The legal ethical wall** (D8) is the old M5, which the design called "the
feature the whole module exists for". It is in this directory because it
has no mechanism of its own any more:

```
folder:firm-wide#viewer@team:all-timekeepers#member   ← generous, and real
folder:matter-1234#owner@team:matter-1234#member      ← the matter's own grant

folder:matter-1234 is NOT contained by folder:firm-wide   ← half the screen
nothing names user:eve on folder:matter-1234              ← the other half
```

Both halves are absences, and the scenario asserts both: a `path-count`
claim on the matter document, so an added containment edge fails a test
rather than opening a wall, and a `visible-set` claim on the screened
associate, so she cannot even learn the matter exists.

What it does not assert, and cannot, is that the screen stays shut. Any
principal who may share the matter can share it tomorrow. A screen that
must survive a future administrator, an operator or a subpoena is content
under a key the deployment does not hold, and the scenario's prose says
that rather than leaving a reader to infer it.

## Status

All eight are **pending** on the decision API: their expectation tables are
evaluated by the corpus's reference procedure, which pins what `Decide`
must answer without being evidence that it does. Their fixtures' identity
layers and all their structural claims run live.
