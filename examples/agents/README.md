# Agents, services and models

Three non-human principals, three different problems.

## An agent run is a principal

Design §8.1 is explicit that an agent run is "a first-class principal, not
a flag on its parent", because audit and metering must attribute per run,
and KGS §9.5 depends on being able to ask *which agent run, acting for
which user, under which grant, read this privileged fact*.

```
reg.DelegateAgentRun(ctx, parent.ID, iam.AgentRunSpec{TTL: time.Hour, DisplayName: "ingest"})
  → a principal with its own id, kind agent-run, DelegatedBy: parent, ExpiresAt: now+TTL
```

Two consequences, and **A1 is the one scenario in this whole corpus that
runs entirely live** — every assertion in it is against the real registry
today.

**It inherits nothing.** No group membership and no clearance. A delegation
is a discretionary act, and a discretionary act that conferred a clearance
would be anti-goal A3 breached by construction. The scenario's parent holds
`clearance:personal-pascal` and the run holds nothing. The registry also
refuses a run delegating a further run, because a chain of ephemeral
principals has no attributable owner and `captoken` owns delegation depth.

**Deprovisioning cascades, immediately.** The scenario deprovisions a user
who has a live run, and asserts that *both* report deprovisioned and that
every membership read on either returns `ErrPrincipalDeprovisioned` rather
than a list. Not at the next sync, not when the token expires, and no
re-sync clears it — so there is no window in which an orphaned run outlives
the identity that authorized it.

The TTL is garbage collection and never an access control: an expired run
is unusable from its deadline, so a collector that never runs wastes rows
and grants nothing.

## A service principal with write and no read

The kgs researcher enriches a shared gazetteer of public referents so that
entity resolution reads pre-populated data rather than investigating at
merge time. That distinction is leak channel #10: if the researcher only
ran when there was a potential collision, then the researcher having run
would itself reveal a collision.

Its whole grant is one tuple:

```
graph:world#writer@service:researcher
```

A2's table has **two denials with deliberately different reasons**, and
that is the content of the scenario:

```
service:researcher read fact:acme-invoice-total  → deny (classification: personal:pascal)
service:researcher read fact:grocery-total       → deny (no-grant)
```

The second is the one that matters. That fact is private but *unclassified*,
so the mandatory gate has nothing to say about it, and the researcher is
denied because no tuple reaches it. "No read permission on any private
fact" is a property of the grants, not of the labels — a researcher whose
denial depended on classification would read every household fact nobody
thought to mark.

The scenario's third denial is the household reading the world layer, which
it has no grant on: a referent's `updated_at` reveals that somebody looked
it up, so KGS §11.4 makes freshness metadata operator-only.

## A model provider is a trust boundary

During ingest kgs sends content to a language model. KGS §9.5 takes
Palantir's AIP marking allowlists for this: a provider profile declares
which markings it may receive, a provider not allowlisted for `privileged`
never receives privileged content, and the pipeline **fails closed with a
typed error** rather than degrading — because a redaction that is wrong
once is a disclosure.

```
MayReceive(fact:advice-content, allowlisted: [])            → ErrMarkingNotAllowlisted
MayReceive(fact:advice-content, allowlisted: [privileged])  → ok   (the pinned self-hosted model)
MayReceive(fact:filing-date,    allowlisted: [])            → ok   (carries no marking)
```

The gate reads the **resolved** label set, not the content's own
assignments, and that is leak channel #15: a consolidator that saw
privileged evidence and emitted an observation must not have laundered the
marking on the way out. So the derived observation is refused too, because
its label set is the union over its derivation's inputs.

Note also that A3's fixture clears the extractor service through a
*mandatory act* rather than a configuration flag. A pipeline that may see
privileged content is a security decision, and the design gives that kind
of decision exactly one channel.

## Status

**A1 is live.** A2 and A3 are pending on `Decide`; their tables are pinned
against the corpus's reference procedure, and their provider-gate and
label-set claims run today.
