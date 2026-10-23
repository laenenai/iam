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

**It inherits nothing.** Not one group membership. A delegation grants
nothing, so every grant that reaches a run has to be written for it, which
is what makes per-run attribution true rather than nominal. The registry
also refuses a run delegating a further run, because a chain of ephemeral
principals has no attributable owner and `captoken` owns delegation depth.

A1 used to carry two more claims: that the run inherited none of its
parent's clearances, and that no discretionary operation could give it one.
They went with the mandatory tier, and what they protected needs no
protecting now — with grants the only mechanism, "it holds no group
membership" carries the whole of "a delegation confers nothing".

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

A2's table used to have **two denials with deliberately different
reasons**, and that was the content of the scenario:

```
service:researcher read fact:acme-invoice-total  → deny (classification: personal:pascal)
service:researcher read fact:grocery-total       → deny (no-grant)
```

The note on the second row said it was the one that mattered: that fact was
private but *unclassified*, so the mandatory gate had nothing to say about
it, and "no read permission on any private fact" is a property of the
grants and not of the labels — a researcher whose denial depended on
classification would read every household fact nobody thought to mark.

That note is now the whole scenario. Both rows read `deny (no-grant)`, the
contrast is gone, and nothing was weakened by losing it: the stronger of
the two reasons was always the one that survived. **A2 is the scenario the
no-deny decision improves**, and it is worth having one of those written
down next to the ones it costs.

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

The gate reads the **resolved** marking set, not the content's own
assignments, and that is leak channel #15: a consolidator that saw
privileged evidence and emitted an observation must not have laundered the
marking on the way out. So the derived observation is refused too, because
its marking set is the union over its derivation's inputs.

**This is the one place in the corpus a label still runs, and it is worth
being precise about which work it does.** A marking is a *flow* label: it
propagates through derivation as the union of its inputs, it gates egress
at the provider port, and it decides nothing about any principal's access.
That is the same answer `kgs` reached independently when it moved "what may
a hosted model be shown?" out of authorization entirely and down to egress
eligibility at its `LLMProvider` and `EmbeddingProvider` ports. It is why
the allowlist survived the removal of the deny mechanism intact while the
household's classifications did not: this was never a deny on a principal.

**And it is the one place in the corpus where a leak channel got worse.**
A3's fixture used to clear the extractor service through a *mandatory act*
rather than a configuration flag, on the grounds that a pipeline which may
see privileged content is a security decision. Sending content to a hosted
model was therefore guarded twice: the allowlist decided what the provider
could receive, and the mandatory gate decided what the pipeline principal
could read in the first place, so a context assembled from facts the
extractor could not read was impossible for two independent reasons.

One of those is gone. The extractor is in the matter team because somebody
shared the matter with it, which is an ordinary sharing decision, and the
allowlist is now the only thing between privileged content and a
third-party provider. A pipeline principal over-granted by a sharing
mistake reaches content that only the allowlist then stops leaving. `kgs`
recorded the same finding on its own side, and the scenario's last claim
says so rather than leaving the arithmetic to a reader.

## Status

**A1 is live.** A2 and A3 are pending on `Decide` and the tuple store;
their tables are pinned against the corpus's reference procedure, and their
provider-gate and marking-set claims run today.
