// Package agents holds the corpus's use cases for non-human principals:
// an agent run delegated from a user, the world-layer researcher that may
// write public data and read no private fact, and the marking-aware gate
// that decides what a language-model provider is allowed to see.
//
// Design §8.1 makes an agent run a first-class principal rather than a
// flag on its parent, "so audit and metering attribute per run", and KGS
// §9.5 depends on it. The first scenario here is the one that runs
// entirely live today: delegation, non-inheritance, and the deprovision
// cascade are all identity-registry behaviour, and they are the part of
// this corpus that is evidence about `iam` rather than about the corpus's
// own oracle.
//
// The third scenario is the one place in the corpus where a label still
// does work, and it is worth being precise about which work. A marking
// allowlist is an *egress* constraint a consumer's pipeline applies to a
// provider: it decides what content may leave for a third party, and it
// refuses no principal anything. That is why it survived the removal of
// the deny mechanism unchanged while the household's classifications did
// not — what was removed was a policy deny on a principal's access, which
// this never was.
//
// See README.md in this directory.
package agents

import (
	"github.com/laenenai/iam"
	"github.com/laenenai/iam/examples/scenario"
)

// agentKinds is a kgs-shaped schema plus the world layer: a shared
// gazetteer of referents the researcher may write, and tenant-private
// facts it may not read.
func agentKinds() []scenario.ResourceKind {
	return []scenario.ResourceKind{
		{
			Name:      "group",
			Relations: []scenario.Relation{{Name: "member", Direct: true}},
			Actions:   map[string]string{"read": "member"},
		},
		{
			Name: "graph", Shape: scenario.ShapeRow,
			Relations: []scenario.Relation{
				{Name: "owner", Direct: true, Usersets: []string{"group#member"}},
				{Name: "writer", Direct: true, Usersets: []string{"group#member"}},
				{Name: "viewer", Direct: true, Usersets: []string{"group#member"}, Union: []string{"owner"}},
			},
			Actions: map[string]string{"read": "viewer", "write": "writer"},
		},
		{
			Name: "referent", Shape: scenario.ShapeRow,
			Relations: []scenario.Relation{
				{Name: "writer", Direct: true, Usersets: []string{"group#member"}, InheritFromParent: []string{"writer"}},
				{Name: "viewer", Direct: true, Usersets: []string{"group#member"}, InheritFromParent: []string{"viewer"}, Union: []string{"writer"}},
			},
			Actions: map[string]string{"read": "viewer", "write": "writer"},
		},
		{
			Name: "episode", Shape: scenario.ShapeRow,
			Relations: []scenario.Relation{
				{Name: "viewer", Direct: true, Usersets: []string{"group#member"}, InheritFromParent: []string{"viewer"}},
			},
			Actions: map[string]string{"read": "viewer"},
		},
		{
			Name: "fact", Shape: scenario.ShapeRow,
			Relations: []scenario.Relation{
				{Name: "viewer", Direct: true, Usersets: []string{"group#member"}, InheritFromParent: []string{"viewer"}},
			},
			Actions: map[string]string{"read": "viewer"},
		},
		{
			Name: "observation", Shape: scenario.ShapeRow,
			Relations: []scenario.Relation{
				{Name: "viewer", Direct: true, Usersets: []string{"group#member"}, InheritFromParent: []string{"viewer"}},
			},
			Actions: map[string]string{"read": "viewer"},
		},
	}
}

// Scenarios returns the agent use cases.
func Scenarios() []scenario.Scenario {
	return []scenario.Scenario{
		delegationAndCascade(),
		theResearcher(),
		markingAwareModelAccess(),
	}
}

func delegationAndCascade() scenario.Scenario {
	return scenario.Scenario{
		ID:    "A1",
		Title: "A user delegates to an agent run; the run is its own principal; deprovisioning cascades",
		Models: `A user starts a long-running agent job. Design §8.1 makes that run an
			ephemeral principal with its own internal id, created by delegation,
			garbage-collected on a policy TTL — and emphatically not a flag on its
			parent, because audit and metering must attribute per run and KGS §9.5
			depends on being able to ask "which agent run, acting for which user,
			under which grant, read this privileged fact". Two consequences are
			tested here. The run inherits nothing: not one group membership, so
			every grant that reaches it has to be written for it, which is what
			makes per-run attribution true rather than nominal. And when the user
			is deprovisioned, the run dies with them immediately, through the deny
			epoch rather than at the next refresh.

			There were two more claims on this scenario, asserting that the run
			inherited none of its parent's clearances and that no discretionary
			operation could give it one. They went with the mandatory tier, and
			what they protected needs no protecting now: a principal holds exactly
			what has been granted to it, and a delegation grants nothing.

			This scenario is entirely live. It carries no expectation table because
			everything it asserts runs against the real registry today.`,
		Governs: []string{"§8.1 agent runs", "§8.1 deprovisioning", "§9.3 deny epoch", "KGS §9.5"},
		Status:  scenario.StatusLive,
		Fixture: scenario.Fixture{
			Tenant: "household",
			Kinds:  agentKinds(),
			Principals: []scenario.PrincipalSpec{
				{
					Name: "user:pascal", Kind: iam.PrincipalKindUser,
					ClaimGroups: []string{"group:household"},
					Role:        "delegates a long ingest job and stays provisioned",
				},
				{
					Name: "agent-run:ingest-7f3a", Kind: iam.PrincipalKindAgentRun,
					DelegatedBy: "user:pascal",
					Role:        "his run. Its own principal, with its own id, inheriting nothing",
				},
				{
					Name: "user:quentin", Kind: iam.PrincipalKindUser,
					ClaimGroups: []string{"group:household"},
					Role:        "leaves the household part-way through his own long job",
					// Deprovisioned last by Materialize, after his run
					// exists, so the cascade has something to cascade to.
					Deprovisioned: true,
				},
				{
					Name: "agent-run:ingest-9c21", Kind: iam.PrincipalKindAgentRun,
					DelegatedBy: "user:quentin",
					Role:        "his run, which must stop being usable the instant he is deprovisioned",
				},
			},
			Groups: []scenario.GroupSpec{
				{Name: "group:household", Members: []string{"user:pascal", "user:quentin"}},
			},
		},
		Claims: []scenario.Claim{
			scenario.C(scenario.ClaimLiveGroups, "agent-run:ingest-7f3a", "",
				"the run inherits none of its parent's group membership. It is a principal, not a "+
					"view of one, so a grant to the household does not reach the run — and with "+
					"grants the only mechanism there is, that one fact now carries the whole of "+
					"`a delegation confers nothing`"),
			scenario.C(scenario.ClaimLiveGroups, "user:pascal", "group:household",
				"while the parent's own membership is unaffected by having delegated"),
			scenario.C(scenario.ClaimPrincipalUnusable, "user:quentin", "deprovisioned",
				"deprovisioning denies immediately and unconditionally: not at the next sync, not when "+
					"the token expires, and no re-sync clears it"),
			scenario.C(scenario.ClaimPrincipalUnusable, "agent-run:ingest-9c21", "deprovisioned",
				"the cascade. His run reports deprovisioned too, in the same write, so there is no "+
					"window in which an orphaned run outlives the identity that authorized it"),
		},
	}
}

func theResearcher() scenario.Scenario {
	return scenario.Scenario{
		ID:    "A2",
		Title: "The researcher: world-layer write, and no read permission on any private fact",
		Models: `kgs's researcher enriches a shared gazetteer of public referents —
			company registers, places, public figures — so that entity resolution
			reads pre-populated data rather than investigating at merge time. That
			distinction is leak channel #10: if the researcher only ran when there
			was a potential collision, then the researcher having run would itself
			reveal a collision. KGS §10.5 states its permissions in one sentence:
			"it holds no read permission on private facts; it receives a normalized
			identifier and returns public data." This scenario is that sentence as
			a table.

			It used to make its point through a contrast: two denials with
			deliberately different reasons, one classified fact refused by the
			mandatory gate and one ordinary private fact refused because no tuple
			reached it, with a note saying that the second was the row that
			mattered most — because "no read permission on any private fact" is a
			property of the grants and not of the labels, and a researcher whose
			denial depended on classification would read every household fact
			nobody thought to mark.

			That note is now the whole scenario. Both denials are no-grant, the
			contrast is gone, and nothing was weakened by losing it: the stronger
			of the two reasons was always the one that survived. This is the
			scenario the no-deny decision improves rather than costs, and it is
			worth having one of those written down.`,
		Governs: []string{"KGS §10.5", "KGS §11.4", "KGS §8.5 #10", "§8.1 service principals"},
		Status:  scenario.StatusLive,
		Fixture: scenario.Fixture{
			Tenant: "household",
			Kinds:  agentKinds(),
			Principals: []scenario.PrincipalSpec{
				{
					Name: "service:researcher", Kind: iam.PrincipalKindService,
					Role: "the world-layer builder. Writes referents, reads no tenant fact",
				},
				{
					Name: "user:pascal", Kind: iam.PrincipalKindUser,
					ClaimGroups: []string{"group:household"},
					Role:        "owns the household graph",
				},
			},
			Groups: []scenario.GroupSpec{
				{Name: "group:household", Members: []string{"user:pascal"}},
			},
			Containment: []scenario.Edge{
				scenario.E("referent:acme-bv", "graph:world"),
				scenario.E("referent:sint-jozef", "graph:world"),
				scenario.E("episode:invoice-acme", "graph:household"),
				scenario.E("fact:acme-invoice-total", "episode:invoice-acme"),
				scenario.E("episode:grocery-receipt", "graph:household"),
				scenario.E("fact:grocery-total", "episode:grocery-receipt"),
			},
			Tuples: []scenario.Tuple{
				{
					Object: scenario.R("graph:world"), Relation: "writer",
					Subject: scenario.P("service:researcher"),
					Note: "its entire grant: write on the world layer. Not read on anything private, " +
						"and nothing on graph:household at all",
				},
				{
					Object: scenario.R("graph:household"), Relation: "viewer",
					Subject: scenario.US("group:household", "member"),
					Note: "the household's own grant, which does not name the researcher. Note that " +
						"this one is still graph-wide: there is nothing private inside it in this " +
						"fixture, so H1's per-episode shape is not needed here",
				},
			},
		},
		Expect: []scenario.Expectation{
			{
				Principal: "service:researcher", Action: "write", Resource: scenario.R("referent:acme-bv"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "graph:world#writer@service:researcher",
				Note:    "it enriches the shared gazetteer, which is the job",
			},
			{
				Principal: "service:researcher", Action: "read", Resource: scenario.R("referent:acme-bv"),
				Want: scenario.Allow, Reason: scenario.ReasonUnion,
				Because: "graph:world#writer@service:researcher",
				Note: "and reads back what it wrote. The reason is a union and not an inheritance, which " +
					"is worth pinning: `read` resolved through referent#viewer's union with writer, and " +
					"only then up the containment path. A consumer told `inherited` would go looking " +
					"for a viewer grant that does not exist",
			},
			{
				Principal: "service:researcher", Action: "read", Resource: scenario.R("fact:acme-invoice-total"),
				Want: scenario.Deny, Reason: scenario.ReasonNoGrant,
				Note: "the household fact that used to be classified. It is refused for the reason " +
					"the next row was always refused for, which is the stronger of the two",
			},
			{
				Principal: "service:researcher", Action: "read", Resource: scenario.R("fact:grocery-total"),
				Want: scenario.Deny, Reason: scenario.ReasonNoGrant,
				Note: "and the fact nobody ever thought to mark is refused identically. That the two " +
					"rows are now indistinguishable is the point: the researcher's isolation is a " +
					"property of which grants exist, so there is no set of unmarked facts it can " +
					"reach by somebody having forgotten something",
			},
			{
				Principal: "user:pascal", Action: "read", Resource: scenario.R("referent:acme-bv"),
				Want: scenario.Deny, Reason: scenario.ReasonNoGrant,
				Note: "and the household has no read grant on the world layer in this fixture, so the " +
					"gazetteer's freshness metadata is unreachable from a tenant — KGS §11.4's " +
					"`operator-only`, since a referent's updated_at reveals that somebody looked it up",
			},
		},
		Claims: []scenario.Claim{
			scenario.C(scenario.ClaimSchemaAccepted, "referent", "", ""),
			scenario.C(scenario.ClaimLiveGroups, "service:researcher", "",
				"against the real registry: the researcher is in no group, so no grant written to a "+
					"group reaches it. A service principal is not a privileged principal; it is a "+
					"principal with a different kind"),
			scenario.C(scenario.ClaimMarkingSet, "fact:acme-invoice-total", "",
				"and nothing in this fixture is marked at all, which is the whole of what changed: "+
					"the researcher's isolation never needed a label"),
			scenario.C(scenario.ClaimTuplesPerHop, "2", "8",
				"two tuples, two graphs, eight objects — and the researcher's reach is two of the eight"),
		},
	}
}

func markingAwareModelAccess() scenario.Scenario {
	return scenario.Scenario{
		ID:    "A3",
		Title: "Marking-aware model access: a provider not allowlisted for `privileged` never receives it",
		Models: `During ingest kgs sends content to a language model, and that model's
			provider is a trust boundary. KGS §9.5 takes Palantir's AIP marking
			allowlists for this: a provider profile declares which markings it may
			receive, a provider not allowlisted for privileged never receives
			privileged content, and the pipeline fails closed with a typed error
			rather than degrading. The second half is leak channel #15, and it is
			why the gate reads the *resolved* marking set rather than the content's
			own assignments: a consolidator that saw privileged evidence and
			emitted an observation must not have laundered the marking on the way
			out, which the union over a derivation's inputs is what stops.

			This is the one scenario in the corpus a label still runs, and the
			removal of the deny mechanism changed what kind of label it is rather
			than whether it works. A marking is a *flow* label: it propagates
			through derivation as the union of its inputs, it gates egress at the
			provider port, and it decides nothing about any principal's access.
			That is the same answer kgs reached independently, and it is why the
			allowlist survived intact while the household's classifications did
			not — this was never a deny on a principal.

			The honest cost is in the last claim, and it is a real regression
			rather than a neutral change. Sending content to a hosted model used to
			be guarded twice: the marking allowlist decided what the provider could
			receive, *and* the mandatory gate decided what the pipeline principal
			could read in the first place, so a context assembled from facts the
			extractor could not read was impossible for two independent reasons.
			One of those is gone. The allowlist is now the only thing between
			privileged content and a third-party provider, so a pipeline principal
			over-granted by an ordinary sharing mistake reaches content that only
			the allowlist then stops leaving. kgs recorded the same finding on its
			own side: this leak channel is worse, not merely unchanged.`,
		Governs:   []string{"KGS §9.5", "KGS §8.5 #15", "§7.3 typed refusal", "markings as flow labels"},
		Status:    scenario.StatusPending,
		PendingOn: []scenario.Capability{scenario.CapMarkingStore},
		Fixture: scenario.Fixture{
			Tenant: "lawfirm",
			Kinds:  agentKinds(),
			Principals: []scenario.PrincipalSpec{
				{
					Name: "service:extractor", Kind: iam.PrincipalKindService,
					ClaimGroups: []string{"group:matter-team"},
					Role:        "the ingest pipeline. Granted the matter it is processing, and nothing else",
				},
				{
					Name: "user:anne", Kind: iam.PrincipalKindUser,
					ClaimGroups: []string{"group:matter-team"},
					Role:        "the associate on the matter",
				},
				{
					Name: "user:dave", Kind: iam.PrincipalKindUser,
					Role: "a timekeeper who is not on the matter team",
				},
			},
			Groups: []scenario.GroupSpec{
				{
					Name: "group:matter-team", Members: []string{"service:extractor", "user:anne"},
					Note: "the matter team, pipeline included. That the self-hosted pipeline is in it " +
						"is a sharing decision now rather than a mandatory act, which is exactly the " +
						"regression this scenario's last claim records",
				},
			},
			Containment: []scenario.Edge{
				scenario.E("episode:matter-advice", "graph:lawfirm"),
				scenario.E("fact:advice-content", "episode:matter-advice"),
				scenario.E("episode:public-filing", "graph:lawfirm"),
				scenario.E("fact:filing-date", "episode:public-filing"),
				scenario.E("observation:billing-pattern", "graph:lawfirm"),
			},
			Markings: []scenario.Marking{
				{
					Label: "privileged", Enforcement: scenario.EnforcementNone,
					Why: "legal professional privilege, as a flow label. It enforces nothing by " +
						"itself: it propagates through derivation and gates egress at the provider " +
						"port, and it refuses no principal anything. It used to be a policy-enforced " +
						"classification and therefore also a deny, which is the half that went",
				},
			},
			Assignments: []scenario.Assignment{scenario.AS("episode:matter-advice", "privileged")},
			Derivations: []scenario.Derivation{
				{
					Output: scenario.R("observation:billing-pattern"),
					Inputs: []scenario.Ref{scenario.R("fact:advice-content"), scenario.R("fact:filing-date")},
					Note: "the consolidator's output. One privileged input, so the observation is " +
						"privileged — leak channel #15",
				},
			},
			Tuples: []scenario.Tuple{
				{
					Object: scenario.R("episode:matter-advice"), Relation: "viewer",
					Subject: scenario.US("group:matter-team", "member"),
					Note:    "the matter's grant, written on the episode",
				},
				{
					Object: scenario.R("observation:billing-pattern"), Relation: "viewer",
					Subject: scenario.US("group:matter-team", "member"),
					Note: "and the derived observation's own grant. The marking propagates by " +
						"derivation; the grant does not, which is why a derived object needs one " +
						"written for it",
				},
			},
		},
		Expect: []scenario.Expectation{
			{
				Principal: "service:extractor", Action: "read", Resource: scenario.R("fact:advice-content"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "episode:matter-advice#viewer@group:matter-team#member",
				Note: "the pipeline may read it, because somebody shared the matter with it. Whether " +
					"it may *send* it to a given provider is the separate question the claims answer, " +
					"and it is now the only question of the two",
			},
			{
				Principal: "user:dave", Action: "read", Resource: scenario.R("observation:billing-pattern"),
				Want: scenario.Deny, Reason: scenario.ReasonNoGrant,
				Note: "he is not on the matter team, so no grant reaches the derived observation. " +
					"This row used to read `deny, classification, privileged` and to be true even " +
					"if somebody had shared the observation with him by mistake",
			},
			{
				Principal: "user:anne", Action: "read", Resource: scenario.R("observation:billing-pattern"),
				Want: scenario.Allow, Reason: scenario.ReasonUserset,
				Because: "observation:billing-pattern#viewer@group:matter-team#member",
				Note: "a userset and not an inheritance, because the grant is written on the " +
					"observation itself. Worth pinning: the marking arrived by derivation and the " +
					"grant did not, so the two propagate along different edges and a reader " +
					"debugging one must not look for the other",
			},
		},
		Claims: []scenario.Claim{
			scenario.C(scenario.ClaimProviderRefused, "fact:advice-content", "",
				"a hosted provider allowlisted for nothing is refused the privileged fact, with a typed "+
					"ErrMarkingNotAllowlisted. It fails closed rather than degrading to a redacted prompt, "+
					"because a redaction that is wrong once is a disclosure"),
			scenario.C(scenario.ClaimProviderRefused, "observation:billing-pattern", "",
				"and it is refused the derived observation too. This is the row leak channel #15 is "+
					"about: the consolidator saw privileged evidence, so its output cannot be sent "+
					"somewhere the evidence could not have gone"),
			scenario.C(scenario.ClaimProviderPermitted, "fact:advice-content", "privileged",
				"the self-hosted model the legal tenant pinned *is* allowlisted for privileged, so it "+
					"receives it. The gate is an allowlist and not a prohibition on processing"),
			scenario.C(scenario.ClaimProviderPermitted, "fact:filing-date", "",
				"and the public filing goes to any provider, because it carries no marking at all"),
			scenario.C(scenario.ClaimMarkingSet, "observation:billing-pattern", "privileged",
				"the resolved marking set the provider gate reads, computed as the union over the "+
					"derivation's inputs. This is the claim that is now load-bearing on its own: the "+
					"second mechanism that used to stand behind it — a mandatory gate refusing the "+
					"read that assembled the context — no longer exists, so a sharing mistake that "+
					"over-grants the pipeline is stopped here or not at all"),
		},
	}
}
