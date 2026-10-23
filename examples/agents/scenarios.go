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

func securityService() scenario.PrincipalSpec {
	return scenario.PrincipalSpec{
		Name: "service:security", Kind: iam.PrincipalKindService,
		Role: "performs the fixture's mandatory acts",
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
			tested here. The run inherits nothing: no group membership and no
			clearance, because a delegation is a discretionary act and a
			discretionary act that conferred a clearance would be anti-goal A3
			breached. And when the user is deprovisioned, the run dies with them
			immediately, through the deny epoch rather than at the next refresh.

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
				securityService(),
			},
			Groups: []scenario.GroupSpec{
				{Name: "group:household", Members: []string{"user:pascal", "user:quentin"}},
			},
			ClearanceGroups: []scenario.ClearanceGroupSpec{
				{
					Name: "clearance:personal-pascal", Channel: iam.MandatoryChannelClassify,
					Members: []string{"user:pascal"}, Labels: []string{"personal:pascal"},
					Reason: "his own records",
				},
			},
			Classifications: []scenario.Classification{
				{Label: "personal:pascal", Enforcement: scenario.EnforcementPolicy, Why: "his own records"},
			},
		},
		Claims: []scenario.Claim{
			scenario.C(scenario.ClaimLiveGroups, "agent-run:ingest-7f3a", "",
				"the run inherits none of its parent's group membership. It is a principal, not a "+
					"view of one, so a grant to the household does not reach the run"),
			scenario.C(scenario.ClaimLiveClearances, "agent-run:ingest-7f3a", "",
				"and none of its parent's clearances, which is the A3-critical half: the parent holds "+
					"personal:pascal and the run, created by a discretionary act, holds nothing"),
			scenario.C(scenario.ClaimLiveClearances, "user:pascal", "clearance:personal-pascal",
				"while the parent's own clearance is unaffected by having delegated"),
			scenario.C(scenario.ClaimPrincipalUnusable, "user:quentin", "deprovisioned",
				"deprovisioning denies immediately and unconditionally: not at the next sync, not when "+
					"the token expires, and no re-sync clears it"),
			scenario.C(scenario.ClaimPrincipalUnusable, "agent-run:ingest-9c21", "deprovisioned",
				"the cascade. His run reports deprovisioned too, in the same write, so there is no "+
					"window in which an orphaned run outlives the identity that authorized it"),
			scenario.C(scenario.ClaimNoClearanceFromDiscretion, "agent-run:ingest-7f3a", "",
				"and no discretionary operation gives the run a clearance either — including delegating "+
					"a further run from the cleared parent, which the registry refuses outright because "+
					"a chain of ephemeral principals has no attributable owner"),
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
			identifier and returns public data." This scenario is that sentence as a
			table, and the two denials below have deliberately different reasons —
			one classified fact denied by the gate, one ordinary private fact denied
			because no tuple reaches it. A researcher that could read unclassified
			private facts would satisfy the letter of the rule and break it.`,
		Governs:   []string{"KGS §10.5", "KGS §11.4", "KGS §8.5 #10", "§8.1 service principals"},
		Status:    scenario.StatusPending,
		PendingOn: []scenario.Capability{scenario.CapDecide, scenario.CapTupleStore, scenario.CapClassificationStore},
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
				securityService(),
			},
			Groups: []scenario.GroupSpec{
				{Name: "group:household", Members: []string{"user:pascal"}},
			},
			ClearanceGroups: []scenario.ClearanceGroupSpec{
				{
					Name: "clearance:personal-pascal", Channel: iam.MandatoryChannelClassify,
					Members: []string{"user:pascal"}, Labels: []string{"personal:pascal"},
					Reason: "his own records",
				},
			},
			Containment: []scenario.Edge{
				scenario.E("referent:acme-bv", "graph:world"),
				scenario.E("referent:sint-jozef", "graph:world"),
				scenario.E("episode:invoice-acme", "graph:household"),
				scenario.E("fact:acme-invoice-total", "episode:invoice-acme"),
				scenario.E("episode:grocery-receipt", "graph:household"),
				scenario.E("fact:grocery-total", "episode:grocery-receipt"),
			},
			Classifications: []scenario.Classification{
				{Label: "personal:pascal", Enforcement: scenario.EnforcementPolicy, Why: "his own records"},
			},
			Assignments: []scenario.Assignment{scenario.AS("episode:invoice-acme", "personal:pascal")},
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
					Note:    "the household's own grant, which does not name the researcher",
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
				Want: scenario.Deny, Reason: scenario.ReasonClassification, Because: "personal:pascal",
				Note: "the classified household fact. Denied by the gate before any grant is consulted",
			},
			{
				Principal: "service:researcher", Action: "read", Resource: scenario.R("fact:grocery-total"),
				Want: scenario.Deny, Reason: scenario.ReasonNoGrant,
				Note: "the row that matters most. This fact is private but *unclassified*, so the " +
					"mandatory gate has nothing to say about it, and the researcher is denied because " +
					"no tuple reaches it. `No read permission on any private fact` is a property of the " +
					"grants, not of the labels — a researcher whose denial depended on classification " +
					"would read every household fact nobody thought to mark",
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
			scenario.C(scenario.ClaimLiveClearances, "service:researcher", "",
				"against the real registry: the researcher holds no clearance, so even a future "+
					"classification cannot be satisfied by it"),
			scenario.C(scenario.ClaimNoClearanceFromDiscretion, "service:researcher", "",
				"and no discretionary operation gives it one. A service principal is not a privileged "+
					"principal; it is a principal with a different kind"),
			scenario.C(scenario.ClaimTuplesPerHop, "2", "8",
				"two tuples, two graphs, eight objects — and the researcher's reach is two of the eight"),
		},
	}
}

func markingAwareModelAccess() scenario.Scenario {
	return scenario.Scenario{
		ID:    "A3",
		Title: "Marking-aware model access: a provider not allowlisted for `privileged` never receives it",
		Models: `During ingest kgs sends content to a language model, and that model is a
			principal whose provider is a trust boundary. KGS §9.5 takes Palantir's
			AIP marking allowlists for this: a provider profile declares which
			markings it may receive, a provider not allowlisted for privileged never
			receives privileged content, and the pipeline fails closed with a typed
			error rather than degrading. The second half is leak channel #15 and it
			is why the gate reads the *resolved* label set rather than the content's
			own assignments: a consolidator that saw privileged evidence and emitted
			an observation must not have laundered the marking on the way out, and
			design §8.3's derivation union is what stops it.`,
		Governs:   []string{"KGS §9.5", "KGS §8.5 #15", "§7.3 typed refusal", "§8.3 derivation"},
		Status:    scenario.StatusPending,
		PendingOn: []scenario.Capability{scenario.CapDecide, scenario.CapClassificationStore, scenario.CapDerivation},
		Fixture: scenario.Fixture{
			Tenant: "lawfirm",
			Kinds:  agentKinds(),
			Principals: []scenario.PrincipalSpec{
				{
					Name: "service:extractor", Kind: iam.PrincipalKindService,
					ClaimGroups: []string{"group:pipeline"},
					Role:        "the ingest pipeline. Authorized to read the matter it is processing",
				},
				{
					Name: "user:anne", Kind: iam.PrincipalKindUser,
					ClaimGroups: []string{"group:pipeline"},
					Role:        "the cleared associate",
				},
				{
					Name: "user:dave", Kind: iam.PrincipalKindUser,
					Role: "not cleared, and not in the pipeline group",
				},
				securityService(),
			},
			Groups: []scenario.GroupSpec{
				{Name: "group:pipeline", Members: []string{"service:extractor", "user:anne"}},
			},
			ClearanceGroups: []scenario.ClearanceGroupSpec{
				{
					Name: "clearance:privileged", Channel: iam.MandatoryChannelClassify,
					Members: []string{"user:anne", "service:extractor"},
					Labels:  []string{"privileged"},
					Reason: "the matter team and the self-hosted pipeline the legal tenant pinned. " +
						"A mandatory act, because a pipeline that may see privileged content is a " +
						"security decision and not a configuration one",
				},
			},
			Containment: []scenario.Edge{
				scenario.E("episode:matter-advice", "graph:lawfirm"),
				scenario.E("fact:advice-content", "episode:matter-advice"),
				scenario.E("episode:public-filing", "graph:lawfirm"),
				scenario.E("fact:filing-date", "episode:public-filing"),
				scenario.E("observation:billing-pattern", "graph:lawfirm"),
			},
			Classifications: []scenario.Classification{
				{
					Label: "privileged", Enforcement: scenario.EnforcementPolicy,
					Why: "legal professional privilege. Policy-enforced, because the firm must still " +
						"index and search it for the team that may see it",
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
					Object: scenario.R("graph:lawfirm"), Relation: "viewer",
					Subject: scenario.US("group:pipeline", "member"),
				},
			},
		},
		Expect: []scenario.Expectation{
			{
				Principal: "service:extractor", Action: "read", Resource: scenario.R("fact:advice-content"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "graph:lawfirm#viewer@group:pipeline#member",
				Note: "the pipeline may read it, because a mandatory act cleared it. Whether it may " +
					"*send* it to a given provider is the separate question the claims answer",
			},
			{
				Principal: "user:dave", Action: "read", Resource: scenario.R("observation:billing-pattern"),
				Want: scenario.Deny, Reason: scenario.ReasonClassification, Because: "privileged",
				Note: "the derived observation carries the union of its inputs' markings",
			},
			{
				Principal: "user:anne", Action: "read", Resource: scenario.R("observation:billing-pattern"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "graph:lawfirm#viewer@group:pipeline#member",
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
			scenario.C(scenario.ClaimLabelSet, "observation:billing-pattern", "privileged",
				"the resolved label set the provider gate reads, computed as the union over the "+
					"derivation's inputs"),
		},
	}
}
