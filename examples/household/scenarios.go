// Package household holds the scenario the whole project exists for: KGS
// §1, in the owner's own words.
//
//	An invoice marked personal is ingested. His wife must not see the
//	invoice, the supplier's name, the total, or the goods. When *she*
//	uploads an invoice from the same supplier, the graph must silently
//	resolve it to the same supplier — without revealing that a member of
//	the household had already entered it. A school document from their
//	daughter yields a school entity they can both access.
//
// Three of those four sentences are about what must not be learned, and
// the fourth is about dedup staying safe anyway. The mechanism that makes
// both true at once is KGS §7.3's derived existence: an entity exists for
// a principal iff that principal can read at least one assertion that
// references it. The entity's *identity* is shared, so two invoices
// resolve to one supplier; the entity's *existence* is per-principal, so
// neither party learns of the other's facts. There is no entity ACL to get
// wrong.
//
// The fourth scenario here is the will, and it is in this package rather
// than in mandatory because it is the requirement that created design
// §7.3's third tier: "whatever rule ever happens my will document should
// always stay private except if I die and the lawyer gives the access
// key." It is the one scenario where `Decide` returns allow and the
// content is still unreadable.
//
// See README.md in this directory.
package household

import (
	"github.com/laenen-ai/iam"
	"github.com/laenen-ai/iam/examples/scenario"
)

// graphKinds is the registered schema kgs declares (design §8.4, §12):
// `tenant > graph > [compartment] > entity-set | episode > fact`, with the
// entity-set left out of containment in this package and present in
// examples/unexpressible, where finding F3 is.
//
// Facts are row-shaped, which is the quiet reason kgs escapes finding F4:
// "because facts carry attributes rather than entities carrying columns,
// Palantir's object-level + property-level = cell-level security falls out
// of the data model instead of needing a second mechanism" (KGS §9.2). An
// attribute of an entity *is* a fact, so hiding an attribute is hiding a
// row, and a row is what a SQL predicate can hide.
func graphKinds() []scenario.ResourceKind {
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
			Name: "episode", Shape: scenario.ShapeRow,
			Relations: []scenario.Relation{
				{
					Name: "viewer", Direct: true, Usersets: []string{"group#member"},
					InheritFromParent: []string{"viewer"},
				},
			},
			Actions: map[string]string{"read": "viewer"},
		},
		{
			Name: "fact", Shape: scenario.ShapeRow,
			Relations: []scenario.Relation{
				{
					Name: "viewer", Direct: true, Usersets: []string{"group#member"},
					InheritFromParent: []string{"viewer"},
				},
			},
			Actions: map[string]string{"read": "viewer"},
		},
		{
			Name: "entity", Shape: scenario.ShapeRow,
			Relations: []scenario.Relation{
				{Name: "viewer", Direct: true, Usersets: []string{"group#member"}, InheritFromParent: []string{"viewer"}},
			},
			Actions: map[string]string{"read": "viewer"},
		},
	}
}

func person(name, role string) scenario.PrincipalSpec {
	return scenario.PrincipalSpec{Name: name, Kind: iam.PrincipalKindUser, Role: role}
}

func securityService() scenario.PrincipalSpec {
	return scenario.PrincipalSpec{
		Name: "service:household-security", Kind: iam.PrincipalKindService,
		Role: "the actor on the household's mandatory acts. Design §16 question 2 asks whether, " +
			"in a household, that should be the resource owner at creation time; the corpus records " +
			"an actor and does not assume the answer",
	}
}

// Scenarios returns the household use cases.
func Scenarios() []scenario.Scenario {
	return []scenario.Scenario{
		personalInvoice(),
		sameSupplierTwice(),
		daughtersSchoolDocument(),
		theWill(),
	}
}

func personalInvoice() scenario.Scenario {
	return scenario.Scenario{
		ID:    "H1",
		Title: "Pascal's personal invoice: she cannot see the invoice, the supplier, the total or the goods",
		Models: `The driving example, first half. An invoice from ACME is ingested into
			the household graph and marked personal. Eva shares the graph — it is a
			household, they share nearly everything — and must not see this invoice,
			the supplier's name, the total, or the goods. Every one of those four is
			a separate row in the table below because in kgs they are separate
			objects: an episode and three facts, each with its own attributes
			(KGS §9.2's decomposition). One classification on the episode covers all
			four, because design §8.3 resolves a resource's labels over its ancestry
			closure.`,
		Governs:   []string{"KGS §1", "KGS §9.2", "KGS §9.3", "§8.3", "§7.1"},
		Status:    scenario.StatusPending,
		PendingOn: []scenario.Capability{scenario.CapDecide, scenario.CapTupleStore, scenario.CapClassificationStore},
		Fixture: scenario.Fixture{
			Tenant: "household",
			Kinds:  graphKinds(),
			Principals: []scenario.PrincipalSpec{
				person("user:pascal", "ingested the invoice; the only holder of personal:pascal"),
				person("user:eva", "his wife. Shares the household graph and must learn nothing about this episode"),
				securityService(),
			},
			Groups: []scenario.GroupSpec{
				{
					Name: "group:household", Members: []string{"user:pascal", "user:eva"},
					Note: "an ordinary group. It holds the graph-wide grant and can never hold a clearance",
				},
			},
			ClearanceGroups: []scenario.ClearanceGroupSpec{
				{
					Name: "clearance:personal-pascal", Channel: iam.MandatoryChannelClassify,
					Members: []string{"user:pascal"}, Labels: []string{"personal:pascal"},
					Reason: "one household member's own records",
				},
			},
			Containment: []scenario.Edge{
				scenario.E("episode:invoice-acme", "graph:household"),
				scenario.E("fact:acme-supplier-name", "episode:invoice-acme"),
				scenario.E("fact:acme-invoice-total", "episode:invoice-acme"),
				scenario.E("fact:acme-invoice-goods", "episode:invoice-acme"),
				scenario.E("episode:grocery-receipt", "graph:household"),
				scenario.E("fact:grocery-total", "episode:grocery-receipt"),
			},
			Classifications: []scenario.Classification{
				{
					Label: "personal:pascal", Enforcement: scenario.EnforcementPolicy,
					Why: "design §16 question 1: the household case is modelled as a label — `this carries " +
						"personal:pascal and she holds no such clearance` — rather than as a named " +
						"(principal, resource) block, because a label propagates through derivation and a " +
						"named pair would not",
				},
			},
			Assignments: []scenario.Assignment{scenario.AS("episode:invoice-acme", "personal:pascal")},
			Mentions: []scenario.Mention{
				scenario.M("fact:acme-supplier-name", "entity:acme"),
				scenario.M("fact:acme-invoice-total", "entity:acme"),
			},
			Tuples: []scenario.Tuple{
				{
					Object: scenario.R("graph:household"), Relation: "viewer",
					Subject: scenario.US("group:household", "member"),
					Note: "the household shares the graph. This is the ordinary, generous, correct " +
						"discretionary state, and the scenario's whole point is that it is not what decides",
				},
			},
		},
		Expect: []scenario.Expectation{
			{
				Principal: "user:eva", Action: "read", Resource: scenario.R("episode:invoice-acme"),
				Want: scenario.Deny, Reason: scenario.ReasonClassification, Because: "personal:pascal",
				Note: "the invoice",
			},
			{
				Principal: "user:eva", Action: "read", Resource: scenario.R("fact:acme-supplier-name"),
				Want: scenario.Deny, Reason: scenario.ReasonClassification, Because: "personal:pascal",
				Note: "the supplier's name. A separate object, denied by the same single assignment",
			},
			{
				Principal: "user:eva", Action: "read", Resource: scenario.R("fact:acme-invoice-total"),
				Want: scenario.Deny, Reason: scenario.ReasonClassification, Because: "personal:pascal",
				Note: "the total",
			},
			{
				Principal: "user:eva", Action: "read", Resource: scenario.R("fact:acme-invoice-goods"),
				Want: scenario.Deny, Reason: scenario.ReasonClassification, Because: "personal:pascal",
				Note: "the goods. Four denials, one label, nobody enumerated anything",
			},
			{
				Principal: "user:eva", Action: "read", Resource: scenario.R("fact:grocery-total"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "graph:household#viewer@group:household#member",
				Note: "and the household's ordinary life is unaffected: she reads the shared groceries " +
					"through the same graph-wide grant that does not help her with the invoice",
			},
			{
				Principal: "user:pascal", Action: "read", Resource: scenario.R("fact:acme-invoice-total"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "graph:household#viewer@group:household#member",
				Note: "he passes the gate through the clearance group, and then the same household grant " +
					"everybody has is what grants him",
			},
		},
		Claims: []scenario.Claim{
			scenario.C(scenario.ClaimSchemaAccepted, "fact", "",
				"the household's schema is four relations and no exclusion operator"),
			scenario.C(scenario.ClaimLabelSet, "fact:acme-invoice-goods", "personal:pascal",
				"one assignment on the episode reaches every fact inside it (§8.3 through containment)"),
			scenario.C(scenario.ClaimLabelSet, "fact:grocery-total", "",
				"and reaches nothing else, so the label is a label and not a graph-wide mode"),
			scenario.C(scenario.ClaimEntityVisibility, "entity:acme", "user:pascal",
				"KGS leak channel #1: the supplier entity exists for him, because he can read a fact "+
					"that references it, and does not exist for her, because she cannot. Existence is "+
					"derived from authorized assertions and there is no entity ACL to get wrong"),
			scenario.C(scenario.ClaimLiveClearances, "user:eva", "",
				"against the real registry: she is in the household group and holds no clearance"),
			scenario.C(scenario.ClaimLiveGroups, "user:eva", "group:household",
				"both facts from the same registry, in two tiers that cannot reach each other"),
		},
	}
}

func sameSupplierTwice() scenario.Scenario {
	return scenario.Scenario{
		ID:    "H2",
		Title: "She uploads an invoice from the same supplier and learns nothing about his",
		Models: `The driving example's second half, and the hardest sentence in KGS §1:
			when she uploads an invoice from the same supplier, the graph must
			silently resolve it to the same supplier — without revealing that a
			member of the household had already entered it. Resolution is a property
			of entity *identity*, which is shared by referent binding and is
			deliberately not an authorization object (KGS §9.2: "that's what makes
			dedup safe"). Visibility is a property of entity *existence*, which is
			derived per principal from the assertions that principal may read. So
			both invoices bind to one ACME, her facts are hers, his are his, and
			neither of them can count the other's. The leak channels this closes
			are KGS §8.5 numbers 1, 2, 4 and 5.`,
		Governs:   []string{"KGS §1", "KGS §7.3", "KGS §8.5 #1 #2 #4 #5", "KGS §9.2"},
		Status:    scenario.StatusPending,
		PendingOn: []scenario.Capability{scenario.CapDecide, scenario.CapTupleStore, scenario.CapClassificationStore},
		Fixture: scenario.Fixture{
			Tenant: "household",
			Kinds:  graphKinds(),
			Principals: []scenario.PrincipalSpec{
				person("user:pascal", "ingested the first ACME invoice, marked personal"),
				person("user:eva", "ingests the second ACME invoice, marked personal to her"),
				securityService(),
			},
			Groups: []scenario.GroupSpec{
				{Name: "group:household", Members: []string{"user:pascal", "user:eva"}},
			},
			ClearanceGroups: []scenario.ClearanceGroupSpec{
				{
					Name: "clearance:personal-pascal", Channel: iam.MandatoryChannelClassify,
					Members: []string{"user:pascal"}, Labels: []string{"personal:pascal"},
					Reason: "his own records",
				},
				{
					Name: "clearance:personal-eva", Channel: iam.MandatoryChannelClassify,
					Members: []string{"user:eva"}, Labels: []string{"personal:eva"},
					Reason: "her own records. Symmetrical, because a household is not a hierarchy",
				},
			},
			Containment: []scenario.Edge{
				scenario.E("episode:invoice-acme-his", "graph:household"),
				scenario.E("fact:his-acme-supplier", "episode:invoice-acme-his"),
				scenario.E("fact:his-acme-total", "episode:invoice-acme-his"),
				scenario.E("episode:invoice-acme-hers", "graph:household"),
				scenario.E("fact:her-acme-supplier", "episode:invoice-acme-hers"),
				scenario.E("fact:her-acme-total", "episode:invoice-acme-hers"),
			},
			Classifications: []scenario.Classification{
				{Label: "personal:pascal", Enforcement: scenario.EnforcementPolicy, Why: "his own records"},
				{Label: "personal:eva", Enforcement: scenario.EnforcementPolicy, Why: "her own records"},
			},
			Assignments: []scenario.Assignment{
				scenario.AS("episode:invoice-acme-his", "personal:pascal"),
				scenario.AS("episode:invoice-acme-hers", "personal:eva"),
			},
			Mentions: []scenario.Mention{
				scenario.M("fact:his-acme-supplier", "entity:acme"),
				scenario.M("fact:her-acme-supplier", "entity:acme"),
			},
			Tuples: []scenario.Tuple{
				{
					Object: scenario.R("graph:household"), Relation: "viewer",
					Subject: scenario.US("group:household", "member"),
				},
			},
		},
		Expect: []scenario.Expectation{
			{
				Principal: "user:eva", Action: "read", Resource: scenario.R("fact:her-acme-supplier"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "graph:household#viewer@group:household#member",
				Note:    "her own assertion about the supplier, which is what makes ACME exist for her",
			},
			{
				Principal: "user:eva", Action: "read", Resource: scenario.R("fact:his-acme-supplier"),
				Want: scenario.Deny, Reason: scenario.ReasonClassification, Because: "personal:pascal",
				Note: "and his assertion about the same supplier is still invisible. The entity is shared; " +
					"the assertions are not",
			},
			{
				Principal: "user:eva", Action: "read", Resource: scenario.R("fact:his-acme-total"),
				Want: scenario.Deny, Reason: scenario.ReasonClassification, Because: "personal:pascal",
				Note: "leak channels #4 and #5: she cannot read his facts, so a proof count or a " +
					"`12 invoices from this supplier` facet computed over the authorized evidence set " +
					"cannot include them either",
			},
			{
				Principal: "user:pascal", Action: "read", Resource: scenario.R("fact:her-acme-total"),
				Want: scenario.Deny, Reason: scenario.ReasonClassification, Because: "personal:eva",
				Note: "symmetrical. He is the graph's ingester and that confers nothing",
			},
			{
				Principal: "user:pascal", Action: "read", Resource: scenario.R("fact:his-acme-total"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "graph:household#viewer@group:household#member",
			},
		},
		Claims: []scenario.Claim{
			scenario.C(scenario.ClaimEntityVisibility, "entity:acme", "user:eva, user:pascal",
				"the sentence the project exists for, as a test: one supplier entity, existing for both "+
					"of them, through two disjoint sets of assertions. Dedup worked and nothing leaked. "+
					"Had entity existence been an ACL rather than derived, this is the row that would "+
					"have had to choose between resolving to one supplier and keeping them apart"),
			scenario.C(scenario.ClaimLabelSet, "fact:his-acme-total", "personal:pascal", ""),
			scenario.C(scenario.ClaimLabelSet, "fact:her-acme-total", "personal:eva", ""),
			scenario.C(scenario.ClaimLiveClearances, "user:eva", "clearance:personal-eva",
				"against the real registry: she holds exactly her own compartment"),
			scenario.C(scenario.ClaimNoClearanceFromDiscretion, "user:eva", "clearance:personal-eva",
				"and no discretionary operation adds his to it — the detail is what she legitimately "+
					"holds, so the claim is an exact set and not merely `empty`"),
		},
	}
}

func daughtersSchoolDocument() scenario.Scenario {
	return scenario.Scenario{
		ID:    "H3",
		Title: "The daughter's school document yields an entity both parents can read",
		Models: `KGS §1's last sentence, and the one that keeps the household usable: a
			school document from their daughter yields a school entity they can both
			access. Nothing is classified here, which is the point — the mandatory
			layer is for the exceptions, and a design where the household's ordinary
			life needs clearances would have failed. The episode is granted to the
			parents and the facts inherit it at one tuple per hop, so the school
			entity exists for both parents through facts they can both read.`,
		Governs:   []string{"KGS §1", "KGS §7.3", "§8.2 form 3"},
		Status:    scenario.StatusPending,
		PendingOn: []scenario.Capability{scenario.CapDecide, scenario.CapTupleStore},
		Fixture: scenario.Fixture{
			Tenant: "household",
			Kinds:  graphKinds(),
			Principals: []scenario.PrincipalSpec{
				person("user:pascal", "parent"),
				person("user:eva", "parent"),
				person("user:mira", "the daughter, whose school document this is"),
				person("user:neighbour", "not in the household at all"),
			},
			Groups: []scenario.GroupSpec{
				{
					Name: "group:household-parents", Members: []string{"user:pascal", "user:eva"},
					Note: "an ordinary group, which is exactly the right mechanism for ordinary sharing",
				},
			},
			Containment: []scenario.Edge{
				scenario.E("episode:school-report-2026", "graph:household"),
				scenario.E("fact:school-name", "episode:school-report-2026"),
				scenario.E("fact:school-address", "episode:school-report-2026"),
				scenario.E("fact:mira-grade", "episode:school-report-2026"),
			},
			Mentions: []scenario.Mention{
				scenario.M("fact:school-name", "entity:sint-jozef"),
				scenario.M("fact:school-address", "entity:sint-jozef"),
			},
			Tuples: []scenario.Tuple{
				{
					Object: scenario.R("episode:school-report-2026"), Relation: "viewer",
					Subject: scenario.US("group:household-parents", "member"),
					Note: "one tuple on the episode. KGS §9.3's default for a new episode's facts is the " +
						"ingesting principal alone, so this grant is an explicit act and not an accident " +
						"of ingest order",
				},
			},
		},
		Expect: []scenario.Expectation{
			{
				Principal: "user:pascal", Action: "read", Resource: scenario.R("fact:school-name"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "episode:school-report-2026#viewer@group:household-parents#member",
			},
			{
				Principal: "user:eva", Action: "read", Resource: scenario.R("fact:mira-grade"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "episode:school-report-2026#viewer@group:household-parents#member",
				Note:    "both parents, one tuple, three facts",
			},
			{
				Principal: "user:mira", Action: "read", Resource: scenario.R("fact:mira-grade"),
				Want: scenario.Deny, Reason: scenario.ReasonNoGrant,
				Note: "the daughter is a principal in this household and this grant did not name her. " +
					"Deny-by-default is the right direction for a system whose stated why is `reveal less`, " +
					"and giving her access is one more tuple whenever the household decides to",
			},
			{
				Principal: "user:neighbour", Action: "read", Resource: scenario.R("fact:school-name"),
				Want: scenario.Deny, Reason: scenario.ReasonNoGrant,
			},
		},
		Claims: []scenario.Claim{
			scenario.C(scenario.ClaimEntityVisibility, "entity:sint-jozef", "user:eva, user:pascal",
				"the school exists for both parents and for neither the daughter nor the neighbour, "+
					"derived from the facts each of them may read"),
			scenario.C(scenario.ClaimLabelSet, "fact:school-name", "",
				"nothing classified. The mandatory layer is for the exceptions"),
			scenario.C(scenario.ClaimTuplesPerHop, "1", "4",
				"one tuple, four objects"),
			scenario.C(scenario.ClaimPathCount, "fact:school-name", "1",
				"containment here is a tree, because the fact's only container is its episode. Add the "+
					"entity-set KGS §9.3 wants — `my wife can see everything about the school` expressed "+
					"once rather than per fact — and it is not. That is U3"),
		},
	}
}

func theWill() scenario.Scenario {
	return scenario.Scenario{
		ID:    "H4",
		Title: "The will: Decide may return allow and the content is still unreadable",
		Models: `The requirement that created design §7.3's third tier, verbatim:
			"whatever rule ever happens my will document should always stay private
			except if I die and the lawyer gives the access key." Tiers 1 and 2 are
			enforced by policy, which means they are enforced by whoever
			administers policy, and no access-control system can promise that no
			future rule will grant access — rules are mutable and administrators
			exist. So the will is not protected by a decision at all. It is
			encrypted under a key the deployment does not hold, and this module's
			entire responsibility is one field: the classification's enforcement
			class is crypto. This scenario is the only one in the corpus where the
			expectation table says allow and the content is still unreadable, and
			that separation is the thing it exists to demonstrate.`,
		Governs:   []string{"§7.3", "§7 tier table", "§5 decided constraints", "KGS §8.3"},
		Status:    scenario.StatusPending,
		PendingOn: []scenario.Capability{scenario.CapDecide, scenario.CapClassificationStore},
		Fixture: scenario.Fixture{
			Tenant: "household",
			Kinds:  graphKinds(),
			Principals: []scenario.PrincipalSpec{
				person("user:pascal", "the testator. Holds the clearance and still cannot read it"),
				person("user:eva", "holds neither the clearance nor the key"),
				{
					Name: "service:notary", Kind: iam.PrincipalKindService,
					Role: "the lawyer's service principal. Holds an escrow share, which is not " +
						"an iam object — escrow owns the custodians, the ceremony and the dead-man's switch",
				},
				securityService(),
			},
			Groups: []scenario.GroupSpec{
				{Name: "group:household", Members: []string{"user:pascal", "user:eva"}},
			},
			ClearanceGroups: []scenario.ClearanceGroupSpec{
				{
					Name: "clearance:will-pascal", Channel: iam.MandatoryChannelClassify,
					Members: []string{"user:pascal"}, Labels: []string{"will:pascal"},
					Reason: "the testator, while alive",
				},
			},
			Containment: []scenario.Edge{
				scenario.E("episode:will-2026", "graph:household"),
				scenario.E("fact:will-executor", "episode:will-2026"),
				scenario.E("fact:will-bequest", "episode:will-2026"),
			},
			Classifications: []scenario.Classification{
				{
					Label: "will:pascal", Enforcement: scenario.EnforcementCrypto,
					Why: "the one requirement no policy can meet. keyring holds the wrapping, escrow " +
						"holds the shares; this module records the class so a consumer can tell a user " +
						"*why* something is unreadable and so the API refuses processing operations on it " +
						"with a typed error rather than failing obscurely later",
				},
			},
			Assignments: []scenario.Assignment{scenario.AS("episode:will-2026", "will:pascal")},
			Tuples: []scenario.Tuple{
				{
					Object: scenario.R("graph:household"), Relation: "viewer",
					Subject: scenario.US("group:household", "member"),
				},
			},
		},
		Expect: []scenario.Expectation{
			{
				Principal: "user:pascal", Action: "read", Resource: scenario.R("fact:will-bequest"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "graph:household#viewer@group:household#member",
				Note: "allow. He holds the clearance and the household grant, so the decision procedure " +
					"has nothing to object to — and he still cannot read a byte of it. §7.3: tier 3 is " +
					"not part of the decision",
			},
			{
				Principal: "user:eva", Action: "read", Resource: scenario.R("fact:will-bequest"),
				Want: scenario.Deny, Reason: scenario.ReasonClassification, Because: "will:pascal",
				Note: "and the policy tier still denies her, because defence in depth is why the tiers " +
					"compose rather than compete. Her denial does not depend on the key",
			},
			{
				Principal: "service:notary", Action: "read", Resource: scenario.R("fact:will-executor"),
				Want: scenario.Deny, Reason: scenario.ReasonClassification, Because: "will:pascal",
				Note: "the lawyer holds the escrow share and no clearance, which is the correct state " +
					"while the testator is alive: the key material and the policy are independent, and " +
					"neither alone opens the will",
			},
		},
		Claims: []scenario.Claim{
			scenario.C(scenario.ClaimCryptoUnreadable, "fact:will-bequest", "",
				"the claim the table cannot make: whatever the decision procedure answered, reading this "+
					"fails with a typed ErrCryptoEnforced, because the enforcement class is crypto. An "+
					"allow and a readable byte are different things and this is where that stops being "+
					"an abstraction"),
			scenario.C(scenario.ClaimCryptoUnreadable, "episode:will-2026", "",
				"the episode too, through its own assignment"),
			scenario.C(scenario.ClaimProviderRefused, "fact:will-bequest", "personal:pascal",
				"and no model provider receives it either, whatever it is allowlisted for — "+
					"crypto-enforced content is not extracted, indexed, embedded or summarised (§7 tier table)"),
			scenario.C(scenario.ClaimLiveClearances, "service:notary", "",
				"against the real registry: the lawyer's principal exists and holds no clearance. "+
					"What it holds is an escrow share, which is not a row in this module"),
		},
	}
}
