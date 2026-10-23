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
// # What the removal of the mandatory tier did to this package
//
// It changed the fixtures, not the answers, and the change is a cost worth
// reading before the code.
//
// These scenarios used to share the household graph with one generous
// tuple — `graph:household#viewer@group:household#member` — and keep the
// personal invoice private with a classification on the episode. The
// README said, correctly for the time, that "the household's sharing is
// generous and is not what decides". With no classification, sharing *is*
// what decides, so the generous grant had to go: every episode now carries
// its own grant, which is also KGS §9.3's own stated default for a new
// episode ("the ingesting principal alone").
//
// That is the right answer and it costs something real. Privacy inside a
// shared container is now expressed by grant *granularity*, so the
// household writes one tuple per episode where it used to write one per
// graph — at episode cardinality rather than at graph cardinality. Nothing
// in design §9.2's closure budget breaks (a per-episode grant is still one
// tuple reaching every fact inside it, not one per fact), but the tuple
// count the household carries is now a function of how much it ingests
// rather than of how many people live in it.
//
// The fourth scenario here is the will, and it is the requirement that
// created the cryptographic tier: "whatever rule ever happens my will
// document should always stay private except if I die and the lawyer gives
// the access key." It is the one scenario where `Decide` returns allow and
// the content is still unreadable — and, now that nothing else withholds
// anything, the only scenario in the corpus where something is withheld
// from a principal a grant reached.
//
// See README.md in this directory.
package household

import (
	"github.com/laenenai/iam"
	"github.com/laenenai/iam/examples/scenario"
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
		Title: "Pascal's personal invoice stays his because nobody granted it to her",
		Models: `The driving example, first half. An invoice from ACME is ingested into
			the household graph and he keeps it to himself. Eva shares the
			household's ordinary life and must not see this invoice, the supplier's
			name, the total, or the goods. Every one of those four is a separate row
			in the table below because in kgs they are separate objects: an episode
			and three facts, each with its own attributes (KGS §9.2's
			decomposition). One grant on the episode covers all four, because a
			grant on a container reaches every descendant.

			This scenario used to work the other way round, and the difference is
			the whole of the no-deny decision in one fixture. The household shared
			the graph with one tuple, both of them read nearly everything through
			it, and the invoice was kept private by a classification on the episode
			that denied her regardless of that grant. That classification was a
			deny administered by policy, and the corpus's own U2 showed what
			routing ordinary household privacy through it cost: the label was an
			absolute no owner could lift, so "don't show her this invoice" and "no
			future rule may ever open this" became the same mechanism.

			So the grant moved down a level. There is no graph-wide tuple; each
			episode is granted to whoever may see it, which is also KGS §9.3's own
			default for a new episode's facts. The four denials below are now
			ordinary default-deny, they are the same four denials, and they are
			liftable by him at any time — which is what he actually wanted.`,
		Governs:   []string{"KGS §1", "KGS §9.2", "KGS §9.3", "§8.2 form 3", "no-deny anti-goal"},
		Status:    scenario.StatusPending,
		PendingOn: []scenario.Capability{scenario.CapDecide, scenario.CapTupleStore},
		Fixture: scenario.Fixture{
			Tenant: "household",
			Kinds:  graphKinds(),
			Principals: []scenario.PrincipalSpec{
				person("user:pascal", "ingested the invoice and granted it to nobody else"),
				person("user:eva", "his wife. Shares the household's ordinary life and must learn "+
					"nothing about this episode"),
			},
			Groups: []scenario.GroupSpec{
				{
					Name: "group:household", Members: []string{"user:pascal", "user:eva"},
					Note: "the household. It is the subject of every grant they share, and it is " +
						"deliberately not the subject of a grant on the graph itself",
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
			Mentions: []scenario.Mention{
				scenario.M("fact:acme-supplier-name", "entity:acme"),
				scenario.M("fact:acme-invoice-total", "entity:acme"),
			},
			Tuples: []scenario.Tuple{
				{
					Object: scenario.R("episode:grocery-receipt"), Relation: "viewer",
					Subject: scenario.US("group:household", "member"),
					Note: "the household's ordinary, generous, correct sharing — on the episode " +
						"rather than on the graph, which is the shape change this scenario records",
				},
				{
					Object: scenario.R("episode:invoice-acme"), Relation: "viewer",
					Subject: scenario.P("user:pascal"),
					Note:    "and his own episode, named to him alone",
				},
			},
		},
		Expect: []scenario.Expectation{
			{
				Principal: "user:eva", Action: "read", Resource: scenario.R("episode:invoice-acme"),
				Want: scenario.Deny, Reason: scenario.ReasonNoGrant,
				Note: "the invoice. This row used to read `deny, classification, personal:pascal`",
			},
			{
				Principal: "user:eva", Action: "read", Resource: scenario.R("fact:acme-supplier-name"),
				Want: scenario.Deny, Reason: scenario.ReasonNoGrant,
				Note: "the supplier's name. A separate object, denied by the same single absent grant",
			},
			{
				Principal: "user:eva", Action: "read", Resource: scenario.R("fact:acme-invoice-total"),
				Want: scenario.Deny, Reason: scenario.ReasonNoGrant,
				Note: "the total",
			},
			{
				Principal: "user:eva", Action: "read", Resource: scenario.R("fact:acme-invoice-goods"),
				Want: scenario.Deny, Reason: scenario.ReasonNoGrant,
				Note: "the goods. Four denials, one grant that was not written, and nobody " +
					"enumerated anything",
			},
			{
				Principal: "user:eva", Action: "read", Resource: scenario.R("fact:grocery-total"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "episode:grocery-receipt#viewer@group:household#member",
				Note: "and the household's ordinary life is unaffected: she reads the shared " +
					"groceries through the household grant, which is now written per episode",
			},
			{
				Principal: "user:pascal", Action: "read", Resource: scenario.R("fact:acme-invoice-total"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "episode:invoice-acme#viewer@user:pascal",
				Note: "while he reads his own through his own grant. He can add her to it this " +
					"afternoon, which a classification would not have let him do",
			},
		},
		Claims: []scenario.Claim{
			scenario.C(scenario.ClaimSchemaAccepted, "fact", "",
				"the household's schema is four relations and no exclusion operator — and there is "+
					"now nothing an exclusion operator could have been written instead of"),
			scenario.C(scenario.ClaimMarkingSet, "fact:acme-invoice-goods", "",
				"nothing is marked. Privacy is not a marking any more: a marking says what the "+
					"content is, and this fixture's privacy is entirely in which grants exist"),
			scenario.C(scenario.ClaimEntityVisibility, "entity:acme", "user:pascal",
				"KGS leak channel #1, and the claim that is unchanged by any of this: the supplier "+
					"entity exists for him because he can read a fact that references it, and does not "+
					"exist for her because she cannot. Existence is derived from authorized assertions "+
					"and there is no entity ACL to get wrong — which is why this half of the household "+
					"requirement never depended on the deny mechanism at all"),
			scenario.C(scenario.ClaimLiveGroups, "user:eva", "group:household",
				"against the real registry: she is in the household group, and that group now grants "+
					"exactly what somebody wrote a tuple for"),
			scenario.C(scenario.ClaimTuplesPerHop, "2", "6",
				"two tuples reach six objects. The cost of the change is visible here: it was one "+
					"tuple reaching seven, and a household that ingests a thousand episodes writes a "+
					"thousand tuples rather than one"),
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
			are KGS §8.5 numbers 1, 2, 4 and 5.

			This is the scenario the removal of the mandatory tier touched least,
			and that is itself the finding. The old fixture gave each of them a
			symmetrical clearance — a household is not a hierarchy — and the
			symmetry was expensive: two clearance groups, two labels, and two
			absolutes that neither of them could lift. Two per-episode grants do
			the same job here, because the property that makes dedup safe was
			never the deny. It was derived existence.`,
		Governs:   []string{"KGS §1", "KGS §7.3", "KGS §8.5 #1 #2 #4 #5", "KGS §9.2"},
		Status:    scenario.StatusPending,
		PendingOn: []scenario.Capability{scenario.CapDecide, scenario.CapTupleStore},
		Fixture: scenario.Fixture{
			Tenant: "household",
			Kinds:  graphKinds(),
			Principals: []scenario.PrincipalSpec{
				person("user:pascal", "ingested the first ACME invoice and kept it"),
				person("user:eva", "ingests the second ACME invoice and keeps it"),
			},
			Groups: []scenario.GroupSpec{
				{
					Name: "group:household", Members: []string{"user:pascal", "user:eva"},
					Note: "it exists, and in this fixture it holds no grant at all. A group is a " +
						"subject a grant may name, never an access level",
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
			Mentions: []scenario.Mention{
				scenario.M("fact:his-acme-supplier", "entity:acme"),
				scenario.M("fact:her-acme-supplier", "entity:acme"),
			},
			Tuples: []scenario.Tuple{
				{
					Object: scenario.R("episode:invoice-acme-his"), Relation: "viewer",
					Subject: scenario.P("user:pascal"),
				},
				{
					Object: scenario.R("episode:invoice-acme-hers"), Relation: "viewer",
					Subject: scenario.P("user:eva"),
					Note:    "symmetrical, because a household is not a hierarchy",
				},
			},
		},
		Expect: []scenario.Expectation{
			{
				Principal: "user:eva", Action: "read", Resource: scenario.R("fact:her-acme-supplier"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "episode:invoice-acme-hers#viewer@user:eva",
				Note:    "her own assertion about the supplier, which is what makes ACME exist for her",
			},
			{
				Principal: "user:eva", Action: "read", Resource: scenario.R("fact:his-acme-supplier"),
				Want: scenario.Deny, Reason: scenario.ReasonNoGrant,
				Note: "and his assertion about the same supplier is still invisible. The entity is " +
					"shared; the assertions are not",
			},
			{
				Principal: "user:eva", Action: "read", Resource: scenario.R("fact:his-acme-total"),
				Want: scenario.Deny, Reason: scenario.ReasonNoGrant,
				Note: "leak channels #4 and #5: she cannot read his facts, so a proof count or a " +
					"`12 invoices from this supplier` facet computed over the authorized evidence set " +
					"cannot include them either",
			},
			{
				Principal: "user:pascal", Action: "read", Resource: scenario.R("fact:her-acme-total"),
				Want: scenario.Deny, Reason: scenario.ReasonNoGrant,
				Note: "symmetrical. He is the graph's first ingester and that confers nothing",
			},
			{
				Principal: "user:pascal", Action: "read", Resource: scenario.R("fact:his-acme-total"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "episode:invoice-acme-his#viewer@user:pascal",
			},
		},
		Claims: []scenario.Claim{
			scenario.C(scenario.ClaimEntityVisibility, "entity:acme", "user:eva, user:pascal",
				"the sentence the project exists for, as a test: one supplier entity, existing for both "+
					"of them, through two disjoint sets of assertions. Dedup worked and nothing leaked. "+
					"Had entity existence been an ACL rather than derived, this is the row that would "+
					"have had to choose between resolving to one supplier and keeping them apart"),
			scenario.C(scenario.ClaimMarkingSet, "fact:his-acme-total", "",
				"and neither episode is marked, where the old fixture needed a label per household "+
					"member to say the same thing"),
			scenario.C(scenario.ClaimLiveGroups, "user:eva", "group:household",
				"against the real registry: she is in the household group, which grants her nothing "+
					"here. That is the shape of a group — a subject, not a level"),
			scenario.C(scenario.ClaimTuplesPerHop, "2", "6",
				"two tuples, six objects, two disjoint reaches of three"),
		},
	}
}

func daughtersSchoolDocument() scenario.Scenario {
	return scenario.Scenario{
		ID:    "H3",
		Title: "The daughter's school document yields an entity both parents can read",
		Models: `KGS §1's last sentence, and the one that keeps the household usable: a
			school document from their daughter yields a school entity they can both
			access. Nothing was ever classified here, which is why this is the one
			household scenario the removal of the mandatory tier left untouched: it
			was already an episode granted to a group, with the facts inheriting it
			at one tuple per hop, and the school entity existing for both parents
			through facts they can both read.

			It is worth reading immediately after H1 for that reason. H1's fixture
			had to change shape and this one did not, which locates exactly what
			the mandatory tier was carrying: not sharing, not derived existence,
			but only the case where a container is shared and one thing inside it
			is not.`,
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
			scenario.C(scenario.ClaimMarkingSet, "fact:school-name", "",
				"nothing marked, and nothing to mark. This fixture reads identically before and "+
					"after the mandatory tier's removal"),
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
		Title: "The will: Decide returns allow and the content is still unreadable",
		Models: `The requirement that created the cryptographic tier, verbatim:
			"whatever rule ever happens my will document should always stay private
			except if I die and the lawyer gives the access key." The decision
			procedure is enforced by whoever administers grants, and no
			access-control system can promise that no future rule will grant
			access — rules are mutable and administrators exist. So the will is not
			protected by a decision at all. It is encrypted under a key the
			deployment does not hold, and this module's entire responsibility is
			one field: the marking's enforcement class is crypto.

			This scenario mattered before and it matters more now. It used to be
			one of three tiers, with a classification denying Eva as a second line
			of defence "because the tiers compose rather than compete". There is no
			second line any more, which means two things. The policy half of the
			will's protection is now exactly what D6 and H1 use — the episode is
			not inside a container anybody else holds, and no grant names her — and
			it is liftable by him, as every grant is. And the crypto half is the
			only mechanism left in the design that withholds something from a
			principal a grant *did* reach: the first row below is an allow that
			cannot be read.

			That is not a loss. A classification was administered by whoever held
			the classify permission, so it never survived "whatever rule ever
			happens" either; it only read as though it did. The honest tier table
			now has one entry that survives an administrator and it is this one.`,
		Governs:   []string{"§7.3 cryptographic tier", "§7 tier table", "§5 decided constraints", "KGS §8.3"},
		Status:    scenario.StatusPending,
		PendingOn: []scenario.Capability{scenario.CapDecide, scenario.CapTupleStore},
		Fixture: scenario.Fixture{
			Tenant: "household",
			Kinds:  graphKinds(),
			Principals: []scenario.PrincipalSpec{
				person("user:pascal", "the testator. Holds the grant and still cannot read it"),
				person("user:eva", "holds neither a grant on it nor the key"),
				{
					Name: "service:notary", Kind: iam.PrincipalKindService,
					Role: "the lawyer's service principal. Holds an escrow share, which is not " +
						"an iam object — escrow owns the custodians, the ceremony and the dead-man's switch",
				},
			},
			Groups: []scenario.GroupSpec{
				{
					Name: "group:household", Members: []string{"user:pascal", "user:eva"},
					Note: "the household, holding the grant on the ordinary episode and nothing on the will",
				},
			},
			Containment: []scenario.Edge{
				scenario.E("episode:grocery-receipt", "graph:household"),
				scenario.E("fact:grocery-total", "episode:grocery-receipt"),
				scenario.E("episode:will-2026", "graph:household"),
				scenario.E("fact:will-executor", "episode:will-2026"),
				scenario.E("fact:will-bequest", "episode:will-2026"),
			},
			Markings: []scenario.Marking{
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
					Object: scenario.R("episode:grocery-receipt"), Relation: "viewer",
					Subject: scenario.US("group:household", "member"),
					Note:    "the household's ordinary sharing, so the fixture is not private by being empty",
				},
				{
					Object: scenario.R("episode:will-2026"), Relation: "viewer",
					Subject: scenario.P("user:pascal"),
					Note: "and the will, granted to him alone. This tuple is the entire policy-level " +
						"protection the will has, and it is worth exactly what any grant is worth",
				},
			},
		},
		Expect: []scenario.Expectation{
			{
				Principal: "user:pascal", Action: "read", Resource: scenario.R("fact:will-bequest"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "episode:will-2026#viewer@user:pascal",
				Note: "allow. He holds the grant, so the decision procedure has nothing to object " +
					"to — and he still cannot read a byte of it. The cryptographic tier is not part " +
					"of the decision, and this is the only row in the corpus where that distinction " +
					"has anything left to do",
			},
			{
				Principal: "user:eva", Action: "read", Resource: scenario.R("fact:will-bequest"),
				Want: scenario.Deny, Reason: scenario.ReasonNoGrant,
				Note: "and she is denied by the ordinary mechanism: nobody granted it to her. This " +
					"row used to read `deny, classification, will:pascal`, and the change is not " +
					"cosmetic — her denial is now liftable by him, where before it was not even " +
					"liftable by him. For a will that is the correct direction: he should be able to " +
					"show it to her, and she should not be able to decrypt it if he does not",
			},
			{
				Principal: "service:notary", Action: "read", Resource: scenario.R("fact:will-executor"),
				Want: scenario.Deny, Reason: scenario.ReasonNoGrant,
				Note: "the lawyer holds the escrow share and no grant, which is the correct state " +
					"while the testator is alive: the key material and the policy are independent, " +
					"and neither alone opens the will",
			},
			{
				Principal: "user:eva", Action: "read", Resource: scenario.R("fact:grocery-total"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "episode:grocery-receipt#viewer@group:household#member",
				Note:    "while the household's ordinary life goes on through the household grant",
			},
		},
		Claims: []scenario.Claim{
			scenario.C(scenario.ClaimCryptoUnreadable, "fact:will-bequest", "",
				"the claim the table cannot make: whatever the decision procedure answered, reading "+
					"this fails with a typed ErrCryptoEnforced, because the enforcement class is "+
					"crypto. An allow and a readable byte are different things and this is where that "+
					"stops being an abstraction"),
			scenario.C(scenario.ClaimCryptoUnreadable, "episode:will-2026", "",
				"the episode too, through its own assignment"),
			scenario.C(scenario.ClaimCryptoUnreadable, "fact:will-executor", "",
				"and the other fact inside it, through the episode. Sealing a container seals what "+
					"is in it, which is the one kind of propagation that survived — because it is a "+
					"property of the ciphertext rather than a rule somebody administers"),
			scenario.C(scenario.ClaimProviderRefused, "fact:will-bequest", "",
				"and no model provider receives it either, whatever it is allowlisted for — "+
					"crypto-enforced content is not extracted, indexed, embedded or summarised"),
			scenario.C(scenario.ClaimMarkingSet, "fact:grocery-total", "",
				"while the grocery receipt carries nothing, so the marking is a marking and not a "+
					"graph-wide mode"),
			scenario.C(scenario.ClaimLiveGroups, "service:notary", "",
				"against the real registry: the lawyer's principal exists and is in no group. What "+
					"it holds is an escrow share, which is not a row in this module"),
		},
	}
}
