// Package mandatory holds the corpus's tier-2 use cases: classifications
// on resources, clearances on principals, and the one invariant this whole
// module exists for — design §4/A3's "no sequence of discretionary
// operations, performed by any principal, can cause a classification gate
// to pass for a principal that does not satisfy it".
//
// The legal conflict screen is the scenario that drove the design: a
// matter is classified, only the matter team is cleared, and a firm-wide
// grant cannot defeat it. Lakekeeper, the one production open-source
// ReBAC-over-a-hierarchy implementation, has no deny mechanism at all
// (design §5a), which is the strongest available evidence that absolutes
// do not belong in the relationship layer. That is why every scenario here
// uses a classification and none uses an exclusion.
//
// See README.md in this directory for the shape of each answer.
package mandatory

import (
	"github.com/laenen-ai/iam"
	"github.com/laenen-ai/iam/examples/scenario"
)

// legalKinds is the registered schema a law firm's document store declares
// — CAS's `tenant > fileset > document > slot` with a matter as the
// fileset (design §8.4, §12).
func legalKinds() []scenario.ResourceKind {
	resource := func(name string) scenario.ResourceKind {
		return scenario.ResourceKind{
			Name:  name,
			Shape: scenario.ShapeColumnar,
			Relations: []scenario.Relation{
				{Name: "owner", Direct: true, Usersets: []string{"group#member", "role#assignee"}},
				{
					Name: "editor", Direct: true,
					Usersets:          []string{"group#member", "role#assignee"},
					InheritFromParent: []string{"editor"},
					Union:             []string{"owner"},
				},
				{
					Name: "viewer", Direct: true,
					Usersets:          []string{"group#member", "role#assignee"},
					InheritFromParent: []string{"viewer"},
					Union:             []string{"editor", "owner"},
				},
			},
			Actions: map[string]string{"read": "viewer", "write": "editor", "share": "owner"},
		}
	}
	return []scenario.ResourceKind{
		{
			Name:      "group",
			Relations: []scenario.Relation{{Name: "member", Direct: true}},
			Actions:   map[string]string{"read": "member"},
		},
		{
			Name: "role",
			Relations: []scenario.Relation{
				{Name: "assignee", Direct: true, Usersets: []string{"group#member"}},
				{Name: "ownership", Direct: true},
			},
			Actions: map[string]string{"assume": "assignee"},
		},
		resource("matter"),
		resource("fileset"),
		resource("document"),
	}
}

func user(name, role string, claimGroups ...string) scenario.PrincipalSpec {
	return scenario.PrincipalSpec{Name: name, Kind: iam.PrincipalKindUser, ClaimGroups: claimGroups, Role: role}
}

func securityService() scenario.PrincipalSpec {
	return scenario.PrincipalSpec{
		Name: "service:security-admin", Kind: iam.PrincipalKindService,
		Role: "the firm's security function: the actor on every mandatory act in this fixture",
	}
}

// Scenarios returns the mandatory use cases.
func Scenarios() []scenario.Scenario {
	return []scenario.Scenario{
		ethicalWall(),
		needToKnow(),
		everyoneExceptBob(),
		newJoiner(),
		everyAdminAttemptsTheGate(),
		derivationPropagation(),
	}
}

func ethicalWall() scenario.Scenario {
	return scenario.Scenario{
		ID:    "M1",
		Title: "The legal ethical wall: a firm-wide grant cannot defeat a conflict screen",
		Models: `The firm acts for Nordwind. A partner who once acted for Nordwind's
			opponent must never see the matter, and the firm's document store has a
			firm-wide grant on everything so that timekeepers can work. Both of
			those are true at once, which is exactly the situation CAS §9.3 says
			deny-wins exists for: "a conflict screen says this partner must not see
			this matter and must not be defeatable by a firm-wide grant." In this
			design that is not a deny rule at all — it is design §7.1's conjunction.
			The matter carries a classification, the matter team holds the
			clearance, and the firm-wide grant is irrelevant to anyone who does not.`,
		Governs:   []string{"§7.1", "§7.2", "§8.3", "CAS §9.3", "A3"},
		Status:    scenario.StatusPending,
		PendingOn: []scenario.Capability{scenario.CapDecide, scenario.CapTupleStore, scenario.CapClassificationStore},
		Fixture: scenario.Fixture{
			Tenant: "lawfirm",
			Kinds:  legalKinds(),
			Principals: []scenario.PrincipalSpec{
				user("user:anne", "associate on the Nordwind matter team", "group:all-timekeepers"),
				user("user:dave", "partner, conflicted: once acted for the opponent", "group:all-timekeepers"),
				user("user:ruth", "managing partner. Holds every discretionary power the firm has", "group:all-timekeepers"),
				securityService(),
			},
			Groups: []scenario.GroupSpec{
				{
					Name:    "group:all-timekeepers",
					Members: []string{"user:anne", "user:dave", "user:ruth"},
					Note:    "an ordinary, directory-synced *tier-1* group. It can hold grants and never a clearance",
				},
			},
			ClearanceGroups: []scenario.ClearanceGroupSpec{
				{
					Name:    "clearance:matter-1234-team",
					Channel: iam.MandatoryChannelClassify,
					Members: []string{"user:anne"},
					Labels:  []string{"conflict:matter-1234"},
					Reason:  "conflict screen on matter 1234: the matter team only",
				},
			},
			Containment: []scenario.Edge{
				scenario.E("fileset:pleadings", "matter:1234"),
				scenario.E("document:statement-of-claim", "fileset:pleadings"),
				scenario.E("document:engagement-letter", "matter:1234"),
				scenario.E("document:firm-newsletter", "matter:0000"),
			},
			Classifications: []scenario.Classification{
				{
					Label: "conflict:matter-1234", Enforcement: scenario.EnforcementPolicy,
					Why: "an ethical wall. Enforced by policy rather than by a key, because the firm's own " +
						"systems must still index and search the matter for the team that may see it",
				},
			},
			Assignments: []scenario.Assignment{scenario.AS("matter:1234", "conflict:matter-1234")},
			Tuples: []scenario.Tuple{
				{
					Object: scenario.R("matter:1234"), Relation: "viewer",
					Subject: scenario.US("group:all-timekeepers", "member"),
					Note:    "the firm-wide grant. Real, deliberate, and powerless against the screen",
				},
				{
					Object: scenario.R("matter:0000"), Relation: "viewer",
					Subject: scenario.US("group:all-timekeepers", "member"),
					Note:    "the same grant shape on an unclassified matter, for contrast",
				},
				{
					Object: scenario.R("document:statement-of-claim"), Relation: "owner",
					Subject: scenario.P("user:ruth"),
					Note: "the managing partner owns the document outright. Ownership is the strongest " +
						"discretionary relation there is and it does not help her",
				},
			},
		},
		Expect: []scenario.Expectation{
			{
				Principal: "user:anne", Action: "read", Resource: scenario.R("document:statement-of-claim"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "matter:1234#viewer@group:all-timekeepers#member",
				Note: "she passes the gate through the clearance group, and then the ordinary firm-wide " +
					"grant is what actually grants her. The two tiers compose rather than competing",
			},
			{
				Principal: "user:dave", Action: "read", Resource: scenario.R("document:statement-of-claim"),
				Want: scenario.Deny, Reason: scenario.ReasonClassification, Because: "conflict:matter-1234",
				Note: "the screen. He holds the firm-wide grant and it is never consulted, because §7.1 " +
					"evaluates the gate first so the attempt is auditable without being informative",
			},
			{
				Principal: "user:dave", Action: "read", Resource: scenario.R("matter:1234"),
				Want: scenario.Deny, Reason: scenario.ReasonClassification, Because: "conflict:matter-1234",
				Note: "and he cannot see the matter itself, so he cannot learn it exists by being refused it",
			},
			{
				Principal: "user:ruth", Action: "read", Resource: scenario.R("document:statement-of-claim"),
				Want: scenario.Deny, Reason: scenario.ReasonClassification, Because: "conflict:matter-1234",
				Note: "the managing partner, who owns the document. This row is the design's hardest claim: " +
					"an absolute that survives any owner and any project admin",
			},
			{
				Principal: "user:dave", Action: "read", Resource: scenario.R("document:firm-newsletter"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "matter:0000#viewer@group:all-timekeepers#member",
				Note:    "the screen is a label on one matter, not a change to how the firm works",
			},
		},
		Claims: []scenario.Claim{
			scenario.C(scenario.ClaimSchemaAccepted, "matter", "",
				"the firm's schema contains no exclusion operator, so CI accepts it (§4/A3 corollary 3)"),
			scenario.C(scenario.ClaimLabelSet, "document:statement-of-claim", "conflict:matter-1234",
				"the label was assigned to the matter and the document two hops down carries it, because "+
					"§8.3 resolves classifications over the ancestry closure as well as over derivation"),
			scenario.C(scenario.ClaimLiveClearances, "user:dave", "",
				"against the real registry: the conflicted partner holds no clearance"),
			scenario.C(scenario.ClaimLiveClearances, "user:ruth", "",
				"and neither does the managing partner. Clearances are administered by a security function, "+
					"not conferred by seniority"),
			scenario.C(scenario.ClaimNoClearanceFromDiscretion, "user:dave", "",
				"every discretionary operation the registry exposes is applied on Dave's behalf — added to "+
					"every group, the issuer asserting the compartment's own name as a claim, an agent run "+
					"delegated from a cleared colleague, an ordinary group id presented as a clearance group "+
					"id — and he still holds none"),
		},
	}
}

func needToKnow() scenario.Scenario {
	return scenario.Scenario{
		ID:    "M2",
		Title: "Need-to-know, the positive form: restrict a matter to a named team",
		Models: `The same mechanism written the other way round. M1 excludes one
			conflicted partner from an otherwise open matter; here the matter is
			closed and a named team is let in. This is the form that scales, because
			it does not require anybody to remember an exclusion: the rule is one
			label on the matter, and the question "who may see this" has exactly one
			answer — whoever the mandatory channel admitted. Design §8.3's note on
			administration is the reason this is tractable: a directory-synced
			clearance group keeps a firm workable, because employment is an
			authoritative fact rather than a discretionary share.`,
		Governs:   []string{"§8.3", "§7.1", "KGS §9.3"},
		Status:    scenario.StatusPending,
		PendingOn: []scenario.Capability{scenario.CapDecide, scenario.CapTupleStore, scenario.CapClassificationStore},
		Fixture: scenario.Fixture{
			Tenant: "lawfirm",
			Kinds:  legalKinds(),
			Principals: []scenario.PrincipalSpec{
				user("user:sven", "on the deal team", "group:all-timekeepers"),
				user("user:tara", "on the deal team", "group:all-timekeepers"),
				user("user:umar", "a timekeeper with no need to know", "group:all-timekeepers"),
				user("user:vera", "a timekeeper with no need to know", "group:all-timekeepers"),
				securityService(),
			},
			Groups: []scenario.GroupSpec{
				{
					Name:    "group:all-timekeepers",
					Members: []string{"user:sven", "user:tara", "user:umar", "user:vera"},
				},
			},
			ClearanceGroups: []scenario.ClearanceGroupSpec{
				{
					Name:    "clearance:project-seagull",
					Channel: iam.MandatoryChannelClassify,
					Members: []string{"user:sven", "user:tara"},
					Labels:  []string{"need-to-know:project-seagull"},
					Reason:  "deal team for project Seagull, admitted by the security function",
				},
			},
			Containment: []scenario.Edge{
				scenario.E("fileset:due-diligence", "matter:5678"),
				scenario.E("document:target-valuation", "fileset:due-diligence"),
				scenario.E("document:spa-draft", "fileset:due-diligence"),
			},
			Classifications: []scenario.Classification{
				{
					Label: "need-to-know:project-seagull", Enforcement: scenario.EnforcementPolicy,
					Why: "a deal compartment. One label at the matter covers everything inside it",
				},
			},
			Assignments: []scenario.Assignment{scenario.AS("matter:5678", "need-to-know:project-seagull")},
			Tuples: []scenario.Tuple{
				{
					Object: scenario.R("matter:5678"), Relation: "viewer",
					Subject: scenario.US("group:all-timekeepers", "member"),
					Note: "the firm-wide grant again, unchanged. Closing a matter is a mandatory act " +
						"and never an edit to the firm's sharing",
				},
			},
		},
		Expect: []scenario.Expectation{
			{
				Principal: "user:sven", Action: "read", Resource: scenario.R("document:target-valuation"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "matter:5678#viewer@group:all-timekeepers#member",
			},
			{
				Principal: "user:tara", Action: "read", Resource: scenario.R("document:spa-draft"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "matter:5678#viewer@group:all-timekeepers#member",
			},
			{
				Principal: "user:umar", Action: "read", Resource: scenario.R("document:target-valuation"),
				Want: scenario.Deny, Reason: scenario.ReasonClassification, Because: "need-to-know:project-seagull",
			},
			{
				Principal: "user:vera", Action: "read", Resource: scenario.R("document:spa-draft"),
				Want: scenario.Deny, Reason: scenario.ReasonClassification, Because: "need-to-know:project-seagull",
				Note: "two denials and nobody wrote an exclusion. Add a fifth timekeeper tomorrow and " +
					"they are denied too, with no rule to remember",
			},
		},
		Claims: []scenario.Claim{
			scenario.C(scenario.ClaimSchemaAccepted, "matter", "", ""),
			scenario.C(scenario.ClaimLabelSet, "document:spa-draft", "need-to-know:project-seagull",
				"one assignment on the matter reaches every document inside it"),
			scenario.C(scenario.ClaimTuplesPerHop, "1", "4",
				"one grant tuple, one classification assignment, four objects. The positive form costs "+
					"no more than the negative one and cannot be forgotten"),
			scenario.C(scenario.ClaimLiveClearances, "user:sven", "clearance:project-seagull", ""),
			scenario.C(scenario.ClaimLiveClearances, "user:umar", "", ""),
		},
	}
}

func everyoneExceptBob() scenario.Scenario {
	return scenario.Scenario{
		ID:    "M3",
		Title: "`Everyone except Bob`, as a clearance group that does not contain Bob",
		Models: `A two-thousand-person firm needs one person kept out of one thing. In a
			relationship model with an exclusion operator this is a rule that has to
			appear in every permission on every resource type and be remembered for
			every type added later, where one omission is a silent bypass rather than
			an error — design §5a, and the reason this design has no such operator.
			Here it is a clearance group that does not contain Bob, maintained
			through the mandatory channel, and the sentence design §8.3 uses is the
			whole answer: "rather than 1,999 individual grants". The channel is
			directory-sync, because the membership tracks employment, which is an
			authoritative fact somebody else already maintains.`,
		Governs:   []string{"§8.3", "§5a exclusion", "§7.2.1 locality"},
		Status:    scenario.StatusPending,
		PendingOn: []scenario.Capability{scenario.CapDecide, scenario.CapTupleStore, scenario.CapClassificationStore},
		Fixture: scenario.Fixture{
			Tenant: "lawfirm",
			Kinds:  legalKinds(),
			Principals: []scenario.PrincipalSpec{
				user("user:alice", "staff", "group:all-staff"),
				user("user:bob", "the one person kept out", "group:all-staff"),
				user("user:chen", "staff", "group:all-staff"),
				securityService(),
			},
			Groups: []scenario.GroupSpec{
				{
					Name:    "group:all-staff",
					Members: []string{"user:alice", "user:bob", "user:chen"},
					Note:    "Bob is in the ordinary group, because he works here. That is the point",
				},
			},
			ClearanceGroups: []scenario.ClearanceGroupSpec{
				{
					Name:    "clearance:staff-except-bob",
					Channel: iam.MandatoryChannelDirectorySync,
					Members: []string{"user:alice", "user:chen"},
					Labels:  []string{"restricted:not-bob"},
					Reason:  "directory sync: all staff bar the named exclusion, maintained by HR's feed",
				},
			},
			Containment: []scenario.Edge{
				scenario.E("document:board-minutes", "fileset:governance"),
				scenario.E("document:staff-handbook", "fileset:governance"),
			},
			Classifications: []scenario.Classification{
				{
					Label: "restricted:not-bob", Enforcement: scenario.EnforcementPolicy,
					Why: "one person must not see the board minutes. Expressed as a positive clearance " +
						"whose membership happens to omit him",
				},
			},
			Assignments: []scenario.Assignment{scenario.AS("document:board-minutes", "restricted:not-bob")},
			Tuples: []scenario.Tuple{
				{
					Object: scenario.R("fileset:governance"), Relation: "viewer",
					Subject: scenario.US("group:all-staff", "member"),
					Note:    "one grant for the whole firm, and it is not edited to keep Bob out",
				},
			},
		},
		Expect: []scenario.Expectation{
			{
				Principal: "user:alice", Action: "read", Resource: scenario.R("document:board-minutes"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "fileset:governance#viewer@group:all-staff#member",
			},
			{
				Principal: "user:bob", Action: "read", Resource: scenario.R("document:board-minutes"),
				Want: scenario.Deny, Reason: scenario.ReasonClassification, Because: "restricted:not-bob",
				Note: "he holds the firm-wide grant and is a member of the ordinary group. The clearance " +
					"group is a different object in a different tier and he is not in it",
			},
			{
				Principal: "user:bob", Action: "read", Resource: scenario.R("document:staff-handbook"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "fileset:governance#viewer@group:all-staff#member",
				Note: "and the exclusion is local to the one document that carries the label, which is " +
					"the opposite of an exclusion operator being local to the permission it is written in",
			},
		},
		Claims: []scenario.Claim{
			scenario.C(scenario.ClaimSchemaAccepted, "document", "",
				"no exclusion operator anywhere, so the schema lint accepts it"),
			scenario.C(scenario.ClaimLiveClearances, "user:bob", "",
				"against the real registry: he is in the ordinary group and in no clearance group"),
			scenario.C(scenario.ClaimLiveGroups, "user:bob", "group:all-staff",
				"both facts at once, from the same registry, in two different tiers"),
			scenario.C(scenario.ClaimNoClearanceFromDiscretion, "user:bob", "",
				"and no discretionary operation puts him in it"),
		},
	}
}

func newJoiner() scenario.Scenario {
	return scenario.Scenario{
		ID:    "M4",
		Title: "A new joiner holds no clearances and sees nothing classified",
		Models: `Somebody starts on Monday. Their first login JIT-provisions them from
			their token: they exist, they are in the groups their claims named, and
			they can do their job. They hold no clearance, so they see nothing
			classified until a mandatory act includes them. Design §8.3 states this
			as fail-closed behaviour and the registry makes it structural rather
			than remembered: every clearance write demands an iam.MandatoryAct,
			Claims carries neither an actor nor a channel, and MandatoryAct's fields
			are unexported — so the provisioning path cannot construct the witness
			it would need. This scenario's claims run live, which means the property
			is tested rather than described.`,
		Governs:   []string{"§8.3", "§8.1 JIT"},
		Status:    scenario.StatusPending,
		PendingOn: []scenario.Capability{scenario.CapDecide, scenario.CapClassificationStore},
		Fixture: scenario.Fixture{
			Tenant: "lawfirm",
			Kinds:  legalKinds(),
			Principals: []scenario.PrincipalSpec{
				user("user:newjoiner", "started this morning; the issuer asserted two groups",
					"group:all-timekeepers", "group:litigation"),
				user("user:anne", "already on the matter team", "group:all-timekeepers"),
				securityService(),
			},
			Groups: []scenario.GroupSpec{
				{Name: "group:all-timekeepers", Members: []string{"user:anne"}},
			},
			ClearanceGroups: []scenario.ClearanceGroupSpec{
				{
					Name:    "clearance:matter-1234-team",
					Channel: iam.MandatoryChannelClassify,
					Members: []string{"user:anne"},
					Labels:  []string{"conflict:matter-1234"},
					Reason:  "matter team as at the new joiner's start date",
				},
			},
			Containment: []scenario.Edge{
				scenario.E("document:statement-of-claim", "matter:1234"),
				scenario.E("document:firm-handbook", "matter:0000"),
			},
			Classifications: []scenario.Classification{
				{Label: "conflict:matter-1234", Enforcement: scenario.EnforcementPolicy, Why: "ethical wall"},
			},
			Assignments: []scenario.Assignment{scenario.AS("matter:1234", "conflict:matter-1234")},
			Tuples: []scenario.Tuple{
				{
					Object: scenario.R("matter:1234"), Relation: "viewer",
					Subject: scenario.US("group:all-timekeepers", "member"),
				},
				{
					Object: scenario.R("matter:0000"), Relation: "viewer",
					Subject: scenario.US("group:all-timekeepers", "member"),
				},
			},
		},
		Expect: []scenario.Expectation{
			{
				Principal: "user:newjoiner", Action: "read", Resource: scenario.R("document:firm-handbook"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "matter:0000#viewer@group:all-timekeepers#member",
				Note: "his claim-derived group membership is real and joinable on day one, so he can " +
					"do unclassified work immediately. Provisioning is not a bottleneck",
			},
			{
				Principal: "user:newjoiner", Action: "read", Resource: scenario.R("document:statement-of-claim"),
				Want: scenario.Deny, Reason: scenario.ReasonClassification, Because: "conflict:matter-1234",
				Note: "and nothing classified, through the same grant, until a mandatory act includes him",
			},
		},
		Claims: []scenario.Claim{
			scenario.C(scenario.ClaimLiveGroups, "user:newjoiner", "group:all-timekeepers, group:litigation",
				"JIT provisioning upserted both claim-derived groups into the registry as joinable rows"),
			scenario.C(scenario.ClaimLiveClearances, "user:newjoiner", "",
				"and gave him no clearance. Identity is not clearance, and the type system is what "+
					"makes that true rather than a convention: the provisioning path cannot construct a "+
					"MandatoryAct, because Claims carries no actor and no channel"),
			scenario.C(scenario.ClaimNoClearanceFromDiscretion, "user:newjoiner", "",
				"including when the issuer asserts the compartment's own name as a claim-derived group — "+
					"the widest discretionary channel there is, since an IdP administrator controls it"),
		},
	}
}

func everyAdminAttemptsTheGate() scenario.Scenario {
	return scenario.Scenario{
		ID:    "M5",
		Title: "A project admin, an owner and a group admin each attempt the gate; all fail",
		Models: `Design §4/A3 is the anti-goal this module exists for, and it is stated
			as a testable invariant: no sequence of discretionary operations —
			grants, shares, role assignments, ownership transfers, schema changes or
			link creation — performed by any principal, including owners and project
			admins, can cause a classification gate to pass for a principal that
			does not satisfy it. This scenario is that invariant with the attack
			already carried out. Eve is not a victim of a missing grant: she has
			been given everything. She owns the document outright, she holds the
			project-admin role, she administers the group that holds the firm-wide
			grant, somebody wrote her a direct viewer tuple, and a share link names
			her. She is still denied, by a label, for a reason the corpus names.`,
		Governs:   []string{"A3", "§7.1", "§7.2", "§8.3"},
		Status:    scenario.StatusPending,
		PendingOn: []scenario.Capability{scenario.CapDecide, scenario.CapTupleStore, scenario.CapClassificationStore},
		Fixture: scenario.Fixture{
			Tenant: "lawfirm",
			Kinds:  legalKinds(),
			Principals: []scenario.PrincipalSpec{
				user("user:eve", "the principal every discretionary power in the firm has been pointed at",
					"group:all-timekeepers", "group:admins"),
				user("user:anne", "on the matter team, and the only principal who may read it", "group:all-timekeepers"),
				securityService(),
			},
			Groups: []scenario.GroupSpec{
				{Name: "group:all-timekeepers", Members: []string{"user:eve", "user:anne"}},
				{
					Name: "group:admins", Members: []string{"user:eve"},
					Note: "she administers this group, so she can add anyone to it, including herself",
				},
			},
			ClearanceGroups: []scenario.ClearanceGroupSpec{
				{
					Name:    "clearance:matter-9999-team",
					Channel: iam.MandatoryChannelClassify,
					Members: []string{"user:anne"},
					Labels:  []string{"conflict:matter-9999"},
					Reason:  "matter 9999 is screened to its team",
				},
			},
			Containment: []scenario.Edge{
				scenario.E("role:project-admin", "matter:9999"),
				scenario.E("fileset:evidence", "matter:9999"),
				scenario.E("document:witness-statement", "fileset:evidence"),
			},
			Classifications: []scenario.Classification{
				{Label: "conflict:matter-9999", Enforcement: scenario.EnforcementPolicy, Why: "ethical wall on matter 9999"},
			},
			Assignments: []scenario.Assignment{scenario.AS("matter:9999", "conflict:matter-9999")},
			Tuples: []scenario.Tuple{
				{
					Object: scenario.R("role:project-admin"), Relation: "assignee",
					Subject: scenario.P("user:eve"), Note: "attempt 1: a role assignment",
				},
				{
					Object: scenario.R("matter:9999"), Relation: "owner",
					Subject: scenario.US("role:project-admin", "assignee"),
					Note:    "attempt 2: the project-admin role owns the matter, so she owns the matter",
				},
				{
					Object: scenario.R("document:witness-statement"), Relation: "owner",
					Subject: scenario.P("user:eve"), Note: "attempt 3: an ownership transfer of the document itself",
				},
				{
					Object: scenario.R("document:witness-statement"), Relation: "viewer",
					Subject: scenario.P("user:eve"), Note: "attempt 4: a direct grant, written by somebody who could",
				},
				{
					Object: scenario.R("matter:9999"), Relation: "viewer",
					Subject: scenario.US("group:admins", "member"),
					Note:    "attempt 5: a grant to the group she administers",
				},
				{
					Object: scenario.R("fileset:evidence"), Relation: "editor",
					Subject: scenario.US("group:all-timekeepers", "member"),
					Note:    "attempt 6: the firm-wide grant, at a level between the label and the document",
				},
			},
		},
		Expect: []scenario.Expectation{
			{
				Principal: "user:eve", Action: "read", Resource: scenario.R("document:witness-statement"),
				Want: scenario.Deny, Reason: scenario.ReasonClassification, Because: "conflict:matter-9999",
				Note: "six discretionary grants, five of them hers to make, and the gate is evaluated " +
					"before any of them is looked at",
			},
			{
				Principal: "user:eve", Action: "write", Resource: scenario.R("document:witness-statement"),
				Want: scenario.Deny, Reason: scenario.ReasonClassification, Because: "conflict:matter-9999",
			},
			{
				Principal: "user:eve", Action: "share", Resource: scenario.R("matter:9999"),
				Want: scenario.Deny, Reason: scenario.ReasonClassification, Because: "conflict:matter-9999",
				Note: "she cannot even exercise the ownership she holds, so she cannot escalate by " +
					"re-granting to a third party",
			},
			{
				Principal: "user:anne", Action: "read", Resource: scenario.R("document:witness-statement"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "fileset:evidence#editor@group:all-timekeepers#member",
				Note: "the matter is readable by its team through the ordinary firm-wide grant, so the " +
					"scenario is not passing because nothing works",
			},
		},
		Claims: []scenario.Claim{
			scenario.C(scenario.ClaimSchemaAccepted, "matter", "",
				"every attempt above is written in the permitted subset, which is what makes the "+
					"adversarial suite enumerable at all: a restricted language is one you can exhaust"),
			scenario.C(scenario.ClaimNoClearanceFromDiscretion, "user:eve", "",
				"the live half, against the real registry: added to every ordinary group including the "+
					"one she administers, re-provisioned with the compartment's name asserted as a claim, "+
					"an agent run delegated from the cleared associate, and an ordinary group's id "+
					"presented where a clearance group's is expected — all of it, and she holds none"),
			scenario.C(scenario.ClaimLiveClearances, "user:anne", "clearance:matter-9999-team",
				"meanwhile the one principal a mandatory act admitted holds exactly one clearance"),
		},
	}
}

func derivationPropagation() scenario.Scenario {
	return scenario.Scenario{
		ID:    "M6",
		Title: "A pipeline cannot launder a classification by deriving",
		Models: `kgs's consolidator reads filtered facts and writes derived beliefs back
			into the same store. If classifications stopped propagating at the read
			boundary — which is what Foundry does, and design §5a quotes it — a
			belief derived from privileged evidence would land unclassified, and the
			whole mandatory layer would have a door in it marked "run a pipeline".
			So design §8.3 propagates through derivation unconditionally: a derived
			object carries the union of its inputs' classifications, consumers
			declare the derivation and the module computes the union. This scenario
			includes the laundering attempt explicitly — an output with no
			assignment of its own, derived from a classified input — and the
			classification is still there.`,
		Governs:   []string{"§8.3 derivation", "A3 corollary 1", "KGS §8.7", "KGS §8.5 #15"},
		Status:    scenario.StatusPending,
		PendingOn: []scenario.Capability{scenario.CapDecide, scenario.CapClassificationStore, scenario.CapDerivation},
		Fixture: scenario.Fixture{
			Tenant: "lawfirm",
			Kinds: append(legalKinds(),
				scenario.ResourceKind{
					Name: "fact", Shape: scenario.ShapeRow,
					Relations: []scenario.Relation{
						{Name: "viewer", Direct: true, Usersets: []string{"group#member"}, InheritFromParent: []string{"viewer"}},
					},
					Actions: map[string]string{"read": "viewer"},
				},
				scenario.ResourceKind{
					Name: "observation", Shape: scenario.ShapeRow,
					Relations: []scenario.Relation{
						{Name: "viewer", Direct: true, Usersets: []string{"group#member"}, InheritFromParent: []string{"viewer"}},
					},
					Actions: map[string]string{"read": "viewer"},
				},
			),
			Principals: []scenario.PrincipalSpec{
				user("user:anne", "cleared for the privileged matter", "group:all-timekeepers"),
				user("user:dave", "not cleared", "group:all-timekeepers"),
				{
					Name: "service:consolidator", Kind: iam.PrincipalKindService,
					Role: "reads facts it is authorized for and writes derived beliefs back",
				},
				securityService(),
			},
			Groups: []scenario.GroupSpec{
				{Name: "group:all-timekeepers", Members: []string{"user:anne", "user:dave"}},
			},
			ClearanceGroups: []scenario.ClearanceGroupSpec{
				{
					Name: "clearance:privileged", Channel: iam.MandatoryChannelClassify,
					Members: []string{"user:anne"}, Labels: []string{"privileged"},
					Reason: "legal professional privilege: the matter team only",
				},
			},
			Containment: []scenario.Edge{
				scenario.E("fact:advice-given", "matter:1234"),
				scenario.E("fact:invoice-raised", "matter:0000"),
				scenario.E("observation:billing-pattern", "matter:0000"),
				scenario.E("observation:laundered", "matter:0000"),
			},
			Classifications: []scenario.Classification{
				{Label: "privileged", Enforcement: scenario.EnforcementPolicy, Why: "legal professional privilege"},
			},
			Assignments: []scenario.Assignment{scenario.AS("matter:1234", "privileged")},
			Derivations: []scenario.Derivation{
				{
					Output: scenario.R("observation:billing-pattern"),
					Inputs: []scenario.Ref{scenario.R("fact:advice-given"), scenario.R("fact:invoice-raised")},
					Note:   "one privileged input and one ordinary one: the union is privileged",
				},
				{
					Output: scenario.R("observation:laundered"),
					Inputs: []scenario.Ref{scenario.R("fact:advice-given")},
					Note: "the laundering attempt: written into an unclassified matter, with no " +
						"assignment of its own, by a pipeline that read a privileged input",
				},
			},
			Tuples: []scenario.Tuple{
				{
					Object: scenario.R("matter:1234"), Relation: "viewer",
					Subject: scenario.US("group:all-timekeepers", "member"),
				},
				{
					Object: scenario.R("matter:0000"), Relation: "viewer",
					Subject: scenario.US("group:all-timekeepers", "member"),
				},
			},
		},
		Expect: []scenario.Expectation{
			{
				Principal: "user:dave", Action: "read", Resource: scenario.R("observation:laundered"),
				Want: scenario.Deny, Reason: scenario.ReasonClassification, Because: "privileged",
				Note: "the row that matters. The observation lives in an unclassified matter, carries no " +
					"label of its own, and is denied because it was *derived* from privileged evidence",
			},
			{
				Principal: "user:dave", Action: "read", Resource: scenario.R("observation:billing-pattern"),
				Want: scenario.Deny, Reason: scenario.ReasonClassification, Because: "privileged",
				Note: "the union of a privileged input and an ordinary one is privileged, not the intersection",
			},
			{
				Principal: "user:dave", Action: "read", Resource: scenario.R("fact:invoice-raised"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "matter:0000#viewer@group:all-timekeepers#member",
				Note:    "the ordinary input is readable, so propagation is not simply denying everything",
			},
			{
				Principal: "user:anne", Action: "read", Resource: scenario.R("observation:laundered"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "matter:0000#viewer@group:all-timekeepers#member",
				Note:    "and the cleared principal reads the derived belief normally",
			},
		},
		Claims: []scenario.Claim{
			scenario.C(scenario.ClaimLabelSet, "observation:laundered", "privileged",
				"the derived object's resolved label set, computed as the union over its inputs, "+
					"transitively, with no read boundary (§8.3, departing from Foundry)"),
			scenario.C(scenario.ClaimLabelSet, "observation:billing-pattern", "privileged",
				"union and not intersection: one privileged input is enough"),
			scenario.C(scenario.ClaimLabelSet, "fact:invoice-raised", "",
				"and the ordinary input resolves to no label, so the propagation is not a blanket"),
			scenario.C(scenario.ClaimProviderRefused, "observation:billing-pattern", "",
				"KGS leak channel #15: a model provider allowlisted for nothing never receives the "+
					"derived observation either, because the gate reads the same resolved label set"),
		},
	}
}
