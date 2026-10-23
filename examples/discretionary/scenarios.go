// Package discretionary holds the corpus's grant-layer use cases, which
// are now the only policy layer there is: sharing a folder, nesting
// containers, a workspace with roles, a grant to a team, a share link, an
// ownership transfer, finding a deep object without seeing its siblings,
// and — since the mandatory tier's removal — the legal ethical wall, which
// is a grant nobody writes.
//
// Every scenario here is expressed in design §8.2's four composition forms
// and nothing else, which is what §8.5 means by calling the restriction a
// feature: the permitted subset is exactly what flattens into §9's
// closures, and a scenario that needed a fifth form would be a scenario
// this package could not contain. Two of them are in
// examples/unexpressible for that reason.
//
// This package used to be prefaced by "nothing in this directory can keep
// anybody out — if you are looking for 'this person must never see this',
// you want examples/mandatory". That directory is gone, and so is the
// second half of the sentence. Default-deny is what keeps people out, and
// the only thing stronger than a grant nobody wrote is a key the
// deployment does not hold, which is `escrow` rather than any row in this
// module. D8 is that answer written down.
//
// See README.md in this directory for the shape of each answer before the
// code.
package discretionary

import (
	"github.com/laenenai/iam"
	"github.com/laenenai/iam/examples/scenario"
)

// driveKinds is the registered schema a Drive-shaped consumer declares
// (design §8.4): a team whose membership is a userset, a role as a
// first-class object parented to a container, and two nestable resource
// kinds whose `viewer` is inherited from their parent at one tuple per
// hop.
//
// Note what is *not* here. There is no `blocked` relation and no
// `but not`: the schema lint rejects an exclusion operator, and the reason
// is no longer that absolutes belong in another tier but that there is no
// other tier and no deny at all. There is no per-resource-type role,
// because a role is an object: adding `report` below costs one kind and no
// roles.
func driveKinds() []scenario.ResourceKind {
	container := func(name string) scenario.ResourceKind {
		return scenario.ResourceKind{
			Name:  name,
			Shape: scenario.ShapeColumnar,
			Relations: []scenario.Relation{
				{Name: "owner", Direct: true, Usersets: []string{"team#member", "role#assignee"}},
				{
					Name: "editor", Direct: true,
					Usersets:          []string{"team#member", "role#assignee"},
					InheritFromParent: []string{"editor"},
					Union:             []string{"owner"},
				},
				{
					Name: "viewer", Direct: true,
					Usersets:          []string{"team#member", "role#assignee"},
					InheritFromParent: []string{"viewer"},
					Union:             []string{"editor", "owner"},
				},
			},
			Actions: map[string]string{"read": "viewer", "write": "editor", "share": "owner"},
		}
	}
	return []scenario.ResourceKind{
		{
			Name:      "team",
			Relations: []scenario.Relation{{Name: "member", Direct: true}},
			Actions:   map[string]string{"read": "member"},
		},
		{
			Name: "role",
			Relations: []scenario.Relation{
				{Name: "assignee", Direct: true, Usersets: []string{"team#member"}},
				{Name: "ownership", Direct: true},
			},
			Actions: map[string]string{"assume": "assignee", "administer": "ownership"},
		},
		{
			Name: "workspace", Shape: scenario.ShapeColumnar,
			Relations: []scenario.Relation{
				{Name: "owner", Direct: true, Usersets: []string{"team#member", "role#assignee"}},
				{Name: "editor", Direct: true, Usersets: []string{"team#member", "role#assignee"}, Union: []string{"owner"}},
				{Name: "viewer", Direct: true, Usersets: []string{"team#member", "role#assignee"}, Union: []string{"editor", "owner"}},
			},
			Actions: map[string]string{"read": "viewer", "write": "editor", "share": "owner"},
		},
		container("folder"),
		container("document"),
		container("report"),
	}
}

func user(name, role string, claimGroups ...string) scenario.PrincipalSpec {
	return scenario.PrincipalSpec{
		Name:        name,
		Kind:        iam.PrincipalKindUser,
		ClaimGroups: claimGroups,
		Role:        role,
	}
}

// Scenarios returns the discretionary use cases.
func Scenarios() []scenario.Scenario {
	return []scenario.Scenario{
		folderShare(),
		nestedContainers(),
		workspaceRoles(),
		grantToTeam(),
		linkSharing(),
		ownershipTransfer(),
		navigationalVisibility(),
		ethicalWall(),
	}
}

func folderShare() scenario.Scenario {
	return scenario.Scenario{
		ID:    "D1",
		Title: "Google-Drive-style folder share inherits down at one tuple per hop",
		Models: `Anne shares a project folder with Ben. Ben gets everything in it, and
			everything added to it later, and nobody writes a grant per file. This is
			the behaviour design §8.2 names explicitly — "sharing a folder shares its
			contents; this is the Drive behaviour" — and it is form 3,
			tuple-to-userset inheritance. The number that matters is in the claim
			rather than the prose: one tuple reaches five objects, and anti-goal A2's
			closure budget exists to catch the implementation that writes five.`,
		Governs:   []string{"§8.2 form 3", "§9.2", "A2"},
		Status:    scenario.StatusPending,
		PendingOn: []scenario.Capability{scenario.CapDecide, scenario.CapTupleStore},
		Fixture: scenario.Fixture{
			Tenant: "acme",
			Kinds:  driveKinds(),
			Principals: []scenario.PrincipalSpec{
				user("user:anne", "owns the folder"),
				user("user:ben", "the person it is shared with"),
				user("user:carol", "an unrelated colleague, shares nothing"),
			},
			Containment: []scenario.Edge{
				scenario.E("document:brief", "folder:project-apollo"),
				scenario.E("document:budget", "folder:project-apollo"),
				scenario.E("document:timeline", "folder:project-apollo"),
				scenario.E("document:retro", "folder:project-apollo"),
			},
			Tuples: []scenario.Tuple{
				{
					Object: scenario.R("folder:project-apollo"), Relation: "owner",
					Subject: scenario.P("user:anne"),
					Note:    "Anne created the folder",
				},
				{
					Object: scenario.R("folder:project-apollo"), Relation: "viewer",
					Subject: scenario.P("user:ben"),
					Note:    "the one share, written once on the container",
				},
			},
		},
		Expect: []scenario.Expectation{
			{
				Principal: "user:ben", Action: "read", Resource: scenario.R("document:brief"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "folder:project-apollo#viewer@user:ben",
				Note:    "reached through the container, not through a tuple on the document",
			},
			{
				Principal: "user:ben", Action: "read", Resource: scenario.R("document:retro"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "folder:project-apollo#viewer@user:ben",
				Note:    "a document added later needs no new grant",
			},
			{
				Principal: "user:ben", Action: "write", Resource: scenario.R("document:brief"),
				Want: scenario.Deny, Reason: scenario.ReasonNoGrant,
				Note: "viewer is not editor; the share's shape is inherited too",
			},
			{
				Principal: "user:anne", Action: "write", Resource: scenario.R("document:budget"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "folder:project-apollo#owner@user:anne",
				Note:    "the owner's write reaches the contents through the same hop, by union with owner",
			},
			{
				Principal: "user:carol", Action: "read", Resource: scenario.R("document:brief"),
				Want: scenario.Deny, Reason: scenario.ReasonNoGrant,
				Note: "nothing reaches Carol, and a deny is rendered as not-found",
			},
		},
		Claims: []scenario.Claim{
			scenario.C(scenario.ClaimSchemaAccepted, "folder", "",
				"the whole share is expressible in §8.5's permitted subset, so it flattens into §9's closure"),
			scenario.C(scenario.ClaimTuplesPerHop, "2", "5",
				"two tuples reach five objects. A per-object materialization would have written one row per "+
					"(object, subject) pair, which is the cross product §9.2 forbids and A2 budgets against"),
		},
	}
}

func nestedContainers() scenario.Scenario {
	return scenario.Scenario{
		ID:    "D2",
		Title: "Several levels of nested containers, still one tuple",
		Models: `The same share, four levels deep: a department folder contains a year,
			which contains a client, which contains the document. Lakekeeper's
			pre-v4.12 model is the warning here — a single warehouse check over 68
			namespaces and 353 tables cost 59,378 dispatches because each descendant
			re-resolved authorization upward. Design §8.2 adopts their fix, the
			bare/effective split, and §9's projection is what makes it survive A2's
			depth-6, ten-million-row budget. This scenario pins the semantics the
			projection must preserve: the answer at depth four is the same as the
			answer at depth one, and it came from the same single tuple.`,
		Governs:   []string{"§8.2 form 3", "§8.2 bare/effective", "§9.2"},
		Status:    scenario.StatusPending,
		PendingOn: []scenario.Capability{scenario.CapDecide, scenario.CapTupleStore},
		Fixture: scenario.Fixture{
			Tenant: "acme",
			Kinds:  driveKinds(),
			Principals: []scenario.PrincipalSpec{
				user("user:dana", "the auditor, granted at the top"),
				user("user:erik", "granted in the middle"),
			},
			Containment: []scenario.Edge{
				scenario.E("folder:2026", "folder:finance"),
				scenario.E("folder:client-nordwind", "folder:2026"),
				scenario.E("document:ledger", "folder:client-nordwind"),
				scenario.E("document:receipts", "folder:client-nordwind"),
				scenario.E("folder:client-sudwest", "folder:2026"),
				scenario.E("document:sudwest-ledger", "folder:client-sudwest"),
			},
			Tuples: []scenario.Tuple{
				{
					Object: scenario.R("folder:finance"), Relation: "viewer",
					Subject: scenario.P("user:dana"),
					Note:    "one tuple at the root reaches four levels",
				},
				{
					Object: scenario.R("folder:client-nordwind"), Relation: "editor",
					Subject: scenario.P("user:erik"),
					Note:    "a grant in the middle reaches down and not up",
				},
			},
		},
		Expect: []scenario.Expectation{
			{
				Principal: "user:dana", Action: "read", Resource: scenario.R("document:ledger"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "folder:finance#viewer@user:dana",
				Note:    "four hops up, one tuple",
			},
			{
				Principal: "user:erik", Action: "write", Resource: scenario.R("document:receipts"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "folder:client-nordwind#editor@user:erik",
			},
			{
				Principal: "user:erik", Action: "read", Resource: scenario.R("document:sudwest-ledger"),
				Want: scenario.Deny, Reason: scenario.ReasonNoGrant,
				Note: "inheritance goes down. A grant on one client's folder reaches nothing in a sibling's",
			},
			{
				Principal: "user:erik", Action: "read", Resource: scenario.R("folder:2026"),
				Want: scenario.Deny, Reason: scenario.ReasonNoGrant,
				Note: "and it reaches nothing above itself either — navigational visibility (D7) is a " +
					"separate, weaker right than read",
			},
		},
		Claims: []scenario.Claim{
			scenario.C(scenario.ClaimSchemaAccepted, "folder", "", "nesting needs no new form"),
			scenario.C(scenario.ClaimTuplesPerHop, "2", "7",
				"two tuples reach seven objects across four levels"),
			scenario.C(scenario.ClaimPathCount, "document:ledger", "1",
				"containment here is a tree, so §8.2's `only on the direct path` means something. "+
					"The moment it is not — see U3 — it does not"),
		},
	}
}

func workspaceRoles() scenario.Scenario {
	return scenario.Scenario{
		ID:    "D3",
		Title: "A workspace with roles, where adding a resource type adds no roles",
		Models: `A workspace has members, and members have roles: reader, contributor,
			administrator. The naive model makes a permission per (role, resource
			kind) pair and multiplies on every new kind. Design §8.2 takes
			Lakekeeper's answer instead — a role is an object parented to a
			container, with ` + "`assignee`" + ` and ` + "`ownership`" + ` relations, and permissions are
			defined over relations. This scenario is the proof: the workspace
			contains documents and reports, two kinds, and the same single tuple
			grants both. Add a third kind tomorrow and the role table does not
			change.`,
		Governs:   []string{"§8.2 roles as objects", "§8.2 form 2", "§2 goal 5"},
		Status:    scenario.StatusPending,
		PendingOn: []scenario.Capability{scenario.CapDecide, scenario.CapTupleStore},
		Fixture: scenario.Fixture{
			Tenant: "acme",
			Kinds:  driveKinds(),
			Principals: []scenario.PrincipalSpec{
				user("user:frank", "workspace reader, through a role"),
				user("user:gita", "workspace administrator, through a role"),
				user("user:hugo", "in the engineering team, which holds the reader role"),
				user("user:iris", "not in the workspace at all"),
			},
			Groups: []scenario.GroupSpec{
				{Name: "team:eng", Members: []string{"user:hugo"}, Note: "an ordinary, discretionary team"},
			},
			Containment: []scenario.Edge{
				scenario.E("role:ws-reader", "workspace:atlas"),
				scenario.E("role:ws-admin", "workspace:atlas"),
				scenario.E("folder:docs", "workspace:atlas"),
				scenario.E("document:onboarding", "folder:docs"),
				scenario.E("report:q3-usage", "workspace:atlas"),
			},
			Tuples: []scenario.Tuple{
				{
					Object: scenario.R("role:ws-reader"), Relation: "assignee",
					Subject: scenario.P("user:frank"), Note: "a role assignment is a tuple on the role",
				},
				{
					Object: scenario.R("role:ws-reader"), Relation: "assignee",
					Subject: scenario.US("team:eng", "member"),
					Note:    "a whole team can hold a role; the role is still one object",
				},
				{
					Object: scenario.R("role:ws-admin"), Relation: "assignee",
					Subject: scenario.P("user:gita"),
				},
				{
					Object: scenario.R("workspace:atlas"), Relation: "viewer",
					Subject: scenario.US("role:ws-reader", "assignee"),
					Note:    "the one tuple that makes the reader role mean `may read this workspace`",
				},
				{
					Object: scenario.R("workspace:atlas"), Relation: "owner",
					Subject: scenario.US("role:ws-admin", "assignee"),
				},
			},
		},
		Expect: []scenario.Expectation{
			{
				Principal: "user:frank", Action: "read", Resource: scenario.R("document:onboarding"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "workspace:atlas#viewer@role:ws-reader#assignee",
				Note:    "the role reaches a document three hops down",
			},
			{
				Principal: "user:frank", Action: "read", Resource: scenario.R("report:q3-usage"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "workspace:atlas#viewer@role:ws-reader#assignee",
				Note: "the same tuple, a different resource kind. This row and the one above are the " +
					"whole point: `report` was added to the schema and no role was touched",
			},
			{
				Principal: "user:hugo", Action: "read", Resource: scenario.R("report:q3-usage"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "workspace:atlas#viewer@role:ws-reader#assignee",
				Note:    "a team holding a role: two usersets in a row, resolved by one mechanism",
			},
			{
				Principal: "user:gita", Action: "write", Resource: scenario.R("document:onboarding"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "workspace:atlas#owner@role:ws-admin#assignee",
				Note:    "the admin role reaches write by union with owner",
			},
			{
				Principal: "user:frank", Action: "write", Resource: scenario.R("document:onboarding"),
				Want: scenario.Deny, Reason: scenario.ReasonNoGrant,
				Note: "reader is reader, at every depth and in every kind",
			},
			{
				Principal: "user:iris", Action: "read", Resource: scenario.R("report:q3-usage"),
				Want: scenario.Deny, Reason: scenario.ReasonNoGrant,
			},
		},
		Claims: []scenario.Claim{
			scenario.C(scenario.ClaimSchemaAccepted, "workspace", "",
				"roles-as-objects needs no form beyond the userset; there is no cross product anywhere in the schema"),
			scenario.C(scenario.ClaimTuplesPerHop, "5", "6",
				"five tuples: three role assignments and two workspace grants. Six objects reached, two "+
					"resource kinds, three principals, and not one of those numbers multiplies the others"),
		},
	}
}

func grantToTeam() scenario.Scenario {
	return scenario.Scenario{
		ID:    "D4",
		Title: "Grant to a team as a userset; a membership change takes effect with no re-grant",
		Models: `Engineering gets access to the engineering handbook. The grant names
			` + "`team:eng#member`" + ` rather than its members, which is design §8.2's form 2,
			and the consequence is the one anti-goal A2 budgets for: when somebody
			joins the team, the authorization answer changes and *no grant is
			rewritten*. Sharing a 100,000-object container with a 50-member team
			must write 50 membership rows, not 5,000,000 projection rows, and the
			reason it can is that membership is the only set this design expands
			(§9.2's first closure). The membership half of this scenario runs live
			against the real registry today.`,
		Governs:   []string{"§8.2 form 2", "§8.1", "§9.2", "A2"},
		Status:    scenario.StatusPending,
		PendingOn: []scenario.Capability{scenario.CapDecide, scenario.CapTupleStore},
		Fixture: scenario.Fixture{
			Tenant: "acme",
			Kinds:  driveKinds(),
			Principals: []scenario.PrincipalSpec{
				user("user:jonas", "an engineer", "team:eng"),
				user("user:kim", "an engineer", "team:eng"),
				user("user:lena", "joins engineering during the scenario"),
			},
			Groups: []scenario.GroupSpec{
				{
					Name:    "team:eng",
					Members: []string{"user:jonas", "user:kim"},
					Note:    "declared once; materialized into real registry rows and read by the oracle",
				},
			},
			Containment: []scenario.Edge{
				scenario.E("document:handbook", "folder:eng-docs"),
				scenario.E("document:runbook", "folder:eng-docs"),
			},
			Tuples: []scenario.Tuple{
				{
					Object: scenario.R("folder:eng-docs"), Relation: "viewer",
					Subject: scenario.US("team:eng", "member"),
					Note:    "one tuple, naming the team and not its members",
				},
			},
		},
		Expect: []scenario.Expectation{
			{
				Principal: "user:jonas", Action: "read", Resource: scenario.R("document:handbook"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "folder:eng-docs#viewer@team:eng#member",
				Note:    "a userset grant on a container: form 2 inside form 3",
			},
			{
				Principal: "user:kim", Action: "read", Resource: scenario.R("document:runbook"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "folder:eng-docs#viewer@team:eng#member",
			},
			{
				Principal: "user:lena", Action: "read", Resource: scenario.R("document:handbook"),
				Want: scenario.Deny, Reason: scenario.ReasonNoGrant,
				Note: "before she joins. The claim below then adds her through the real registry",
			},
		},
		Claims: []scenario.Claim{
			scenario.C(scenario.ClaimSchemaAccepted, "folder", "", ""),
			scenario.C(scenario.ClaimLiveGroups, "user:jonas", "team:eng",
				"the claim-derived group the issuer asserted became a real, joinable registry row — "+
					"which is the whole reason identity lives in this module (§8.1: claims cannot be joined)"),
			scenario.C(scenario.ClaimMembershipChangeTakesEffect, "user:lena", "team:eng",
				"adding Lena changes what the predicate joins against and rewrites no grant. This runs "+
					"against the real registry"),
			scenario.C(scenario.ClaimTuplesPerHop, "1", "3",
				"one tuple for a whole team against a whole container"),
		},
	}
}

func linkSharing() scenario.Scenario {
	return scenario.Scenario{
		ID:    "D5",
		Title: "Link sharing: the subject is a capability token's bearer identity",
		Models: `Somebody sends a link to the lunch menu. Design §8.2 makes that a tuple
			whose subject is a capability token's bearer identity, minted and
			constrained by ` + "`captoken`" + `; this module stores the relationship and does
			not interpret caveats. That division is in CHARTER.md and it is why
			there is no expiry, no attenuation and no revocation chain anywhere in
			this scenario: the bearer identity is a principal like any other, so
			link sharing costs one tuple and no mechanism.`,
		Governs:   []string{"§8.2 link sharing", "§3 not a token library"},
		Status:    scenario.StatusPending,
		PendingOn: []scenario.Capability{scenario.CapDecide, scenario.CapTupleStore},
		Fixture: scenario.Fixture{
			Tenant: "acme",
			Kinds:  driveKinds(),
			Principals: []scenario.PrincipalSpec{
				user("user:marta", "shared the link"),
				{
					Name: "service:link-bearer-7f3a", Kind: iam.PrincipalKindService,
					Role: "the bearer identity captoken minted for one share link; iam stores the " +
						"relationship, captoken owns the caveats",
				},
				user("user:nour", "has no link and no grant"),
			},
			Containment: []scenario.Edge{
				scenario.E("document:lunch-menu", "folder:canteen"),
				scenario.E("document:supplier-contract", "folder:canteen"),
			},
			Tuples: []scenario.Tuple{
				{
					Object: scenario.R("folder:canteen"), Relation: "owner",
					Subject: scenario.P("user:marta"),
				},
				{
					Object: scenario.R("document:lunch-menu"), Relation: "viewer",
					Subject: scenario.P("service:link-bearer-7f3a"),
					Note: "written on the document, not the folder: a link shares one thing, " +
						"and the shape of the share is the shape of the tuple",
				},
			},
		},
		Expect: []scenario.Expectation{
			{
				Principal: "service:link-bearer-7f3a", Action: "read", Resource: scenario.R("document:lunch-menu"),
				Want: scenario.Allow, Reason: scenario.ReasonDirect,
				Because: "document:lunch-menu#viewer@service:link-bearer-7f3a",
			},
			{
				Principal: "service:link-bearer-7f3a", Action: "read", Resource: scenario.R("document:supplier-contract"),
				Want: scenario.Deny, Reason: scenario.ReasonNoGrant,
				Note: "a link to one document is not a link to its folder. Inheritance goes down, " +
					"and the tuple was written at the bottom",
			},
			{
				Principal: "service:link-bearer-7f3a", Action: "write", Resource: scenario.R("document:lunch-menu"),
				Want: scenario.Deny, Reason: scenario.ReasonNoGrant,
			},
			{
				Principal: "user:nour", Action: "read", Resource: scenario.R("document:lunch-menu"),
				Want: scenario.Deny, Reason: scenario.ReasonNoGrant,
				Note: "holding no link is holding no relation",
			},
		},
		Claims: []scenario.Claim{
			scenario.C(scenario.ClaimSchemaAccepted, "document", "",
				"a bearer identity is a principal, so link sharing is form 1 and needs no new form"),
		},
	}
}

func ownershipTransfer() scenario.Scenario {
	return scenario.Scenario{
		ID:    "D6",
		Title: "Ownership transfer carries everything, because grants are all there is to carry",
		Models: `Pascal hands the estate folder to his sister. Everything in the folder
			moves with it: she becomes owner, she can share it, she can read the
			contents, and he keeps only what he was left.

			That used to be half the story. The folder also carried a
			` + "`personal:pascal`" + ` classification, and the scenario's point was that
			design §8.3 forbade a classification from being "transferred with
			ownership" — so the new owner of a classified folder was an owner who
			could not read it, which was correct and initially surprising. There is
			no classification now, so the answer is the plain one, and this
			scenario's job is to show where the thing it used to protect went.

			It went to two places, both in the fixture below. A record the new
			owner must not see is a record that is not in the container being
			transferred: ` + "`document:letter`" + ` sits outside ` + "`folder:estate`" + ` and no grant
			reaches her, which is "never granted" doing the work a label used to
			do. And a record that must stay unreadable whatever a future owner
			decides is not a policy question at all — that is H4, and the
			mechanism is ` + "`escrow`" + `.`,
		Governs:   []string{"§8.2 form 1", "§7.1", "no-deny anti-goal"},
		Status:    scenario.StatusPending,
		PendingOn: []scenario.Capability{scenario.CapDecide, scenario.CapTupleStore},
		Fixture: scenario.Fixture{
			Tenant: "household",
			Kinds:  driveKinds(),
			Principals: []scenario.PrincipalSpec{
				user("user:pascal", "the original owner, who keeps one document and gives away the rest"),
				user("user:paula", "the new owner after the transfer"),
			},
			Containment: []scenario.Edge{
				scenario.E("document:deed", "folder:estate"),
				scenario.E("document:inventory", "folder:estate"),
				// Deliberately *not* in folder:estate. This edge's
				// absence is the whole mechanism.
				scenario.E("document:letter", "folder:pascal-private"),
			},
			Tuples: []scenario.Tuple{
				{
					Object: scenario.R("folder:estate"), Relation: "owner",
					Subject: scenario.P("user:paula"),
					Note:    "the transfer: ownership is a tuple, so transferring it is a tuple write",
				},
				{
					Object: scenario.R("folder:estate"), Relation: "viewer",
					Subject: scenario.P("user:pascal"),
					Note:    "the previous owner keeps a viewer relation",
				},
				{
					Object: scenario.R("folder:pascal-private"), Relation: "owner",
					Subject: scenario.P("user:pascal"),
					Note: "and the one container he did not hand over. Nothing names her on it, " +
						"which is the only policy-level way to withhold something now",
				},
			},
		},
		Expect: []scenario.Expectation{
			{
				Principal: "user:paula", Action: "share", Resource: scenario.R("folder:estate"),
				Want: scenario.Allow, Reason: scenario.ReasonDirect,
				Because: "folder:estate#owner@user:paula",
				Note: "she is the owner and that is now the end of it. This row used to be a deny " +
					"from the gate, which was evaluated first and made even her ownership unusable",
			},
			{
				Principal: "user:paula", Action: "read", Resource: scenario.R("document:deed"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "folder:estate#owner@user:paula",
				Note:    "and the contents come with the container, through one hop and by union with owner",
			},
			{
				Principal: "user:paula", Action: "read", Resource: scenario.R("document:letter"),
				Want: scenario.Deny, Reason: scenario.ReasonNoGrant,
				Note: "the row that replaces the old classification deny. It is a deny of exactly the " +
					"strength the mechanism has: nobody granted it to her, and he can grant it to her " +
					"tomorrow if he changes his mind — which a classification could not, and which is " +
					"the right answer for a private letter and the wrong one for an absolute",
			},
			{
				Principal: "user:pascal", Action: "share", Resource: scenario.R("folder:estate"),
				Want: scenario.Deny, Reason: scenario.ReasonNoGrant,
				Note: "he gave ownership away, and the discretionary layer did transfer",
			},
			{
				Principal: "user:pascal", Action: "read", Resource: scenario.R("document:deed"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "folder:estate#viewer@user:pascal",
				Note:    "while the viewer relation he kept still reaches the contents",
			},
		},
		Claims: []scenario.Claim{
			scenario.C(scenario.ClaimSchemaAccepted, "folder", "",
				"the transfer needs no form beyond the direct tuple, and there is nothing in this "+
					"schema that a transfer could fail to carry"),
			scenario.C(scenario.ClaimPathCount, "document:letter", "1",
				"the withheld document's only container is the one she holds nothing on. That is the "+
					"structural fact the withholding rests on, so it is asserted rather than described — "+
					"add one containment edge from folder:estate and the withholding is gone"),
			scenario.C(scenario.ClaimTuplesPerHop, "3", "5",
				"three tuples reach five objects. Two containers and one wall, where the wall is the "+
					"container nobody wrote a tuple for"),
		},
	}
}

func navigationalVisibility() scenario.Scenario {
	return scenario.Scenario{
		ID:    "D7",
		Title: "Bottom-up navigational visibility: the path to it, and only that path",
		Models: `Eva can read one school report, four levels down. She has to be able to
			find it, which means seeing the folders above it — and she must not
			learn that the finance folder beside them exists. Design §8.2 takes
			Lakekeeper's bi-directional inheritance for this and makes it an
			explicit ` + "`visible_below`" + `-style relation rather than a read-time
			derivation, because it is how a consumer answers "find the thing you may
			see" without revealing its siblings. KGS §7.3 folds it back in,
			replacing implicit derived existence with something a differential test
			can assert: reachable, and reachable by exactly one path.`,
		Governs:   []string{"§8.2 bottom-up visibility", "KGS §7.3", "KGS §8.5 #1"},
		Status:    scenario.StatusPending,
		PendingOn: []scenario.Capability{scenario.CapVisibleBelow, scenario.CapTupleStore},
		Fixture: scenario.Fixture{
			Tenant: "household",
			Kinds:  driveKinds(),
			Principals: []scenario.PrincipalSpec{
				user("user:eva", "may read exactly one deep document"),
				user("user:pascal", "owns the household folder"),
			},
			Containment: []scenario.Edge{
				scenario.E("folder:school", "folder:household"),
				scenario.E("folder:school-2026", "folder:school"),
				scenario.E("document:report-card", "folder:school-2026"),
				scenario.E("document:absence-note", "folder:school-2026"),
				scenario.E("folder:finance", "folder:household"),
				scenario.E("document:invoice", "folder:finance"),
			},
			Tuples: []scenario.Tuple{
				{
					Object: scenario.R("document:report-card"), Relation: "viewer",
					Subject: scenario.P("user:eva"),
					Note:    "one grant, at the bottom",
				},
			},
		},
		Expect: []scenario.Expectation{
			{
				Principal: "user:eva", Action: "read", Resource: scenario.R("document:report-card"),
				Want: scenario.Allow, Reason: scenario.ReasonDirect,
				Because: "document:report-card#viewer@user:eva",
			},
			{
				Principal: "user:eva", Action: "read", Resource: scenario.R("document:absence-note"),
				Want: scenario.Deny, Reason: scenario.ReasonNoGrant,
				Note: "navigational visibility of an ancestor is not read access to its other children. " +
					"That distinction is the whole value of making it a separate, weaker relation",
			},
			{
				Principal: "user:eva", Action: "read", Resource: scenario.R("folder:household"),
				Want: scenario.Deny, Reason: scenario.ReasonNoGrant,
				Note: "she can navigate the ancestor; she cannot read it",
			},
		},
		Claims: []scenario.Claim{
			scenario.C(scenario.ClaimSchemaAccepted, "folder", "", ""),
			scenario.C(scenario.ClaimVisibleSet, "user:eva",
				"document:report-card, folder:household, folder:school, folder:school-2026",
				"the document and the three folders above it. Not folder:finance, not document:invoice, "+
					"not document:absence-note — the set is compared exactly, so a sibling appearing is a failure"),
			scenario.C(scenario.ClaimVisibleSet, "user:pascal", "",
				"he holds no tuple in this fixture, so he navigates to nothing. Visibility is derived from "+
					"grants and never from being the household's owner in some ambient sense"),
			scenario.C(scenario.ClaimPathCount, "document:report-card", "1",
				"one path, which is what makes `only the direct path` a well-defined restriction here. "+
					"U3 is the same scenario with a kgs entity-set added, where it is not"),
		},
	}
}

// ethicalWall is the scenario the old examples/mandatory package called
// "the feature the whole module exists for". It is in this package now,
// which is itself the finding: a conflict screen has no policy mechanism
// of its own any more, so it lives among the ordinary grants and is
// expressed by the absence of one.
func ethicalWall() scenario.Scenario {
	return scenario.Scenario{
		ID:    "D8",
		Title: "The legal ethical wall is a grant nobody wrote, and that is all it is now",
		Models: `A firm acts for one side of a dispute and screens the matter from
			everybody not on its team. CAS §9.3 called this a conflict screen "that
			no firm-wide grant may defeat", design §1 cited it as one of the two
			requirements this module exists for, and the corpus's old M5 asserted
			it at length: a classification on the matter, a clearance group holding
			the team, and an adversarial suite applying every discretionary
			operation available to prove the gate stayed shut.

			All of that is gone, and this scenario is the honest replacement
			rather than a quiet deletion. The screen is now the ordinary
			default-deny: the firm-wide grant is written on the firm-wide
			container, the matter is not inside it, and nothing names the screened
			associate on the matter. That is a real and sufficient mechanism for
			the everyday case, and it is weaker than what the design used to claim
			in exactly one way worth stating plainly: it survives nobody. Any
			principal who may share the matter can share it with the screened
			associate tomorrow, and no row in this module will object. A screen
			that must survive a future administrator, an operator or a subpoena is
			not a policy object at all — it is content under a key the deployment
			does not hold, which is ` + "`escrow`" + `, and H4 is what that looks like.

			The reason that trade is the right one is that the old mechanism did
			not deliver what it appeared to either. A classification was
			administered by whoever held the classify permission, so it was only
			as absolute as that administration — and routing ordinary privacy
			through the same mechanism turned every household preference into an
			absolute no owner could lift. One honest weak mechanism and one honest
			absolute beat one mechanism that read as absolute and was not.`,
		Governs: []string{"CAS §9.3", "§1", "§7.1", "no-deny anti-goal"},
		Status:  scenario.StatusPending,
		PendingOn: []scenario.Capability{
			scenario.CapDecide, scenario.CapTupleStore, scenario.CapVisibleBelow,
		},
		Fixture: scenario.Fixture{
			Tenant: "lawfirm",
			Kinds:  driveKinds(),
			Principals: []scenario.PrincipalSpec{
				user("user:anne", "on the matter team", "team:all-timekeepers", "team:matter-1234"),
				user("user:eve", "a timekeeper, screened off this matter", "team:all-timekeepers"),
				user("user:dave", "the managing partner, who is also screened", "team:all-timekeepers"),
			},
			Groups: []scenario.GroupSpec{
				{
					Name:    "team:all-timekeepers",
					Members: []string{"user:anne", "user:eve", "user:dave"},
					Note: "employment is an authoritative fact, so this group is the one the " +
						"directory maintains. It used to need to be a clearance group for the " +
						"`everyone except Bob` shape; it is an ordinary group now, because " +
						"`everyone except Bob` is a grant Bob is not in",
				},
				{
					Name:    "team:matter-1234",
					Members: []string{"user:anne"},
					Note:    "the matter team. Eve and Dave are deliberately not in it",
				},
			},
			Containment: []scenario.Edge{
				scenario.E("document:firm-handbook", "folder:firm-wide"),
				scenario.E("document:precedent-bank", "folder:firm-wide"),
				// folder:matter-1234 is a root, deliberately. The absent
				// containment edge into folder:firm-wide is half the
				// screen; the absent tuple is the other half.
				scenario.E("document:witness-statement", "folder:matter-1234"),
				scenario.E("document:advice-note", "folder:matter-1234"),
			},
			Tuples: []scenario.Tuple{
				{
					Object: scenario.R("folder:firm-wide"), Relation: "viewer",
					Subject: scenario.US("team:all-timekeepers", "member"),
					Note: "the firm-wide grant, written as generously as a real firm writes it. " +
						"It is in the fixture precisely so that the scenario is not passing " +
						"because nothing is shared",
				},
				{
					Object: scenario.R("folder:matter-1234"), Relation: "owner",
					Subject: scenario.US("team:matter-1234", "member"),
					Note:    "and the matter's own grant, naming the team and nobody else",
				},
			},
		},
		Expect: []scenario.Expectation{
			{
				Principal: "user:anne", Action: "read", Resource: scenario.R("document:witness-statement"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "folder:matter-1234#owner@team:matter-1234#member",
				Note:    "the matter team reads the matter",
			},
			{
				Principal: "user:eve", Action: "read", Resource: scenario.R("document:firm-handbook"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "folder:firm-wide#viewer@team:all-timekeepers#member",
				Note: "and the firm-wide grant works, for her, on everything it covers. The screen " +
					"is not a narrower firm",
			},
			{
				Principal: "user:eve", Action: "read", Resource: scenario.R("document:advice-note"),
				Want: scenario.Deny, Reason: scenario.ReasonNoGrant,
				Note: "the screen. The firm-wide grant does not reach the matter because the matter " +
					"is not inside the firm-wide container — inheritance goes down, and there is no " +
					"edge to come down. This row used to read `deny, classification, " +
					"conflict:matter-1234`",
			},
			{
				Principal: "user:dave", Action: "read", Resource: scenario.R("document:witness-statement"),
				Want: scenario.Deny, Reason: scenario.ReasonNoGrant,
				Note: "and the managing partner is screened by the same absence as everybody else. " +
					"There is no seniority in a grant he does not hold, which is the one property " +
					"the old mechanism had that this one keeps",
			},
		},
		Claims: []scenario.Claim{
			scenario.C(scenario.ClaimSchemaAccepted, "folder", "",
				"no exclusion operator anywhere, and nothing to exclude with. The screen is in the "+
					"containment graph and the tuple set, not in a relation definition"),
			scenario.C(scenario.ClaimPathCount, "document:advice-note", "1",
				"the matter document's only container is the matter folder. That single fact is what "+
					"the screen rests on, so it is asserted: a containment edge from folder:firm-wide "+
					"added by any future consumer write would open the screen silently, and this claim "+
					"is what fails when it does"),
			scenario.C(scenario.ClaimVisibleSet, "user:eve", "folder:firm-wide",
				"and she cannot navigate to the matter either, so she does not learn that a matter she "+
					"is screened off exists. The set is compared exactly, which is the strongest thing "+
					"this scenario can still assert"),
			scenario.C(scenario.ClaimVisibleSet, "user:anne",
				"folder:firm-wide, folder:matter-1234",
				"while the team member navigates to both"),
			scenario.C(scenario.ClaimTuplesPerHop, "2", "6",
				"two tuples, six objects, and the screen costs nothing: it is the grant that was not "+
					"written"),
		},
	}
}
