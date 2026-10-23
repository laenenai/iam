// Package unexpressible holds the use cases this design cannot currently
// express, each located at the exact relation, rule or closure that cannot
// be written.
//
// It is the most valuable package in the corpus, and the reason is in
// design §8.5's last paragraph: "where a real requirement cannot be
// expressed in the subset, the answer is a classification, not a richer
// language. If a requirement arrives that is neither — that is a design
// conversation, not a configuration change." These are the requirements
// that are neither, plus two where "use a classification" is technically
// available and changes the requirement into a different one.
//
// Every scenario here *demonstrates* its gap rather than asserting it. The
// harness refuses an unexpressible scenario that does not carry a claim
// which runs — the schema lint rejecting the relation, DirectPath refusing
// a DAG, RowEnforceable reporting that a column cannot be hidden by a
// `WHERE` clause, an ancestry closure moving under an ordinary data write,
// or an unprivileged principal successfully clearing itself. So if the
// design grows to cover one of these, the corresponding claim starts
// failing and says so.
//
// UNEXPRESSIBLE.md in the parent directory is the prose version: what each
// use case is, why the design cannot express it, which §17 finding it maps
// to, and what supporting it would cost.
package unexpressible

import (
	"github.com/laenenai/iam"
	"github.com/laenenai/iam/examples/scenario"
)

func group() scenario.ResourceKind {
	return scenario.ResourceKind{
		Name:      "group",
		Relations: []scenario.Relation{{Name: "member", Direct: true}},
		Actions:   map[string]string{"read": "member"},
	}
}

func rowKind(name string, extra ...scenario.Relation) scenario.ResourceKind {
	relations := []scenario.Relation{
		{
			Name: "viewer", Direct: true, Usersets: []string{"group#member"},
			InheritFromParent: []string{"viewer"},
		},
	}
	relations = append(relations, extra...)
	return scenario.ResourceKind{
		Name: name, Shape: scenario.ShapeRow, Relations: relations,
		Actions: map[string]string{"read": "viewer"},
	}
}

func person(name, role string) scenario.PrincipalSpec {
	return scenario.PrincipalSpec{Name: name, Kind: iam.PrincipalKindUser, Role: role}
}

func securityService() scenario.PrincipalSpec {
	return scenario.PrincipalSpec{
		Name: "service:security", Kind: iam.PrincipalKindService,
		Role: "performs the fixture's mandatory acts",
	}
}

// Scenarios returns the use cases the design cannot express.
func Scenarios() []scenario.Scenario {
	return []scenario.Scenario{
		ontologyScopeExclusion(),
		classificationIsNotADiscretionaryHide(),
		dagContainment(),
		attributeScopedOnColumns(),
		predicateDefinedEntitySet(),
		whoMayClassify(),
	}
}

func ontologyScopeExclusion() scenario.Scenario {
	return scenario.Scenario{
		ID:    "U1",
		Title: "`May read Person entities but not salary facts` cannot be written at all",
		Models: `KGS §9.3 lists ontology scope as one of its rule dimensions: "a rule
			may name a type or predicate (may read Person entities but not salary
			facts), which is what makes property-level security expressible." It is
			an ordinary HR requirement and the firm's administrator expects to click
			it. Design §8.5 permits union, usersets and tuple-to-userset
			inheritance, and nothing else: no intersection, no exclusion, no
			conditional expression over attributes. This rule is two of the three
			forbidden things at once — conditioned on the fact's predicate, and
			exclusionary in shape — so there is no relation definition that
			expresses it. The scenario writes the rule the requirement needs,
			exactly as a consumer would want to declare it, and the schema lint
			refuses the whole fixture. Every row in the table below is therefore
			unreachable: not denied, not allowed, unanswerable.`,
		Governs: []string{"§17 F7", "§8.5", "§5a exclusion operators", "KGS §9.3 ontology scope"},
		Status:  scenario.StatusUnexpressible,
		Finding: "F7 (ontology scope)",
		Cost: "Adding a tier-1 form conditioned on resource attributes costs §9's projection, which is " +
			"what buys the entire A2 budget: union, usersets and inheritance precompute into a closure " +
			"and a conditional expression does not. An exclusion operator additionally costs the A3 " +
			"invariant, because exclusion in a relationship model is local to the permission it is " +
			"written in, so it would have to be repeated on every relation of every resource kind and " +
			"remembered for every kind added later — N permissions by M exclusion dimensions, growing " +
			"with the schema, where one omission is a silent bypass rather than an error. The cheaper " +
			"resolutions are: kgs drops the ontology-scope dimension and expresses the same requirement " +
			"as a classification (which U2 shows changes what the requirement means), or `Predicate` " +
			"grows a second return value — a permitted-predicate set the consumer applies — which moves " +
			"part of the A3 trust boundary into consumer code (the same choice F4 forces).",
		Fixture: scenario.Fixture{
			Tenant: "lawfirm",
			Kinds: []scenario.ResourceKind{
				group(),
				rowKind("graph"),
				rowKind("entity"),
				{
					Name: "fact", Shape: scenario.ShapeRow,
					Relations: []scenario.Relation{
						{
							Name: "viewer", Direct: true, Usersets: []string{"group#member"},
							InheritFromParent: []string{"viewer"},
							// The rule the requirement needs, written the
							// way a consumer would want to declare it.
							// Design §8.5 permits neither field.
							AttributeCondition: "fact.predicate != 'salary'",
							Exclude:            []string{"salary_reader"},
						},
					},
					Actions: map[string]string{"read": "viewer"},
				},
			},
			Principals: []scenario.PrincipalSpec{
				person("user:hr-analyst", "may read the people and not their salaries"),
				person("user:hr-director", "may read both"),
				securityService(),
			},
			Groups: []scenario.GroupSpec{
				{Name: "group:hr", Members: []string{"user:hr-analyst", "user:hr-director"}},
			},
			Containment: []scenario.Edge{
				scenario.E("entity:person-jonas", "graph:hr"),
				scenario.E("fact:jonas-job-title", "graph:hr"),
				scenario.E("fact:jonas-salary", "graph:hr"),
			},
			Tuples: []scenario.Tuple{
				{
					Object: scenario.R("graph:hr"), Relation: "viewer",
					Subject: scenario.US("group:hr", "member"),
					Note:    "the ordinary grant. It is the exclusion that has nowhere to live",
				},
			},
		},
		Expect: []scenario.Expectation{
			{
				Principal: "user:hr-analyst", Action: "read", Resource: scenario.R("entity:person-jonas"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because:     "graph:hr#viewer@group:hr#member",
				Unreachable: "F7: the fixture's schema is refused in full, so even the rows it would have allowed are unanswerable",
				Note:        "she may read the Person",
			},
			{
				Principal: "user:hr-analyst", Action: "read", Resource: scenario.R("fact:jonas-job-title"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because:     "graph:hr#viewer@group:hr#member",
				Unreachable: "F7: same refusal",
				Note:        "and the ordinary facts about them",
			},
			{
				Principal: "user:hr-analyst", Action: "read", Resource: scenario.R("fact:jonas-salary"),
				Want: scenario.Deny, Reason: scenario.ReasonNoGrant,
				Unreachable: "F7: the only mechanism that would produce this deny is a conditional or exclusionary " +
					"relation, and §8.5 permits neither. There is no tier-1 rule to write",
				Note: "the row the requirement is about",
			},
			{
				Principal: "user:hr-director", Action: "read", Resource: scenario.R("fact:jonas-salary"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because:     "graph:hr#viewer@group:hr#member",
				Unreachable: "F7: and the exemption for the director has nowhere to live either",
				Note:        "the director's exemption is the half that makes a classification the wrong answer — see U2",
			},
		},
		Claims: []scenario.Claim{
			scenario.C(scenario.ClaimSchemaRejected, "fact#viewer", "classification",
				"the demonstration: the schema lint refuses the fixture, and the refusal names the "+
					"classification mechanism, because design §4/A3 requires the error to point the "+
					"consumer at what it should use instead rather than merely saying no"),
		},
	}
}

func classificationIsNotADiscretionaryHide() scenario.Scenario {
	return scenario.Scenario{
		ID:    "U2",
		Title: "`Use a classification` turns `don't show her the salary` into an absolute nobody can lift",
		Models: `U1's requirement, taking design §8.5 at its word: express it as a
			classification. It works, and it is the wrong answer, and this scenario
			is what that costs rather than an argument about it. A classification is
			mandatory: design §8.3 says it "cannot be granted away, delegated,
			transferred with ownership, or satisfied by any tier-1 relation", and
			"there is no API that grants a clearance as a side effect of sharing".
			So the HR director's perfectly ordinary "actually, show her this one
			salary, she's running the review" has no operation behind it. What
			began as a discretionary preference about one field has become an
			absolute of the same kind as a legal ethical wall, administered by
			whoever holds the classify permission, and the resource's owner cannot
			lift it. §17 F7 says exactly this in one sentence; the scenario is that
			sentence with the attempted lift actually attempted.`,
		Governs: []string{"§17 F7", "§8.3", "§8.5", "§16 Q2"},
		Status:  scenario.StatusUnexpressible,
		Finding: "F7 (classification workaround)",
		Cost: "Nothing to build, and that is the problem: the workaround is free and it silently " +
			"promotes a discretionary rule to a mandatory one. Supporting the requirement *as stated* " +
			"needs one of three things. (a) A third tier-1 form — a scoped, delegable restriction — " +
			"which costs the projection for the reason U1 gives. (b) A second rule shape in the " +
			"mandatory layer: a `(principal, resource)` block or a lift, which design §16 question 1 " +
			"explicitly assumes is not needed and which would double the A3 adversarial suite, since " +
			"every absolute would then have two ways to be satisfied instead of one. (c) Accept the " +
			"promotion and make it visible: a consumer-facing distinction between a classification " +
			"meaning `legally absolute` and one meaning `hidden by preference`, with different " +
			"administration, which is two mandatory layers wearing one name. The honest short-term " +
			"answer is to tell consumers that this requirement has no discretionary form, and to make " +
			"the API say so rather than letting them discover it after a classification is in place.",
		Fixture: scenario.Fixture{
			Tenant: "lawfirm",
			Kinds: []scenario.ResourceKind{
				group(),
				rowKind("graph"),
				rowKind("entity"),
				rowKind("fact"),
			},
			Principals: []scenario.PrincipalSpec{
				person("user:hr-analyst", "the analyst whose access the director wants to widen by one fact"),
				person("user:hr-director", "the resource owner, and the person who cannot do it"),
				securityService(),
			},
			Groups: []scenario.GroupSpec{
				{Name: "group:hr", Members: []string{"user:hr-analyst", "user:hr-director"}},
			},
			ClearanceGroups: []scenario.ClearanceGroupSpec{
				{
					Name: "clearance:salary-readers", Channel: iam.MandatoryChannelClassify,
					Members: []string{"user:hr-director"}, Labels: []string{"sensitive:salary"},
					Reason: "the classification workaround: whoever may read salaries at all",
				},
			},
			Containment: []scenario.Edge{
				scenario.E("entity:person-jonas", "graph:hr"),
				scenario.E("fact:jonas-job-title", "graph:hr"),
				scenario.E("fact:jonas-salary", "graph:hr"),
			},
			Classifications: []scenario.Classification{
				{
					Label: "sensitive:salary", Enforcement: scenario.EnforcementPolicy,
					Why: "the workaround §8.5 recommends. It is mandatory, which the requirement never " +
						"asked for and cannot undo",
				},
			},
			Assignments: []scenario.Assignment{scenario.AS("fact:jonas-salary", "sensitive:salary")},
			Tuples: []scenario.Tuple{
				{
					Object: scenario.R("graph:hr"), Relation: "viewer",
					Subject: scenario.US("group:hr", "member"),
				},
				{
					Object: scenario.R("fact:jonas-salary"), Relation: "viewer",
					Subject: scenario.P("user:hr-analyst"),
					Note: "the director's attempted lift, written as the most direct grant there is: " +
						"a tuple naming her on the fact itself. It is a correct, permitted tier-1 write " +
						"and it changes nothing",
				},
			},
		},
		Expect: []scenario.Expectation{
			{
				Principal: "user:hr-analyst", Action: "read", Resource: scenario.R("fact:jonas-job-title"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "graph:hr#viewer@group:hr#member",
				Note:    "the ordinary facts still work, so the workaround is not simply broken",
			},
			{
				Principal: "user:hr-analyst", Action: "read", Resource: scenario.R("fact:jonas-salary"),
				Want: scenario.Deny, Reason: scenario.ReasonClassification, Because: "sensitive:salary",
				Note: "the workaround does deliver the requirement's first half, and this row passes. " +
					"The gate denies her the salary",
			},
			{
				Principal: "user:hr-director", Action: "read", Resource: scenario.R("fact:jonas-salary"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "graph:hr#viewer@group:hr#member",
				Note:    "and the director reads it, through the clearance group",
			},
			{
				Principal: "user:hr-analyst", Action: "read", Resource: scenario.R("fact:jonas-salary"),
				Want: scenario.Allow, Reason: scenario.ReasonDirect,
				Because: "fact:jonas-salary#viewer@user:hr-analyst",
				Unreachable: "F7: the requirement's second half. The director owns the fact, wrote the most " +
					"direct grant the model has, and cannot lift the label. There is no discretionary " +
					"operation that satisfies a classification — by design, and that design is right for " +
					"an ethical wall and wrong for a preference about a column",
				Note: "this is the row the whole scenario exists for",
			},
		},
		Claims: []scenario.Claim{
			scenario.C(scenario.ClaimSchemaAccepted, "fact", "",
				"note that the workaround's schema is perfectly legal — the gap is not a lint failure, "+
					"which is what makes it easy to adopt by accident"),
			scenario.C(scenario.ClaimAbsoluteHasNoLift, "user:hr-analyst", "",
				"the demonstration, run against the real registry: every discretionary operation the "+
					"module exposes is applied on the analyst's behalf — added to every group, the issuer "+
					"asserting the clearance group's own name, an agent run delegated from the cleared "+
					"director, an ordinary group id presented as a clearance group id — and she still "+
					"holds no clearance. In M5 that is the feature. Here it is the bill"),
			scenario.C(scenario.ClaimLiveClearances, "user:hr-director", "clearance:salary-readers",
				"and the only way in is the mandatory channel, which the resource's owner may not "+
					"necessarily use — design §16 question 2, still open, decides whether she may at all"),
		},
	}
}

func dagContainment() scenario.Scenario {
	return scenario.Scenario{
		ID:    "U3",
		Title: "Containment is a DAG once entity-sets are involved, so `only the direct path` names nothing",
		Models: `KGS §9.3 wants entity-sets: "a named, graph-scoped grouping of entities
			with their own rules, nestable — this is how 'my wife can see everything
			about the school and the daughter, nothing about my business' is
			expressed once rather than per fact." That is the right requirement and
			the household depends on it. But a fact then has an episode *and* zero
			or more entity-sets as containers, so design §9.2's ancestry closure
			stops being a path and becomes a many-to-many relation at fact
			cardinality, and design §8.2's bottom-up navigational visibility — which
			grants list rights on an object's ancestors "and only on the direct
			path" — is restricting itself to something that does not exist. D7 is
			the same scenario with a tree, where the restriction is exact and
			testable. Here DirectPath refuses, and that refusal is the finding.`,
		Governs: []string{"§17 F3", "§9.2", "§8.2 bottom-up visibility", "KGS §7.3", "KGS §9.3 entity-sets"},
		Status:  scenario.StatusUnexpressible,
		Finding: "F3 (DAG containment)",
		Cost: "Three resolutions, and §17 marks the finding blocking for §9.2 because the choice " +
			"changes the projection's shape rather than its tuning. (a) Entity-sets stop being an " +
			"authorization container and become a query convenience, which removes a kgs capability the " +
			"household scenario is written around. (b) The ancestry closure becomes explicitly " +
			"many-to-many, maintained on every fact write at ten-million-row cardinality — which is the " +
			"closure cost A2's budget is written to catch, and the one place where this design's " +
			"load-bearing performance claim could quietly stop holding. (c) `visible_below` is " +
			"redefined for multiple paths, which needs a decision nobody has made yet: the union of " +
			"every path (so a principal granted one deep fact can enumerate every entity-set it " +
			"belongs to, which is leak channel #1 reopened from a new direction), the intersection, or " +
			"a single designated primary container per object. The corpus cannot choose for the owner, " +
			"and until somebody does, `only on the direct path` should not appear in the design as " +
			"though it were implementable.",
		Fixture: scenario.Fixture{
			Tenant: "household",
			Kinds: []scenario.ResourceKind{
				group(),
				rowKind("graph"),
				rowKind("episode"),
				rowKind("fact"),
				{
					Name: "entity-set", Shape: scenario.ShapeRow,
					Relations: []scenario.Relation{
						{
							Name: "viewer", Direct: true, Usersets: []string{"group#member"},
							InheritFromParent: []string{"viewer"},
						},
						{Name: "visible_below", Direct: true},
					},
					Actions: map[string]string{"read": "viewer", "navigate": "visible_below"},
				},
			},
			Principals: []scenario.PrincipalSpec{
				person("user:eva", "may see everything about the school, nothing about the business"),
				person("user:pascal", "owns the graph"),
			},
			Containment: []scenario.Edge{
				scenario.E("episode:school-report-2026", "graph:household"),
				scenario.E("entity-set:school", "graph:household"),
				scenario.E("entity-set:family", "graph:household"),
				// The fact's two containers. Both are legitimate: the
				// episode it was asserted in, and the entity-set that
				// groups what it is about.
				scenario.E("fact:school-name", "episode:school-report-2026"),
				scenario.E("fact:school-name", "entity-set:school"),
				// And a second entity-set, because entity-sets are
				// nestable and an entity belongs to as many as apply.
				scenario.E("fact:mira-attends-school", "episode:school-report-2026"),
				scenario.E("fact:mira-attends-school", "entity-set:school"),
				scenario.E("fact:mira-attends-school", "entity-set:family"),
			},
			Tuples: []scenario.Tuple{
				{
					Object: scenario.R("entity-set:school"), Relation: "viewer",
					Subject: scenario.P("user:eva"),
					Note:    "the grant KGS §9.3 wants: expressed once on the set, not per fact",
				},
				{
					Object: scenario.R("graph:household"), Relation: "viewer",
					Subject: scenario.P("user:pascal"),
				},
			},
		},
		Expect: []scenario.Expectation{
			{
				Principal: "user:eva", Action: "read", Resource: scenario.R("fact:school-name"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "entity-set:school#viewer@user:eva",
				Note: "the grant on the entity-set reaches the fact, so the *decision* is fine. " +
					"Finding F3 is not about the decision; it is about the closure that implements it " +
					"and about navigation",
			},
			{
				Principal: "user:eva", Action: "navigate", Resource: scenario.R("entity-set:family"),
				Want: scenario.Deny, Reason: scenario.ReasonNoGrant,
				Unreachable: "F3: she holds a relation on fact:mira-attends-school through entity-set:school, " +
					"and that fact is also contained by entity-set:family. Whether navigational " +
					"visibility reaches entity-set:family depends on whether `the direct path` means the " +
					"union of paths, the intersection, or a designated one — and the design does not say, " +
					"because it was written assuming there is one path",
				Note: "the undecidable row",
			},
		},
		Claims: []scenario.Claim{
			scenario.C(scenario.ClaimPathCount, "fact:school-name", "2",
				"two containment paths, both legitimate: through the episode it was asserted in and "+
					"through the entity-set that groups what it is about"),
			scenario.C(scenario.ClaimPathCount, "fact:mira-attends-school", "3",
				"and three for a fact in two entity-sets. The count grows with the data, not with the schema"),
			scenario.C(scenario.ClaimNoDirectPath, "fact:school-name", "",
				"the demonstration: DirectPath refuses with ErrNoDirectPath. D7's identical claim "+
					"succeeds, because there the containment is a tree. The difference between those two "+
					"scenarios is one containment edge that KGS §9.3 requires"),
		},
	}
}

func attributeScopedOnColumns() scenario.Scenario {
	return scenario.Scenario{
		ID:    "U4",
		Title: "An attribute-scoped classification on a columnar resource cannot be enforced by a row predicate",
		Models: `Design §8.3 says a classification "may be declared over a whole
			resource, or over a named attribute or field of it, which is how
			property-level and cell-level security compose without a second
			mechanism". For kgs that is true and free: a fact carries one attribute,
			so hiding the attribute is hiding the row. For CAS it is not, because a
			document's fields are columns of one row, and design §9 compiles
			authorization into a ` + "`WHERE`" + ` fragment the consumer joins — and a ` + "`WHERE`" + `
			fragment hides rows, not columns. So the decision procedure can answer
			"may she see document:payroll.salary" correctly while ` + "`Predicate`" + `, which
			is the surface carrying the traffic, cannot express the answer at all.
			This is §17 F4, and it is marked "pick one before phase 1 fixes the API"
			for a reason: the two resolutions are two different modules.`,
		Governs: []string{"§17 F4", "§8.3 scoped", "§9", "§9.1", "CAS §9.3"},
		Status:  scenario.StatusUnexpressible,
		Finding: "F4 (attribute scope vs row predicate)",
		Cost: "Two options and they are not variations of each other. (a) `Predicate` returns a " +
			"fragment *plus* a permitted-attribute set, and the consumer applies the second part. That " +
			"is cheap to build and it moves a piece of the A3 trust boundary into consumer code: the " +
			"module would no longer be able to say that no sequence of operations opens a gate, because " +
			"a consumer that forgets to apply the attribute set is a disclosure this module cannot " +
			"prevent or detect. If it is chosen, the differential audit (§9.4) must cover consumer " +
			"compliance and not only projection divergence, which is a larger audit than the one " +
			"designed. (b) This module becomes a query rewriter, parsing and rewriting SELECT lists " +
			"across three consumers' query builders. That keeps the trust boundary intact and is a " +
			"different module with a different charter — and CHARTER.md's `it must not contain` list " +
			"would have to grow a line either way. A third, cheaper answer exists for CAS " +
			"specifically: make sensitive document fields their own addressable resources, so the " +
			"columnar case becomes a row case, at the cost of a schema migration in CAS and a " +
			"cardinality increase in its tables.",
		Fixture: scenario.Fixture{
			Tenant: "acme",
			Kinds: []scenario.ResourceKind{
				group(),
				{
					Name: "fileset", Shape: scenario.ShapeColumnar,
					Relations: []scenario.Relation{
						{Name: "viewer", Direct: true, Usersets: []string{"group#member"}, InheritFromParent: []string{"viewer"}},
					},
					Actions: map[string]string{"read": "viewer"},
				},
				{
					// A CAS document: its fields are columns of one row.
					// This single field is the whole finding.
					Name: "document", Shape: scenario.ShapeColumnar,
					Relations: []scenario.Relation{
						{Name: "viewer", Direct: true, Usersets: []string{"group#member"}, InheritFromParent: []string{"viewer"}},
					},
					Actions: map[string]string{"read": "viewer"},
				},
				// For contrast: the same requirement over a kgs fact,
				// which is row-shaped and therefore fine.
				rowKind("fact"),
			},
			Principals: []scenario.PrincipalSpec{
				person("user:eva", "may read the payroll document and not its salary column"),
				person("user:hr-director", "may read both"),
				securityService(),
			},
			Groups: []scenario.GroupSpec{
				{Name: "group:staff", Members: []string{"user:eva", "user:hr-director"}},
			},
			ClearanceGroups: []scenario.ClearanceGroupSpec{
				{
					Name: "clearance:salary-readers", Channel: iam.MandatoryChannelClassify,
					Members: []string{"user:hr-director"},
					Labels:  []string{"restricted:salary-column", "restricted:salary-fact"},
					Reason:  "whoever may read salaries",
				},
			},
			Containment: []scenario.Edge{
				scenario.E("document:payroll", "fileset:hr"),
				scenario.E("fact:jonas-salary", "fileset:hr"),
			},
			Classifications: []scenario.Classification{
				{
					Label: "restricted:salary-column", Enforcement: scenario.EnforcementPolicy,
					Attribute: "salary",
					Why: "scoped to one attribute of a columnar resource. §8.3 permits declaring it; " +
						"§9's compiled predicate cannot enforce it",
				},
				{
					Label: "restricted:salary-fact", Enforcement: scenario.EnforcementPolicy,
					Attribute: "value",
					Why: "the identical requirement over a row-shaped kgs fact, which *is* enforceable, " +
						"because the attribute is the row",
				},
			},
			Assignments: []scenario.Assignment{
				scenario.AS("document:payroll", "restricted:salary-column"),
				scenario.AS("fact:jonas-salary", "restricted:salary-fact"),
			},
			Tuples: []scenario.Tuple{
				{
					Object: scenario.R("fileset:hr"), Relation: "viewer",
					Subject: scenario.US("group:staff", "member"),
				},
			},
		},
		Expect: []scenario.Expectation{
			{
				Principal: "user:eva", Action: "read", Resource: scenario.R("document:payroll"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "fileset:hr#viewer@group:staff#member",
				Note: "she may read the document, and correctly so: a classification scoped to one " +
					"attribute does not gate the whole resource. That is also precisely what makes the " +
					"finding bite — the gate lets the row through and something else has to hide the column",
			},
			{
				Principal: "user:eva", Action: "read", Resource: scenario.R("document:payroll.salary"),
				Want: scenario.Deny, Reason: scenario.ReasonClassification, Because: "restricted:salary-column",
				Unreachable: "F4: the decision procedure answers this correctly and `Predicate` cannot. " +
					"A consumer that calls Decide per cell has abandoned §9 and post-filters, which is " +
					"KGS leak channel #6; a consumer that calls Predicate receives a row filter that " +
					"returns the row with the salary in it",
				Note: "the undeliverable row",
			},
			{
				Principal: "user:eva", Action: "read", Resource: scenario.R("fact:jonas-salary.value"),
				Want: scenario.Deny, Reason: scenario.ReasonClassification, Because: "restricted:salary-fact",
				Note: "the same requirement over a row-shaped resource, and this one is deliverable: " +
					"hiding the attribute is hiding the row, so the compiled fragment can do it",
			},
			{
				Principal: "user:hr-director", Action: "read", Resource: scenario.R("fact:jonas-salary.value"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "fileset:hr#viewer@group:staff#member",
			},
		},
		Claims: []scenario.Claim{
			scenario.C(scenario.ClaimRowEnforceable, "restricted:salary-column", "false",
				"the demonstration: the classification is declarable and not enforceable by the "+
					"predicate design §9 compiles, because it is scoped to an attribute of a "+
					"columnar resource"),
			scenario.C(scenario.ClaimRowEnforceable, "restricted:salary-fact", "true",
				"and the contrast that makes the finding precise rather than general: the identical "+
					"requirement over a row-shaped kind is enforceable. F4 is a property of the "+
					"consumer's storage shape, not of attribute scoping as such — which is why kgs is "+
					"fine and CAS is not"),
			scenario.C(scenario.ClaimSchemaAccepted, "document", "",
				"and nothing in the schema is wrong, so no lint catches this. It is caught by asking "+
					"what the compiled predicate can express, which is what RowEnforceable does"),
		},
	}
}

func predicateDefinedEntitySet() scenario.Scenario {
	return scenario.Scenario{
		ID:    "U5",
		Title: "A predicate-defined entity-set makes authorization a function of data a later write changes",
		Models: `KGS §9.3 allows an entity-set to be "definable either explicitly or by
			predicate", and notes the consequence itself: "a predicate-defined
			entity-set makes authorization a function of data, so a later-asserted
			fact can change what an earlier rule covers." The requirement is real
			and attractive — "Eva can see all Belgian suppliers" is one rule that
			stays correct as suppliers arrive. What it costs is that an ordinary
			data write, made by somebody with no authorization permission at all,
			moves an authorization answer. There is no authorization operation to
			audit, nothing for design §9.3's deny epoch to be bumped by, and the
			restrictive direction of the change — a supplier *leaving* the set —
			rides the same path as the permissive one, which is exactly the
			asymmetry §9.3 says must never be reversed.`,
		Governs: []string{"§17 F7 (predicate-defined entity-sets)", "§17 F3", "§9.3", "§8.5", "KGS §9.3"},
		Status:  scenario.StatusUnexpressible,
		Finding: "F7 (predicate-defined sets) + F3",
		Cost: "KGS §9.3 already prices part of this: such a set is materialized with a declared " +
			"staleness bound and staleness fails closed. What is missing is the restrictive direction. " +
			"Design §9.3's one rule is that the restrictive change propagates on the fast path and the " +
			"permissive change may lag; here both changes are the same event — an ordinary fact write " +
			"in a consumer's own transaction — so either every such write synchronously re-evaluates " +
			"every predicate-defined set that could reference the row (which puts authorization " +
			"maintenance on the hot write path at fact cardinality, and §10 established that a grant " +
			"and a consumer's write cannot commit atomically in any deployment shape), or the " +
			"restrictive direction lags and a removed supplier stays visible for the staleness window. " +
			"Neither is free, and the second is a disclosure the design elsewhere refuses to accept. " +
			"The containment half additionally lands in F3: a predicate-defined set is a container " +
			"whose membership nobody wrote, so the ancestry closure it participates in cannot be " +
			"maintained from an authorization event at all. The cheapest honest resolution is to permit " +
			"predicate-defined sets only where the predicate is over immutable or append-only " +
			"attributes, and to say so in the design rather than discovering it per consumer.",
		Fixture: scenario.Fixture{
			Tenant: "household",
			Kinds: []scenario.ResourceKind{
				group(),
				rowKind("graph"),
				rowKind("entity"),
				rowKind("entity-set"),
			},
			Principals: []scenario.PrincipalSpec{
				person("user:eva", "granted every Belgian supplier, once, by a rule over data"),
				person("user:pascal", "asserts an ordinary fact later, holding no authorization permission"),
			},
			Containment: []scenario.Edge{
				scenario.E("entity-set:belgian-suppliers", "graph:household"),
				{
					Child: scenario.R("entity:acme"), Parent: scenario.R("entity-set:belgian-suppliers"),
					Kind:      scenario.EdgePredicate,
					Predicate: "entity has a fact country = 'BE'",
				},
			},
			Tuples: []scenario.Tuple{
				{
					Object: scenario.R("entity-set:belgian-suppliers"), Relation: "viewer",
					Subject: scenario.P("user:eva"),
					Note:    "one grant, and it is the only authorization write in the whole scenario",
				},
			},
			LaterWrites: []scenario.LaterWrite{
				{
					What: "Pascal asserts `entity:hidden-co country = BE`, an ordinary fact write in his " +
						"own transaction, holding no grant, deny, policy-set or classify permission",
					AddEdges: []scenario.Edge{
						{
							Child: scenario.R("entity:hidden-co"), Parent: scenario.R("entity-set:belgian-suppliers"),
							Kind:      scenario.EdgePredicate,
							Predicate: "entity has a fact country = 'BE'",
						},
					},
				},
			},
		},
		Expect: []scenario.Expectation{
			{
				Principal: "user:eva", Action: "read", Resource: scenario.R("entity:acme"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "entity-set:belgian-suppliers#viewer@user:eva",
				Note:    "the rule works, which is why it is attractive",
			},
			{
				Principal: "user:eva", Action: "read", Resource: scenario.R("entity:hidden-co"),
				Want: scenario.Deny, Reason: scenario.ReasonNoGrant,
				Note: "before the write, the company is outside the set and she cannot see it",
			},
			{
				Principal: "user:eva", Action: "read", Resource: scenario.R("entity:hidden-co"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "entity-set:belgian-suppliers#viewer@user:eva",
				Unreachable: "F7/F3: after Pascal's ordinary fact write she can, and no authorization " +
					"operation occurred. There is nothing to audit under §8.6, nothing to bump the deny " +
					"epoch, and the same mechanism run backwards is a stale *grant* on the restrictive " +
					"direction, which §9.3 forbids",
				Note: "the row that has no owner",
			},
		},
		Claims: []scenario.Claim{
			scenario.C(scenario.ClaimStableUnderWrite, "entity:hidden-co", "false",
				"the demonstration: the entity's ancestry closure — the set §9.2's predicate joins "+
					"against — changes when an ordinary data write lands. The claim asserts the "+
					"instability, so if predicate-defined containment is ever removed or constrained to "+
					"immutable attributes, this claim fails and the scenario leaves this package"),
			scenario.C(scenario.ClaimStableUnderWrite, "entity:acme", "true",
				"while an entity already in the set is unaffected, which is what makes this a "+
					"membership problem rather than a general instability"),
			scenario.C(scenario.ClaimSchemaAccepted, "entity-set", "",
				"and again the schema is legal. Nothing in §8.5's lint can see this, because the "+
					"forbidden thing is not in the relation definitions — it is in the containment edges"),
		},
	}
}

func whoMayClassify() scenario.Scenario {
	return scenario.Scenario{
		ID:    "U6",
		Title: "Nothing checks whether the actor on a mandatory act may classify at all",
		Models: `Found while writing this corpus rather than taken from §17, and it is
			the gap that most undercuts the scenarios that pass. Design §8.3 makes
			clearance-group membership move only "through the classify permission or
			an authoritative directory sync", and §8.3's closing line is that
			"creating and assigning classifications is itself permissioned and
			audited, and is not a power that ownership confers". The registry
			enforces the *witness*: every clearance write demands an
			iam.MandatoryAct carrying a channel, an actor, a reason and an instant,
			and MandatoryAct's fields are unexported so one cannot be forged. What
			nothing enforces is the actor's authority, because design §16 question 2
			— deployment-level security admin, per-tenant security admin, or the
			resource owner at creation time — is unanswered. So an ordinary user can
			construct an act naming itself, add itself to a clearance group, and
			satisfy a mandatory gate. M5 asserts that no discretionary operation
			opens a gate, and that is true; this scenario shows that the mandatory
			channel is open to everyone, which reaches the same place by a different
			door.`,
		Governs: []string{"§16 Q2", "§8.3", "A3", "§13 adversarial suite"},
		Status:  scenario.StatusUnexpressible,
		Finding: "§16 Q2 (who may classify)",
		Cost: "Not in the §17 register, and it should be. Small to build and it needs a decision first, " +
			"which is why it is here rather than in a task list. " +
			"task list. The §16 candidates have different costs: a deployment-level security admin is " +
			"one role and breaks the household case, where the owner reasonably classifies their own " +
			"invoice at creation; a per-tenant security admin fits the legal case and needs the role to " +
			"exist before the first classification does; the resource owner at creation time with " +
			"changes restricted afterwards fits the household and reintroduces, for the creation " +
			"window, exactly the ownership-confers-classification power §8.3 forbids. Whichever is " +
			"chosen, the mechanism is the same shape: MandatoryAct's construction stops being free and " +
			"starts requiring a checked capability, which means `iam.NewMandatoryAct` loses its " +
			"current signature and the A3 adversarial suite gains the mandatory channel as an attack " +
			"surface it does not currently cover. Until then, no scenario in this corpus may claim that " +
			"a clearance cannot be obtained — only that it cannot be obtained *discretionarily*, which " +
			"is a narrower and much weaker statement than the design reads as making.",
		Fixture: scenario.Fixture{
			Tenant: "lawfirm",
			Kinds: []scenario.ResourceKind{
				group(),
				rowKind("matter"),
				rowKind("document"),
			},
			Principals: []scenario.PrincipalSpec{
				person("user:eve", "an ordinary associate, holding no classify permission and no clearance"),
				person("user:anne", "on the matter team, admitted by the security function"),
				securityService(),
			},
			Groups: []scenario.GroupSpec{
				{Name: "group:all-timekeepers", Members: []string{"user:eve", "user:anne"}},
			},
			ClearanceGroups: []scenario.ClearanceGroupSpec{
				{
					Name: "clearance:matter-9999-team", Channel: iam.MandatoryChannelClassify,
					Members: []string{"user:anne"}, Labels: []string{"conflict:matter-9999"},
					Reason: "the matter team. Eve is deliberately not in it",
				},
			},
			Containment: []scenario.Edge{
				scenario.E("document:witness-statement", "matter:9999"),
			},
			Classifications: []scenario.Classification{
				{Label: "conflict:matter-9999", Enforcement: scenario.EnforcementPolicy, Why: "an ethical wall"},
			},
			Assignments: []scenario.Assignment{scenario.AS("matter:9999", "conflict:matter-9999")},
			Tuples: []scenario.Tuple{
				{
					Object: scenario.R("matter:9999"), Relation: "viewer",
					Subject: scenario.US("group:all-timekeepers", "member"),
				},
			},
		},
		Expect: []scenario.Expectation{
			{
				Principal: "user:anne", Action: "read", Resource: scenario.R("document:witness-statement"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "matter:9999#viewer@group:all-timekeepers#member",
				Note:    "the matter team reads the matter, as in M1",
			},
			{
				Principal: "user:eve", Action: "read", Resource: scenario.R("document:witness-statement"),
				Want: scenario.Deny, Reason: scenario.ReasonClassification, Because: "conflict:matter-9999",
				Note: "and the screen holds against every discretionary operation, as M5 asserts at length",
			},
			{
				Principal: "user:eve", Action: "read", Resource: scenario.R("document:witness-statement"),
				Want: scenario.Deny, Reason: scenario.ReasonClassification, Because: "conflict:matter-9999",
				Unreachable: "§16 Q2: this deny must survive Eve performing a mandatory act on her own behalf, " +
					"and today it does not. The claim below adds her to the clearance group with a " +
					"self-issued act that the registry accepts, after which the gate opens for her and " +
					"the ethical wall is gone. The corpus cannot express `the mandatory channel is " +
					"closed to her`, because there is no permission to express it with",
				Note: "the row the design reads as promising and does not yet deliver",
			},
		},
		Claims: []scenario.Claim{
			scenario.C(scenario.ClaimAnyActorMayClassify, "user:eve", "clearance:matter-9999-team",
				"the demonstration, against the real registry: an ordinary associate constructs a "+
					"MandatoryAct naming herself, the registry accepts it, and she is now in the "+
					"conflict screen's clearance group. The claim passes today and is written to fail "+
					"the moment a classify permission lands — at which point this scenario moves out "+
					"of UNEXPRESSIBLE.md and the §17 register loses an entry"),
			scenario.C(scenario.ClaimSchemaAccepted, "matter", "",
				"nothing about the tier-1 schema is involved. The gap is in the mandatory channel, "+
					"which is the one place the corpus's other scenarios take on trust"),
		},
	}
}
