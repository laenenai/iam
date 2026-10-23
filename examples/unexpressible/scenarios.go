// Package unexpressible holds the use cases this design cannot currently
// express, each located at the exact relation, rule or closure that cannot
// be written.
//
// It is the most valuable package in the corpus. Design §8.5's last
// paragraph used to read "where a real requirement cannot be expressed in
// the subset, the answer is a classification, not a richer language. If a
// requirement arrives that is neither — that is a design conversation, not
// a configuration change." The first sentence went with the deny
// mechanism, which makes the second one apply to everything in here.
//
// # What the removal of the deny mechanism did to this package
//
// It closed two scenarios and made one strictly worse, and the arithmetic
// is worth stating because it is not a tidy win.
//
// Two are gone, resolved by deletion rather than by being solved. U2
// showed that answering a discretionary requirement with a classification
// converted a preference into an absolute no owner could lift; there is no
// classification to answer with, so the gap has nothing left to be a gap
// in. U6 showed that nothing checked whether the actor on a mandatory act
// was allowed to classify at all; there are no mandatory acts.
//
// One is worse. U1 — "may read Person entities but not salary facts" —
// had two candidate resolutions, and the cheaper one was "express it as a
// classification, accepting what U2 says that costs". That resolution no
// longer exists, so U1's only remaining option is the expensive one, which
// moves part of the trust boundary into consumer code. See U1's Cost.
//
// One is redirected. U4 asked whether an attribute-scoped *classification*
// could hide a column. As written it is moot. The problem underneath it is
// not: a `WHERE` fragment still hides rows rather than columns, whatever
// tier the restriction is written in, so U4 now asks the question without
// the label and lands in the same place as U1.
//
// Every scenario here *demonstrates* its gap rather than asserting it. The
// harness refuses an unexpressible scenario that does not carry a claim
// which runs — the schema lint rejecting the relation, DirectPath refusing
// a DAG, AttributeEnforceable reporting that a column cannot be hidden by
// a `WHERE` clause, or an ancestry closure moving under an ordinary data
// write. So if the design grows to cover one of these, the corresponding
// claim starts failing and says so.
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

// Scenarios returns the use cases the design cannot express.
//
// There were six. U2 (the classification workaround promoting a
// preference to an absolute) and U6 (nothing checking whether an actor may
// classify) are resolved by deletion and are recorded as such in
// ../UNEXPRESSIBLE.md rather than silently dropped.
func Scenarios() []scenario.Scenario {
	return []scenario.Scenario{
		ontologyScopeExclusion(),
		dagContainment(),
		attributeScopedOnColumns(),
		predicateDefinedEntitySet(),
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
			unreachable: not denied, not allowed, unanswerable.

			This scenario got strictly harder when the deny mechanism was removed,
			and that is the most important thing on it. It used to have two
			candidate resolutions, and the cheap one was "kgs drops the
			ontology-scope dimension and expresses the requirement as a
			classification scoped to the salary attribute". That option had a
			price — the corpus's own U2 existed to show it, because the label
			turned a preference into an absolute no owner could lift — but it
			existed, and for a requirement that genuinely was absolute it was the
			right answer. There is no classification now, so the only remaining
			resolution is the expensive one: ` + "`Predicate`" + ` returns a
			permitted-attribute or permitted-predicate set alongside its fragment
			and the *consumer* applies it, which moves part of the trust boundary
			into consumer code where this module can neither enforce nor detect a
			consumer that forgets.

			It is also now the same question as U4 rather than a cousin of it. The
			design already said F4 and F7 resolve to the same fork; with the
			classification route deleted they are one fork with one option on
			it.`,
		Governs: []string{"§17 F7", "§17 F4", "§8.5", "KGS §9.3 ontology scope"},
		Status:  scenario.StatusUnexpressible,
		Finding: "F7 (ontology scope) + F4",
		Cost: "Adding a form conditioned on resource attributes costs §9's projection, which is what " +
			"buys the entire A2 budget: union, usersets and inheritance precompute into a closure and " +
			"a conditional expression does not. An exclusion operator costs that and more, and is now " +
			"refused on a stronger ground than locality — there is no deny mechanism at all, so an " +
			"exclusion operator is not a badly-scoped absolute but a mechanism the design has ruled " +
			"out. " +
			"What changed is the alternative. Expressing the requirement as a classification scoped " +
			"to the attribute was the cheap resolution and it no longer exists — the mechanism was " +
			"deleted, not deprecated — so one option remains inside this module: `Predicate` grows a " +
			"second return value, a permitted-predicate or permitted-attribute set the consumer " +
			"applies. The price is worth stating precisely now that it is unavoidable rather than one " +
			"of two: a consumer that forgets to apply the set is a disclosure this module can neither " +
			"prevent nor detect, and if it is chosen the §9.4 differential audit must cover consumer " +
			"compliance and not only projection divergence. The alternative is that kgs drops the " +
			"dimension, which is now the only resolution that keeps the trust boundary where it is.",
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
				Unreachable: "F7: the only mechanism that would produce this deny is a conditional or " +
					"exclusionary relation, and §8.5 permits neither. There is no rule to write, and " +
					"no second tier left to write it in either",
				Note: "the row the requirement is about",
			},
			{
				Principal: "user:hr-director", Action: "read", Resource: scenario.R("fact:jonas-salary"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because:     "graph:hr#viewer@group:hr#member",
				Unreachable: "F7: and the exemption for the director has nowhere to live either",
				Note: "the director's exemption used to be the half that made a classification the " +
					"wrong answer, which was U2's entire subject. It is now simply a second row with " +
					"no mechanism behind it, like the one above",
			},
		},
		Claims: []scenario.Claim{
			scenario.C(scenario.ClaimSchemaRejected, "fact#viewer", "F7",
				"the demonstration: the schema lint refuses the fixture, and the refusal names the "+
					"open findings rather than an alternative mechanism. That changed with this "+
					"refactor and the change is deliberate — the lint used to point the consumer at "+
					"the classification mechanism, and a refusal naming a mechanism that no longer "+
					"exists is worse than one admitting the requirement has no form"),
			scenario.C(scenario.ClaimAttributeEnforceable, "fact:jonas-salary.predicate", "true",
				"and the contrast that locates the gap precisely: a kgs fact is row-shaped, so a "+
					"restriction at this granularity would be enforceable by the compiled fragment if "+
					"there were any way to *express* it. U1's gap is the rule language; U4's is the "+
					"fragment. They now share their only resolution"),
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
		Title: "An attribute-scoped restriction cannot be enforced by a row predicate, whatever tier it is written in",
		Models: `Eva may read the payroll document and not its salary column.

			As this scenario used to be written, the requirement is moot. Design
			§8.3 offered a classification "declared over a whole resource, or over
			a named attribute or field of it, which is how property-level and
			cell-level security compose without a second mechanism", and the
			scenario's subject was that the gate could answer
			"may she see document:payroll.salary" correctly while ` + "`Predicate`" + ` could
			not express the answer at all. There is no classification, so there is
			no attribute-scoped label to be unenforceable.

			The problem underneath it did not move an inch, which is why this
			scenario is redirected rather than deleted. Design §9 compiles
			authorization into a ` + "`WHERE`" + ` fragment the consumer joins, and a ` + "`WHERE`" + `
			fragment hides rows and not columns. That is a property of SQL and of
			the consumer's storage shape, and it was never a property of which
			tier the restriction was written in. So the scenario asks the same
			question with the label taken out: given a resource whose attributes
			are columns of one row, can the fragment express a restriction at
			attribute granularity? It cannot, and the fixture carries the
			row-shaped contrast beside it so the finding stays precise rather than
			general — kgs is fine because a fact *is* an attribute, and CAS is not
			because a document's fields are columns.

			What changed is the remedy, not the finding. F4 used to have three
			answers and one of them was "declare it as a classification scoped to
			the attribute, accepting that it becomes mandatory". That is gone, so
			F4 and F7 are now one fork with one option on it: ` + "`Predicate`" + ` returns a
			permitted-attribute set the consumer applies. Read U1 next; it is the
			same decision from the rule-language side.`,
		Governs: []string{"§17 F4", "§17 F7", "§9", "§9.1", "CAS §9.3"},
		Status:  scenario.StatusUnexpressible,
		Finding: "F4 (attribute granularity vs row predicate)",
		Cost: "Two options, and they are not variations of each other. (a) `Predicate` returns a " +
			"fragment *plus* a permitted-attribute set, and the consumer applies the second part. " +
			"That is cheap to build and it moves a piece of the trust boundary into consumer code: " +
			"the module would no longer be able to say that nothing but a grant permits anything, " +
			"because a consumer that forgets to apply the attribute set is a disclosure this module " +
			"can neither prevent nor detect. If it is chosen, the differential audit (§9.4) must " +
			"cover consumer compliance and not only projection divergence, which is a larger audit " +
			"than the one designed. (b) This module becomes a query rewriter, parsing and rewriting " +
			"SELECT lists across three consumers' query builders. That keeps the trust boundary " +
			"intact and is a different module with a different charter — and CHARTER.md's `it must " +
			"not contain` list would have to grow a line either way. " +
			"A third, cheaper answer exists for CAS specifically and is unaffected by any of this: " +
			"make sensitive document fields their own addressable resources, so the columnar case " +
			"becomes a row case and an ordinary grant reaches it. It costs a schema migration in CAS " +
			"and a cardinality increase in its tables, and it needs no new mechanism here. With the " +
			"classification route deleted, it is now the only resolution that needs nothing of this " +
			"module at all, which makes it more attractive than it was rather than less.",
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
			},
			Groups: []scenario.GroupSpec{
				{Name: "group:staff", Members: []string{"user:eva", "user:hr-director"}},
			},
			Containment: []scenario.Edge{
				scenario.E("document:payroll", "fileset:hr"),
				scenario.E("fact:jonas-salary", "fileset:hr"),
			},
			Tuples: []scenario.Tuple{
				{
					Object: scenario.R("fileset:hr"), Relation: "viewer",
					Subject: scenario.US("group:staff", "member"),
					Note: "the ordinary grant, and the only mechanism in the fixture. Note that it " +
						"reaches both the columnar document and the row-shaped fact identically — " +
						"the difference the finding is about appears only when something tries to " +
						"restrict below the object",
				},
			},
		},
		Expect: []scenario.Expectation{
			{
				Principal: "user:eva", Action: "read", Resource: scenario.R("document:payroll"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "fileset:hr#viewer@group:staff#member",
				Note: "she may read the document, and correctly so: the grant is on the fileset and " +
					"reaches it. That is also precisely what makes the finding bite — the fragment " +
					"lets the row through and something else has to hide the column",
			},
			{
				Principal: "user:eva", Action: "read", Resource: scenario.R("document:payroll.salary"),
				Want: scenario.Deny, Reason: scenario.ReasonNoGrant,
				Unreachable: "F4: there is nothing that produces this deny. There is no rule language " +
					"for it (U1) and there would be no way to compile it if there were, because a " +
					"`WHERE` fragment hides rows and not columns. A consumer that calls Decide per " +
					"cell has abandoned §9 and post-filters, which is KGS leak channel #6; a consumer " +
					"that calls Predicate receives a row filter returning the row with the salary in " +
					"it. This row used to be reachable by Decide and unreachable by Predicate, which " +
					"was a narrower and more confusing gap",
				Note: "the undeliverable row",
			},
			{
				Principal: "user:eva", Action: "read", Resource: scenario.R("fact:jonas-salary.value"),
				Want: scenario.Deny, Reason: scenario.ReasonNoGrant,
				Unreachable: "F7, not F4: over a row-shaped resource the *fragment* could express this " +
					"restriction — hiding the attribute is hiding the row — and there is still no way " +
					"to write the rule. The two halves of the problem separate cleanly here, which is " +
					"what the two claims below assert",
				Note: "the same requirement over a row-shaped resource. Enforceable and still " +
					"unwritable",
			},
			{
				Principal: "user:hr-director", Action: "read", Resource: scenario.R("fact:jonas-salary"),
				Want: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "fileset:hr#viewer@group:staff#member",
				Note:    "and the whole-object grant works for both of them, which is all there is",
			},
		},
		Claims: []scenario.Claim{
			scenario.C(scenario.ClaimAttributeEnforceable, "document:payroll.salary", "false",
				"the demonstration, and it needs no label to make it: a restriction at this "+
					"granularity cannot be enforced by the fragment design §9 compiles, because the "+
					"attribute is a column of a columnar kind and a `WHERE` clause hides rows"),
			scenario.C(scenario.ClaimAttributeEnforceable, "fact:jonas-salary.value", "true",
				"and the contrast that makes the finding precise rather than general: the identical "+
					"granularity over a row-shaped kind is enforceable. F4 is a property of the "+
					"consumer's storage shape, which is why kgs is fine and CAS is not — and why "+
					"CAS's own cheapest resolution is to make the field a row"),
			scenario.C(scenario.ClaimSchemaAccepted, "document", "",
				"and nothing in the schema is wrong, so no lint catches this. It is caught by asking "+
					"what the compiled fragment can express, which is what AttributeEnforceable does"),
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
