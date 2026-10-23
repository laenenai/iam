// Package scenario is the language the `iam` use-case corpus is written
// in, plus the harness that runs it.
//
// A scenario in this corpus is data, not a test function. It carries a
// fixture — tenants, principals, ordinary groups, clearance groups,
// containers and their containment edges, relation tuples, classifications
// and their enforcement classes — and an expectation table of
// (principal, action, resource) -> allow | deny in which every row names
// the *reason*: which tuple granted it, which classification denied it. A
// scenario that passes for the wrong reason is worse than one that fails,
// so the harness matches the reason as well as the verdict.
//
// # Why data and not tests
//
// The same corpus has to run three times against three different things:
// the in-memory registry that exists today, the Postgres registry, and the
// decision API (`Decide`, `Predicate`) that does not exist yet. A test
// function can only ever run against what it was written against. A
// fixture plus a table can be replayed against any evaluator, and the
// difference between two evaluators' answers to the same table is exactly
// design §9.4's differential authorization audit.
//
// # What runs today, and what is pending on what
//
// The identity half of every fixture is *materialized against a real
// registry* — JIT provisioning, ordinary and clearance-group membership,
// agent-run delegation, deprovisioning — so those assertions are live.
//
// The tier-1 tuple store and the tier-2 classification store do not exist,
// so expectation tables are evaluated by the reference decision procedure
// in oracle.go. That oracle implements design §7.1's conjunction over
// design §8.2's four permitted composition forms and nothing else: it
// refuses, with ErrUnexpressible, anything outside §8.5's subset. It is a
// test oracle and deliberately not an engine — its value is that it is the
// restriction made executable, so a scenario the design cannot express
// fails here rather than being argued about.
//
// Every scenario whose table needs the real API therefore carries
// StatusPending and the capabilities it waits on. pending.go explains the
// two mechanisms that stop a pending scenario from staying pending
// silently.
package scenario

import (
	"fmt"
	"strings"
	"time"

	"github.com/laenenai/iam"
)

// Ref names one object in a fixture: a container, a resource, a role, a
// group. The notation is the design's own — `document:x`, `folder:shared`,
// `team:eng` — with an optional attribute suffix, `document:x.salary`, for
// the attribute-scoped rules of design §8.3 and finding F4.
type Ref struct {
	// Kind is the registered resource kind, the part before the colon.
	Kind string
	// ID identifies the object within its kind.
	ID string
	// Attribute names a field of the object, or is empty for the whole
	// object. An attribute-scoped reference is the finest granularity the
	// design claims (§8.3's "over a named attribute or field of it") and
	// the one finding F4 says a row predicate cannot enforce.
	Attribute string
}

// R parses the compact notation used throughout the corpus:
// `kind:id` or `kind:id.attribute`. A string that is not in that form
// yields a Ref whose Kind is empty, which every lint and every claim
// rejects, so a typo in fixture data fails rather than silently naming
// nothing.
func R(s string) Ref {
	kind, rest, ok := strings.Cut(s, ":")
	if !ok {
		return Ref{}
	}
	id, attr, hasAttr := strings.Cut(rest, ".")
	if !hasAttr {
		return Ref{Kind: kind, ID: id}
	}
	return Ref{Kind: kind, ID: id, Attribute: attr}
}

// Object returns r with any attribute suffix dropped: the object an
// attribute belongs to.
func (r Ref) Object() Ref { return Ref{Kind: r.Kind, ID: r.ID} }

// IsZero reports whether r names nothing.
func (r Ref) IsZero() bool { return r.Kind == "" && r.ID == "" }

// String renders r in the corpus notation.
func (r Ref) String() string {
	if r.Attribute != "" {
		return r.Kind + ":" + r.ID + "." + r.Attribute
	}
	return r.Kind + ":" + r.ID
}

// Shape is how a resource kind's attributes are stored, which decides
// whether an attribute-scoped classification can be enforced by a `WHERE`
// clause at all. This is finding F4 made a field.
type Shape string

const (
	// ShapeRow means each attribute of the resource is its own row, so an
	// attribute-scoped rule is a row predicate like any other. A kgs fact
	// is row-shaped: "facts carry attributes rather than entities carrying
	// columns" (KGS §9.2).
	ShapeRow Shape = "row"
	// ShapeColumnar means the resource's attributes are columns of one
	// row. An attribute-scoped classification over a columnar kind cannot
	// be enforced by a row predicate — a `WHERE` clause hides rows, not
	// columns — which is finding F4. A CAS document is columnar.
	ShapeColumnar Shape = "columnar"
)

// Relation is one relation definition in a registered schema (design
// §8.4), restricted to the four composition forms of §8.2. The fields are
// named after the forms rather than after a policy language, so a form
// outside the subset has nowhere to be written — except the two fields
// below that exist only so the lint has something to reject.
type Relation struct {
	// Name is the relation's name, as it appears in a tuple.
	Name string
	// Direct permits form 1: tuples whose subject is a principal.
	Direct bool
	// Usersets permits form 2: the `kind#relation` shapes this relation
	// accepts as a userset subject, such as `group#member` or
	// `role#assignee`. A userset subject whose shape is not listed is a
	// schema violation, which is how a clearance group is kept out of a
	// tier-1 tuple by the lint as well as by the type system.
	Usersets []string
	// InheritFromParent permits form 3, tuple-to-userset inheritance
	// (`viewer from parent`): the relation names on this object's parents
	// that confer this relation. One tuple on the container reaches every
	// descendant, which is the Google Drive behaviour of design §8.2.
	InheritFromParent []string
	// Union permits form 4: other relations on the *same* object that
	// confer this one.
	Union []string

	// Exclude is form 5, which does not exist. It is declarable only so
	// that the corpus can hand the lint an exclusionary relation and
	// assert the refusal, which is design §4/A3's "CI lints registered
	// schemas and rejects any exclusion operator". No scenario outside
	// examples/unexpressible may set it.
	Exclude []string
	// AttributeCondition is a condition over resource attributes, which
	// §8.5 also excludes. Declarable for the same reason as Exclude, and
	// it is the shape finding F7's "may read Person but not salary"
	// requirement arrives in.
	AttributeCondition string
}

// ResourceKind is one registered object type: its relations, the actions
// that map onto them, and the storage shape that decides whether an
// attribute-scoped classification is enforceable.
type ResourceKind struct {
	// Name is the kind, the part before the colon in a Ref.
	Name string
	// Shape is how the kind stores its attributes. See Shape.
	Shape Shape
	// Relations are the kind's relation definitions.
	Relations []Relation
	// Actions maps an action name a consumer asks about onto the relation
	// that permits it. Design §8.4: "the actions that map onto relations".
	Actions map[string]string
}

// Userset is a subject that is a set of principals rather than one
// principal: `team:eng#member`, `role:ws-reader#assignee`. Groups, teams
// and roles need no special mechanism — a userset is resolved by asking
// whether the principal holds that relation on that object, which is the
// same question as any other.
type Userset struct {
	// Object is the object the relation is held on.
	Object Ref
	// Relation is the relation name.
	Relation string
}

// String renders the userset as `object#relation`.
func (u Userset) String() string { return u.Object.String() + "#" + u.Relation }

// Subject is a tuple's subject: exactly one of a principal or a userset.
type Subject struct {
	// Principal is a fixture-local principal name in the design's
	// notation, `user:anne` or `service:researcher`. It matches a
	// PrincipalSpec.Name.
	Principal string
	// Userset is set instead of Principal for form 2.
	Userset *Userset
}

// P returns a principal subject.
func P(name string) Subject { return Subject{Principal: name} }

// US returns a userset subject over `object#relation`.
func US(object, relation string) Subject {
	u := Userset{Object: R(object), Relation: relation}
	return Subject{Userset: &u}
}

// String renders the subject.
func (s Subject) String() string {
	if s.Userset != nil {
		return s.Userset.String()
	}
	return s.Principal
}

// Tuple is one relation tuple, `object#relation@subject` (design §8.2).
type Tuple struct {
	// Object is the object the relation is written on.
	Object Ref
	// Relation is the relation name.
	Relation string
	// Subject is who or what holds it.
	Subject Subject
	// Note records why this tuple exists, for the corpus's own
	// readability. It is never matched against anything.
	Note string
}

// T builds a tuple from the compact notation: T("folder:shared", "viewer",
// P("user:anne")).
func T(object, relation string, subject Subject) Tuple {
	return Tuple{Object: R(object), Relation: relation, Subject: subject}
}

// String renders the tuple in the design's notation.
func (t Tuple) String() string {
	return t.Object.String() + "#" + t.Relation + "@" + t.Subject.String()
}

// EdgeKind distinguishes a containment edge that is a stored fact from one
// that is a function of data.
type EdgeKind string

const (
	// EdgeExplicit is a stored containment edge: this document is in that
	// fileset because somebody put it there.
	EdgeExplicit EdgeKind = "explicit"
	// EdgePredicate is a containment edge defined by a predicate over
	// data, which is KGS §9.3's predicate-defined entity-set. Membership
	// changes when data changes, so authorization changes without any
	// authorization operation having happened. See examples/unexpressible.
	EdgePredicate EdgeKind = "predicate"
)

// Edge is one containment edge, child contained by parent. Design §9.2's
// ancestry closure is the transitive closure of these.
type Edge struct {
	// Child is the contained object.
	Child Ref
	// Parent is the container.
	Parent Ref
	// Kind is whether the edge is stored or derived from data.
	Kind EdgeKind
	// Predicate states, in prose, the data condition an EdgePredicate edge
	// depends on. It is documentation for the reader and the subject of
	// the ClaimStableUnderWrite claim; nothing evaluates it.
	Predicate string
}

// E returns an explicit containment edge: E("document:invoice",
// "fileset:household") reads "the document is contained by the fileset".
func E(child, parent string) Edge {
	return Edge{Child: R(child), Parent: R(parent), Kind: EdgeExplicit}
}

// EnforcementClass is design §7.3's one field: whether a classification is
// enforced by policy, which an administrator administers, or by a key the
// deployment does not hold.
type EnforcementClass string

const (
	// EnforcementPolicy means the classification is enforced by this
	// module's decision procedure.
	EnforcementPolicy EnforcementClass = "policy"
	// EnforcementCrypto means the content is encrypted under a key the
	// deployment does not hold (`keyring` + `escrow`). Decide may return
	// allow for such a resource and the caller still cannot read it. The
	// decision API and the enforcement tier are different things, which is
	// what examples/household's will scenario exists to show.
	EnforcementCrypto EnforcementClass = "crypto"
)

// Classification is a label on resources; a principal satisfies it by
// holding the matching clearance (design §8.3). It is mandatory: no tuple,
// no owner and no sequence of discretionary operations can satisfy it.
type Classification struct {
	// Label is the classification's name, `personal:pascal`,
	// `conflict:matter-1234`.
	Label string
	// Enforcement is the enforcement class.
	Enforcement EnforcementClass
	// Attribute scopes the classification to one named attribute of the
	// resources it is assigned to, or is empty for the whole resource.
	Attribute string
	// Why records the real-world rule the label encodes.
	Why string
}

// Assignment attaches a classification to a resource. The gate resolves a
// resource's label set over its ancestry closure and its derivation inputs
// as well as its own assignments (design §8.3).
type Assignment struct {
	// Resource is the object the label is attached to.
	Resource Ref
	// Label is the classification's label.
	Label string
}

// AS returns an assignment: AS("document:invoice", "personal:pascal").
func AS(resource, label string) Assignment {
	return Assignment{Resource: R(resource), Label: label}
}

// Derivation declares that Output was derived from Inputs, so Output
// carries the union of their classifications (design §8.3). A pipeline
// cannot launder a classification by deriving, and unlike Foundry there is
// no read boundary at which propagation stops.
type Derivation struct {
	// Output is the derived object.
	Output Ref
	// Inputs are the objects it was derived from.
	Inputs []Ref
	// Note records what the derivation is, for readability.
	Note string
}

// PrincipalSpec is one principal in a fixture. It is materialized against
// a real registry: a user or service through JIT provisioning from claims,
// an agent run through delegation.
type PrincipalSpec struct {
	// Name is the fixture-local name in the design's notation,
	// `user:anne`. Tuples and expectations reference it by this string.
	Name string
	// Kind is the principal kind. An agent run must also set DelegatedBy.
	Kind iam.PrincipalKind
	// Issuer is the OIDC issuer the claims arrived from. Empty means the
	// fixture's default issuer.
	Issuer string
	// Subject is the external subject claim. Empty means Name's local
	// part, which keeps fixture data terse.
	Subject string
	// ClaimGroups are the group names the issuer asserted. They are
	// upserted into the registry on sight and are *ordinary* groups: a
	// claim can never name a clearance group, and the mandatory scenarios
	// prove it by trying.
	ClaimGroups []string
	// DelegatedBy names the parent principal for an agent run.
	DelegatedBy string
	// TTL is the agent run's TTL. Zero means one hour.
	TTL time.Duration
	// Deprovisioned marks the principal deprovisioned immediately after
	// provisioning, for the cascade and immediate-denial scenarios.
	Deprovisioned bool
	// Role records what this principal is in the modelled situation.
	Role string
}

// GroupSpec is one ordinary, tier-1 group. Its membership is
// discretionary: anybody who may share may change it.
type GroupSpec struct {
	// Name is the group object's name, `team:eng`.
	Name string
	// Members are principal names added through the local channel, which
	// claim reconciliation never removes.
	Members []string
	// Note records what the group is.
	Note string
}

// ClearanceGroupSpec is one clearance group: a mandatory object whose
// membership moves only through a mandatory channel and which can never be
// referenced in a tier-1 tuple (design §8.3).
type ClearanceGroupSpec struct {
	// Name is the clearance group's name. The corpus spells every one
	// `clearance:...` so the lint can refuse a tuple naming one on sight.
	Name string
	// Channel is the mandatory channel that administers it, fixed at
	// creation.
	Channel iam.MandatoryChannel
	// Members are the principal names the mandatory channel admitted.
	Members []string
	// Labels are the classification labels this group's members satisfy.
	// This is tier-2 state that the identity registry deliberately does
	// not hold — it belongs to the classification store, which does not
	// exist yet — so in this corpus the membership is live and the label
	// binding is fixture data.
	Labels []string
	// Reason is the mandatory act's reason, recorded in the group's trail.
	Reason string
}

// DirectClearance is a clearance held by one principal rather than through
// a clearance group. Design §8.3 permits both.
type DirectClearance struct {
	// Principal is the holder's fixture-local name.
	Principal string
	// Label is the classification satisfied.
	Label string
}

// Fixture is the declarative world a scenario is decided against.
type Fixture struct {
	// Tenant is a human label for the tenant; the real TenantID is minted
	// at materialization.
	Tenant string
	// Issuer is the default OIDC issuer for principals that name none.
	Issuer string
	// Kinds are the registered resource kinds and their relations.
	Kinds []ResourceKind
	// Principals, Groups and ClearanceGroups are the identity layer, and
	// are materialized against a real registry.
	Principals      []PrincipalSpec
	Groups          []GroupSpec
	ClearanceGroups []ClearanceGroupSpec
	// DirectClearances are clearances held by a principal directly.
	DirectClearances []DirectClearance
	// Containment is the containment graph. Design §9.2 calls its
	// transitive closure the ancestry closure.
	Containment []Edge
	// Tuples are the tier-1 grants.
	Tuples []Tuple
	// Classifications are the tier-2 label definitions.
	Classifications []Classification
	// Assignments attach labels to resources.
	Assignments []Assignment
	// Derivations declare derived objects, whose label set is the union of
	// their inputs'.
	Derivations []Derivation
	// Mentions record which facts reference which entities. KGS §7.3
	// derives an entity's *existence* for a principal rather than giving
	// it an ACL: an entity exists for P iff P can read at least one
	// assertion that references it. That is leak channel #1's mitigation,
	// and it is the mechanism that makes cross-principal dedup safe — two
	// principals can hold the same supplier entity through different
	// facts without either learning of the other's.
	Mentions []Mention
	// LaterWrites are writes that happen *after* the expectation table is
	// evaluated, used by ClaimStableUnderWrite to show where a write
	// changes an authorization answer with no authorization operation
	// having occurred.
	LaterWrites []LaterWrite
}

// Mention records that a fact references an entity.
type Mention struct {
	// Fact is the assertion.
	Fact Ref
	// Entity is the entity it references.
	Entity Ref
}

// M returns a mention: M("fact:supplier-name", "entity:acme").
func M(fact, entity string) Mention { return Mention{Fact: R(fact), Entity: R(entity)} }

// LaterWrite is an ordinary data write, declared so a claim can show what
// it does to an authorization answer.
type LaterWrite struct {
	// What describes the write in prose.
	What string
	// AddEdges are containment edges the write creates — the case that
	// matters is a predicate-defined entity-set gaining a member because a
	// fact was asserted.
	AddEdges []Edge
	// AddAssignments are classification assignments the write creates.
	AddAssignments []Assignment
}

// Verdict is the answer to one expectation row.
type Verdict string

const (
	// Allow is a permitted decision.
	Allow Verdict = "allow"
	// Deny is a refusal. In every consumer it is rendered as "not found",
	// never as "forbidden" (CAS §9.4, KGS leak channel #9).
	Deny Verdict = "deny"
)

// ReasonKind names *why* a verdict came out the way it did. The harness
// matches it, because a scenario that passes for the wrong reason is worse
// than one that fails: a deny that should have come from a classification
// and came instead from a missing grant would pass a verdict-only table
// while the mandatory control was broken.
type ReasonKind string

const (
	// ReasonDirect is form 1: a tuple naming the principal on the
	// resource itself.
	ReasonDirect ReasonKind = "direct-tuple"
	// ReasonUserset is form 2: a tuple whose subject is a userset the
	// principal belongs to.
	ReasonUserset ReasonKind = "userset-tuple"
	// ReasonInherited is form 3: a tuple on an ancestor, reaching the
	// resource through containment at one tuple per hop.
	ReasonInherited ReasonKind = "inherited-tuple"
	// ReasonUnion is form 4: another relation on the same object confers
	// this one.
	ReasonUnion ReasonKind = "union"
	// ReasonNoGrant is a deny because no tuple reaches the principal. The
	// everyday deny, and the default.
	ReasonNoGrant ReasonKind = "no-grant"
	// ReasonClassification is a deny from the mandatory gate: the
	// resource carries a classification the principal does not satisfy.
	// No tuple can produce an allow against it.
	ReasonClassification ReasonKind = "classification"
	// ReasonPrincipalUnusable is a deny because the principal is
	// deprovisioned, expired or staler than the deployment's bound. It is
	// evaluated before either tier.
	ReasonPrincipalUnusable ReasonKind = "principal-unusable"
)

// Expectation is one row of the table: a principal, an action, a resource,
// the verdict, and the named reason.
type Expectation struct {
	// Principal is the fixture-local principal name.
	Principal string
	// Action is an action name registered on the resource's kind.
	Action string
	// Resource is the object or attribute being decided.
	Resource Ref
	// Want is the required verdict.
	Want Verdict
	// Reason is the required reason kind.
	Reason ReasonKind
	// Because names the specific tuple or classification responsible, in
	// the design's notation: `folder:shared#viewer@team:eng#member`, or
	// `personal:pascal`. The harness compares it exactly, so a scenario
	// cannot drift into passing through a different grant than the one it
	// documents. Empty means "do not check which one", which is only
	// acceptable for ReasonNoGrant.
	Because string
	// Note explains the row in the modelled situation.
	Note string
	// Unreachable marks a row the design cannot deliver, naming why. Such
	// a row is *not* evaluated against the reference oracle — it is the
	// requirement written down precisely, and the gap is demonstrated
	// instead by a structural claim that runs. A scenario carrying an
	// unreachable row must carry such a claim, and the harness refuses one
	// that does not: a requirement declared impossible with nothing
	// executable behind the declaration is prose, which is what this
	// corpus exists not to be.
	Unreachable string
}

// Status is what the corpus can honestly say about a scenario today.
type Status string

const (
	// StatusLive means every assertion in the scenario runs against the
	// real module: the identity fixture is materialized against a real
	// registry and the structural claims are evaluated. Nothing in a live
	// scenario depends on an API that does not exist.
	StatusLive Status = "live"
	// StatusPending means the scenario's expectation table needs the
	// decision API. Its identity fixture and its structural claims still
	// run; its table is evaluated by the reference oracle and is *not*
	// yet evidence about `iam`. PendingOn names what it waits for, and
	// pending.go describes the two mechanisms that make it fail loudly
	// when that arrives.
	StatusPending Status = "pending"
	// StatusUnexpressible means the design cannot express the use case at
	// all. The scenario exists to locate the gap precisely: its claims
	// assert the refusal, so the gap is demonstrated rather than
	// asserted, and Finding and Cost record which §17 finding it maps to
	// and what supporting it would cost. See examples/UNEXPRESSIBLE.md.
	StatusUnexpressible Status = "unexpressible"
)

// Scenario is one use case: a prose header, the design sections that
// govern it, a fixture, an expectation table, and the structural claims
// that can be checked today.
type Scenario struct {
	// ID is the corpus-stable identifier, `D1`, `M4`, `H2`, `A3`, `U1`.
	ID string
	// Title is a one-line name.
	Title string
	// Models is the one-paragraph prose header: what real situation this
	// models and which design section governs it.
	Models string
	// Governs lists the design sections that decide this scenario.
	Governs []string
	// Status is what the corpus can say about it today.
	Status Status
	// PendingOn lists the capabilities a StatusPending scenario waits on.
	PendingOn []Capability
	// Finding is the §17 finding a StatusUnexpressible scenario maps to.
	Finding string
	// Cost is what supporting a StatusUnexpressible use case would cost.
	Cost string
	// Fixture is the world.
	Fixture Fixture
	// Expect is the expectation table.
	Expect []Expectation
	// Claims are the structural assertions that run today with no
	// decision API: that a relation fits §8.5's subset or is rejected by
	// the lint, that sharing a container costs one tuple per hop, that a
	// resource has exactly one containment path or several, that a
	// classification is enforceable by a row predicate, that an ancestry
	// closure is stable under a later data write.
	Claims []Claim
}

// Validate reports whether s is a well-formed scenario. It is the corpus's
// own fixture lint: a scenario naming a principal that does not exist, or
// an action its kind does not register, would otherwise pass for the wrong
// reason.
func (s Scenario) Validate() error {
	if s.ID == "" || s.Title == "" {
		return fmt.Errorf("scenario %q: needs an id and a title", s.ID)
	}
	if strings.TrimSpace(s.Models) == "" {
		return fmt.Errorf("scenario %s: needs a prose header saying what it models", s.ID)
	}
	if len(s.Governs) == 0 {
		return fmt.Errorf("scenario %s: needs at least one governing design section", s.ID)
	}
	switch s.Status {
	case StatusLive:
		if len(s.PendingOn) != 0 {
			return fmt.Errorf("scenario %s: a live scenario cannot be pending on anything", s.ID)
		}
	case StatusPending:
		if len(s.PendingOn) == 0 {
			return fmt.Errorf("scenario %s: a pending scenario must name what it is pending on", s.ID)
		}
	case StatusUnexpressible:
		if s.Finding == "" || s.Cost == "" {
			return fmt.Errorf("scenario %s: an unexpressible scenario must name its §17 finding and its cost", s.ID)
		}
	default:
		return fmt.Errorf("scenario %s: unknown status %q", s.ID, s.Status)
	}
	if s.Status == StatusLive && len(s.Expect) != 0 {
		return fmt.Errorf("scenario %s: it carries an expectation table, which needs the decision API, so it is "+
			"pending and not live — a live scenario is one whose every assertion runs today", s.ID)
	}
	if s.Status == StatusUnexpressible {
		if len(s.Unreachable()) == 0 {
			return fmt.Errorf("scenario %s: an unexpressible scenario must mark at least one expectation row "+
				"unreachable, so that what cannot be expressed is written down precisely", s.ID)
		}
		demonstrated := false
		for _, c := range s.Claims {
			if gapClaims[c.Kind] {
				demonstrated = true
				break
			}
		}
		if !demonstrated {
			return fmt.Errorf("scenario %s: an unexpressible scenario must carry a claim that demonstrates the gap "+
				"(one of schema-rejected, no-direct-path, row-enforceable, stable-under-write); without one the "+
				"claim that the design cannot do this is prose rather than a test", s.ID)
		}
	}
	return s.Fixture.validateAgainst(s)
}

func (f Fixture) validateAgainst(s Scenario) error {
	names := make(map[string]bool, len(f.Principals))
	for _, p := range f.Principals {
		if p.Name == "" || R(p.Name).Kind == "" {
			return fmt.Errorf("scenario %s: principal name %q must be in kind:id form", s.ID, p.Name)
		}
		names[p.Name] = true
	}
	labels := make(map[string]bool, len(f.Classifications))
	for _, c := range f.Classifications {
		labels[c.Label] = true
	}
	for _, a := range f.Assignments {
		if !labels[a.Label] {
			return fmt.Errorf("scenario %s: assignment of %q names no declared classification", s.ID, a.Label)
		}
	}
	for _, cg := range f.ClearanceGroups {
		for _, l := range cg.Labels {
			if !labels[l] {
				return fmt.Errorf("scenario %s: clearance group %s satisfies undeclared label %q", s.ID, cg.Name, l)
			}
		}
	}
	for i, e := range s.Expect {
		if !names[e.Principal] {
			return fmt.Errorf("scenario %s: expectation %d names unknown principal %q", s.ID, i, e.Principal)
		}
		if e.Resource.IsZero() {
			return fmt.Errorf("scenario %s: expectation %d has no resource", s.ID, i)
		}
		if e.Want != Allow && e.Want != Deny {
			return fmt.Errorf("scenario %s: expectation %d has verdict %q", s.ID, i, e.Want)
		}
		if e.Because == "" && e.Reason != ReasonNoGrant && e.Reason != ReasonPrincipalUnusable {
			return fmt.Errorf("scenario %s: expectation %d must name the tuple or classification responsible", s.ID, i)
		}
	}
	return nil
}

// gapClaims are the claim kinds that demonstrate a gap in the design
// rather than confirming a property of it. An unexpressible scenario must
// carry at least one, so that what it says cannot be done is shown by code
// that runs rather than asserted in a comment.
var gapClaims = map[ClaimKind]bool{
	ClaimSchemaRejected:      true,
	ClaimNoDirectPath:        true,
	ClaimRowEnforceable:      true,
	ClaimStableUnderWrite:    true,
	ClaimAbsoluteHasNoLift:   true,
	ClaimAnyActorMayClassify: true,
}

// Unreachable returns the expectation rows the design cannot deliver.
func (s Scenario) Unreachable() []Expectation {
	var out []Expectation
	for _, e := range s.Expect {
		if e.Unreachable != "" {
			out = append(out, e)
		}
	}
	return out
}

// Kind returns the named resource kind, or false.
func (f Fixture) Kind(name string) (ResourceKind, bool) {
	for _, k := range f.Kinds {
		if k.Name == name {
			return k, true
		}
	}
	return ResourceKind{}, false
}

// Relation returns the named relation on the named kind, or false.
func (f Fixture) Relation(kind, relation string) (Relation, bool) {
	k, ok := f.Kind(kind)
	if !ok {
		return Relation{}, false
	}
	for _, r := range k.Relations {
		if r.Name == relation {
			return r, true
		}
	}
	return Relation{}, false
}

// Classification returns the named label definition, or false.
func (f Fixture) Classification(label string) (Classification, bool) {
	for _, c := range f.Classifications {
		if c.Label == label {
			return c, true
		}
	}
	return Classification{}, false
}

// Principal returns the named principal spec, or false.
func (f Fixture) Principal(name string) (PrincipalSpec, bool) {
	for _, p := range f.Principals {
		if p.Name == name {
			return p, true
		}
	}
	return PrincipalSpec{}, false
}
