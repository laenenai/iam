package scenario

import (
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
)

// Capability names one piece of `iam` a scenario's expectation table needs
// before it can be evidence about this module rather than about the corpus
// oracle. The names are the design's own.
type Capability string

const (
	// CapDecide is design §6's single-decision surface,
	// `iam.Decide(principal, action, resource, at)`.
	//
	// **It has arrived**, as `iam.Authorizer.Decide(ctx, iam.Request)` —
	// a point decision over a container, its ancestors and a principal's
	// live group membership. Nothing in the corpus pends on it any more,
	// and the constant stays because the tripwire reports what has
	// arrived rather than only what is waited on, and because a scenario
	// added tomorrow should not have to re-invent the name.
	CapDecide Capability = "Decide"
	// CapPredicate is design §6's second and more important surface: a
	// composable SQL fragment plus its bound parameters, embedded in the
	// consumer's own statement. A consumer that can only call Decide will
	// post-filter, which is KGS leak channel #6.
	CapPredicate Capability = "Predicate"
	// CapTupleStore is the relation-tuple store of design §8.2 and the
	// registered-schema registry of §8.4.
	//
	// Nothing pends on it any more either, and the reason is worth more
	// than the constant. What arrived is not a tuple store: it is grants
	// on containers, a containment tree, and a schema that declares
	// container kinds and permission names. Every pending scenario that
	// waited on "the tuple store" actually wanted somewhere to write its
	// fixture's grants, and that exists — examples/scenario/realapi.go
	// translates a tuple into a grant with no loss for thirteen of the
	// fourteen fixtures. Arbitrary relation tuples remain deliberately
	// unbuilt (see internal/authz's package doc), so the constant names
	// something real that does not exist, and no scenario should pend on
	// it unless it genuinely needs a relation that is not containment or
	// membership.
	CapTupleStore Capability = "TupleStore"
	// CapDerivation is the declared-derivation surface, through which a
	// derived object acquires the union of its inputs' markings. It still
	// names something real — content derived from sealed content is
	// sealed, and a consumer's egress gate has to be able to see that —
	// and it is no longer an authorization input, so nothing pending
	// waits on it.
	CapDerivation Capability = "Derivation"
	// CapVisibleBelow is design §8.2's bottom-up navigational visibility
	// as an explicit relation. Untouched by the removal of the mandatory
	// tier: it is a grant-layer relation, D7's table waits on it, and F3
	// still decides what it can even mean once containment is a DAG.
	CapVisibleBelow Capability = "VisibleBelow"
	// CapAttributePredicate is a `Predicate` that can express an
	// attribute-scoped restriction over a columnar resource kind — a
	// fragment plus a permitted-attribute set the consumer applies.
	//
	// It means more than it did, not less. It used to be one of two ways
	// to meet an attribute-granular requirement, the other being "declare
	// a classification scoped to that attribute". That option is gone, so
	// this is now the *only* candidate resolution for findings F4 and F7
	// both, and it is the one that moves part of the trust boundary into
	// consumer code.
	//
	// Nothing in the corpus pends on it, and that is a known hole rather
	// than a tidy state: U1 and U4 are the scenarios it would release, and
	// they are `unexpressible` rather than `pending`, so AssertTripwire —
	// which only looks at pending scenarios — will not fire when
	// `PermittedAttributes` reaches the facade. Whoever lands it has to
	// remember those two by hand.
	CapAttributePredicate Capability = "AttributePredicate"

	// CapNestedGroupMember is a group one of whose members is itself a
	// group — design §8.2's form 2 applied to its own output, and the one
	// thing D3 needs and cannot have. `iam` rules it out twice over and on
	// purpose: a group's members are principals, never other groups, and
	// there are no roles as first-class objects with relations of their
	// own for a userset to be resolved through instead. See
	// internal/authz's package doc, which states both absences as
	// decisions.
	//
	// It is worth being exact about what D3 loses, because it is one row
	// and not the scenario: `role:ws-reader#assignee@team:eng#member`, a
	// whole team holding a role. A principal assigned the role by name
	// works; the team does not. Roles-as-objects is otherwise intact, and
	// the scenario's point — that adding a resource kind adds no roles —
	// is carried by the rows that do run.
	//
	// The needles below are the shapes such a capability would have to
	// arrive in on this module's surface, and they are a guess about a
	// future method name rather than a certainty. That is the honest
	// weakness of a string tripwire, and it is why pending.txt exists
	// beside it: a name nobody predicted lands the change as a reviewed
	// ledger diff instead.
	CapNestedGroupMember Capability = "NestedGroupMember"

	// CapMarkingStore is design §8.3's markings and their enforcement
	// class, stored in this module. H4 and A3 wait on it.
	//
	// `Decide` never reading a marking is the design and is not the gap:
	// the cryptographic tier is deliberately not part of the decision.
	// The gap is that this layer stores no marking *at all*, so a
	// consumer cannot ask this module why content is unreadable, and the
	// claims that carry H4's and A3's whole point —
	// ClaimCryptoUnreadable, ClaimProviderRefused, ClaimMarkingSet — are
	// answered by the corpus's own marking resolution over fixture data.
	// Those two scenarios' expectation tables are fully live against
	// `iam.Decide`; what is not live is the half that matters most in
	// them, which is why they are honestly still pending.
	//
	// The needles are the design's own vocabulary rather than a guess:
	// §8.3 calls them markings and calls the field an enforcement class,
	// and the corpus has used both names since it was written.
	CapMarkingStore Capability = "MarkingStore"

	// There was a CapClassificationStore here: the tier-2 store of labels
	// on resources and clearances on clearance groups. It went with the
	// deny mechanism. The scenarios that waited on it now wait on
	// CapMarkingStore for the half of it that was never a deny — a label
	// saying what content *is* — and on nothing at all for the half that
	// was, because what they assert about access has become an ordinary
	// question about grants.
)

// Available reports which capabilities this build of `iam` actually has.
// It is empty today, and it is deliberately not a hand-maintained list of
// booleans: the tripwire below is what notices when it stops being empty,
// because a flag somebody has to remember to flip is exactly how a pending
// scenario stays pending forever.
func Available() []Capability { return nil }

// tripwireSymbols are the strings whose appearance in the module's public
// golden file means a capability has arrived. api.txt is regenerated by an
// ordinary test that `mise test` already runs, so landing a capability and
// regenerating the golden file is enough to set this off — no discipline
// required, and nothing to remember.
//
// A needle has to match wherever the capability will actually be written
// down, which is not always the facade: `Decide(ctx` is here beside
// `func Decide(` because the decision surface arrived as a method on a
// port rather than as a facade function. See scannedHeaders.
var tripwireSymbols = map[Capability][]string{
	CapDecide:             {"func Decide(", "Decide(ctx"},
	CapPredicate:          {"func Predicate(", "type Predicate"},
	CapTupleStore:         {"type Tuple", "func WriteTuple"},
	CapDerivation:         {"type Derivation", "func DeclareDerivation"},
	CapVisibleBelow:       {"VisibleBelow"},
	CapAttributePredicate: {"type AttributePredicate", "PermittedAttributes"},
	CapNestedGroupMember:  {"AddGroupToGroup", "AddNestedGroup", "NestedGroups", "GroupInGroup"},
	CapMarkingStore:       {"type Marking", "MarkingsOf", "EnforcementClass"},
}

// facadeHeader is the line api.txt uses to start the facade's own
// section.
const facadeHeader = "package iam // ."

// scannedHeaders are the api.txt sections the tripwire reads, and the list
// is the fix for a hole that let a capability land unnoticed.
//
// # Why the facade's own section was not enough
//
// The rule used to be "scan only the facade, because a capability has
// arrived when a *consumer* can name it, which per CONVENTIONS means when
// it reaches the facade". That rule is still right about *when* a
// capability has arrived and was wrong about *where* the arrival is
// written down. `Decide` reached consumers as a method on a port the
// facade re-exports by alias — `type Authorizer = authz.Authorizer` — so
// the facade's section grew one `type Authorizer` line and the string
// `Decide(ctx` appeared only under `package authz // internal/authz`. A
// consumer could call `iam.Authorizer.Decide` and the tripwire reported
// nothing. Fourteen pending scenarios stayed pending and the mechanism
// built to prevent exactly that said nothing at all.
//
// So the sections scanned are the facade's plus those of the internal
// packages whose types the facade re-exports for this surface. That is
// also why api.txt lists the internal packages in the first place: its own
// header says "the facade re-exports their types as aliases: a change to
// one of those signatures changes what a consumer sees".
//
// # What it costs, stated rather than hidden
//
// A symbol in `internal/authz` or `internal/domain` that the facade does
// *not* alias will now trip the wire even though no consumer can name it.
// That is the wrong answer in the cheap direction: an early tripwire costs
// one argument about a status line, and a late one costs exactly what just
// happened. The alternative — resolving each alias in the facade's section
// back to its internal declaration — is a Go-source parse of a text file
// that is deliberately not Go source.
//
// The whole file is still not scanned, and the reason is unchanged:
// examples/scenario necessarily declares a `Tuple`, a `Marking` and a
// `Decide` of its own, so `package scenario // examples/scenario` would
// match three needles the day it was written. Those live in their own
// section, which is why adding the two sections below is safe and adding
// that one would not be.
var scannedHeaders = []string{
	facadeHeader,
	"package authz // internal/authz",
	"package domain // internal/domain",
}

// Tripwire reads the module's public golden file and reports every
// capability that has arrived where a consumer can reach it. A non-empty
// result means at least one pending scenario must now be wired to the real
// API and have its status changed, and RunCorpus turns that into a test
// failure naming the scenarios.
//
// It scans the sections named by scannedHeaders rather than the facade's
// alone — see that variable for the hole this closed and what the wider
// scan costs. Every section it is told to scan must be present: a tripwire
// that silently watches nothing is worse than no tripwire, and a section
// that quietly stopped existing is how one becomes the other.
//
// This is the first of the two mechanisms that stop a pending scenario
// from staying pending silently, and it is the automatic one: api.txt is
// regenerated by an ordinary test that `mise test` already runs, so a
// capability reaching the public surface sets this off with nothing to
// remember. The second mechanism is pending.txt, the ledger below, which
// makes any change to the pending set a reviewed diff.
func Tripwire(apiGoldenPath string) ([]Capability, error) {
	raw, err := os.ReadFile(apiGoldenPath) //nolint:gosec // a fixed path inside the repository
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", apiGoldenPath, err)
	}

	sections := make([]string, 0, len(scannedHeaders))
	for _, header := range scannedHeaders {
		section, err := facadeSection(string(raw), header, apiGoldenPath)
		if err != nil {
			return nil, err
		}
		sections = append(sections, section)
	}
	surface := strings.Join(sections, "\n")

	var arrived []Capability
	for capability, needles := range tripwireSymbols {
		for _, n := range needles {
			if strings.Contains(surface, n) {
				arrived = append(arrived, capability)
				break
			}
		}
	}
	slices.Sort(arrived)
	return arrived, nil
}

// facadeSection returns one package's part of the golden file: everything
// from its header to the next package section. A golden file missing the
// requested section is an error rather than an empty result, because a
// tripwire that silently watches nothing is worse than no tripwire.
//
// It is still called facadeSection because the facade is the section that
// matters most, and it takes the header as an argument because the facade
// is not the only one that matters: see scannedHeaders for why scanning
// the facade alone was blind to a capability that arrived as a method on
// an aliased port.
func facadeSection(surface, header, path string) (string, error) {
	start := strings.Index(surface, header)
	if start < 0 {
		return "", fmt.Errorf("%s contains no %q section, so the pending tripwire has nothing to watch there; "+
			"if the golden file's format changed, or that package was renamed or removed, scenario/pending.go "+
			"must change with it", path, header)
	}
	rest := surface[start+len(header):]
	if end := strings.Index(rest, "\npackage "); end >= 0 {
		return rest[:end], nil
	}
	return rest, nil
}

// LedgerLine is one row of the pending ledger.
type LedgerLine struct {
	// ID is the scenario id.
	ID string
	// Status is live, pending or unexpressible.
	Status Status
	// Waiting is what a pending scenario waits on, or the §17 finding an
	// unexpressible one maps to.
	Waiting string
	// Title is the scenario's one-line name.
	Title string
}

// Ledger renders the corpus's status as a stable, diffable text table. It
// is committed as examples/pending.txt and verified by an ordinary test,
// which is the point: a scenario silently staying pending forever is the
// failure mode this corpus is most at risk of, and the only reliable
// defence is that the set of pending scenarios is a file somebody has to
// change on purpose.
func Ledger(scenarios []Scenario) string {
	lines := make([]LedgerLine, 0, len(scenarios))
	for _, s := range scenarios {
		waiting := ""
		switch s.Status {
		case StatusPending:
			names := make([]string, 0, len(s.PendingOn))
			for _, c := range s.PendingOn {
				names = append(names, string(c))
			}
			sort.Strings(names)
			waiting = strings.Join(names, "+")
		case StatusUnexpressible:
			waiting = s.Finding
		case StatusLive:
			waiting = "-"
		}
		lines = append(lines, LedgerLine{ID: s.ID, Status: s.Status, Waiting: waiting, Title: s.Title})
	}
	sort.Slice(lines, func(i, j int) bool { return lines[i].ID < lines[j].ID })

	var b strings.Builder
	b.WriteString("# iam use-case corpus — status ledger.\n")
	b.WriteString("#\n")
	b.WriteString("# Regenerate with: go test ./examples/... -run TestLedger -update-ledger\n")
	b.WriteString("#\n")
	b.WriteString("# live           every assertion runs against the real module today: the\n")
	b.WriteString("#                identity fixture, the grants, and the expectation table,\n")
	b.WriteString("#                which is answered by iam.Decide and the corpus's reference\n")
	b.WriteString("#                oracle and diffed between them (design §9.4).\n")
	b.WriteString("# pending        the scenario waits on the named `iam` capability. Everything\n")
	b.WriteString("#                it can run still runs, and most pending tables are now\n")
	b.WriteString("#                answered by both evaluators too — what is missing is the\n")
	b.WriteString("#                half of the scenario's claim about the design that no code\n")
	b.WriteString("#                here can carry yet.\n")
	b.WriteString("# unexpressible  the design cannot express the use case; the named §17\n")
	b.WriteString("#                finding is where it bites. See UNEXPRESSIBLE.md.\n")
	b.WriteString("#\n")
	b.WriteString("# A pending row that stays pending after its capability lands is the\n")
	b.WriteString("# failure mode this corpus exists to avoid, so two things watch it: the\n")
	b.WriteString("# api.txt tripwire in scenario/pending.go, which fails automatically, and\n")
	b.WriteString("# this file, which makes every change to the set a reviewed diff.\n\n")

	widthID, widthStatus, widthWaiting := len("ID"), len("STATUS"), len("WAITING ON")
	for _, l := range lines {
		widthID = max(widthID, len(l.ID))
		widthStatus = max(widthStatus, len(string(l.Status)))
		widthWaiting = max(widthWaiting, len(l.Waiting))
	}
	format := fmt.Sprintf("%%-%ds  %%-%ds  %%-%ds  %%s\n", widthID, widthStatus, widthWaiting)
	fmt.Fprintf(&b, format, "ID", "STATUS", "WAITING ON", "SCENARIO")
	for _, l := range lines {
		fmt.Fprintf(&b, format, l.ID, string(l.Status), l.Waiting, l.Title)
	}
	return b.String()
}
