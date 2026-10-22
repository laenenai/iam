package domain_test

import (
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/laenen-ai/iam/internal/domain"
)

// negativeCompileFile is the file that must not compile, relative to the
// module root. See its own header, and domain.ClearanceGroupID's doc
// comment, for what it proves.
const negativeCompileFile = "internal/domain/testdata/ordinary_group_id_is_not_a_clearance_group_id.go"

// TestOrdinaryGroupIDIsNotAClearanceGroupID is the compile-time half of
// design §8.3's tier separation: it hands the Go compiler a program that
// tries, five different ways, to use an ordinary GroupID where a
// ClearanceGroupID is required, and requires every one of them to be
// rejected.
//
// A runtime test cannot express this. The whole point of making the
// distinction a type-system fact is that the mistake is unwriteable, so
// the only way to test it is to write it somewhere the compiler can see it
// and the build cannot — which is what testdata/ is for. The companion
// runtime assertion, for ids that arrive as text and so bypass the type
// system entirely, is the registry suite's
// OrdinaryGroupCannotActAsClearanceGroup subtest.
func TestOrdinaryGroupIDIsNotAClearanceGroupID(t *testing.T) {
	t.Parallel()

	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skipf("no go toolchain on PATH, cannot run a compile-failure test: %v", err)
	}

	root := moduleRoot(t)
	out, err := runGoBuild(t, goTool, root)
	if err == nil {
		t.Fatalf("%s compiled successfully; it must not.\n"+
			"An ordinary group id can now be used as a clearance group id, so a discretionary\n"+
			"group-membership change can open a mandatory gate (design §8.3, anti-goal A3).\n"+
			"See domain.ClearanceGroupID's doc comment.", negativeCompileFile)
	}

	// Require a *type* error, not just any failure: a missing import, a
	// typo, or a renamed identifier would also make the build fail and
	// would make this test pass for the wrong reason.
	text := string(out)
	wantFragments := []string{
		"cannot use group",
		"cannot convert group",
		"cannot use clearance",
		"cannot convert clearance",
		"unexported field s",
	}
	found := 0
	for _, f := range wantFragments {
		if strings.Contains(text, f) {
			found++
		}
	}
	if found == 0 {
		t.Fatalf("%s failed to compile, but not with a type error — this test may be passing for the wrong reason.\ngo build said:\n%s",
			negativeCompileFile, text)
	}
	t.Logf("compiler rejected the file as required:\n%s", text)
}

// runGoBuild compiles the negative file from the module root, discarding
// any output binary, and returns the combined compiler output.
func runGoBuild(t *testing.T, goTool, root string) ([]byte, error) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), goTool, "build", "-o", filepath.Join(t.TempDir(), "unwanted"), negativeCompileFile) //nolint:gosec // goTool is exec.LookPath's own answer and the file path is this package's own constant
	cmd.Dir = root
	return cmd.CombinedOutput()
}

// moduleRoot returns the directory holding this module's go.mod, asked of
// the go tool rather than assumed from this test file's location.
func moduleRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "go", "env", "GOMOD").Output() //nolint:gosec // a fixed, argument-free query to the go tool on PATH
	if err != nil {
		t.Skipf("cannot locate the module root: %v", err)
	}
	gomod := strings.TrimSpace(string(out))
	if gomod == "" || gomod == "/dev/null" {
		t.Skip("not running inside a module; cannot compile the negative test file")
	}
	return filepath.Dir(gomod)
}

func TestNewMandatoryAct(t *testing.T) {
	t.Parallel()

	clock := domain.NewFixedClock(time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC))
	actor := domain.NewPrincipalID(clock)

	cases := []struct {
		name    string
		channel domain.MandatoryChannel
		actor   domain.PrincipalID
		reason  string
		at      time.Time
		wantErr bool
	}{
		{"classify", domain.MandatoryChannelClassify, actor, "matter 4471 conflict screen", clock.Now(), false},
		{"directory sync", domain.MandatoryChannelDirectorySync, actor, "hr feed: joined 2026-10-01", clock.Now(), false},
		{"unknown channel", domain.MandatoryChannel("share"), actor, "because the owner said so", clock.Now(), true},
		{"empty channel", domain.MandatoryChannel(""), actor, "r", clock.Now(), true},
		{"no actor", domain.MandatoryChannelClassify, "", "r", clock.Now(), true},
		{"no reason", domain.MandatoryChannelClassify, actor, "", clock.Now(), true},
		{"whitespace reason", domain.MandatoryChannelClassify, actor, "   \t\n ", clock.Now(), true},
		{"no instant", domain.MandatoryChannelClassify, actor, "r", time.Time{}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			act, err := domain.NewMandatoryAct(tc.channel, tc.actor, tc.reason, tc.at)
			if tc.wantErr {
				if !errors.Is(err, domain.ErrMandatoryChannelRequired) {
					t.Fatalf("NewMandatoryAct error = %v, want ErrMandatoryChannelRequired", err)
				}
				if !act.IsZero() {
					t.Fatal("a rejected act must be the zero value, so a caller ignoring the error cannot use it as a witness")
				}
				return
			}
			if err != nil {
				t.Fatalf("NewMandatoryAct: %v", err)
			}
			if act.IsZero() {
				t.Fatal("a valid act reports IsZero")
			}
			if act.Channel() != tc.channel || act.Actor() != tc.actor || !act.At().Equal(tc.at) {
				t.Fatalf("act round-trip mismatch: got (%q, %q, %v)", act.Channel(), act.Actor(), act.At())
			}
		})
	}
}

// TestZeroMandatoryActWitnessesNothing pins the property the registry port
// relies on: the value a caller gets for free, without naming a channel,
// an actor or a reason, is recognizably not a witness.
func TestZeroMandatoryActWitnessesNothing(t *testing.T) {
	t.Parallel()

	var act domain.MandatoryAct
	if !act.IsZero() {
		t.Fatal("the zero MandatoryAct must report IsZero")
	}
	if act.Channel().Valid() {
		t.Fatal("the zero MandatoryAct's channel must not be a valid mandatory channel")
	}
}

func TestClearanceGroupIDRoundTrip(t *testing.T) {
	t.Parallel()

	clock := domain.NewFixedClock(time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC))
	id := domain.NewClearanceGroupID(clock)
	if id.IsZero() {
		t.Fatal("a freshly minted clearance group id reports IsZero")
	}

	parsed, err := domain.ParseClearanceGroupID(id.String())
	if err != nil {
		t.Fatalf("ParseClearanceGroupID: %v", err)
	}
	if parsed != id {
		t.Fatalf("round-trip mismatch: %q != %q", parsed.String(), id.String())
	}

	var zero domain.ClearanceGroupID
	if !zero.IsZero() || zero.String() != "" {
		t.Fatal("the zero clearance group id must be recognizable as naming nothing")
	}

	// A syntactically valid ULID parses whatever it names: the parser is
	// not, and cannot be, the authority on an id's kind. That authority is
	// the registry's, via ErrGroupKindMismatch — see the suite.
	ordinary := domain.NewGroupID(clock)
	if _, err := domain.ParseClearanceGroupID(string(ordinary)); err != nil {
		t.Fatalf("ParseClearanceGroupID of a well-formed ULID must succeed on syntax alone: %v", err)
	}

	if _, err := domain.ParseClearanceGroupID("not-a-ulid"); !errors.Is(err, domain.ErrMalformedID) {
		t.Fatalf("ParseClearanceGroupID(%q) error = %v, want ErrMalformedID", "not-a-ulid", err)
	}
}
