// This file must NOT compile. It is the negative half of design §8.3's
// requirement that an ordinary tier-1 group can never stand where a
// clearance group is required, and it lives under testdata/ so the go
// tool's package patterns ignore it — TestOrdinaryGroupIDIsNotAClearanceGroupID
// compiles it by explicit filename and asserts the compiler rejects it.
//
// If this file ever builds, the type-system guarantee described in
// domain.ClearanceGroupID's doc comment has been lost: it would mean a
// team's id can be turned into a clearance group's id, so anybody able to
// add a member to that team could open a mandatory gate through a
// discretionary operation. That is anti-goal A3, breached by construction.
package main

import "github.com/laenen-ai/iam/internal/domain"

// wantsClearanceGroup stands in for every Registry method that takes a
// clearance group id.
func wantsClearanceGroup(domain.ClearanceGroupID) {}

// wantsGroup stands in for every Registry method that takes an ordinary
// group id.
func wantsGroup(domain.GroupID) {}

func main() {
	clock := domain.SystemClock{}
	group := domain.NewGroupID(clock)
	clearance := domain.NewClearanceGroupID(clock)

	// 1. An ordinary group id passed where a clearance group is required.
	wantsClearanceGroup(group)

	// 2. The conversion a plain named-string type would have allowed:
	//    one word that silently promotes a team to a clearance group.
	wantsClearanceGroup(domain.ClearanceGroupID(group))

	// 3. The reverse direction, so a clearance group cannot be referenced
	//    where a tier-1 group is expected either (design §8.3: a clearance
	//    group can never appear in a tier-1 tuple).
	wantsGroup(clearance)
	wantsGroup(domain.GroupID(clearance))

	// 4. Nor through the underlying representation: the field is
	//    unexported, so no package outside domain can reach it.
	wantsClearanceGroup(domain.ClearanceGroupID{s: string(group)})
}
