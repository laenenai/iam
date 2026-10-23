// Package examples is the `iam` use-case corpus: eighteen real
// requirements, drawn from the three consumer designs rather than
// invented, written as declarative scenarios and run against whatever
// evaluator exists.
//
// Start with README.md in this directory. It says what the corpus is, how
// to run it, how a scenario is put together, and — the question a consumer
// actually arrives with — how to express a given kind of rule, or that it
// cannot be expressed and what that costs. UNEXPRESSIBLE.md is the honest
// list.
//
// There were twenty-six, and the arithmetic of the difference is the
// record of one decision. Six mandatory scenarios are gone with the tier
// they tested, and the one of them that mattered most — the legal ethical
// wall, which the design called the feature the whole module exists for —
// is now D8 in examples/discretionary, where it is expressed by the
// absence of a grant. Two unexpressible scenarios are resolved by
// deletion rather than by being solved, and ../UNEXPRESSIBLE.md records
// them as such instead of dropping them quietly.
//
// This file is only the aggregator. The scenarios live in the four
// subdirectories, each with its own README; the language they are written
// in and the harness that runs them live in examples/scenario.
package examples

import (
	"github.com/laenenai/iam/examples/agents"
	"github.com/laenenai/iam/examples/discretionary"
	"github.com/laenenai/iam/examples/household"
	"github.com/laenenai/iam/examples/scenario"
	"github.com/laenenai/iam/examples/unexpressible"
)

// All returns every scenario in the corpus, in reading order: the
// discretionary layer first because it is now the only policy layer, then
// the household scenario the whole project exists for, then agents, and
// last the use cases the design cannot express.
//
// There is no mandatory layer. It was removed with the deny mechanism: see
// the design document's "no deny mechanism" anti-goal. An absolute is a
// key the deployment does not hold, which is `escrow`, not a policy row.
func All() []scenario.Scenario {
	var out []scenario.Scenario
	out = append(out, discretionary.Scenarios()...)
	out = append(out, household.Scenarios()...)
	out = append(out, agents.Scenarios()...)
	out = append(out, unexpressible.Scenarios()...)
	return out
}
