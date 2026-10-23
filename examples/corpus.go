// Package examples is the `iam` use-case corpus: twenty-odd real
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
// This file is only the aggregator. The scenarios live in the five
// subdirectories, each with its own README; the language they are written
// in and the harness that runs them live in examples/scenario.
package examples

import (
	"github.com/laenenai/iam/examples/agents"
	"github.com/laenenai/iam/examples/discretionary"
	"github.com/laenenai/iam/examples/household"
	"github.com/laenenai/iam/examples/mandatory"
	"github.com/laenenai/iam/examples/scenario"
	"github.com/laenenai/iam/examples/unexpressible"
)

// All returns every scenario in the corpus, in reading order: the
// discretionary layer first because it is the everyday one, then the
// mandatory layer that no discretionary act can defeat, then the household
// scenario the whole project exists for, then agents, and last the use
// cases the design cannot express.
func All() []scenario.Scenario {
	var out []scenario.Scenario
	out = append(out, discretionary.Scenarios()...)
	out = append(out, mandatory.Scenarios()...)
	out = append(out, household.Scenarios()...)
	out = append(out, agents.Scenarios()...)
	out = append(out, unexpressible.Scenarios()...)
	return out
}
