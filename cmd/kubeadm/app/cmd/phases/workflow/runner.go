/*
Copyright 2018 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package workflow

import (
	"fmt"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// phaseSeparator defines the separator to be used when concatenating nested
// phase names
const phaseSeparator = "/"

// RunnerOptions defines the options supported during the execution of a
// kubeadm composable workflows
type RunnerOptions struct {
	// FilterPhases defines the list of phases to be executed (if empty, all).
	FilterPhases []string

	// SkipPhases defines the list of phases to be excluded by execution (if empty, none).
	SkipPhases []string
}

// RunData defines the data shared among all the phases included in the workflow, that is any type.
type RunData = interface{}

// Runner implements management of composable kubeadm workflows.
type Runner struct {
	// Options that regulate the runner behavior.
	Options RunnerOptions

	// Phases composing the workflow to be managed by the runner.
	Phases []Phase

	// runDataInitializer defines a function that creates the runtime data shared
	// among all the phases included in the workflow
	runDataInitializer func() (RunData, error)

	// runData is part of the internal state of the runner and it is used for implementing
	// a singleton in the InitData methods (thus avoiding to initialize data
	// more than one time)
	runData RunData

	// phaseRunners is part of the internal state of the runner and provides
	// a list of wrappers to phases composing the workflow with contextual
	// information supporting phase execution.
	phaseRunners []*phaseRunner
}

// phaseRunner provides a wrapper to a Phase with the addition of a set
// of contextual information derived by the workflow managed by the Runner.
// TODO: If we ever decide to get more sophisticated we can swap this type with a well defined dag or tree library.
type phaseRunner struct {
	// Phase provide access to the phase implementation
	Phase

	// provide access to the parent phase in the workflow managed by the Runner.
	parent *phaseRunner

	// level define the level of nesting of this phase into the workflow managed by
	// the Runner.
	level int

	// selfPath contains all the elements of the path that identify the phase into
	// the workflow managed by the Runner.
	selfPath []string

	// generatedName is the full name of the phase, that corresponds to the absolute
	// path of the phase in the workflow managed by the Runner.
	generatedName string

	// use is the phase usage string that will be printed in the workflow help.
	// It corresponds to the relative path of the phase in the workflow managed by the Runner.
	use string
}

// NewRunner return a new runner for composable kubeadm workflows.
func NewRunner() *Runner {
	return &Runner{
		Phases: []Phase{},
	}
}

// AppendPhase adds the given phase to the ordered sequence of phases managed by the runner.
func (e *Runner) AppendPhase(t Phase) {
	e.Phases = append(e.Phases, t)
}

// computePhaseRunFlags return a map defining which phase should be run and which not.
// PhaseRunFlags are computed according to RunnerOptions.
func (e *Runner) computePhaseRunFlags() (map[string]bool, error) {
	// Initialize support data structure
	phaseRunFlags := map[string]bool{}
	phaseHierarchy := map[string][]string{}
	e.visitAll(func(p *phaseRunner) error {
		// Initialize phaseRunFlags assuming that all the phases should be run.
		phaseRunFlags[p.generatedName] = true

		// Initialize phaseHierarchy for the current phase (the list of phases
		// depending on the current phase
		phaseHierarchy[p.generatedName] = []string{}

		// Register current phase as part of its own parent hierarchy
		parent := p.parent
		for parent != nil {
			phaseHierarchy[parent.generatedName] = append(phaseHierarchy[parent.generatedName], p.generatedName)
			parent = parent.parent
		}
		return nil
	})

	// If a filter option is specified, set all phaseRunFlags to false except for
	// the phases included in the filter and their hierarchy of nested phases.
	if len(e.Options.FilterPhases) > 0 {
		for i := range phaseRunFlags {
			phaseRunFlags[i] = false
		}
		for _, f := range e.Options.FilterPhases {
			if _, ok := phaseRunFlags[f]; !ok {
				return phaseRunFlags, errors.Errorf("invalid phase name: %s", f)
			}
			phaseRunFlags[f] = true
			for _, c := range phaseHierarchy[f] {
				phaseRunFlags[c] = true
			}
		}
	}

	// If a phase skip option is specified, set the corresponding phaseRunFlags
	// to false and apply the same change to the underlying hierarchy
	for _, f := range e.Options.SkipPhases {
		if _, ok := phaseRunFlags[f]; !ok {
			return phaseRunFlags, errors.Errorf("invalid phase name: %s", f)
		}
		phaseRunFlags[f] = false
		for _, c := range phaseHierarchy[f] {
			phaseRunFlags[c] = false
		}
	}

	return phaseRunFlags, nil
}

// SetDataInitializer allows to setup a function that initialize the runtime data shared
// among all the phases included in the workflow.
func (e *Runner) SetDataInitializer(builder func() (RunData, error)) {
	e.runDataInitializer = builder
}

// InitData triggers the creation of runtime data shared among all the phases included in the workflow.
// This action can be executed explicitly out, when it is necessary to get the RunData
// before actually executing Run, or implicitly when invoking Run.
func (e *Runner) InitData() (RunData, error) {
	if e.runData == nil && e.runDataInitializer != nil {
		var err error
		if e.runData, err = e.runDataInitializer(); err != nil {
			return nil, err
		}
	}

	return e.runData, nil
}

// Run the kubeadm composable kubeadm workflows.
func (e *Runner) Run() error {
	e.prepareForExecution()

	// determine which phase should be run according to RunnerOptions
	phaseRunFlags, err := e.computePhaseRunFlags()
	if err != nil {
		return err
	}

	// builds the runner data
	var data RunData
	if data, err = e.InitData(); err != nil {
		return err
	}

	err = e.visitAll(func(p *phaseRunner) error {
		// if the phase should not be run, skip the phase.
		if run, ok := phaseRunFlags[p.generatedName]; !run || !ok {
			return nil
		}

		// If the phase defines a condition to be checked before executing the phase action.
		if p.RunIf != nil {
			// Check the condition and returns if the condition isn't satisfied (or fails)
			ok, err := p.RunIf(data)
			if err != nil {
				return errors.Wrapf(err, "error execution run condition for phase %s", p.generatedName)
			}

			if !ok {
				return nil
			}
		}

		// Runs the phase action (if defined)
		if p.Run != nil {
			if err := p.Run(data); err != nil {
				return errors.Wrapf(err, "error execution phase %s", p.generatedName)
			}
		}

		return nil
	})

	return err
}

// Help returns text with the list of phases included in the workflow.
func (e *Runner) Help(cmdUse string) string {
	e.prepareForExecution()

	// computes the max length of for each phase use line
	maxLength := 0
	e.visitAll(func(p *phaseRunner) error {
		if !p.Hidden {
			length := len(p.use)
			if maxLength < length {
				maxLength = length
			}
		}
		return nil
	})

	// prints the list of phases indented by level and formatted using the maxlength
	// the list is enclosed in a mardown code block for ensuring better readability in the public web site
	line := fmt.Sprintf("The %q command executes the following internal workflow:\n", cmdUse)
	line += "```\n"
	offset := 2
	e.visitAll(func(p *phaseRunner) error {
		if !p.Hidden {
			padding := maxLength - len(p.use) + offset
			line += strings.Repeat(" ", offset*p.level) // indentation
			line += p.use                               // name + aliases
			line += strings.Repeat(" ", padding)        // padding right up to max length (+ offset for spacing)
			line += p.Short                             // phase short description
			line += "\n"
		}

		return nil
	})
	line += "```"
	return line
}

// BindToCommand bind the Runner to a cobra command by altering
// command help, adding phase related flags and by adding phases subcommands
// Please note that this command needs to be done once all the phases are added to the Runner.
func (e *Runner) BindToCommand(cmd *cobra.Command) {
	if len(e.Phases) == 0 {
		return
	}

	// alters the command description to show available phases
	if cmd.Long != "" {
		cmd.Long = fmt.Sprintf("%s\n\n%s\n", cmd.Long, e.Help(cmd.Use))
	} else {
		cmd.Long = fmt.Sprintf("%s\n\n%s\n", cmd.Short, e.Help(cmd.Use))
	}

	// adds phase related flags
	cmd.Flags().StringSliceVar(&e.Options.SkipPhases, "skip-phases", nil, "List of phases to be skipped")

	// adds the phases subcommand
	phaseCommand := &cobra.Command{
		Use:   "phase",
		Short: fmt.Sprintf("use this command to invoke single phase of the %s workflow", cmd.Name()),
		Args:  cobra.NoArgs, // this forces cobra to fail if a wrong phase name is passed
	}

	cmd.AddCommand(phaseCommand)

	// generate all the nested subcommands for invoking single phases
	subcommands := map[string]*cobra.Command{}
	e.visitAll(func(p *phaseRunner) error {
		// creates nested phase subcommand
		var phaseCmd = &cobra.Command{
			Use:     strings.ToLower(p.Name),
			Short:   p.Short,
			Long:    p.Long,
			Example: p.Example,
			Aliases: p.Aliases,
			Run: func(cmd *cobra.Command, args []string) {
				e.Options.FilterPhases = []string{p.generatedName}
				if err := e.Run(); err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(1)
				}
			},
			Args: cobra.NoArgs, // this forces cobra to fail if a wrong phase name is passed
		}

		// makes the new command inherits flags from the main command
		cmd.LocalNonPersistentFlags().VisitAll(func(f *pflag.Flag) {
			phaseCmd.Flags().AddFlag(f)
		})

		// adds the command to parent
		if p.level == 0 {
			phaseCommand.AddCommand(phaseCmd)
		} else {
			subcommands[p.parent.generatedName].AddCommand(phaseCmd)
		}

		subcommands[p.generatedName] = phaseCmd
		return nil
	})
}

// visitAll provides a utility method for visiting all the phases in the workflow
// in the execution order and executing a func on each phase.
// Nested phase are visited immediately after their parent phase.
func (e *Runner) visitAll(fn func(*phaseRunner) error) error {
	for _, currentRunner := range e.phaseRunners {
		if err := fn(currentRunner); err != nil {
			return err
		}
	}
	return nil
}

// prepareForExecution initialize the internal state of the Runner (the list of phaseRunner).
func (e *Runner) prepareForExecution() {
	e.phaseRunners = []*phaseRunner{}
	var parentRunner *phaseRunner
	for _, phase := range e.Phases {
		addPhaseRunner(e, parentRunner, phase)
	}
}

// addPhaseRunner adds the phaseRunner for a given phase to the phaseRunners list
func addPhaseRunner(e *Runner, parentRunner *phaseRunner, phase Phase) {
	// computes contextual information derived by the workflow managed by the Runner.
	generatedName := strings.ToLower(phase.Name)
	use := generatedName
	selfPath := []string{generatedName}

	if parentRunner != nil {
		generatedName = strings.Join([]string{parentRunner.generatedName, generatedName}, phaseSeparator)
		use = fmt.Sprintf("%s%s", phaseSeparator, use)
		selfPath = append(parentRunner.selfPath, selfPath...)
	}

	// creates the phaseRunner
	currentRunner := &phaseRunner{
		Phase:         phase,
		parent:        parentRunner,
		level:         len(selfPath) - 1,
		selfPath:      selfPath,
		generatedName: generatedName,
		use:           use,
	}

	// adds to the phaseRunners list
	e.phaseRunners = append(e.phaseRunners, currentRunner)

	// iterate for the nested, ordered list of phases, thus storing
	// phases in the expected executing order (child phase are stored immediately after their parent phase).
	for _, childPhase := range phase.Phases {
		addPhaseRunner(e, currentRunner, childPhase)
	}
}
