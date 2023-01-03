/*
Copyright 2023 The Kubernetes Authors.

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

// Package main is an example of an archetypal gengo/v2 tool which generates
// code into the same package(s) it used as input(s).
package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/pflag"
	"k8s.io/gengo/v2/args"
	"k8s.io/gengo/v2/generator"
	"k8s.io/gengo/v2/namer"
	"k8s.io/gengo/v2/types"
	"k8s.io/klog/v2"
)

func main() {
	klog.InitFlags(nil)
	gengo := getArgs()

	if err := gengo.Execute(getGlobalNamers(), getDefaultNamer(), getPackages); err != nil {
		klog.Fatalf("ERROR: %v", err)
	}
	klog.V(2).Info("completed successfully")
}

// getArgs returns the arguments for this tool.
func getArgs() *args.GeneratorArgs {
	//FIXME: rename to something more friendly, like gengo.Args()
	stdArgs := args.Default()
	stdArgs.CustomArgs = &customArgs{}
	stdArgs.Validate = validateArgs
	// Set any other non-standard defaults here.
	return stdArgs
}

// customArgs captures any non-standard arguments this tool needs.
type customArgs struct {
	NamePrefix string
}

// AddFlagsTo adds the generator flags to the flag set.
func (ca customArgs) AddFlagsTo(fs *pflag.FlagSet) {
	pflag.CommandLine.StringVar(&ca.NamePrefix, "name-prefix", "",
		"An optional prefix for generated names")
}

// validateArgs checks the given arguments.
func validateArgs(stdArgs *args.GeneratorArgs) error {
	if _, ok := stdArgs.CustomArgs.(*customArgs); !ok {
		return fmt.Errorf("failed to read custom args: %T", arguments.CustomArgs)
	}

	// FIXME: should this be standard?
	if len(stdArgs.OutputFileBaseName) == 0 {
		return fmt.Errorf("output file base name cannot be empty")
	}

	return nil
}

// getGlobalNamers returns the name systems available to all generators in
// all packages in this tool.  Individual generators can add their own later.
func getGlobalNamers() map[string]namer.Namer {
	return map[string]namer.Namer{
		// This namer is used for generating UpperCamelCase names.  Since we
		// only handle types within a package, we don't need any additional
		// parts of the package name (the 0 argument).
		"public": namer.NewPublicNamer(0),
	}
}

// getDefaultNamer returns the default name system for ordering the types to be
// processed by the generators in this package.
func getDefaultNamer() string {
	// For this tool, order only matters within a package, so this will suffice.
	return "public"
}

// getPackages returns a set of packages to be processed by this tool.
func getPackages(context *generator.Context, arguments *args.GeneratorArgs) []generator.Package {
	boilerplate, err := arguments.GoBoilerplate()
	if err != nil {
		klog.Fatalf("Failed loading boilerplate: %v", err)
	}

	customArgs := arguments.CustomArgs.(*customArgs) // already validated
	namePrefix := customArgs.NamePrefix

	var packages []generator.Package

	for _, in := range context.Inputs {
		klog.V(5).Infof("Considering pkg %q", in)
		pkg := context.Universe[in]
		if pkg == nil { // e.g. the input had no Go files
			continue
		}

		packages = append(packages,
			&generator.SimplePackage{
				PackageName: pkg.Name,
				PackagePath: pkg.Path,
				PackageDir:  pkg.SourcePath,
				HeaderText:  boilerplate,
				FilterFunc: func(c *generator.Context, t *types.Type) bool {
					// This is called for every type in c.Universe, but we only
					// want to process types in this package.
					if t.Name.Package == pkg.Path {
						klog.V(5).Infof("Keeping type %v", t.Name.Name)
						return true
					}
					klog.V(6).Infof("Excluding type %v", t.Name.Name)
					return false
				},
				GeneratorFunc: func(c *generator.Context) []generator.Generator {
					return []generator.Generator{
						newGenerator(arguments.OutputFileBaseName, pkg.Path, namePrefix),
					}
				},
			})
	}
	return packages
}

// xOrErrorGenerator produces a file with autogenerated <x>OrError types.
type xOrErrorGenerator struct {
	generator.SimpleGenerator // for default impls of most methods
	targetPackage             string
	namePrefix                string
	imports                   namer.ImportTracker
}

func newGenerator(outputFileBase, targetPackage string, namePrefix string) generator.Generator {
	return &xOrErrorGenerator{
		SimpleGenerator: generator.SimpleGenerator{
			OptionalName: outputFileBase,
		},
		targetPackage: targetPackage,
		namePrefix:    namePrefix,
		imports:       generator.NewImportTracker(), //FIXME: pass this pkg?
	}
}

func (g *xOrErrorGenerator) Namers(c *generator.Context) map[string]namer.Namer {
	// Have the raw namer for this file track what it imports.
	return map[string]namer.Namer{
		"raw": namer.NewRawNamer(g.targetPackage, g.imports),
	}
}

func (g *xOrErrorGenerator) Filter(c *generator.Context, t *types.Type) bool {
	// Only handle public types.
	if namer.IsPrivateGoName(t.Name.Name) {
		klog.V(6).Infof("Excluding private type %v", t.Name.Name)
		return false
	}
	klog.V(2).Infof("Type %v is eligible for generation", t.Name.Name)
	return true
}

func (g *xOrErrorGenerator) isOtherPackage(pkg string) bool {
	if pkg == g.targetPackage {
		return false
	}
	if strings.HasSuffix(pkg, "\""+g.targetPackage+"\"") {
		return false
	}
	return true
}

func (g *xOrErrorGenerator) Imports(c *generator.Context) (imports []string) {
	//FIXME: do I need anything here?
	importLines := []string{}
	for _, singleImport := range g.imports.ImportLines() {
		if g.isOtherPackage(singleImport) {
			importLines = append(importLines, singleImport)
		}
	}
	return importLines
}

func argsFromType(ts ...*types.Type) generator.Args {
	a := generator.Args{
		"type": ts[0],
	}
	return a
}

func (g *xOrErrorGenerator) GenerateType(c *generator.Context, t *types.Type, w io.Writer) error {
	klog.V(5).Infof("Generating OrError type for type %v", t.Name.Name)

	sw := generator.NewSnippetWriter(w, c, "$", "$")
	args := argsFromType(t)

	sw.Do(fmt.Sprintf("// %s$.type|raw$OrError holds either a $.type|raw$ or an error.\n", g.namePrefix), args)
	sw.Do(fmt.Sprintf("type %s$.type|raw$OrError struct {\n", g.namePrefix), args)
	sw.Do("  Value *$.type|raw$\n", args)
	sw.Do("  Error error\n", args)
	sw.Do("}\n", args)

	return sw.Error()
}
