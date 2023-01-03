/*
Copyright 2015 The Kubernetes Authors.

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

package generator

import (
	"k8s.io/gengo/v2/types"
)

// SimplePackage contains a simple implementation of Package.
type SimplePackage struct {
	// Short name of package, used in the "package xxxx" line.
	PackageName string
	// Import path of the package, and the location on disk of the package.
	PackagePath string
	// The location of the package on disk.
	PackageDir string

	// Emitted at the top of every file.
	HeaderText []byte

	// Emitted only for a "doc.go" file; appended to the HeaderText for
	// that file.
	PackageDocumentation []byte

	// If non-nil, will be called on "Generators"; otherwise, the static
	// list will be used. So you should set only one of these two fields.
	GeneratorFunc func(*Context) []Generator
	GeneratorList []Generator

	// Optional; filters the types exposed to the generators.
	FilterFunc func(*Context, *types.Type) bool
}

func (d *SimplePackage) Name() string       { return d.PackageName }
func (d *SimplePackage) Path() string       { return d.PackagePath }
func (d *SimplePackage) SourcePath() string { return d.PackageDir }

func (d *SimplePackage) Filter(c *Context, t *types.Type) bool {
	if d.FilterFunc != nil {
		return d.FilterFunc(c, t)
	}
	return true
}

func (d *SimplePackage) Generators(c *Context) []Generator {
	if d.GeneratorFunc != nil {
		return d.GeneratorFunc(c)
	}
	return d.GeneratorList
}

func (d *SimplePackage) Header(filename string) []byte {
	if filename == "doc.go" {
		return append(d.HeaderText, d.PackageDocumentation...)
	}
	return d.HeaderText
}

var (
	_ = Package(&SimplePackage{})
)
