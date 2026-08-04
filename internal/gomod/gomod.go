// Copyright 2026 Netflix, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

// Package gomod finds the Go modules in a repository and reads their go.mod
// files. Comparing Go versions is here too, because anything else naming one —
// a GOTOOLCHAIN setting, a golang image tag — is only worth comparing against a
// go directive.
package gomod

import (
	"go/version"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/mod/modfile"
)

// Walk calls fn for every file under root, in filepath.WalkDir's order. vendor
// and testdata are skipped, along with the dot- and underscore-prefixed
// directories the go command ignores.
func Walk(root string, fn func(path string) error) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return fn(path)
		}
		name := d.Name()
		skip := name == "vendor" || name == "testdata" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")
		// root is always walked, whatever it is named.
		if path != root && skip {
			return fs.SkipDir
		}
		return nil
	})
}

// Modules returns the directories under root holding a go.mod, outermost first.
func Modules(root string) ([]string, error) {
	var dirs []string
	err := Walk(root, func(path string) error {
		if filepath.Base(path) == "go.mod" {
			dirs = append(dirs, filepath.Dir(path))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// A directory sorts before everything under it, so this puts each module
	// ahead of the modules nested in it, and gives every caller the same order
	// twice.
	slices.Sort(dirs)
	return dirs, nil
}

// HighestGoDirective returns the highest go directive of the modules in dirs,
// or "" if none of them declares one.
func HighestGoDirective(dirs []string) (string, error) {
	var highest string
	for _, dir := range dirs {
		mod, err := Read(dir)
		if err != nil {
			return "", err
		}
		if mod.Go != nil && Higher(mod.Go.Version, highest) {
			highest = mod.Go.Version
		}
	}
	return highest, nil
}

// Read parses dir's go.mod.
func Read(dir string) (*modfile.File, error) {
	name := filepath.Join(dir, "go.mod")
	data, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	return modfile.Parse(name, data, nil)
}

// Higher reports whether Go version a is above b, each written as a go
// directive writes it, e.g. "1.26" or "1.26.0".
func Higher(a, b string) bool {
	return version.Compare("go"+FullVersion(a), "go"+FullVersion(b)) > 0
}

// IsVersion reports whether v is a Go version at all.
func IsVersion(v string) bool {
	return version.IsValid("go" + v)
}

// FullVersion gives a Go version that the GOTOOLCHAIN expects.
func FullVersion(v string) string {
	if !IsVersion(v) {
		return v
	}
	if version.Lang("go"+v) == "go"+v {
		return v + ".0"
	}
	return v
}
