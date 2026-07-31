// Copyright 2026 Netflix, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package gomod finds the Go modules in a repository and reads their go.mod
// files. Comparing Go versions is here too, because anything else naming one — a
// GOTOOLCHAIN setting, a golang image tag — is only worth comparing against a go
// directive.
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
// directories the go command ignores: what is under those belongs to another
// module or to no build at all, so it is not the repository's own to read or to
// edit.
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
	// A directory sorts before everything under it, so this puts each module ahead
	// of the modules nested in it, and gives every caller the same order twice.
	slices.Sort(dirs)
	return dirs, nil
}

// HighestGoDirective returns the highest go directive of the modules in dirs, or
// "" if none of them declares one. It is what every module in the repository can
// be built by, so it is the version anything else naming a Go version has to keep
// up with.
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

// Read parses dir's go.mod. It is read here rather than through `go mod edit
// -json` because the go command refuses to run under a go directive above its own
// version, which is what the directive is read to decide.
func Read(dir string) (*modfile.File, error) {
	name := filepath.Join(dir, "go.mod")
	data, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	return modfile.Parse(name, data, nil)
}

// Higher reports whether Go version a is above b, each written as a go directive
// writes it, e.g. "1.26" or "1.26.0". The prefix makes them the toolchain names
// go/version compares, which orders a release candidate correctly where semver
// reads it as invalid and so as lower than everything.
//
// Both are given all three components first, so a version naming only a language
// is the release [FullVersion] says it stands for: 1.26 and 1.26.0 are the same
// version here, where go/version alone puts the language below its first release.
// Two versions being compared come from two places that need not write them the
// same way, and the one written shorter is not the older for it.
func Higher(a, b string) bool {
	return version.Compare("go"+FullVersion(a), "go"+FullVersion(b)) > 0
}

// IsVersion reports whether v is a Go version at all, so that a caller comparing
// versions from two places can tell that both are ones [Higher] orders.
func IsVersion(v string) bool {
	return version.IsValid("go" + v)
}

// FullVersion gives a Go version all three components, which is the only form
// GOTOOLCHAIN accepts, there being no toolchain named go1.26 to fetch. It is also
// the release a version naming only a language stands for, which is what makes two
// versions written in different places comparable. Anything that is not a Go
// version at all comes back as it went in.
func FullVersion(v string) string {
	if !IsVersion(v) {
		return v
	}
	// A version equal to its own language version names no release, so it stands
	// for that language's first. A release candidate already names one, however few
	// components it has: go1.26rc1 is a release of the go1.26 language, and
	// go1.26rc1.0 is not a version at all.
	if version.Lang("go"+v) == "go"+v {
		return v + ".0"
	}
	return v
}
