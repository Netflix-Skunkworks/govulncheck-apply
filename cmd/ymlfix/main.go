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

// Command ymlfix raises a version recorded in a YAML file to the one a repository
// of Go modules now needs.
//
//	go install github.com/netflix-skunkworks/govulncheck-apply/cmd/ymlfix@latest
//	ymlfix -path .tool-versions.goVersion config.yml
//	ymlfix -path .lint.golangci-version -version v2.4.0 config.yml
//
// CI usually builds with a toolchain its own configuration names rather than with
// a repository's go directive, so a standard-library fix that raises the directive
// leaves that configuration behind, and the build then fails on the very module
// that was fixed.
//
// -path names the version to raise, as the mapping keys that reach it separated
// by dots, the way yq names one. It addresses a key, not a file: the first example
// above raises the goVersion key under tool-versions, in a file called config.yml.
//
// Without -version, the version raised to is the highest go directive of the
// modules under the working directory, which is what every module in the
// repository can be built by. -version gives one instead, for something whose
// version is not a Go version: a pinned linter, say, whose own releases have to be
// looked up somewhere this program knows nothing about.
//
// A version is only ever raised, never lowered, and a path naming no version is
// left alone: a repository that does not declare one does not want one. The file
// is edited in place, and named on stdout when it changed.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"
	"unicode/utf8"

	"golang.org/x/mod/semver"
	"gopkg.in/yaml.v3"

	"github.com/netflix-skunkworks/govulncheck-apply/internal/gomod"
)

var (
	keyPath = flag.String("path", "", "Dot-separated mapping keys naming the version to raise: a `path` of .tool-versions.goVersion is the goVersion key under tool-versions.")
	raiseTo = flag.String("version", "", "Raise it to this `version`. If left blank, the highest go directive in any go.mod will be used.")
)

func main() {
	flag.Parse()
	if *keyPath == "" || flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "Usage: ymlfix -path <path> [-version <version>] <file>")
		flag.PrintDefaults()
		os.Exit(2)
	}
	raised, err := raise(flag.Arg(0), *keyPath, *raiseTo)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if raised {
		fmt.Println(flag.Arg(0))
	}
}

// raise rewrites the version at path in the YAML file called name, raising it to
// version, or to the highest go directive under the working directory when version
// is empty, and reports whether it rewrote anything.
func raise(name, path, version string) (bool, error) {
	file, err := os.ReadFile(name)
	if err != nil {
		return false, err
	}
	have, at, err := find(file, path)
	if err != nil {
		return false, fmt.Errorf("%s: %v", name, err)
	}
	if have == "" {
		return false, nil
	}

	want := version
	if want == "" {
		dirs, err := gomod.Modules(".")
		if err != nil {
			return false, err
		}
		highest, err := gomod.HighestGoDirective(dirs)
		if err != nil {
			return false, err
		}
		// No module here declares a go directive, so there is no version for the
		// file to keep up with. Nothing to do rather than a failure.
		if highest == "" {
			return false, nil
		}
		want = gomod.FullVersion(highest)
	}

	// A version can carry a digest, as in v2.10.1@sha256:ea84d1..., which is no
	// part of what orders it. Raising writes over the version and the digest both,
	// there being no way to work out another release's.
	pinned, _, _ := strings.Cut(have, "@")
	higher, err := above(want, pinned)
	if err != nil {
		return false, fmt.Errorf("%s at %s: %v", name, path, err)
	}
	if !higher {
		return false, nil
	}

	raised := slices.Concat(file[:at], []byte(want), file[at+len(have):])
	if err := os.WriteFile(name, raised, 0o644); err != nil {
		return false, err
	}
	return true, nil
}

// above reports whether version a is above b. The two are written and ordered
// differently depending on what they are versions of, so both have to be of a
// kind: semver, as a module version is, or a go directive's, as a toolchain
// version is.
//
// Ordering across the two kinds is an error rather than an answer. Each ordering
// reads a version of the other kind as invalid, and sorts an invalid one below
// everything, so whichever argument it happens to recognize wins — meaning the
// answer would be neither right nor reliably "no".
func above(a, b string) (bool, error) {
	switch {
	case semver.IsValid(a) && semver.IsValid(b):
		return semver.Compare(a, b) > 0, nil
	case gomod.IsVersion(a) && gomod.IsVersion(b):
		return gomod.Higher(a, b), nil
	}
	return false, fmt.Errorf("cannot order %q against %q: not both module versions, and not both Go versions", a, b)
}

// find returns the version at a dot-separated path of mapping keys through file,
// and where in file it starts. Both are zero when the path reaches no version,
// since one that is not written down is not one to raise.
func find(file []byte, path string) (string, int, error) {
	var document yaml.Node
	if err := yaml.Unmarshal(file, &document); err != nil {
		return "", 0, err
	}
	node := &document
	if node.Kind == yaml.DocumentNode && len(node.Content) == 1 {
		node = node.Content[0]
	}
	for key := range strings.SplitSeq(strings.TrimPrefix(path, "."), ".") {
		if key == "" {
			return "", 0, fmt.Errorf("path %q has an empty key", path)
		}
		if node = mapping(node, key); node == nil {
			return "", 0, nil
		}
	}
	if node.Kind != yaml.ScalarNode || node.Value == "" {
		return "", 0, nil
	}

	// A node's value is the scalar as parsed, so the quotes that may surround it in
	// the file are not part of it and the column reported is where they start. It is
	// searched for from there rather than assumed to be at it, and not found at all
	// if the position was not one this file's own bytes produced.
	at := offset(file, node.Line, node.Column)
	i := bytes.Index(file[at:], []byte(node.Value))
	if i < 0 {
		return "", 0, fmt.Errorf("%q is not written literally at line %d of the file", node.Value, node.Line)
	}
	return node.Value, at + i, nil
}

// mapping returns what a mapping node holds for key, or nil for anything else. A
// mapping's children are its keys and values one after the other.
func mapping(node *yaml.Node, key string) *yaml.Node {
	if node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

// offset returns the byte at the line and column a [yaml.Node] reports, both
// counted from one, or the end of the file where it holds no such position. A
// column counts characters rather than bytes, so the line is walked a rune at a
// time to reach it.
func offset(file []byte, line, column int) int {
	var at int
	for range line - 1 {
		i := bytes.IndexByte(file[at:], '\n')
		if i < 0 {
			return len(file)
		}
		at += i + 1
	}
	for range column - 1 {
		if at >= len(file) {
			break
		}
		_, size := utf8.DecodeRune(file[at:])
		at += size
	}
	return at
}
