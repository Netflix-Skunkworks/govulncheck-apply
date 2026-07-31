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

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// config is the shape the program was written for: a build configuration naming
// the Go toolchain CI builds with, and a linter pinned by module version.
const config = `# Build configuration.
tool-versions:
  buf: 1.28.1

  goVersion: 1.21

command-configs:
  lint:
    golangci-version: v2.10.1@sha256:ea84d1
`

// TestFind covers reaching a version through a file's mappings, and finding where
// its own text starts, which is what a raise rewrites and nothing else.
func TestFind(t *testing.T) {
	for _, tt := range []struct {
		name    string
		file    string
		path    string
		want    string
		wantErr bool
	}{
		{
			name: "a nested key",
			file: config,
			path: ".tool-versions.goVersion",
			want: "1.21",
		},
		{
			name: "a key three deep, whose value carries a digest",
			file: config,
			path: ".command-configs.lint.golangci-version",
			want: "v2.10.1@sha256:ea84d1",
		},
		{
			// The column a node reports is where its quotes start, so the value's
			// own text has to be found from there rather than assumed to be at it.
			name: "a quoted value",
			file: "tools:\n  goVersion: \"1.21\"\n",
			path: ".tools.goVersion",
			want: "1.21",
		},
		{
			name: "a value in a flow mapping",
			file: "tools: {buf: 1.28.1, goVersion: 1.21}\n",
			path: ".tools.goVersion",
			want: "1.21",
		},
		{
			name: "a leading dot is optional",
			file: config,
			path: "tool-versions.goVersion",
			want: "1.21",
		},
		{
			// A version that is not written down is not one to raise, so a path
			// reaching nothing is not an error.
			name: "a key that is not there",
			file: config,
			path: ".tool-versions.rust",
		},
		{
			name: "a key under one that is not there",
			file: config,
			path: ".toolchains.go",
		},
		{
			name: "a key whose value is a mapping, not a version",
			file: config,
			path: ".tool-versions",
		},
		{
			name: "a key with no value",
			file: "tools:\n  goVersion:\n",
			path: ".tools.goVersion",
		},
		{
			name: "an empty file",
			file: "",
			path: ".tools.goVersion",
		},
		{
			name:    "a path with an empty key",
			file:    config,
			path:    ".tool-versions..goVersion",
			wantErr: true,
		},
		{
			name:    "a file that is not YAML",
			file:    "tools:\n\tgoVersion: 1.21\n",
			path:    ".tools.goVersion",
			wantErr: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, at, err := find([]byte(tt.file), tt.path)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("find(%q, %q) = %q at %d, want an error", tt.file, tt.path, got, at)
				}
				return
			}
			if err != nil {
				t.Fatalf("find(%q, %q) failed: %v", tt.file, tt.path, err)
			}
			if got != tt.want {
				t.Errorf("find(%q, %q) = %q, want %q", tt.file, tt.path, got, tt.want)
			}
			// The offset is only meaningful with a version to go with it, and it
			// has to be where that version's own bytes are: a raise writes over
			// them and leaves every other byte of the file alone.
			if got == "" {
				return
			}
			end := at + len(got)
			if end > len(tt.file) {
				t.Errorf("find(%q, %q) = %q at %d, which runs past the end of the file", tt.file, tt.path, got, at)
			} else if tt.file[at:end] != got {
				t.Errorf("find(%q, %q) = %q at %d, where the file has %q", tt.file, tt.path, got, at, tt.file[at:end])
			}
		})
	}
}

// TestAbove covers ordering the two kinds of version this raises, and refusing to
// order one kind against the other, where the answer would come out of whichever
// ordering recognized its argument rather than out of the versions.
func TestAbove(t *testing.T) {
	for _, tt := range []struct {
		want, have string
		raises     bool
		wantErr    bool
	}{
		{have: "1.21", want: "1.21.9", raises: true},
		{have: "1.21.9", want: "1.21", raises: false},
		{have: "1.24.0", want: "1.24", raises: false},
		// A configuration naming 1.22 means the 1.22 toolchain line, so it is
		// already up to date for a module on go 1.22.
		{have: "1.22", want: "1.22.0", raises: false},
		{have: "1.25.0", want: "1.26rc1", raises: true},
		{have: "v2.10.1", want: "v2.99.0", raises: true},
		{have: "v2.99.0", want: "v2.10.1", raises: false},
		{have: "v2.10.1", want: "v2.10.1", raises: false},
		{have: "1.21", want: "v2.99.0", wantErr: true},
		{have: "v2.10.1", want: "1.21.9", wantErr: true},
		{have: "latest", want: "1.21.9", wantErr: true},
	} {
		t.Run(tt.have+" to "+tt.want, func(t *testing.T) {
			got, err := above(tt.want, tt.have)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("above(%q, %q) = %v, want an error", tt.want, tt.have, got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.raises {
				t.Errorf("above(%q, %q) = %v, want %v", tt.want, tt.have, got, tt.raises)
			}
		})
	}
}

// TestRaise covers what a run leaves on disk. Every byte the version does not
// occupy has to survive, comments and blank lines included, because the file is
// one a person wrote and goes on reading.
func TestRaise(t *testing.T) {
	for _, tt := range []struct {
		name        string
		file        string
		path        string
		version     string
		goDirective string
		want        string
		wantRewrote bool
	}{
		{
			name:        "raises a toolchain to the repository's go directive",
			file:        config,
			path:        ".tool-versions.goVersion",
			goDirective: "1.21.9",
			want:        strings.Replace(config, "goVersion: 1.21\n", "goVersion: 1.21.9\n", 1),
			wantRewrote: true,
		},
		{
			// The go directive is what CI has to keep up with, and a toolchain at
			// or above it already builds every module here.
			name:        "leaves a toolchain already past the go directive alone",
			file:        config,
			path:        ".tool-versions.goVersion",
			goDirective: "1.20.5",
			want:        config,
		},
		{
			name:        "raises a pinned version, dropping the digest with it",
			file:        config,
			path:        ".command-configs.lint.golangci-version",
			version:     "v2.99.0",
			want:        strings.Replace(config, "v2.10.1@sha256:ea84d1", "v2.99.0", 1),
			wantRewrote: true,
		},
		{
			name:    "leaves a pin already past the version alone",
			file:    config,
			path:    ".command-configs.lint.golangci-version",
			version: "v2.0.0",
			want:    config,
		},
		{
			// A repository that does not declare a version does not want one.
			name:        "adds nothing where the path names no version",
			file:        config,
			path:        ".tool-versions.rust",
			goDirective: "1.21.9",
			want:        config,
		},
		{
			name:        "raises a value in a flow mapping without reflowing it",
			file:        "tool-versions: {buf: 1.28.1, goVersion: 1.21} # pinned\n",
			path:        ".tool-versions.goVersion",
			goDirective: "1.21.9",
			want:        "tool-versions: {buf: 1.28.1, goVersion: 1.21.9} # pinned\n",
			wantRewrote: true,
		},
		{
			// A key sharing the line carries a version that looks the same, so the
			// one raised has to be found from where the go key's own value starts.
			name:        "leaves a sibling holding the same version alone",
			file:        "tool-versions: {node: 1.21.0, goVersion: 1.21.0}\n",
			path:        ".tool-versions.goVersion",
			goDirective: "1.21.9",
			want:        "tool-versions: {node: 1.21.0, goVersion: 1.21.9}\n",
			wantRewrote: true,
		},
		{
			// Reading the document and writing it back would drop the blank line,
			// requote the value and reflow the comment, none of which is part of
			// what YAML calls the data. Only the version's own bytes are written.
			name:        "keeps quotes, a trailing comment and the blank lines around them",
			file:        "app-type: go-project\n\ntool-versions:\n\n  goVersion: \"1.21\" # the floor CI builds with\n",
			path:        ".tool-versions.goVersion",
			goDirective: "1.21.9",
			want:        "app-type: go-project\n\ntool-versions:\n\n  goVersion: \"1.21.9\" # the floor CI builds with\n",
			wantRewrote: true,
		},
		{
			// Nothing here says what Go the repository is on, so there is no version
			// for the file to keep up with, and no failure either.
			name: "leaves the file alone with no go directive anywhere",
			file: config,
			path: ".tool-versions.goVersion",
			want: config,
		},
		{
			name:        "raises a minor to all three components",
			file:        "tools:\n  goVersion: 1.21\n",
			path:        ".tools.goVersion",
			goDirective: "1.26",
			want:        "tools:\n  goVersion: 1.26.0\n",
			wantRewrote: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if tt.goDirective != "" {
				goMod := "module example.com/m\n\ngo " + tt.goDirective + "\n"
				if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			name := filepath.Join(dir, "config.yml")
			if err := os.WriteFile(name, []byte(tt.file), 0o644); err != nil {
				t.Fatal(err)
			}

			t.Chdir(dir)
			rewrote, err := raise(name, tt.path, tt.version)
			if err != nil {
				t.Errorf("raise(%q, %q) failed: %v", tt.path, tt.version, err)
			}
			if rewrote != tt.wantRewrote {
				t.Errorf("raise(%q, %q) = %v, want %v", tt.path, tt.version, rewrote, tt.wantRewrote)
			}

			raised, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(string(raised), tt.want); diff != "" {
				t.Errorf("config.yml after raise(%q, %q) differs (-got +want):\n%s", tt.path, tt.version, diff)
			}
		})
	}
}
