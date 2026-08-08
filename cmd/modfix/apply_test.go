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
	"testing"

	"github.com/google/go-cmp/cmp"
)

// moduleDir writes goMod to a fresh temp directory and returns the directory.
func moduleDir(t *testing.T, goMod string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// goModText returns dir's go.mod.
func goModText(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestGoModEditGo(t *testing.T) {
	tests := []struct {
		name    string
		version string
		in      string
		want    string
	}{
		{
			name:    "bumps the go directive",
			version: "1.21.9",
			in: `module example.com/m

go 1.21.0
`,
			want: `module example.com/m

go 1.21.9
`,
		},
		{
			name:    "drops a toolchain older than the fix",
			version: "1.21.9",
			in: `module example.com/m

go 1.21.0

toolchain go1.21.4
`,
			want: `module example.com/m

go 1.21.9
`,
		},
		{
			name:    "keeps a toolchain newer than the fix",
			version: "1.21.9",
			in: `module example.com/m

go 1.21.0

toolchain go1.22.0
`,
			want: `module example.com/m

go 1.21.9

toolchain go1.22.0
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := moduleDir(t, tt.in)
			if err := goModEditGo(dir, tt.version); err != nil {
				t.Fatal(err)
			}
			if got := goModText(t, dir); got != tt.want {
				t.Errorf("goModEditGo(%q) produced go.mod:\n%s\nwant:\n%s", tt.version, got, tt.want)
			}
		})
	}
}

func TestBumpReplacedModules(t *testing.T) {
	fixed := map[string]string{"golang.org/x/text": "v0.3.7"}
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "bumps a self replace pinning the vulnerable version",
			in: `module example.com/m

go 1.23

require golang.org/x/text v0.3.5

replace golang.org/x/text => golang.org/x/text v0.3.5
`,
			want: `module example.com/m

go 1.23

require golang.org/x/text v0.3.5

replace golang.org/x/text => golang.org/x/text v0.3.7
`,
		},
		{
			name: "preserves the old-version selector when bumping",
			in: `module example.com/m

go 1.23

replace golang.org/x/text v1.0.0 => golang.org/x/text v0.3.5
`,
			want: `module example.com/m

go 1.23

replace golang.org/x/text v1.0.0 => golang.org/x/text v0.3.7
`,
		},
		{
			name: "leaves a fork redirect alone",
			in: `module example.com/m

go 1.23

replace golang.org/x/text => example.com/fork v1.0.0
`,
			want: `module example.com/m

go 1.23

replace golang.org/x/text => example.com/fork v1.0.0
`,
		},
		{
			name: "leaves a local-path replace alone",
			in: `module example.com/m

go 1.23

replace golang.org/x/text => ../fork
`,
			want: `module example.com/m

go 1.23

replace golang.org/x/text => ../fork
`,
		},
		{
			name: "leaves an unfixed module alone",
			in: `module example.com/m

go 1.23

replace example.com/other => example.com/other v1.0.0
`,
			want: `module example.com/m

go 1.23

replace example.com/other => example.com/other v1.0.0
`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := moduleDir(t, tt.in)
			if err := bumpReplacedModules(dir, fixed); err != nil {
				t.Fatal(err)
			}
			if got := goModText(t, dir); got != tt.want {
				t.Errorf("bumpReplacedModules(%v) produced go.mod:\n%s\nwant:\n%s", fixed, got, tt.want)
			}
		})
	}
}

func TestCarvedOut(t *testing.T) {
	tests := []struct {
		name string
		said string
		want map[string]string
	}{
		{
			name: "a carve-out, as go prints it",
			said: `go: example.com/foo imports
	google.golang.org/grpc/status imports
	google.golang.org/genproto/googleapis/rpc/status: ambiguous import: found package google.golang.org/genproto/googleapis/rpc/status in multiple modules:
	google.golang.org/genproto v0.0.0-20220921223823-23cae91e6737 (/go/pkg/mod/google.golang.org/genproto@v0.0.0-20220921223823-23cae91e6737/googleapis/rpc/status)
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260414002931-afd174a4e478 (/go/pkg/mod/google.golang.org/genproto/googleapis/rpc@v0.0.0-20260414002931-afd174a4e478/status)
`,
			want: map[string]string{"google.golang.org/genproto": "v0.0.0-20260414002931-afd174a4e478"},
		},
		{
			name: "one module carved into twice takes the higher version",
			said: `	example.com/a/one/pkg: ambiguous import: found package example.com/a/one/pkg in multiple modules:
	example.com/a v0.0.0-20200101000000-aaaaaaaaaaaa (dir)
	example.com/a/two v0.0.0-20200202000000-bbbbbbbbbbbb (dir)
	example.com/a/one v0.0.0-20200303000000-cccccccccccc (dir)
`,
			want: map[string]string{"example.com/a": "v0.0.0-20200303000000-cccccccccccc"},
		},
		{
			// A tag of the nested module names no version of the outer one.
			name: "a nested module carrying its own tags is left alone",
			said: `	example.com/a/sub/pkg: ambiguous import: found package example.com/a/sub/pkg in multiple modules:
	example.com/a v1.0.0 (dir)
	example.com/a/sub v2.0.0 (dir)
`,
			want: map[string]string{},
		},
		{
			name: "two modules neither nesting in the other",
			said: `	example.com/one/pkg: ambiguous import: found package example.com/one/pkg in multiple modules:
	example.com/one v0.0.0-20200101000000-aaaaaaaaaaaa (dir)
	example.com/two v0.0.0-20200101000000-bbbbbbbbbbbb (dir)
`,
			want: map[string]string{},
		},
		{
			// Nesting that only holds across the boundary between two reports.
			name: "nesting only across two reports",
			said: `	example.com/a/pkg: ambiguous import: found package example.com/a/pkg in multiple modules:
	example.com/a v0.0.0-20200101000000-aaaaaaaaaaaa (dir)
	example.com/x v0.0.0-20200101000000-bbbbbbbbbbbb (dir)
	example.com/b/pkg: ambiguous import: found package example.com/b/pkg in multiple modules:
	example.com/a/sub v0.0.0-20200303000000-cccccccccccc (dir)
	example.com/y v0.0.0-20200101000000-dddddddddddd (dir)
`,
			want: map[string]string{},
		},
		{
			name: "a module cache path holding a space",
			said: `	example.com/a/pkg: ambiguous import: found package example.com/a/pkg in multiple modules:
	example.com/a v0.0.0-20200101000000-aaaaaaaaaaaa (/Users/first last/go/pkg/mod/example.com/a)
	example.com/a/sub v0.0.0-20200202000000-bbbbbbbbbbbb (/Users/first last/go/pkg/mod/example.com/a/sub)
`,
			want: map[string]string{"example.com/a": "v0.0.0-20200202000000-bbbbbbbbbbbb"},
		},
		{
			name: "module lines with no report above them",
			said: `	example.com/a v0.0.0-20200101000000-aaaaaaaaaaaa (dir)
	example.com/a/sub v0.0.0-20200202000000-bbbbbbbbbbbb (dir)
`,
			want: map[string]string{},
		},
		{
			name: "a failure that is not an ambiguity",
			said: `go: example.com/foo imports
	example.com/gone: no required module provides package example.com/gone
`,
			want: map[string]string{},
		},
		{
			name: "nothing said",
			said: "",
			want: map[string]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(carvedOut(tt.said), tt.want); diff != "" {
				t.Errorf("carvedOut() diff (-got +want):\n%s", diff)
			}
		})
	}
}
