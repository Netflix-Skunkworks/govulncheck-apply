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
)

// inModule writes goMod to a fresh temp directory and switches into it, so the
// go.mod editors (which act on the working directory's go.mod) operate on it.
func inModule(t *testing.T, goMod string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
}

// readGoMod returns the working directory's go.mod.
func readGoMod(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("go.mod")
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
			inModule(t, tt.in)
			if err := goModEditGo(tt.version); err != nil {
				t.Fatal(err)
			}
			if got := readGoMod(t); got != tt.want {
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
			inModule(t, tt.in)
			if err := bumpReplacedModules(fixed); err != nil {
				t.Fatal(err)
			}
			if got := readGoMod(t); got != tt.want {
				t.Errorf("bumpReplacedModules(%v) produced go.mod:\n%s\nwant:\n%s", fixed, got, tt.want)
			}
		})
	}
}
