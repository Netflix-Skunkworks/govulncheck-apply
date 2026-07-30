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
	"go/token"
	"strings"
	"testing"
)

// failureList is what report writes above the modules it gave up on.
const failureList = "Modules that could not be remediated:\n\n"

// table builds a case's expectation from its rows, against the header report
// writes once. No rows means no output at all.
func table(rows ...string) string {
	if len(rows) == 0 {
		return ""
	}
	return tableHeader + strings.Join(rows, "\n") + "\n"
}

func TestReport(t *testing.T) {
	called := vuln{
		osv:     "GO-2021-0113",
		url:     "https://pkg.go.dev/vuln/GO-2021-0113",
		summary: "Panic in golang.org/x/text/language",
		module:  "golang.org/x/text",
		found:   "v0.3.5",
		fixedIn: "v0.3.7",
		trace: []frame{
			{Package: "golang.org/x/text/language", Function: "Parse"},
			{Package: "example.com/foo", Function: "main",
				Position: &token.Position{Filename: "main.go", Line: 10, Column: 28}},
		},
	}
	// The same advisory renders the same way whichever module reports it, so the
	// row is written once with the directory left to fill in.
	rowFor := func(dir string) string {
		return "| `" + dir + "` | [GO-2021-0113](https://pkg.go.dev/vuln/GO-2021-0113) | " +
			"Panic in golang.org/x/text/language | golang.org/x/text@v0.3.5 | v0.3.7 | " +
			"main.go:10:28 foo.main → language.Parse |"
	}
	stdlibVuln := vuln{
		osv:     "GO-2024-2687",
		url:     "https://pkg.go.dev/vuln/GO-2024-2687",
		module:  stdlib,
		found:   "v1.21.0",
		fixedIn: "v1.21.9",
	}

	for _, tt := range []struct {
		name    string
		modules []moduleReport
		want    string
	}{
		{
			name:    "nothing to say is written as nothing",
			modules: []moduleReport{{dir: "."}, {dir: "sub"}},
		},
		{
			name:    "a fixed advisory, with where it was reached from",
			modules: []moduleReport{{dir: ".", vulns: []vuln{called}}},
			want:    table(rowFor(".")),
		},
		{
			name:    "the standard library reads as a toolchain name, not a semver",
			modules: []moduleReport{{dir: ".", vulns: []vuln{stdlibVuln}}},
			want: table("| `.` | [GO-2024-2687](https://pkg.go.dev/vuln/GO-2024-2687) |  | " +
				"stdlib@go1.21.0 | go1.21.9 | not called |"),
		},
		{
			name: "what was left behind says so where the version would be",
			modules: []moduleReport{{dir: ".", vulns: []vuln{
				{osv: "GO-1", module: "example.com/a", found: "v1.0.0", stillReported: true},
				{osv: "GO-2", module: "example.com/b", found: "v1.0.0", fixedIn: "v1.1.0", stillReported: true},
			}}},
			want: table(
				"| `.` | GO-1 |  | example.com/a@v1.0.0 | no fix published | not called |",
				"| `.` | GO-2 |  | example.com/b@v1.0.0 | v1.1.0 (fix did not take) | not called |"),
		},
		{
			// The version is formatted before it is decorated, or a standard-library
			// advisory with no published fix would read as "gono fix published".
			name: "a standard-library advisory with no published fix",
			modules: []moduleReport{{dir: ".", vulns: []vuln{
				{osv: "GO-3", module: stdlib, found: "v1.21.0", stillReported: true},
			}}},
			want: table("| `.` | GO-3 |  | stdlib@go1.21.0 | no fix published | not called |"),
		},
		{
			name: "one row per module, and the modules that failed listed after",
			modules: []moduleReport{
				{dir: ".", vulns: []vuln{called}},
				{dir: "broken", err: "govulncheck: exit status 1"},
				{dir: "sub", vulns: []vuln{called}},
			},
			want: table(rowFor("."), rowFor("sub")) +
				"\n" + failureList + "- `broken`: govulncheck: exit status 1\n",
		},
		{
			name:    "a failure alone is still worth reporting",
			modules: []moduleReport{{dir: ".", err: "still changing after 5 passes"}},
			want:    failureList + "- `.`: still changing after 5 passes\n",
		},
		{
			// modfile.Parse reports a malformed go.mod as newline-joined errors,
			// which would otherwise break the list open.
			name:    "an error spanning lines stays on its bullet",
			modules: []moduleReport{{dir: ".", err: "go.mod:3: unknown directive\ngo.mod:7: bad | version"}},
			want:    failureList + "- `.`: go.mod:3: unknown directive go.mod:7: bad \\| version\n",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var out strings.Builder
			if err := report(&out, tt.modules); err != nil {
				t.Fatalf("report(%+v) failed: %v", tt.modules, err)
			}
			if got := out.String(); got != tt.want {
				t.Errorf("report() =\n%s\nwant:\n%s", got, tt.want)
			}
		})
	}
}

// TestCell covers the two characters that would break a table out of its row.
func TestCell(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{"plain", "plain"},
		{"a | b", `a \| b`},
		{"two\nlines", "two lines"},
		{"  padded\t", "padded"},
	} {
		if got := cell(tt.in); got != tt.want {
			t.Errorf("cell(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestCallSite(t *testing.T) {
	vulnerable := frame{
		Module:   "golang.org/x/text",
		Package:  "golang.org/x/text/language",
		Function: "Parse",
		Position: &token.Position{Filename: "language/parse.go", Line: 33, Column: 6},
	}
	caller := frame{
		Module:   "example.com/foo",
		Package:  "example.com/foo",
		Function: "main",
		Position: &token.Position{Filename: "main.go", Line: 10, Column: 28},
	}

	for _, tt := range []struct {
		name  string
		trace []frame
		want  string
	}{
		{
			name:  "the outermost frame is the call, trace[0] is what it reaches",
			trace: []frame{vulnerable, caller},
			want:  "main.go:10:28 foo.main → language.Parse",
		},
		{
			name: "a pointer receiver reads as a call on it, and a closure as its function",
			trace: []frame{vulnerable, {
				Package: "example.com/foo/handler", Receiver: "*Server", Function: "Handle$1",
				Position: &token.Position{Filename: "handler/server.go", Line: 7, Column: 2},
			}},
			want: "handler/server.go:7:2 handler.Server.Handle → language.Parse",
		},
		{
			// The module and package granularities report a single frame and no
			// position, so there is no call to name.
			name:  "a coarser finding has nothing to render",
			trace: []frame{vulnerable},
			want:  "",
		},
		{
			name:  "a frame without a position has nothing to render either",
			trace: []frame{vulnerable, {Module: "example.com/foo"}},
			want:  "",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := callSite(tt.trace); got != tt.want {
				t.Errorf("callSite(%+v) = %q, want %q", tt.trace, got, tt.want)
			}
		})
	}
}

// TestPackageName covers the import paths whose last element is not the name a
// package is imported under.
func TestPackageName(t *testing.T) {
	for _, tt := range []struct{ importPath, want string }{
		{"golang.org/x/text/language", "language"},
		{"github.com/dgrijalva/jwt-go", "jwt"},
		{"github.com/go-redis/redis", "redis"},
		{"gopkg.in/yaml.v2", "yaml"},
		{"example.com/foo/v2", "foo"},
		{"net/http", "http"},
	} {
		if got := packageName(tt.importPath); got != tt.want {
			t.Errorf("packageName(%q) = %q, want %q", tt.importPath, got, tt.want)
		}
	}
}
