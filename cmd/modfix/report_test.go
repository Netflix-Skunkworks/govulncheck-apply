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

	"github.com/google/go-cmp/cmp"
)

// failureList is what report writes above the modules it gave up on.
const failureList = "Modules that could not be remediated:\n\n"

// vulnerable is the frame an advisory is against, caller the frame in the scanned
// module that reaches it, and invoke a frame between the two.
var (
	vulnerable = frame{
		Module: "golang.org/x/text", Package: "golang.org/x/text/language", Function: "Parse",
		Position: &token.Position{Filename: "language/parse.go", Line: 33, Column: 6},
	}
	caller = frame{
		Module: "example.com/foo", Package: "example.com/foo", Function: "main",
		Position: &token.Position{Filename: "main.go", Line: 10, Column: 28},
	}
	invoke = frame{
		Package: "google.golang.org/grpc", Receiver: "ClientConn", Function: "Invoke",
	}
	xtext = vuln{
		osv: "GO-2021-0113", url: "https://pkg.go.dev/vuln/GO-2021-0113",
		summary: "Panic in golang.org/x/text/language",
		module:  "golang.org/x/text", found: "v0.3.5", fixedIn: "v0.3.7",
		traces: [][]frame{{vulnerable, caller}},
	}
)

func TestReport(t *testing.T) {
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
			name:    "an advisory the module's own code reaches",
			modules: []moduleReport{{dir: ".", vulns: []vuln{xtext}}},
			want: "govulncheck found (and this PR fixes) 1 vulnerability:\n\n" +
				"Vulnerability #1: [GO-2021-0113](https://pkg.go.dev/vuln/GO-2021-0113) — Panic in golang.org/x/text/language\n\n" +
				"<details>\n<summary>Details</summary>\n\n```\n" +
				"  Module: golang.org/x/text\n" +
				"    Found in: golang.org/x/text@v0.3.5\n" +
				"    Fixed in: golang.org/x/text@v0.3.7\n" +
				"    Example traces found:\n" +
				"      #1: main.go:10:28: foo.main calls language.Parse\n" +
				"```\n\n</details>\n",
		},
		{
			// The standard library is named as govulncheck names it, by the package
			// rather than the stdlib module path, and at a toolchain version.
			name: "a standard-library advisory the module only carries",
			modules: []moduleReport{{dir: ".", vulns: []vuln{{
				osv: "GO-2024-2687", url: "https://pkg.go.dev/vuln/GO-2024-2687",
				summary: "Improper header parsing in net/http",
				module:  stdlib, pkg: "net/http", found: "v1.21.0", fixedIn: "v1.21.9",
			}}}},
			want: "govulncheck found (and this PR fixes) 1 vulnerability:\n\n" +
				"Vulnerability #1: [GO-2024-2687](https://pkg.go.dev/vuln/GO-2024-2687) — Improper header parsing in net/http\n\n" +
				"<details>\n<summary>Details</summary>\n\n```\n" +
				"  Standard library\n" +
				"    Found in: net/http@go1.21.0\n" +
				"    Fixed in: net/http@go1.21.9\n" +
				"```\n\n</details>\n",
		},
		{
			name: "an advisory with no published fix, and one the fix did not take",
			modules: []moduleReport{{dir: ".", vulns: []vuln{
				{osv: "GO-1", module: "example.com/a", found: "v1.0.0", stillReported: true},
				{osv: "GO-2", module: "example.com/b", found: "v1.0.0", fixedIn: "v1.1.0", stillReported: true},
			}}},
			want: "govulncheck found (and this PR fixes) 2 vulnerabilities:\n\n" +
				"Vulnerability #1: GO-1\n\n" +
				"<details>\n<summary>Details</summary>\n\n```\n" +
				"  Module: example.com/a\n" +
				"    Found in: example.com/a@v1.0.0\n" +
				"    Fixed in: no fix published\n" +
				"```\n\n</details>\n" +
				"\n" +
				"Vulnerability #2: GO-2\n\n" +
				"<details>\n<summary>Details</summary>\n\n```\n" +
				"  Module: example.com/b\n" +
				"    Found in: example.com/b@v1.0.0\n" +
				"    Fixed in: example.com/b@v1.1.0 (fix did not take)\n" +
				"```\n\n</details>\n",
		},
		{
			// Minimal version selection can land above the version that fixes the
			// advisory, so the version the run left is named where it differs.
			name: "a version selected above the one that fixes it",
			modules: []moduleReport{{dir: ".", vulns: []vuln{{
				osv: "GO-5", module: "golang.org/x/crypto", found: "v0.48.0",
				selected: "v0.53.0", fixedIn: "v0.52.0",
			}}}},
			want: "govulncheck found (and this PR fixes) 1 vulnerability:\n\n" +
				"Vulnerability #1: GO-5\n\n" +
				"<details>\n<summary>Details</summary>\n\n```\n" +
				"  Module: golang.org/x/crypto\n" +
				"    Found in: golang.org/x/crypto@v0.48.0\n" +
				"    Fixed in: golang.org/x/crypto@v0.52.0\n" +
				"    Selected: golang.org/x/crypto@v0.53.0\n" +
				"```\n\n</details>\n",
		},
		{
			name: "every way an advisory is reached is listed",
			modules: []moduleReport{{dir: ".", vulns: []vuln{{
				osv: "GO-6", module: "google.golang.org/grpc", found: "v1.81.1", fixedIn: "v1.82.1",
				traces: [][]frame{{vulnerable, invoke, caller}, {vulnerable, caller}},
			}}}},
			want: "govulncheck found (and this PR fixes) 1 vulnerability:\n\n" +
				"Vulnerability #1: GO-6\n\n" +
				"<details>\n<summary>Details</summary>\n\n```\n" +
				"  Module: google.golang.org/grpc\n" +
				"    Found in: google.golang.org/grpc@v1.81.1\n" +
				"    Fixed in: google.golang.org/grpc@v1.82.1\n" +
				"    Example traces found:\n" +
				"      #1: main.go:10:28: foo.main calls grpc.ClientConn.Invoke, which eventually calls language.Parse\n" +
				"      #2: main.go:10:28: foo.main calls language.Parse\n" +
				"```\n\n</details>\n",
		},
		{
			// govulncheck reports a finding per reachable symbol, and two of them can
			// differ only in frames no sentence names. A list of identical lines tells
			// a reader nothing.
			name: "traces that read the same are written once",
			modules: []moduleReport{{dir: ".", vulns: []vuln{{
				osv: "GO-8", module: "example.com/a", found: "v1.0.0", fixedIn: "v1.1.0",
				traces: [][]frame{
					{vulnerable, {Package: "example.com/one", Function: "first"}, invoke, caller},
					{vulnerable, {Package: "example.com/two", Function: "second"}, invoke, caller},
				},
			}}}},
			want: "govulncheck found (and this PR fixes) 1 vulnerability:\n\n" +
				"Vulnerability #1: GO-8\n\n" +
				"<details>\n<summary>Details</summary>\n\n```\n" +
				"  Module: example.com/a\n" +
				"    Found in: example.com/a@v1.0.0\n" +
				"    Fixed in: example.com/a@v1.1.0\n" +
				"    Example traces found:\n" +
				"      #1: main.go:10:28: foo.main calls grpc.ClientConn.Invoke, which eventually calls language.Parse\n" +
				"```\n\n</details>\n",
		},
		{
			// Numbering runs across the whole report, so two modules reporting the
			// same advisory produce two entries rather than a repeated number.
			name: "an entry per module reporting it, and the modules that failed after",
			modules: []moduleReport{
				{dir: ".", vulns: []vuln{{osv: "GO-7", module: "example.com/a", found: "v1.0.0", fixedIn: "v1.1.0"}}},
				{dir: "broken", err: "govulncheck: exit status 1"},
				{dir: "sub", vulns: []vuln{{osv: "GO-7", module: "example.com/a", found: "v1.0.0", fixedIn: "v1.1.0"}}},
			},
			want: "govulncheck found (and this PR fixes) 2 vulnerabilities:\n\n" +
				"Vulnerability #1: GO-7\n\n" +
				"<details>\n<summary>Details</summary>\n\n```\n" +
				"  Module: example.com/a\n" +
				"    Found in: example.com/a@v1.0.0\n" +
				"    Fixed in: example.com/a@v1.1.0\n" +
				"```\n\n</details>\n" +
				"\n" +
				"Vulnerability #2: GO-7\n\n" +
				"<details>\n<summary>Details</summary>\n\n```\n" +
				"  Module: example.com/a\n" +
				"    Found in: example.com/a@v1.0.0\n" +
				"    Fixed in: example.com/a@v1.1.0\n" +
				"```\n\n</details>\n" +
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
			modules: []moduleReport{{dir: ".", err: "go.mod:3: unknown directive\ngo.mod:7: bad version"}},
			want:    failureList + "- `.`: go.mod:3: unknown directive go.mod:7: bad version\n",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var out strings.Builder
			if err := report(&out, tt.modules); err != nil {
				t.Fatalf("report(%+v) failed: %v", tt.modules, err)
			}
			if diff := cmp.Diff(out.String(), tt.want); diff != "" {
				t.Errorf("report() differs (-got +want):\n%s", diff)
			}
		})
	}
}

// TestOneLine covers what would break a bullet out of its line.
func TestOneLine(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{"plain", "plain"},
		{"two\nlines", "two lines"},
		{"  padded\t", "padded"},
	} {
		if got := oneLine(tt.in); got != tt.want {
			t.Errorf("oneLine(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestCallSite covers govulncheck's own wording for a call trace, so that a reader
// of both reports sees the same sentence.
func TestCallSite(t *testing.T) {
	for _, tt := range []struct {
		name  string
		trace []frame
		want  string
	}{
		{
			name:  "a direct call names the two ends",
			trace: []frame{vulnerable, caller},
			want:  "main.go:10:28: foo.main calls language.Parse",
		},
		{
			name: "a pointer receiver reads as a call on it, and a closure as its function",
			trace: []frame{vulnerable, {
				Package: "example.com/foo/handler", Receiver: "*Server", Function: "Handle$1",
				Position: &token.Position{Filename: "handler/server.go", Line: 7, Column: 2},
			}},
			want: "handler/server.go:7:2: handler.Server.Handle calls language.Parse",
		},
		{
			// Naming only the two ends would read as a direct call that is not
			// there, so what the caller reaches for is named too.
			name:  "a deeper trace names what the caller calls to get there",
			trace: []frame{vulnerable, invoke, caller},
			want:  "main.go:10:28: foo.main calls grpc.ClientConn.Invoke, which eventually calls language.Parse",
		},
		{
			name:  "the frames past that one are not named",
			trace: []frame{vulnerable, {Package: "example.com/deep", Function: "inner"}, invoke, caller},
			want:  "main.go:10:28: foo.main calls grpc.ClientConn.Invoke, which eventually calls language.Parse",
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
