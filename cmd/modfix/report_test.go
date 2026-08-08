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
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestReport(t *testing.T) {
	for _, tt := range []struct {
		name  string
		vulns []vuln
		want  string
	}{
		{
			name:  "nothing to say is written as nothing",
			vulns: nil,
		},
		{
			name: "an advisory with a fix that took",
			vulns: []vuln{{
				osv: "GO-2021-0113", url: "https://pkg.go.dev/vuln/GO-2021-0113",
				summary: "Panic in golang.org/x/text/language",
				module:  "golang.org/x/text", found: "v0.3.5", fixedIn: "v0.3.7",
			}},
			want: "govulncheck found 1 vulnerability; this PR fixes 1:\n\n" +
				"**[GO-2021-0113](https://pkg.go.dev/vuln/GO-2021-0113)**: Panic in golang.org/x/text/language\n\n" +
				"    golang.org/x/text v0.3.5 -> v0.3.7\n",
		},
		{
			// The standard library is named as govulncheck names it, by the package
			// rather than the stdlib module path, and at a toolchain version.
			name: "a standard-library advisory",
			vulns: []vuln{{
				osv: "GO-2024-2687", url: "https://pkg.go.dev/vuln/GO-2024-2687",
				summary: "Improper header parsing in net/http",
				module:  stdlib, pkg: "net/http", found: "v1.21.0", fixedIn: "v1.21.9",
			}},
			want: "govulncheck found 1 vulnerability; this PR fixes 1:\n\n" +
				"**[GO-2024-2687](https://pkg.go.dev/vuln/GO-2024-2687)**: Improper header parsing in net/http\n\n" +
				"    net/http go1.21.0 -> go1.21.9\n",
		},
		{
			name: "an advisory with no published fix, and one the fix did not take",
			vulns: []vuln{
				{osv: "GO-1", module: "example.com/a", found: "v1.0.0", stillReported: true},
				{osv: "GO-2", module: "example.com/b", found: "v1.0.0", fixedIn: "v1.1.0", stillReported: true},
			},
			want: "govulncheck found 2 vulnerabilities; this PR fixes 0, 1 does not have a fix ready yet, 1 unable to fix:\n\n" +
				"**GO-1**\n\n" +
				"    example.com/a v1.0.0, no fix published\n" +
				"\n" +
				"**GO-2**\n\n" +
				"    example.com/b v1.0.0 -> v1.1.0 (fix did not take)\n",
		},
		{
			// Minimal version selection can land above the version that fixes the
			// advisory, so the version the run left is named where it differs.
			name: "a version selected above the one that fixes it",
			vulns: []vuln{{
				osv: "GO-5", module: "golang.org/x/crypto", found: "v0.48.0",
				selected: "v0.53.0", fixedIn: "v0.52.0",
			}},
			want: "govulncheck found 1 vulnerability; this PR fixes 1:\n\n" +
				"**GO-5**\n\n" +
				"    golang.org/x/crypto v0.48.0 -> v0.52.0 (selected v0.53.0)\n",
		},
		{
			// Another advisory's fix can raise a module this one has no fix for, so
			// the version the run left is named here too.
			name: "a module raised past an advisory with no fix",
			vulns: []vuln{{
				osv: "GO-4", module: "golang.org/x/net", found: "v0.20.0",
				selected: "v0.38.0", stillReported: true,
			}},
			want: "govulncheck found 1 vulnerability; this PR fixes 0, 1 does not have a fix ready yet:\n\n" +
				"**GO-4**\n\n" +
				"    golang.org/x/net v0.20.0, no fix published (selected v0.38.0)\n",
		},
		{
			name: "both notes on one advisory",
			vulns: []vuln{{
				osv: "GO-3", module: "example.com/c", found: "v1.0.0",
				selected: "v1.2.0", fixedIn: "v1.1.0", stillReported: true,
			}},
			want: "govulncheck found 1 vulnerability; this PR fixes 0, 1 unable to fix:\n\n" +
				"**GO-3**\n\n" +
				"    example.com/c v1.0.0 -> v1.1.0 (selected v1.2.0, fix did not take)\n",
		},
		{
			// Each module's outcome is reported on its own, so two modules
			// reporting the same advisory produce an entry each.
			name:  "an entry per module reporting it",
			vulns: []vuln{{osv: "GO-7", module: "example.com/a", found: "v1.0.0", fixedIn: "v1.1.0"}, {osv: "GO-7", module: "example.com/a", found: "v1.0.0", fixedIn: "v1.1.0"}},
			want: "govulncheck found 2 vulnerabilities; this PR fixes 2:\n\n" +
				"**GO-7**\n\n" +
				"    example.com/a v1.0.0 -> v1.1.0\n" +
				"\n" +
				"**GO-7**\n\n" +
				"    example.com/a v1.0.0 -> v1.1.0\n",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var out strings.Builder
			if err := report(&out, tt.vulns); err != nil {
				t.Fatalf("report(%+v) failed: %v", tt.vulns, err)
			}
			if diff := cmp.Diff(out.String(), tt.want); diff != "" {
				t.Errorf("report() differs (-got +want):\n%s", diff)
			}
		})
	}
}

// TestOneLine covers what would break an entry out of its line.
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
