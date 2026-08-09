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

// unexported lets cmp read the fields of the types this package keeps to itself.
// These are white-box tests, in the same package as what they compare.
var unexported = cmp.AllowUnexported(vuln{}, fixes{})

// TestToolchain covers the toolchain govulncheck is built under. The selection
// only ever raises: golang.org/x/vuln's own go directive is newer than many of the
// modules being scanned, so naming an older toolchain would fail the install.
func TestToolchain(t *testing.T) {
	for _, tt := range []struct{ name, highest, local, want string }{
		{"raises to a bare go directive", "1.26", "1.25.0", "go1.26.0+auto"},
		{"raises to a patch go directive", "1.25.12", "1.25.0", "go1.25.12+auto"},
		{"keeps the local toolchain when it is newer", "1.21.0", "1.26.0", "local+auto"},
		{"keeps the local toolchain with no go directive", "", "1.26.0", "local+auto"},
		{"keeps the local toolchain at an equal go directive", "1.26.0", "1.26.0", "local+auto"},
		{"treats a bare directive as its .0 patch", "1.26", "1.26.0", "local+auto"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := toolchain(tt.highest, tt.local); got != tt.want {
				t.Errorf("toolchain(%q, %q) = %q, want %q", tt.highest, tt.local, got, tt.want)
			}
		})
	}
}

// TestParse checks what a stream is read for: the highest fix per module, and
// what to say about each advisory. The module and package granularities
// govulncheck emits per advisory have to fold into one, taking the package name
// from the only one that has it.
func TestParse(t *testing.T) {
	stream := `
{"osv": {"id": "GO-TEST-0001", "summary": "Panic in x/text", "database_specific": {"url": "https://pkg.go.dev/vuln/GO-TEST-0001"}}}
{"finding": {"osv": "GO-TEST-0001", "fixed_version": "v0.3.7", "trace": [{"module": "golang.org/x/text", "version": "v0.3.5"}]}}
{"finding": {"osv": "GO-TEST-0001", "fixed_version": "v0.3.7", "trace": [{"module": "golang.org/x/text", "version": "v0.3.5", "package": "golang.org/x/text/language"}]}}
{"finding": {"osv": "GO-TEST-0002", "fixed_version": "v0.3.8", "trace": [{"module": "golang.org/x/text", "version": "v0.3.7"}]}}
{"finding": {"osv": "GO-TEST-0003", "trace": [{"module": "example.com/unfixable", "version": "v1.0.0"}]}}
{"osv": {"id": "GO-TEST-0004", "database_specific": {"url": "https://pkg.go.dev/vuln/GO-TEST-0004"}}}
{"finding": {"osv": "GO-TEST-0004", "fixed_version": "v1.21.9", "trace": [{"module": "stdlib", "version": "v1.21.0"}]}}
{"config": {"scanner_name": "govulncheck"}}
{"progress": {"message": "Scanning your code and 42 packages across 7 dependent modules for known vulnerabilities..."}}
`
	wantFix := fixes{
		modules:   map[string]string{"golang.org/x/text": "v0.3.8"},
		goVersion: "v1.21.9",
	}
	wantReported := map[string]vuln{
		"GO-TEST-0001": {
			osv: "GO-TEST-0001", url: "https://pkg.go.dev/vuln/GO-TEST-0001",
			summary: "Panic in x/text", module: "golang.org/x/text",
			pkg: "golang.org/x/text/language", found: "v0.3.5", fixedIn: "v0.3.7",
		},
		"GO-TEST-0002": {osv: "GO-TEST-0002", module: "golang.org/x/text", found: "v0.3.7", fixedIn: "v0.3.8"},
		"GO-TEST-0003": {osv: "GO-TEST-0003", module: "example.com/unfixable", found: "v1.0.0"},
		"GO-TEST-0004": {
			osv: "GO-TEST-0004", url: "https://pkg.go.dev/vuln/GO-TEST-0004",
			module: "stdlib", found: "v1.21.0", fixedIn: "v1.21.9",
		},
	}

	fix, reported, err := parse(strings.NewReader(stream))
	if err != nil {
		t.Fatalf("parse(%q) failed: %v", stream, err)
	}
	// Compared whole: nothing else may reach fix.modules, and the stdlib fix is
	// the thing that could wrongly land there.
	if diff := cmp.Diff(fix, wantFix, unexported); diff != "" {
		t.Errorf("parse() fixes differ (-got +want):\n%s", diff)
	}
	if diff := cmp.Diff(reported, wantReported, unexported); diff != "" {
		t.Errorf("parse() reported differ (-got +want):\n%s", diff)
	}
}

// TestExcludedByBuildConstraints covers the one loading failure that is not the
// module's problem: the packages an operating system it does not target would
// need. Everything else has to keep failing the module, which is what most of
// these cases check.
func TestExcludedByBuildConstraints(t *testing.T) {
	for _, tt := range []struct {
		name string
		said string
		want bool
	}{
		{
			name: "every error is an exclusion, as govulncheck prints them",
			said: `govulncheck: loading packages: 
There are errors with the provided package patterns:

-: build constraints exclude all Go files in /go/pkg/mod/golang.org/x/sys@v0.47.0/windows
-: build constraints exclude all Go files in /go/pkg/mod/golang.org/x/sys@v0.47.0/windows/registry

For details on package patterns, see https://pkg.go.dev/cmd/go#hdr-Package_lists_and_patterns.
`,
			want: true,
		},
		{
			name: "an exclusion beside an error of another kind",
			said: `There are errors with the provided package patterns:

-: build constraints exclude all Go files in /go/pkg/mod/golang.org/x/sys@v0.47.0/windows
-: no required module provides package example.invalid/nope

For details on package patterns, see https://pkg.go.dev/cmd/go#hdr-Package_lists_and_patterns.
`,
			want: false,
		},
		{
			// The go command has a second rendering, which names the import
			// chain and runs over several lines. Refusing it is deliberate: a
			// line the parse cannot read has to fail the module rather than be
			// passed over.
			name: "an exclusion carrying the import chain that reached it",
			said: `There are errors with the provided package patterns:

-: package example.com/root
	imports example.com/root/svc: build constraints exclude all Go files in /go/pkg/mod/example.com/dep@v1.0.0/svc

For details on package patterns, see https://pkg.go.dev/cmd/go#hdr-Package_lists_and_patterns.
`,
			want: false,
		},
		{
			name: "a failure that names no error at all",
			said: "govulncheck: no packages matched the provided patterns\n",
			want: false,
		},
		{
			name: "an error section holding no error",
			said: `There are errors with the provided package patterns:

For details on package patterns, see https://pkg.go.dev/cmd/go#hdr-Package_lists_and_patterns.
`,
			want: false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := excludedByBuildConstraints(tt.said); got != tt.want {
				t.Errorf("excludedByBuildConstraints(%q) = %v, want %v", tt.said, got, tt.want)
			}
		})
	}
}
