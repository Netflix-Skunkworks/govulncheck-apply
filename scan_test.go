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
	"maps"
	"reflect"
	"strings"
	"testing"
)

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

func TestHighestGoDirective(t *testing.T) {
	goMods := []string{
		"module example.com/a\n\ngo 1.21.0\n",
		"module example.com/b\n\ngo 1.25.3\n",
		"module example.com/c\n\ngo 1.22\n",
		"module example.com/d\n",
	}
	var dirs []string
	for _, goMod := range goMods {
		dirs = append(dirs, moduleDir(t, goMod))
	}
	got, err := highestGoDirective(dirs)
	if err != nil {
		t.Fatalf("highestGoDirective(%q) failed: %v", goMods, err)
	}
	if want := "1.25.3"; got != want {
		t.Errorf("highestGoDirective(%q) = %q, want %q", goMods, got, want)
	}
}

// TestParse checks the two things a finding is read for: the highest fix per
// module, and every OSV id seen against whether a fix was published for it.
func TestParse(t *testing.T) {
	stream := `
{"finding": {"osv": "GO-TEST-0001", "fixed_version": "v0.3.7", "trace": [{"module": "golang.org/x/text"}]}}
{"finding": {"osv": "GO-TEST-0001", "fixed_version": "v0.3.7", "trace": [{"module": "golang.org/x/text"}, {"module": "example.com/m"}]}}
{"finding": {"osv": "GO-TEST-0002", "fixed_version": "v0.3.8", "trace": [{"module": "golang.org/x/text"}]}}
{"finding": {"osv": "GO-TEST-0003", "trace": [{"module": "example.com/unfixable"}]}}
{"finding": {"osv": "GO-TEST-0004", "fixed_version": "v1.21.9", "trace": [{"module": "stdlib"}]}}
{"config": {"scanner_name": "govulncheck"}}
{"progress": {"message": "Scanning your code and 42 packages across 7 dependent modules for known vulnerabilities..."}}
`
	wantFix := fixes{
		modules:   map[string]string{"golang.org/x/text": "v0.3.8"},
		goVersion: "v1.21.9",
	}
	wantReported := map[string]bool{
		"GO-TEST-0001": true,
		"GO-TEST-0002": true,
		"GO-TEST-0003": false,
		"GO-TEST-0004": true,
	}

	fix, reported, err := parse(strings.NewReader(stream))
	if err != nil {
		t.Fatalf("parse(%q) failed: %v", stream, err)
	}
	// Compared whole: nothing else may reach fix.modules, and the trace's second
	// frame and the stdlib fix are both things that could wrongly land there.
	if !reflect.DeepEqual(fix, wantFix) {
		t.Errorf("parse() fixes = %+v, want %+v", fix, wantFix)
	}
	if !maps.Equal(reported, wantReported) {
		t.Errorf("parse() reported = %v, want %v", reported, wantReported)
	}
}
