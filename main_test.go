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

func TestClassify(t *testing.T) {
	fixable := vuln{osv: "GO-1", fixedIn: "v1.1.0"}
	unfixable := vuln{osv: "GO-2"}
	for _, tt := range []struct {
		name            string
		seen, remaining map[string]vuln
		want            []vuln
	}{
		{
			// Whether a fix was published does not matter once the advisory is
			// gone: go mod tidy can drop the dependency carrying it outright.
			name: "an advisory the last pass no longer reports is fixed",
			seen: map[string]vuln{"GO-1": fixable, "GO-2": unfixable},
			want: []vuln{fixable, unfixable},
		},
		{
			name:      "an advisory still reported is marked as such",
			seen:      map[string]vuln{"GO-1": fixable},
			remaining: map[string]vuln{"GO-1": fixable},
			want:      []vuln{{osv: "GO-1", fixedIn: "v1.1.0", stillReported: true}},
		},
		{
			name:      "an advisory with no published fix is marked the same way",
			seen:      map[string]vuln{"GO-2": unfixable},
			remaining: map[string]vuln{"GO-2": unfixable},
			want:      []vuln{{osv: "GO-2", stillReported: true}},
		},
		{
			name:      "advisories come back in id order, whichever outcome they land in",
			seen:      map[string]vuln{"GO-2": unfixable, "GO-1": fixable},
			remaining: map[string]vuln{"GO-2": unfixable},
			want:      []vuln{fixable, {osv: "GO-2", stillReported: true}},
		},
		{
			name: "a module with no findings reports nothing",
			seen: map[string]vuln{},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := classify(tt.seen, tt.remaining)
			if diff := cmp.Diff(got, tt.want, unexported); diff != "" {
				t.Errorf("classify(%+v, %+v) differs (-got +want):\n%s", tt.seen, tt.remaining, diff)
			}
		})
	}
}

func TestModules(t *testing.T) {
	layout := []string{
		"go.mod",
		"sub/go.mod",
		"deep/nested/go.mod",
		"vendor/example.com/dep/go.mod",
		"testdata/fixture/go.mod",
		".hidden/go.mod",
		"_ignored/go.mod",
		"notamodule/main.go",
	}
	dir := t.TempDir()
	for _, path := range layout {
		path = filepath.Join(dir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	got, err := modules(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{dir, filepath.Join(dir, "deep", "nested"), filepath.Join(dir, "sub")}
	if diff := cmp.Diff(got, want); diff != "" {
		t.Errorf("modules() over %q differs (-got +want):\n%s", layout, diff)
	}
}
