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
	"reflect"
	"slices"
	"testing"
)

func TestClassify(t *testing.T) {
	for _, tt := range []struct {
		name            string
		seen, remaining map[string]bool
		wantFixed       []string
		wantUnfixed     []unfixed
	}{
		{
			// Whether a fix was published does not matter once the id is gone:
			// go mod tidy can drop the dependency carrying it outright.
			name:      "an id the last pass no longer reports is fixed",
			seen:      map[string]bool{"GO-1": true},
			remaining: map[string]bool{},
			wantFixed: []string{"GO-1"},
		},
		{
			name:        "an id still reported with a published fix did not take",
			seen:        map[string]bool{"GO-1": true},
			remaining:   map[string]bool{"GO-1": true},
			wantUnfixed: []unfixed{{OSV: "GO-1", Reason: fixNotTaken}},
		},
		{
			name:        "an id still reported with no published fix is unfixable",
			seen:        map[string]bool{"GO-1": false},
			remaining:   map[string]bool{"GO-1": false},
			wantUnfixed: []unfixed{{OSV: "GO-1", Reason: noFix}},
		},
		{
			name: "ids are sorted, whichever outcome they land in",
			seen: map[string]bool{"GO-3": true, "GO-1": true, "GO-2": false, "GO-4": true},
			remaining: map[string]bool{
				"GO-2": false,
				"GO-4": true,
			},
			wantFixed:   []string{"GO-1", "GO-3"},
			wantUnfixed: []unfixed{{OSV: "GO-2", Reason: noFix}, {OSV: "GO-4", Reason: fixNotTaken}},
		},
		{
			name:      "a module with no findings reports nothing",
			seen:      map[string]bool{},
			remaining: map[string]bool{},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fixed, unfixed := classify(tt.seen, tt.remaining)
			if !slices.Equal(fixed, tt.wantFixed) {
				t.Errorf("classify(%v, %v) fixed = %q, want %q", tt.seen, tt.remaining, fixed, tt.wantFixed)
			}
			if !reflect.DeepEqual(unfixed, tt.wantUnfixed) {
				t.Errorf("classify(%v, %v) unfixed = %+v, want %+v", tt.seen, tt.remaining, unfixed, tt.wantUnfixed)
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
	if !slices.Equal(got, want) {
		t.Errorf("modules() over %q = %q, want %q", layout, got, want)
	}
}
