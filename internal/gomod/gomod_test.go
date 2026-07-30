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

package gomod

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

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

	got, err := Modules(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{dir, filepath.Join(dir, "deep", "nested"), filepath.Join(dir, "sub")}
	if diff := cmp.Diff(got, want); diff != "" {
		t.Errorf("Modules() over %q differs (-got +want):\n%s", layout, diff)
	}
}

// TestHigher covers the orderings a go directive can ask for. A release candidate
// is the one semver reads as invalid, and so as lower than every release. A
// version naming no patch is the language version, which sits below that
// language's first release, so a caller comparing versions from two places gives
// both of them all three components first.
func TestHigher(t *testing.T) {
	for _, tt := range []struct {
		a, b string
		want bool
	}{
		{"1.26.0", "1.25.3", true},
		{"1.25.3", "1.26.0", false},
		{"1.26", "1.26.0", false},
		{"1.26.0", "1.26", true},
		{"1.26rc1", "1.25.0", true},
		{"1.21.0", "", true},
		{"", "1.21.0", false},
	} {
		if got := Higher(tt.a, tt.b); got != tt.want {
			t.Errorf("Higher(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestFullVersion(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{"1.26", "1.26.0"},
		{"1.26.4", "1.26.4"},
		{"", ""},
	} {
		if got := FullVersion(tt.in); got != tt.want {
			t.Errorf("FullVersion(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
