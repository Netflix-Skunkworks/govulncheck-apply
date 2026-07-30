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
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestRaiseTags(t *testing.T) {
	for _, tt := range []struct {
		name       string
		dockerfile string
		want       string
	}{
		{
			name:       "raises a tag naming only a minor",
			dockerfile: "FROM golang:1.21 AS builder\nRUN go mod download\n",
			want:       "FROM golang:1.21.9 AS builder\nRUN go mod download\n",
		},
		{
			name:       "raises a tag ending the line",
			dockerfile: "FROM golang:1.21",
			want:       "FROM golang:1.21.9",
		},
		{
			name:       "raises a tag already naming a patch",
			dockerfile: "FROM golang:1.21.4 AS builder\n",
			want:       "FROM golang:1.21.9 AS builder\n",
		},
		{
			// A registry prefix and a --platform flag holding a Go template are
			// both part of the FROM line and have to come through as they were.
			name:       "keeps a platform flag and a registry prefix",
			dockerfile: "FROM --platform={{ .Target.Platform }} docker.io/golang:1.21 AS builder\n",
			want:       "FROM --platform={{ .Target.Platform }} docker.io/golang:1.21.9 AS builder\n",
		},
		{
			// The version is found from the end of the match, so a port is not
			// mistaken for the tag separator.
			name:       "keeps a registry port",
			dockerfile: "FROM registry.example.com:5000/golang:1.21\n",
			want:       "FROM registry.example.com:5000/golang:1.21.9\n",
		},
		{
			name:       "keeps a tag suffix",
			dockerfile: "FROM golang:1.21-alpine AS builder\n",
			want:       "FROM golang:1.21.9-alpine AS builder\n",
		},
		{
			name:       "raises every stage that needs it, leaving the rest alone",
			dockerfile: "FROM golang:1.21 AS builder\n\nFROM golang:1.26 AS tools\n\nFROM ubuntu:jammy\n",
			want:       "FROM golang:1.21.9 AS builder\n\nFROM golang:1.26 AS tools\n\nFROM ubuntu:jammy\n",
		},
		{
			// golang:1 already follows the newest release, and golang:latest names
			// no version to compare.
			name:       "leaves a tag naming no minor alone",
			dockerfile: "FROM golang:1 AS builder\nFROM golang:latest AS tools\n",
			want:       "FROM golang:1 AS builder\nFROM golang:latest AS tools\n",
		},
		{
			name:       "leaves an image that merely ends in golang alone",
			dockerfile: "FROM mygolang:1.21 AS builder\n",
			want:       "FROM mygolang:1.21 AS builder\n",
		},
		{
			name:       "leaves a FROM that does not start its line alone",
			dockerfile: "# FROM golang:1.21 was the old builder\nRUN true\n",
			want:       "# FROM golang:1.21 was the old builder\nRUN true\n",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			const version = "1.21.9"
			if got := raiseTags(tt.dockerfile, version); got != tt.want {
				t.Errorf("raiseTags(%q, %q) =\n%q\nwant:\n%q", tt.dockerfile, version, got, tt.want)
			}
		})
	}
}

func TestModule(t *testing.T) {
	dirs := []string{".", "sub", "sub/inner", "subdir"}
	for _, tt := range []struct{ path, want string }{
		{"Dockerfile", "."},
		{"deploy/Dockerfile", "."},
		{"sub/Dockerfile", "sub"},
		{"sub/deploy/Dockerfile", "sub"},
		{"sub/inner/Dockerfile", "sub/inner"},
		{"subdir/Dockerfile", "subdir"},
	} {
		path := filepath.FromSlash(tt.path)
		if got := module(path, dirs); got != tt.want {
			t.Errorf("module(%q, %v) = %q, want %q", path, dirs, got, tt.want)
		}
	}
	// Without a module at the root there is nothing for a Dockerfile beside it to
	// be raised to.
	outside := []string{"sub"}
	if got := module("Dockerfile", outside); got != "" {
		t.Errorf("module(%q, %v) = %q, want %q", "Dockerfile", outside, got, "")
	}
}

// TestRaise covers which Dockerfiles a run reaches: each follows the module it
// sits closest under, and the directories the go command ignores are not the
// repository's to edit.
func TestRaise(t *testing.T) {
	const oldTag = "FROM golang:1.19 AS builder\n"
	repo := map[string]string{
		"Dockerfile":              oldTag,
		"app/go.mod":              "module example.com/app\n\ngo 1.21.9\n",
		"app/Dockerfile":          "FROM golang:1.21 AS builder\n",
		"app/Dockerfile.dev":      "FROM golang:1.20 AS builder\n",
		"app/deploy/Dockerfile":   oldTag,
		"app/inner/go.mod":        "module example.com/inner\n\ngo 1.24.0\n",
		"app/inner/Dockerfile":    "FROM golang:1.24 AS builder\n",
		"app/testdata/Dockerfile": oldTag,
		"app/vendor/x/Dockerfile": oldTag,
		"nodirective/go.mod":      "module example.com/nodirective\n",
		"nodirective/Dockerfile":  oldTag,
		"notes.txt":               oldTag,
	}
	dir := t.TempDir()
	for path, data := range repo {
		path = filepath.Join(dir, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	want := maps.Clone(repo)
	want["app/Dockerfile"] = "FROM golang:1.21.9 AS builder\n"
	want["app/Dockerfile.dev"] = "FROM golang:1.21.9 AS builder\n"
	want["app/deploy/Dockerfile"] = "FROM golang:1.21.9 AS builder\n"
	wantRewritten := []string{"app/Dockerfile", "app/Dockerfile.dev", "app/deploy/Dockerfile"}

	t.Chdir(dir)
	rewritten, err := raise()
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(rewritten, wantRewritten); diff != "" {
		t.Errorf("raise() rewrote (-got +want):\n%s", diff)
	}
	if diff := cmp.Diff(read(t, dir), want); diff != "" {
		t.Errorf("repository after raise() differs (-got +want):\n%s", diff)
	}
}

// read returns every file under dir, keyed by its slash-separated path relative
// to dir, so that a whole repository can be compared at once.
func read(t *testing.T, dir string) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(rel)] = string(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}
