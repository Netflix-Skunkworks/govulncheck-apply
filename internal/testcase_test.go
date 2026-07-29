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

package internal

import (
	"maps"
	"testing"
)

func TestDirectives(t *testing.T) {
	tests := []struct {
		name    string
		comment string
		want    map[string]string
		wantErr bool
	}{
		{
			name:    "comments only",
			comment: "# A called vuln.\n#\n# More about it.\n",
			want:    map[string]string{},
		},
		{
			name:    "comment then directive",
			comment: "# A stdlib vuln.\n\ngotoolchain: go1.21.0\n",
			want:    map[string]string{"gotoolchain": "go1.21.0"},
		},
		{
			name:    "directive before comment",
			comment: "skip: true\n# Why it's disabled.\n",
			want:    map[string]string{"skip": "true"},
		},
		{
			name:    "a comment after a blank line is not a directive",
			comment: "# A vuln.\n\n# go get: treats arguments as exact versions.\n",
			want:    map[string]string{},
		},
		{
			name:    "an uncommented line is an error, not silently dropped",
			comment: "# A vuln.\n\nThe module graph selects v0.3.7.\n",
			wantErr: true,
		},
		{
			name:    "an unmarked one-word line is an error too",
			comment: "description\n",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Directives([]byte(tt.comment))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Directives(%q) = %v, want an error", tt.comment, got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !maps.Equal(got, tt.want) {
				t.Errorf("Directives(%q) = %v, want %v", tt.comment, got, tt.want)
			}
		})
	}
}

func TestDescription(t *testing.T) {
	comment := "# A stdlib vuln.\n#\n# The `go` directive is bumped.\n\ngotoolchain: go1.21.0\n"
	want := "A stdlib vuln.\n\nThe `go` directive is bumped."
	if got := Description([]byte(comment)); got != want {
		t.Errorf("Description() =\n%s\nwant:\n%s", got, want)
	}
}
