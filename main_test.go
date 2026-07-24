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

import "testing"

func TestToolchainStale(t *testing.T) {
	tests := []struct {
		name      string
		toolchain string
		goVersion string
		want      bool
	}{
		{"absent", "", "1.21.9", false},
		{"older patch", "go1.21.4", "1.21.9", true},
		{"older minor", "go1.20.5", "1.21.9", true},
		{"equal", "go1.21.9", "1.21.9", false},
		{"newer patch", "go1.21.10", "1.21.9", false}, // numeric, not lexical, ordering
		{"newer minor", "go1.22.0", "1.21.9", false},
		{"missing patch, older", "go1.21", "1.21.9", true},
		{"missing patch, newer", "go1.22", "1.21.9", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := toolchainStale(tt.toolchain, tt.goVersion); got != tt.want {
				t.Errorf("toolchainStale(%q, %q) = %v, want %v", tt.toolchain, tt.goVersion, got, tt.want)
			}
		})
	}
}
