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

// Package internal holds the testcases/*.txtar scenarios and the code that
// reads them, shared by the test harness and the repro command.
package internal

import (
	"fmt"
	"strings"
)

// Directives parses a testcase's txtar comment: `#` lines are comments
// describing the case, and every other non-blank line is a `key: value`
// directive. Anything else is an error.
func Directives(comment []byte) (map[string]string, error) {
	m := map[string]string{}
	for line := range strings.SplitSeq(string(comment), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok || strings.ContainsAny(key, " \t") {
			return nil, fmt.Errorf("comment line is neither a # comment nor a `key: value` directive: %q", line)
		}
		m[key] = strings.TrimSpace(val)
	}
	return m, nil
}

// Description returns the case's `#` comments with the markers stripped, for the
// repro command to print.
func Description(comment []byte) string {
	var lines []string
	for line := range strings.SplitSeq(string(comment), "\n") {
		if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "#") {
			lines = append(lines, strings.TrimPrefix(strings.TrimPrefix(trimmed, "#"), " "))
		}
	}
	return strings.Join(lines, "\n")
}
