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

// Toolchain returns the GOTOOLCHAIN a case runs under. A gotoolchain directive
// names one as a floor rather than an exact version, so a module whose go
// directive is higher still runs under its own. Which standard library a scan
// reads is settled by the go directive rather than by this.
func Toolchain(directives map[string]string) string {
	if gt := directives["gotoolchain"]; gt != "" {
		return gt + "+auto"
	}
	return "local"
}

// Env returns the space-separated KEY=VALUE pairs an env directive sets, and
// none for a case without one. A case sets the directive where what it asserts
// is that the run overrides it, since a go command default that varies with the
// machine cannot otherwise be reproduced. A pair that is not KEY=VALUE is an
// error rather than something to pass on: the go command would leave the
// variable unset, which is the ambient behaviour the case exists to rule out.
func Env(directives map[string]string) ([]string, error) {
	pairs := strings.Fields(directives["env"])
	for _, pair := range pairs {
		if name, _, ok := strings.Cut(pair, "="); !ok || name == "" {
			return nil, fmt.Errorf("env directive holds %q, want KEY=VALUE", pair)
		}
	}
	return pairs, nil
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
