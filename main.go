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

// Command govulncheck-apply reads a `govulncheck -json` stream on stdin and
// applies the identified fixes to the `go.mod`s in your working directory.
//
//	govulncheck -json ./... | go tool github.com/netflix-skunkworks/govulncheck-apply
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"slices"
	"strings"

	"golang.org/x/mod/semver"
)

func main() {
	fixes, err := parse(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := apply(fixes); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// parse reads a `govulncheck -json` stream and returns, per module, the version
// to upgrade to. It fixes only called vulnerabilities — govulncheck traces those
// to an invoked symbol, so trace[0] carries a Function — and skips the standard
// library, whose fix is a go-directive bump, not a `go get`.
func parse(r io.Reader) (map[string]string, error) {
	dec := json.NewDecoder(r)
	fixes := map[string]string{}
	decoded := false
	for {
		var msg message
		switch err := dec.Decode(&msg); err {
		case nil:
		case io.EOF:
			return fixes, nil
		default:
			// A failure before anything decoded almost always means the input
			// isn't the JSON stream at all (e.g. `-json` was forgotten).
			if decoded {
				return nil, err
			}
			return nil, fmt.Errorf("input could not be parsed. did you pass `govulncheck -json` output to this program? the error was: %w", err)
		}
		decoded = true

		f := msg.Finding
		if f == nil || len(f.Trace) == 0 {
			continue
		}
		vuln := f.Trace[0]
		if vuln.Function == "" || vuln.Module == "stdlib" || f.FixedVersion == "" {
			continue
		}
		// A module can have several called vulns with different fixes; the
		// highest fix covers them all.
		if semver.Compare(f.FixedVersion, fixes[vuln.Module]) > 0 {
			fixes[vuln.Module] = f.FixedVersion
		}
	}
}

func apply(fixes map[string]string) error {
	if len(fixes) == 0 {
		return nil
	}
	var modules []string
	for _, mod := range slices.Sorted(maps.Keys(fixes)) {
		modules = append(modules, mod+"@"+fixes[mod])
	}
	if err := goGet(modules...); err != nil {
		return err
	}
	return goModTidy()
}

// goGet upgrades every module@version spec in a single invocation, so the
// module graph is resolved once.
func goGet(modules ...string) error {
	return run(exec.Command("go", append([]string{"get"}, modules...)...))
}

func goModTidy() error {
	return run(exec.Command("go", "mod", "tidy"))
}

// run executes cmd, surfacing its output on stderr.
func run(cmd *exec.Cmd) error {
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w", strings.Join(cmd.Args, " "), err)
	}
	return nil
}
