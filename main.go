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

// fixes is a remediation: the version to upgrade each module to, and the go
// directive to bump to for standard-library vulns (whose only fix is a newer
// toolchain).
type fixes struct {
	modules   map[string]string // module path -> fixed version
	goVersion string            // fixed version for stdlib vulns, e.g. "v1.21.9"
}

// parse reads a `govulncheck -json` stream and returns the remediation. It fixes
// every reported vulnerability that has a known fix, whether or not the
// vulnerable symbol is actually called.
func parse(r io.Reader) (fixes, error) {
	dec := json.NewDecoder(r)
	fix := fixes{modules: map[string]string{}}
	decoded := false
	for {
		var msg message
		switch err := dec.Decode(&msg); err {
		case nil:
		case io.EOF:
			return fix, nil
		default:
			// A failure before anything decoded almost always means the input
			// isn't the JSON stream at all (e.g. `-json` was forgotten).
			if decoded {
				return fixes{}, err
			}
			return fixes{}, fmt.Errorf("input could not be parsed. did you pass `govulncheck -json` output to this program? the error was: %w", err)
		}
		decoded = true

		f := msg.Finding
		if f == nil || len(f.Trace) == 0 {
			continue
		}
		vuln := f.Trace[0]
		if vuln.Module == "" || f.FixedVersion == "" {
			continue
		}
		// A module can have several vulns with different fixes; keep the highest.
		if vuln.Module == "stdlib" {
			if semver.Compare(f.FixedVersion, fix.goVersion) > 0 {
				fix.goVersion = f.FixedVersion
			}
		} else if semver.Compare(f.FixedVersion, fix.modules[vuln.Module]) > 0 {
			fix.modules[vuln.Module] = f.FixedVersion
		}
	}
}

func apply(fix fixes) error {
	if len(fix.modules) == 0 && fix.goVersion == "" {
		return nil
	}
	if fix.goVersion != "" {
		// govulncheck reports stdlib fixes as e.g. "v1.21.9"; the go directive
		// wants "1.21.9".
		if err := goModEditGo(strings.TrimPrefix(fix.goVersion, "v")); err != nil {
			return err
		}
	}
	if len(fix.modules) > 0 {
		var modules []string
		for _, mod := range slices.Sorted(maps.Keys(fix.modules)) {
			modules = append(modules, mod+"@"+fix.modules[mod])
		}
		if err := goGet(modules...); err != nil {
			return err
		}
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

func goModEditGo(version string) error {
	return run(exec.Command("go", "mod", "edit", "-go="+version))
}

// run executes cmd, surfacing its output on stderr.
func run(cmd *exec.Cmd) error {
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w", strings.Join(cmd.Args, " "), err)
	}
	return nil
}
