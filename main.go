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
//
// Or read the stream from a file, which keeps govulncheck's own exit status:
//
//	govulncheck -json ./... > vulns.json
//	go tool github.com/netflix-skunkworks/govulncheck-apply -f vulns.json
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"slices"
	"strings"

	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

var input = flag.String("f", "", "read the govulncheck -json stream from this `file` instead of stdin. Useful when you want govulncheck's own failures to surface: bash takes a pipeline's exit status from the last command, so piping govulncheck into govulncheck-apply loses a govulncheck failure unless you turn on set -o pipefail, which you may not want over a whole script")

func main() {
	flag.Parse()
	fixes, err := readFixes()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := apply(fixes); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// readFixes parses the stream named by -f, or stdin if the flag is unset.
func readFixes() (fixes, error) {
	if *input == "" {
		return parse(os.Stdin)
	}
	f, err := os.Open(*input)
	if err != nil {
		return fixes{}, err
	}
	defer f.Close()
	return parse(f)
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
		if err := requireModules(fix.modules); err != nil {
			return err
		}
		if err := bumpReplacedModules(fix.modules); err != nil {
			return err
		}
	}
	if err := goModTidy(); err != nil {
		return err
	}
	return goModVendor()
}

// requireModules raises the minimum required version of each module to the
// version that fixes it. A require directive is a minimum, so MVS selects the
// higher of that and whatever the rest of the graph already requires: a module
// another fix carries past its own needs no special handling, and nothing is
// downgraded.
func requireModules(fixed map[string]string) error {
	args := []string{"mod", "edit"}
	for _, mod := range slices.Sorted(maps.Keys(fixed)) {
		args = append(args, "-require="+mod+"@"+fixed[mod])
	}
	return run(exec.Command("go", args...))
}

func goModTidy() error {
	return run(exec.Command("go", "mod", "tidy"))
}

// goModVendor re-syncs the vendor directory, if there is one. `go mod tidy`
// leaves it alone, and a vendor directory that disagrees with go.mod fails every
// later go command with "inconsistent vendoring". The go command keys vendoring
// off vendor/modules.txt, so that file is what decides whether to re-run.
func goModVendor() error {
	if _, err := os.Stat("vendor/modules.txt"); err != nil {
		return nil
	}
	return run(exec.Command("go", "mod", "vendor"))
}

// goModEditGo bumps the go directive to version (e.g. "1.21.9"), then drops any
// toolchain directive left below it (which Go would otherwise ignore or fail on).
func goModEditGo(version string) error {
	if err := run(exec.Command("go", "mod", "edit", "-go="+version)); err != nil {
		return err
	}
	mod, err := readModEdit()
	if err != nil {
		return err
	}
	if mod.Toolchain == "" {
		return nil
	}
	if semver.Compare("v"+strings.TrimPrefix(mod.Toolchain, "go"), "v"+version) < 0 {
		// The toolchain version is less than the Go version: drop it.
		return run(exec.Command("go", "mod", "edit", "-toolchain=none"))
	}
	return nil
}

// bumpReplacedModules updates replace statement versions with the given fixes.
func bumpReplacedModules(fixed map[string]string) error {
	mod, err := readModEdit()
	if err != nil {
		return err
	}
	for _, r := range mod.Replace {
		v, ok := fixed[r.Old.Path]
		if !ok || r.New.Path != r.Old.Path || r.New.Version == "" {
			continue
		}
		replacement := r.Old.String() + "=" + r.New.Path + "@" + v
		if err := run(exec.Command("go", "mod", "edit", "-replace="+replacement)); err != nil {
			return err
		}
	}
	return nil
}

// modEdit is the subset of `go mod edit -json` this tool reads back.
type modEdit struct {
	Toolchain string
	Replace   []replace
}

// replace mirrors one entry of go.mod's replace block.
type replace struct {
	Old module.Version
	New module.Version
}

// readModEdit decodes `go mod edit -json` for the go.mod in the working directory.
func readModEdit() (modEdit, error) {
	out, err := exec.Command("go", "mod", "edit", "-json").Output()
	if err != nil {
		return modEdit{}, fmt.Errorf("go mod edit -json: %w", err)
	}
	var m modEdit
	if err := json.Unmarshal(out, &m); err != nil {
		return modEdit{}, err
	}
	return m, nil
}

// run executes cmd, surfacing its output on stderr.
func run(cmd *exec.Cmd) error {
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w", strings.Join(cmd.Args, " "), err)
	}
	return nil
}
