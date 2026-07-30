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
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/netflix-skunkworks/govulncheck-apply/internal/gomod"
)

// fixes is a remediation: the version to upgrade each module to, and the go
// directive to bump to for standard-library vulns (whose only fix is a newer
// toolchain).
type fixes struct {
	modules   map[string]string // module path -> fixed version
	goVersion string            // fixed version for stdlib vulns, e.g. "v1.21.9"
}

func apply(dir string, fix fixes) error {
	if len(fix.modules) == 0 && fix.goVersion == "" {
		return nil
	}
	if fix.goVersion != "" {
		// govulncheck reports stdlib fixes as e.g. "v1.21.9"; the go directive
		// wants "1.21.9".
		if err := goModEditGo(dir, strings.TrimPrefix(fix.goVersion, "v")); err != nil {
			return err
		}
	}
	if len(fix.modules) > 0 {
		if err := requireModules(dir, fix.modules); err != nil {
			return err
		}
		if err := bumpReplacedModules(dir, fix.modules); err != nil {
			return err
		}
	}
	if err := run(goCmd(dir, "mod", "tidy")); err != nil {
		return err
	}
	return goModVendor(dir)
}

// requireModules raises the minimum required version of each module to the
// version that fixes it. A require directive is a minimum, so MVS selects the
// higher of that and whatever the rest of the graph already requires.
func requireModules(dir string, fixed map[string]string) error {
	args := []string{"mod", "edit"}
	for _, path := range slices.Sorted(maps.Keys(fixed)) {
		args = append(args, "-require="+path+"@"+fixed[path])
	}
	return run(goCmd(dir, args...))
}

// goModVendor re-syncs the vendor directory, if there is one. `go mod tidy`
// leaves it alone, and a vendor directory that disagrees with go.mod fails every
// later go command with "inconsistent vendoring". The go command keys vendoring
// off vendor/modules.txt, so that file is what decides whether to re-run.
func goModVendor(dir string) error {
	if _, err := os.Stat(filepath.Join(dir, "vendor", "modules.txt")); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return run(goCmd(dir, "mod", "vendor"))
}

// goModEditGo bumps the go directive to version (e.g. "1.21.9"), dropping any
// toolchain directive left below it, which the go command rejects. Both go in one
// edit: a run interrupted between two of them would leave behind a go.mod that no
// go command will touch, not even to repair it.
func goModEditGo(dir, version string) error {
	mod, err := gomod.Read(dir)
	if err != nil {
		return err
	}
	args := []string{"mod", "edit", "-go=" + version}
	if mod.Toolchain != nil && gomod.Higher(version, strings.TrimPrefix(mod.Toolchain.Name, "go")) {
		args = append(args, "-toolchain=none")
	}
	return run(goCmd(dir, args...))
}

// bumpReplacedModules raises the version of each replacement that points at the
// same module path, leaving forks and local-path replaces alone. They are raised
// in one edit, so an interrupted run cannot leave some of them behind.
func bumpReplacedModules(dir string, fixed map[string]string) error {
	mod, err := gomod.Read(dir)
	if err != nil {
		return err
	}
	var edits []string
	for _, r := range mod.Replace {
		v, ok := fixed[r.Old.Path]
		if !ok || r.New.Path != r.Old.Path || r.New.Version == "" {
			continue
		}
		edits = append(edits, "-replace="+r.Old.String()+"="+r.New.Path+"@"+v)
	}
	if len(edits) == 0 {
		return nil
	}
	return run(goCmd(dir, append([]string{"mod", "edit"}, edits...)...))
}

func goCmd(dir string, args ...string) *exec.Cmd {
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	cmd.Env = goEnv()
	return cmd
}

// goEnv returns the environment every scan and go command here runs under. A
// workspace's modules are all main modules sharing one build list, so a module
// requiring a vulnerable version is scanned against the higher version a sibling
// requires and its vulnerability is never reported. GOWORK=off drops the
// workspace, leaving each module the only main module, with its own build list.
func goEnv() []string {
	return append(os.Environ(), "GOWORK=off")
}

// run executes cmd, surfacing its output on stderr.
func run(cmd *exec.Cmd) error {
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %v", strings.Join(cmd.Args, " "), err)
	}
	return nil
}
