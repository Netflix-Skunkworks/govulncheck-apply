// Copyright 2026 Netflix, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

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
// version that fixes it.
func requireModules(dir string, fixed map[string]string) error {
	args := []string{"mod", "edit"}
	for _, path := range slices.Sorted(maps.Keys(fixed)) {
		args = append(args, "-require="+path+"@"+fixed[path])
	}
	return run(goCmd(dir, args...))
}

// goModVendor re-syncs the vendor directory, if there is one.
func goModVendor(dir string) error {
	if _, err := os.Stat(filepath.Join(dir, "vendor", "modules.txt")); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return run(goCmd(dir, "mod", "vendor"))
}

// goModEditGo bumps the go directive to version (e.g. "1.21.9").
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
// same module path.
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
