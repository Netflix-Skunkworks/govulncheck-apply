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
		if err := goWorkUse(); err != nil {
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

// goWorkUse raises go.work's own go directive to match the modules it uses.
func goWorkUse() error {
	if _, err := os.Stat("go.work"); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return run(exec.Command("go", "work", "use"))
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

// commandLine names cmd, dropping the program's directory so that the
// govulncheck installed into a temporary directory reads as the command it is.
func commandLine(cmd *exec.Cmd) string {
	args := slices.Clone(cmd.Args)
	args[0] = filepath.Base(args[0])
	return strings.Join(args, " ")
}

// announce prints the command about to run, as a line that runs it again. It
// goes to stderr because stdout carries the report.
func announce(cmd *exec.Cmd) {
	var line []string
	if cmd.Dir != "" && cmd.Dir != "." {
		line = append(line, "cd", shellWord(filepath.ToSlash(cmd.Dir)), "&&")
	}
	line = append(line, environment(cmd)...)
	args := slices.Clone(cmd.Args)
	args[0] = filepath.Base(args[0])
	for _, arg := range args {
		line = append(line, shellWord(arg))
	}
	fmt.Fprintln(os.Stderr, "Running:", strings.Join(line, " "))
}

// environment returns the NAME=value assignments cmd carries that this
// program's own environment does not. A name assigned twice takes its last
// value, as exec does.
func environment(cmd *exec.Cmd) []string {
	if cmd.Env == nil {
		return nil
	}
	ambient := map[string]string{}
	for _, assignment := range os.Environ() {
		name, value, _ := strings.Cut(assignment, "=")
		ambient[name] = value
	}
	set := map[string]string{}
	for _, assignment := range cmd.Env {
		name, value, _ := strings.Cut(assignment, "=")
		set[name] = value
	}
	var out []string
	for _, name := range slices.Sorted(maps.Keys(set)) {
		if was, ok := ambient[name]; !ok || was != set[name] {
			out = append(out, name+"="+shellWord(set[name]))
		}
	}
	return out
}

// shellWord quotes s so that a shell reads it as the single word it is here.
func shellWord(s string) string {
	const safe = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@%+=:,./-_"
	unsafe := func(r rune) bool { return !strings.ContainsRune(safe, r) }
	if s == "" || strings.ContainsFunc(s, unsafe) {
		return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
	}
	return s
}

// run announces and executes cmd, surfacing its output on stderr.
func run(cmd *exec.Cmd) error {
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	announce(cmd)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %v", commandLine(cmd), err)
	}
	return nil
}
