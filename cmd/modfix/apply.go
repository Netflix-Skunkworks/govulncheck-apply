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
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"

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
	if err := tidy(dir); err != nil {
		return err
	}
	return goModVendor(dir)
}

// tidy runs `go mod tidy`. Where the first run fails only because a module
// carve-out left two modules offering one package, it raises the module the
// package was carved out of and runs tidy again. Tidy drops that require
// directive itself when the second run succeeds, and leaves it when it fails.
func tidy(dir string) error {
	cmd := goCmd(dir, "mod", "tidy")
	var said bytes.Buffer
	both := io.MultiWriter(os.Stderr, &said)
	cmd.Stdout, cmd.Stderr = both, both
	announce(cmd)
	ran := cmd.Run()
	if ran == nil {
		return nil
	}
	err := fmt.Errorf("%s: %v", commandLine(cmd), ran)
	carved := carvedOut(said.String())
	if len(carved) == 0 {
		return err
	}
	if edit := requireModules(dir, carved); edit != nil {
		return edit
	}
	if run(goCmd(dir, "mod", "tidy")) != nil {
		// The ambiguity is the failure to report; the second one is in the log
		// just above it.
		return err
	}
	return nil
}

// carvedOut reads `go mod tidy`'s reports of a package offered by more than one
// module, and returns each module a package was carved out of against the
// version to raise it to. Of the modules offering a package, the one whose path
// the others extend is the one it was carved out of: a nested module takes its
// directory out of the module around it, so versions of the outer module from
// before the carve-out still carry a copy of the package.
//
// The version to raise to is the nested module's own. That names a version of
// the outer module only when it is a pseudo-version, because a pseudo-version
// names a commit and the two modules share a repository. A nested module with
// tags of its own is left alone: its tags are not versions of the outer one.
func carvedOut(said string) map[string]string {
	type offering struct{ path, version string }
	carved := map[string]string{}
	for _, report := range strings.Split(said, "ambiguous import")[1:] {
		var offered []offering
		_, lines, _ := strings.Cut(report, "\n")
		for line := range strings.Lines(lines) {
			// A module of a report prints as "path version (directory)". Only
			// the directory can hold a space, so nothing past its bracket is
			// read.
			head, _, bracketed := strings.Cut(line, " (")
			fields := strings.Fields(head)
			if !bracketed || len(fields) != 2 {
				break
			}
			offered = append(offered, offering{fields[0], fields[1]})
		}
		for _, outer := range offered {
			for _, inner := range offered {
				if !strings.HasPrefix(inner.path, outer.path+"/") || !module.IsPseudoVersion(inner.version) {
					continue
				}
				if semver.Compare(inner.version, carved[outer.path]) > 0 {
					carved[outer.path] = inner.version
				}
			}
		}
	}
	return carved
}

// requireModules raises the minimum required version of each module named.
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

// goEnv returns the environment the module edits and the scan run under.
// GOWORK=off has each module scanned against its own go.mod rather than the
// version a workspace would select. cgo is forced on because it is a build
// constraint before it is anything about compiling: with cgo off a file
// importing "C" leaves the package, taking its other imports with it, so a scan
// misses whatever only those imports reach. The go command turns cgo off
// wherever it finds no C compiler, which is what an image carrying only Go has,
// so its default cannot be relied on. Nothing here compiles, so holding the
// files in costs nothing.
func goEnv() []string {
	return append(os.Environ(), "GOWORK=off", "CGO_ENABLED=1")
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
