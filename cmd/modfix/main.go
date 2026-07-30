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

// Command modfix runs govulncheck over the modules under the working directory
// and applies the fixes it reports. Each module is rescanned until a pass leaves
// its go.mod and go.sum alone, because the version a fix selects can itself be
// vulnerable.
//
//	go install github.com/netflix-skunkworks/govulncheck-apply/cmd/modfix@latest
//	modfix
//
// What it found and what became of each advisory is printed to stdout as one
// markdown table, ready to carry into a pull request description. Nothing is
// printed when there was nothing to report.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"

	"github.com/netflix-skunkworks/govulncheck-apply/internal/gomod"
)

// When we bump a version to fix a CVE, the new version may itself have a CVE
// that needs another version bump. So, we need to iteratively scan and bump.
// This is the number of iterations we're willing to do before we break out.
const maxPasses = 5

var dbURL = flag.String("db", "", "vulnerability database `url` for govulncheck to scan against, e.g. file:///tmp/db. Defaults to govulncheck's own default, https://vuln.go.dev")

func main() {
	flag.Parse()
	if err := remediate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func remediate() error {
	dirs, err := gomod.Modules(".")
	if err != nil {
		return err
	}
	if len(dirs) == 0 {
		return errors.New("no go.mod found anywhere under the working directory")
	}

	// We install govulncheck ourselves so that we can control the version. It
	// has to be built at a version >= the Go mod directive it tests. Since we
	// bump the Go directive, the govulncheck version that may already exist on
	// the host machine may no longer be valid.
	//
	// We also don't want to add govulncheck to the `go.mod` and manage it that
	// way, since it's not really this program's job to add tools that the user
	// has to manage.
	//
	// So all in, we install it ourselves, but to a tmpdir.
	bin, err := os.MkdirTemp("", "govulncheck-apply-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(bin) }()
	govulncheck, err := installGovulncheck(bin, dirs)
	if err != nil {
		return err
	}

	// Search for an apply fixes. Record fixes as we go, so that we can report
	// them to the user.
	var modules []moduleReport
	for _, dir := range dirs {
		modules = append(modules, remediateModule(dir, govulncheck, *dbURL))
	}

	// If there is a `go.work`, then run `go work use` to bump its `go`
	// directive to whatever the `go.mod`s use after apply the remediations.
	//
	// Its failure is returned only after the report is written: the fixes are on
	// disk either way, and whatever reports the run has to know what landed.
	workUse := goWorkUse()

	if err := report(os.Stdout, modules); err != nil {
		return err
	}
	return workUse
}

// remediateModule scans the module in dir with govulncheck and applies the
// fixes it identifies. It does so iteratively until a pass leaves go.mod and
// go.sum alone.
//
// A module still changing after maxPasses is reported as an error.
func remediateModule(dir, govulncheck, db string) moduleReport {
	result := moduleReport{dir: filepath.ToSlash(dir)}
	// A fix can introduce a vulnerability of its own, so the report covers every
	// advisory any pass reported, described as the pass that first saw it did.
	seen := map[string]vuln{}
	before, err := modFiles(dir)
	if err != nil {
		return result.withError(err)
	}
	for range maxPasses {
		fix, reported, err := scan(dir, govulncheck, db)
		if err != nil {
			return result.withError(err)
		}
		for osv, v := range reported {
			if _, ok := seen[osv]; !ok {
				seen[osv] = v
			}
		}
		if err := apply(dir, fix); err != nil {
			return result.withError(err)
		}
		after, err := modFiles(dir)
		if err != nil {
			return result.withError(err)
		}
		if bytes.Equal(before, after) {
			selected, err := selectedVersions(dir)
			if err != nil {
				return result.withError(err)
			}
			result.vulns = classify(seen, reported, selected)
			return result
		}
		before = after
	}
	return result.withError(fmt.Errorf("still changing after %d passes", maxPasses))
}

// classify returns every advisory a module's passes reported, in id order, each
// marked with whether the last pass reported it again and with the version of the
// vulnerable module the run settled on. That, with the version that fixes it, is
// everything the report needs to say what became of it.
func classify(seen, remaining map[string]vuln, selected map[string]string) []vuln {
	var out []vuln
	for _, osv := range slices.Sorted(maps.Keys(seen)) {
		v := seen[osv]
		_, v.stillReported = remaining[osv]
		v.selected = selected[v.module]
		out = append(out, v)
	}
	return out
}

// selectedVersions reads back what the module now requires of each module it
// names, keyed the way a finding names it. The go directive is the standard
// library's version, and govulncheck reports that one as a semver.
func selectedVersions(dir string) (map[string]string, error) {
	mod, err := gomod.Read(dir)
	if err != nil {
		return nil, err
	}
	selected := make(map[string]string, len(mod.Require)+1)
	for _, r := range mod.Require {
		selected[r.Mod.Path] = r.Mod.Version
	}
	if mod.Go != nil {
		selected[stdlib] = "v" + mod.Go.Version
	}
	return selected, nil
}

// modFiles returns the files a pass can change that the next scan reads, so that
// a pass which changes none of them ends the rescanning.
func modFiles(dir string) ([]byte, error) {
	var out []byte
	for _, name := range []string{"go.mod", "go.sum"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		out = append(out, data...)
	}
	return out, nil
}

// goWorkUse raises go.work's own go directive to match the modules it uses.
// Scanning with GOWORK=off keeps a raised go directive out of go.work, which can
// leave go.work below the modules it uses, and every workspace-mode command then
// fails with "requires go >= ...".
func goWorkUse() error {
	if _, err := os.Stat("go.work"); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	return run(exec.Command("go", "work", "use"))
}
