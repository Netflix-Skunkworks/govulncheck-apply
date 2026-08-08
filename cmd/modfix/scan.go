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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/mod/semver"

	"github.com/netflix-skunkworks/govulncheck-apply/internal/gomod"
)

// govulncheckPkg is pinned so that a govulncheck release cannot change how a
// repository is analyzed without a change here first. What the database reports
// still moves on its own.
const govulncheckPkg = "golang.org/x/vuln/cmd/govulncheck@v1.6.0"

func installGovulncheck(bin string, dirs []string) (string, error) {
	highest, err := gomod.HighestGoDirective(dirs)
	if err != nil {
		return "", err
	}
	local, err := localGoVersion()
	if err != nil {
		return "", err
	}

	cmd := exec.Command("go", "install", govulncheckPkg)
	// GOFLAGS is cleared because `go install pkg@version` rejects the -mod that
	// the scan sets, and a repository is free to set it too.
	cmd.Env = append(os.Environ(), "GOBIN="+bin, "GOFLAGS=", "GOTOOLCHAIN="+toolchain(highest, local))
	if err := run(cmd); err != nil {
		return "", err
	}
	return filepath.Join(bin, "govulncheck"), nil
}

// toolchain returns the GOTOOLCHAIN to build govulncheck under, given the
// highest go directive to be scanned and the local Go version.
func toolchain(highest, local string) string {
	if highest == "" || !gomod.Higher(highest, local) {
		return "local+auto"
	}
	return "go" + gomod.FullVersion(highest) + "+auto"
}

// localGoVersion returns the version of the toolchain bundled with the go
// command on PATH, e.g. "1.26.0". GOTOOLCHAIN=local keeps the answer from being
// whatever version an ambient setting or a go directive would switch to
// instead.
func localGoVersion() (string, error) {
	cmd := exec.Command("go", "env", "GOVERSION")
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, os.Stderr
	announce(cmd)
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s: %v", commandLine(cmd), err)
	}
	return strings.TrimPrefix(strings.TrimSpace(out.String()), "go"), nil
}

// scan runs govulncheck over the module in dir, against the vulnerability
// database at db, or govulncheck's own default if db is empty. It returns the
// fixes reported, and what was reported about each advisory, keyed by OSV id.
func scan(dir, govulncheck, db string) (fixes, map[string]vuln, error) {
	// Scanning at package rather than symbol granularity, because a fix is worth
	// applying whether or not the vulnerable function is called, and because the
	// symbol granularity is the only one that type-checks the module. Type
	// checking pulls in a C toolchain and every system header any cgo dependency
	// expects, and fails the whole module when one is missing or when a
	// dependency does not compile.
	//
	// Pass -test so that a vulnerability only a test reaches is still reported.
	args := []string{"-scan", "package", "-test", "-json"}
	if db != "" {
		args = append(args, "-db", db)
	}
	cmd := exec.Command(govulncheck, append(args, "./...")...)
	cmd.Dir = dir
	// go.work.sum holds hashes that are not in the workspace modules' own
	// go.sum files, and GOWORK=off does not consult it, so loading the packages
	// fails without -mod=mod to let the go command write the hashes it needs.
	// govulncheck is not a go subcommand, so GOFLAGS is the only way to reach
	// it.
	cmd.Env = append(goEnv(), "GOFLAGS=-mod=mod")
	cmd.Stderr = os.Stderr
	announce(cmd)
	// With -json, govulncheck exits 0 whether or not it found anything, so a
	// failure here is either a module it could not load or one that held no
	// package to load in the first place.
	out, err := cmd.Output()
	if err != nil {
		// It's possible that we just scanned a dir tree with no Go packages. If
		// so, govulncheck will err: but we don't care about those errors. So we
		// ignore those. (Unfortunately govulncheck doesn't expose that error so
		// we have to infer it ourselves)
		empty, listErr := noPackages(dir)
		if listErr != nil {
			return fixes{}, nil, listErr
		}
		if !empty {
			return fixes{}, nil, fmt.Errorf("%s: %v", commandLine(cmd), err)
		}
		// Returning rather than falling through: the scan did not run, so its
		// output holds nothing to find.
		fmt.Fprintf(os.Stderr, "No package in %q to scan; nothing to fix.\n", filepath.ToSlash(dir))
		return fixes{}, nil, nil
	}
	return parse(bytes.NewReader(out))
}

func noPackages(dir string) (bool, error) {
	cmd := goCmd(dir, "list", "./...")
	// The same -mod as the scan: without it the go command stops to complain
	// that go.mod needs updating, for the workspace modules whose requirements
	// only go.work.sum was supplying.
	cmd.Env = append(cmd.Env, "GOFLAGS=-mod=mod")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, os.Stderr
	announce(cmd)
	if err := cmd.Run(); err != nil {
		return false, fmt.Errorf("%s: %v", commandLine(cmd), err)
	}
	return strings.TrimSpace(out.String()) == "", nil
}

// parse reads a `govulncheck -json` stream.
func parse(r io.Reader) (fixes, map[string]vuln, error) {
	dec := json.NewDecoder(r)
	fix := fixes{modules: map[string]string{}}
	reported := map[string]*vuln{}
	advisories := map[string]*osv{}
	for {
		var msg message
		err := dec.Decode(&msg)
		if errors.Is(err, io.EOF) {
			return fix, merge(reported, advisories), nil
		}
		if err != nil {
			return fixes{}, nil, err
		}
		if msg.OSV != nil {
			advisories[msg.OSV.ID] = msg.OSV
		}

		f := msg.Finding
		if f == nil || len(f.Trace) == 0 {
			continue
		}
		vulnerable := f.Trace[0]
		v := reported[f.OSV]
		if v == nil {
			v = &vuln{osv: f.OSV, module: vulnerable.Module, found: vulnerable.Version}
			reported[f.OSV] = v
		}
		if f.FixedVersion != "" {
			v.fixedIn = f.FixedVersion
		}
		// Only the package granularity names a package, and the
		// module-granularity finding can arrive first.
		if v.pkg == "" {
			v.pkg = vulnerable.Package
		}
		if vulnerable.Module == "" || f.FixedVersion == "" {
			continue
		}
		// A module can have several vulns with different fixes; keep the
		// highest.
		if vulnerable.Module == stdlib {
			if semver.Compare(f.FixedVersion, fix.goVersion) > 0 {
				fix.goVersion = f.FixedVersion
			}
		} else if semver.Compare(f.FixedVersion, fix.modules[vulnerable.Module]) > 0 {
			fix.modules[vulnerable.Module] = f.FixedVersion
		}
	}
}

// merge folds each advisory's own prose and link into what was reported about
// it. The two arrive in either order, which is why they are collected apart and
// only brought together once the stream ends.
func merge(reported map[string]*vuln, advisories map[string]*osv) map[string]vuln {
	out := make(map[string]vuln, len(reported))
	for id, v := range reported {
		if a := advisories[id]; a != nil {
			v.summary = a.Summary
			v.url = a.DatabaseSpecific.URL
		}
		out[id] = *v
	}
	return out
}
