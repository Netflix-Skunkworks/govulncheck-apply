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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/version"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/mod/semver"
)

// govulncheckPkg is pinned so that a govulncheck release cannot change how a
// repository is analyzed without a change here first. What the database reports
// still moves on its own.
const govulncheckPkg = "golang.org/x/vuln/cmd/govulncheck@v1.6.0"

func installGovulncheck(bin string, dirs []string) (string, error) {
	highest, err := highestGoDirective(dirs)
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

// highestGoDirective returns the highest go directive of the modules in dirs, or
// "" if none of them declares one.
func highestGoDirective(dirs []string) (string, error) {
	var highest string
	for _, dir := range dirs {
		mod, err := readGoMod(dir)
		if err != nil {
			return "", err
		}
		if mod.Go != nil && higher(mod.Go.Version, highest) {
			highest = mod.Go.Version
		}
	}
	return highest, nil
}

// toolchain returns the GOTOOLCHAIN to build govulncheck under, given the
// highest go directive to be scanned and the local Go version. govulncheck
// type-checks with the go/types compiled into it, so it has to be built by a
// toolchain at least as new as the highest go directive it will scan. Every
// answer is a +auto floor rather than a pin, leaving the go command free to
// upgrade past it for govulncheck's own go directive. A floor at or below the
// local Go version names the local toolchain, which already scans every module
// here; naming its version instead would only fetch a second copy of it.
func toolchain(highest, local string) string {
	if highest == "" || !higher(highest, local) {
		return "local+auto"
	}
	return "go" + fullVersion(highest) + "+auto"
}

// localGoVersion returns the version of the toolchain bundled with the go
// command on PATH, e.g. "1.26.0". GOTOOLCHAIN=local keeps the answer from being
// whatever version an ambient setting or a go directive would switch to instead.
func localGoVersion() (string, error) {
	cmd := exec.Command("go", "env", "GOVERSION")
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("go env GOVERSION: %v", err)
	}
	return strings.TrimPrefix(strings.TrimSpace(out.String()), "go"), nil
}

// higher reports whether Go version a is above b, each written as a go directive
// writes it, e.g. "1.26" or "1.26.0". The prefix makes them the toolchain names
// go/version compares, which orders a release candidate correctly where semver
// reads it as invalid and so as lower than everything.
func higher(a, b string) bool {
	return version.Compare("go"+a, "go"+b) > 0
}

// fullVersion gives a Go version all three components, which is the only form
// GOTOOLCHAIN accepts: there is no toolchain named go1.26 to fetch.
func fullVersion(v string) string {
	if strings.Count(v, ".") == 1 {
		return v + ".0"
	}
	return v
}

// scan runs govulncheck over the module in dir, against the vulnerability
// database at db, or govulncheck's own default if db is empty. It returns the
// fixes reported, and what was reported about each advisory, keyed by OSV id.
func scan(dir, govulncheck, db string) (fixes, map[string]vuln, error) {
	// Pass -test so that a vulnerability only a test reaches is still reported.
	args := []string{"-test", "-json"}
	if db != "" {
		args = append(args, "-db", db)
	}
	cmd := exec.Command(govulncheck, append(args, "./...")...)
	cmd.Dir = dir
	// go.work.sum holds hashes that are not in the workspace modules' own go.sum
	// files, and GOWORK=off does not consult it, so loading the packages fails
	// without -mod=mod to let the go command write the hashes it needs.
	// govulncheck is not a go subcommand, so GOFLAGS is the only way to reach it.
	cmd.Env = append(goEnv(), "GOFLAGS=-mod=mod")
	cmd.Stderr = os.Stderr
	// With -json, govulncheck exits 0 whether or not it found anything, so a
	// failure here means it could not load the packages.
	out, err := cmd.Output()
	if err != nil {
		return fixes{}, nil, fmt.Errorf("govulncheck: %v", err)
	}
	return parse(bytes.NewReader(out))
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
		// Only the package and called-function granularities name a package, and
		// the module-granularity finding can arrive first.
		if v.pkg == "" {
			v.pkg = vulnerable.Package
		}
		// Only the called-function granularity carries a trace worth rendering, and
		// one example of it is enough, as in govulncheck's own report.
		if len(f.Trace) > 1 && v.trace == nil {
			v.trace = f.Trace
		}
		if vulnerable.Module == "" || f.FixedVersion == "" {
			continue
		}
		// A module can have several vulns with different fixes; keep the highest.
		if vulnerable.Module == stdlib {
			if semver.Compare(f.FixedVersion, fix.goVersion) > 0 {
				fix.goVersion = f.FixedVersion
			}
		} else if semver.Compare(f.FixedVersion, fix.modules[vulnerable.Module]) > 0 {
			fix.modules[vulnerable.Module] = f.FixedVersion
		}
	}
}

// merge folds each advisory's own prose and link into what was reported about it.
// The two arrive in either order, which is why they are collected apart and only
// brought together once the stream ends.
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
