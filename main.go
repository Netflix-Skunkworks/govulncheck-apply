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

// Command govulncheck-apply runs govulncheck over the modules under the working
// directory and applies the fixes it reports. Each module is rescanned until a
// pass leaves its go.mod and go.sum alone, because the version a fix selects can
// itself be vulnerable.
//
//	go install github.com/netflix-skunkworks/govulncheck-apply@latest
//	govulncheck-apply
//
// A summary of the OSV ids it fixed, and of those it had to leave, is printed to
// stdout as JSON.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
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
	dirs, err := modules(".")
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
	var report summary
	for _, dir := range dirs {
		report.Modules = append(report.Modules, remediateModule(dir, govulncheck, *dbURL))
	}

	// If there is a `go.work`, then run `go work use` to bump its `go`
	// directive to whatever the `go.mod`s use after apply the remediations.
	workUse := goWorkUse()

	out := json.NewEncoder(os.Stdout)
	out.SetIndent("", "  ")
	if err := out.Encode(report); err != nil {
		return err
	}
	return workUse
}

// summary is what govulncheck-apply prints on stdout for whatever reports the
// run, such as a pull request description or a build log.
type summary struct {
	Modules []moduleSummary `json:"modules"`
}

// moduleSummary is one module's outcome. A module that could not be scanned, or
// that never settled, carries an error and no ids: a run that stopped partway
// cannot say which ids it fixed.
type moduleSummary struct {
	Dir     string    `json:"dir"`
	Fixed   []string  `json:"fixed,omitempty"`
	Unfixed []unfixed `json:"unfixed,omitempty"`
	Error   string    `json:"error,omitempty"`
}

// unfixed is a vulnerability the last pass reported and could not clear.
type unfixed struct {
	OSV    string `json:"osv"`
	Reason string `json:"reason"`
}

// The reasons a vulnerability can be left behind: either the database publishes
// no fixed version, or raising the requirement to it did not shake the
// vulnerable version out of the build list, which usually means a replace
// directive is holding it there.
const (
	noFix       = "no fix published"
	fixNotTaken = "fix did not take"
)

// remediateModule scans the module in dir with govulncheck and applies the
// fixes it identifies. It does so iteratively until a pass leaves go.mod and
// go.sum alone.
//
// A module still changing after maxPasses is reported as an error.
func remediateModule(dir, govulncheck, db string) moduleSummary {
	result := moduleSummary{Dir: filepath.ToSlash(dir)}
	seen := map[string]bool{}
	before, err := modFiles(dir)
	if err != nil {
		return result.withError(err)
	}
	for range maxPasses {
		fix, reported, err := scan(dir, govulncheck, db)
		if err != nil {
			return result.withError(err)
		}
		for osv := range reported {
			seen[osv] = true
		}
		if err := apply(dir, fix); err != nil {
			return result.withError(err)
		}
		after, err := modFiles(dir)
		if err != nil {
			return result.withError(err)
		}
		if bytes.Equal(before, after) {
			result.Fixed, result.Unfixed = classify(seen, reported)
			return result
		}
		before = after
	}
	return result.withError(fmt.Errorf("still changing after %d passes", maxPasses))
}

// classify sorts every OSV id a module's passes reported into the ones the last
// pass no longer reported and the ones it could not clear. seen is every id
// reported at all; remaining maps the ids the last pass still reported to whether
// the database publishes a fix for them.
func classify(seen, remaining map[string]bool) ([]string, []unfixed) {
	var fixed []string
	var left []unfixed
	for _, osv := range slices.Sorted(maps.Keys(seen)) {
		fixable, stillReported := remaining[osv]
		switch {
		case !stillReported:
			fixed = append(fixed, osv)
		case fixable:
			left = append(left, unfixed{OSV: osv, Reason: fixNotTaken})
		default:
			left = append(left, unfixed{OSV: osv, Reason: noFix})
		}
	}
	return fixed, left
}

// withError records why a module was given up on. One module that cannot be
// remediated must not stop the others, so this is reported rather than returned.
func (m moduleSummary) withError(err error) moduleSummary {
	fmt.Fprintf(os.Stderr, "giving up on %s: %v\n", m.Dir, err)
	m.Error = err.Error()
	return m
}

// modules lists the directories under root holding a go.mod, outermost first.
// vendor and testdata are skipped, along with the dotted and underscored
// directories the go command ignores.
func modules(root string) ([]string, error) {
	var dirs []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			if d.Name() == "go.mod" {
				dirs = append(dirs, filepath.Dir(path))
			}
			return nil
		}
		name := d.Name()
		skip := name == "vendor" || name == "testdata" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")
		// root is always walked.
		if path != root && skip {
			return fs.SkipDir
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// A directory sorts before everything under it, so this puts each module
	// ahead of the modules nested in it, and keeps the summary's order stable.
	slices.Sort(dirs)
	return dirs, nil
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
