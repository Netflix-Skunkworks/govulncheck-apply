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

// Command repro sets up a testcases/*.txtar scenario in a temp directory so you
// can run govulncheck-apply against it by hand, outside the test harness.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/tools/txtar"

	"github.com/netflix-skunkworks/govulncheck-apply/internal"
)

var testcase = flag.String("testcase", "", "`name` of the scenario under internal/testcases, e.g. vuln_xtext")

func main() {
	flag.Parse()
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if *testcase == "" {
		return errors.New("no -testcase passed")
	}
	base := filepath.Join("internal", "testcases", *testcase)

	// txtar.ParseFile's error already names the file it could not read.
	archive, err := txtar.ParseFile(base + ".txtar")
	if err != nil {
		return err
	}
	dbArchive, err := txtar.ParseFile(base + ".db.txtar")
	if err != nil {
		return err
	}

	dir, err := os.MkdirTemp("", "repro-"+*testcase+"-")
	if err != nil {
		return err
	}

	// The harness's want_ expectations are not part of the scenario, and would
	// otherwise be left lying in the repository being scanned.
	archive.Files = slices.DeleteFunc(archive.Files, func(f txtar.File) bool {
		return strings.HasPrefix(f.Name, "want_")
	})
	if err := extract(archive, dir); err != nil {
		return fmt.Errorf("extract repo: %v", err)
	}
	db := filepath.Join(dir, "govulncheck-db")
	if err := extract(dbArchive, db); err != nil {
		return fmt.Errorf("extract db: %v", err)
	}

	// govulncheck-apply has to be a binary because it can't be `go run` from
	// inside the scenario's module. It installs its own govulncheck.
	if err := runGo([]string{"GOTOOLCHAIN=local"}, "build", "-o", filepath.Join(dir, "govulncheck-apply"), "github.com/netflix-skunkworks/govulncheck-apply"); err != nil {
		return err
	}

	d, err := internal.Directives(archive.Comment)
	if err != nil {
		return fmt.Errorf("%s.txtar: %v", *testcase, err)
	}
	if desc := internal.Description(archive.Comment); desc != "" {
		fmt.Printf("\n%s\n", desc)
	}
	// The toolchain comes from the same place the harness gets it, so that the
	// scenario reproduces under the toolchain the case is tested with.
	fmt.Printf(`
Scenario ready at %[1]s

  cd %[1]s
  GOTOOLCHAIN=%[2]s ./govulncheck-apply -db file://%[3]s
`, dir, internal.Toolchain(d), db)
	return nil
}

func extract(archive *txtar.Archive, dir string) error {
	fsys, err := txtar.FS(archive)
	if err != nil {
		return err
	}
	return os.CopyFS(dir, fsys)
}

// runGo runs `go args...` with extra environment, streaming output to stderr.
func runGo(env []string, args ...string) error {
	cmd := exec.Command("go", args...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("go %s: %v", strings.Join(args, " "), err)
	}
	return nil
}
