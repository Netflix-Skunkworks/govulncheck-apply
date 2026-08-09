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

// Command repro sets up one of modfix's testcases/*.txtar scenarios in a temp
// directory so you can run the commands against it by hand, outside the test
// harness. Run it from the root of the repository.
//
// dockerfilefix's own scenarios are not set up here: they carry no vulnerability
// database and reproduce by hand in a couple of files.
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

var testcase = flag.String("testcase", "", "`name` of the scenario under cmd/modfix/testcases, e.g. vuln_xtext")

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
	base := filepath.Join("cmd", "modfix", "testcases", *testcase)

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

	// The commands have to be binaries because they can't be `go run` from inside
	// the scenario's module. modfix installs its own govulncheck.
	err = runGo([]string{"GOTOOLCHAIN=local"}, "build", "-o", dir,
		"github.com/netflix-skunkworks/govulncheck-apply/cmd/modfix",
		"github.com/netflix-skunkworks/govulncheck-apply/cmd/dockerfilefix")
	if err != nil {
		return err
	}

	d, err := internal.Directives(archive.Comment)
	if err != nil {
		return fmt.Errorf("%s.txtar: %v", *testcase, err)
	}
	if desc := internal.Description(archive.Comment); desc != "" {
		fmt.Printf("\n%s\n", desc)
	}
	// The toolchain and the environment come from the same place the harness
	// gets them, so that the scenario reproduces the way it is tested.
	caseEnv, err := internal.Env(d)
	if err != nil {
		return fmt.Errorf("%s.txtar: %v", *testcase, err)
	}
	env := append([]string{"GOTOOLCHAIN=" + internal.Toolchain(d)}, caseEnv...)
	fmt.Printf(`
Scenario ready at %[1]s

  cd %[1]s
  %[2]s ./modfix -db file://%[3]s
  ./dockerfilefix
`, dir, strings.Join(env, " "), db)
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
