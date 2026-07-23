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
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/tools/txtar"
)

// govulncheck is pinned to the same version the test harness scans with.
const govulncheck = "golang.org/x/vuln/cmd/govulncheck@v1.6.0"

var testcase = flag.String("testcase", "", "ex: vuln_xtext")

func main() {
	flag.Parse()
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if *testcase == "" {
		return fmt.Errorf("no --testcase passed")
	}
	base := filepath.Join("internal", "testcases", *testcase)

	archive, err := txtar.ParseFile(base + ".txtar")
	if err != nil {
		return fmt.Errorf("parse %s.txtar: %w", *testcase, err)
	}
	dbArchive, err := txtar.ParseFile(base + ".db.txtar")
	if err != nil {
		return fmt.Errorf("parse %s.db.txtar: %w", *testcase, err)
	}

	dir, err := os.MkdirTemp("", "repro-"+*testcase+"-")
	if err != nil {
		return err
	}

	// want_diff.txt is the harness's expected output, not part of the scenario.
	archive.Files = slices.DeleteFunc(archive.Files, func(f txtar.File) bool {
		return f.Name == "want_diff.txt"
	})
	if err := extract(archive, dir); err != nil {
		return fmt.Errorf("extract repo: %w", err)
	}
	db := filepath.Join(dir, "govulncheck-db")
	if err := extract(dbArchive, db); err != nil {
		return fmt.Errorf("extract db: %w", err)
	}

	// Prebuild both tools into dir. govulncheck is built with the local
	// toolchain so a pinned GOTOOLCHAIN applies only to the stdlib analysis, not
	// to building govulncheck itself (which needs a recent Go). The applier must
	// be a binary because it can't be `go run` from inside the scenario's module.
	if err := goTool([]string{"GOTOOLCHAIN=local"}, "build", "-o", filepath.Join(dir, "govulncheck-apply"), "github.com/netflix-skunkworks/govulncheck-apply"); err != nil {
		return err
	}
	if err := goTool([]string{"GOTOOLCHAIN=local", "GOFLAGS=", "GOBIN=" + dir}, "install", govulncheck); err != nil {
		return err
	}

	d := directives(archive.Comment)
	var toolchain string
	if gt := d["gotoolchain"]; gt != "" {
		toolchain = "GOTOOLCHAIN=" + gt + " "
	}
	if desc := d["description"]; desc != "" {
		fmt.Printf("\n%s: %s\n", *testcase, desc)
	}
	fmt.Printf(`
Scenario ready at %[1]s

  cd %[1]s
  %[2]s./govulncheck -db file://%[3]s -json ./... | ./govulncheck-apply
`, dir, toolchain, db)
	return nil
}

func extract(archive *txtar.Archive, dir string) error {
	fsys, err := txtar.FS(archive)
	if err != nil {
		return err
	}
	return os.CopyFS(dir, fsys)
}

// directives parses the leading "key: value" lines of a txtar comment, matching
// the test harness. Parsing stops at the first blank or non-directive line.
func directives(comment []byte) map[string]string {
	m := map[string]string{}
	for line := range strings.SplitSeq(string(comment), "\n") {
		key, val, ok := strings.Cut(line, ":")
		if !ok || strings.ContainsAny(strings.TrimSpace(key), " \t") {
			break
		}
		m[strings.TrimSpace(key)] = strings.TrimSpace(val)
	}
	return m
}

// goTool runs `go args...` with extra environment, streaming output to stderr.
func goTool(env []string, args ...string) error {
	cmd := exec.Command("go", args...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("go %s: %w", strings.Join(args, " "), err)
	}
	return nil
}
