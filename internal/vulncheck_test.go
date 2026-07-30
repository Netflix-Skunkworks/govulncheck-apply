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

package internal

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/tools/txtar"
)

// These name the txtar entries holding a case's expectations. Every case has a
// want_diff.txt; want_report.md is optional.
const (
	wantDiffFile   = "want_diff.txt"
	wantReportFile = "want_report.md"
)

// TestVulncheck runs govulncheck-apply against each txtar repository in
// testcases/ and asserts the resulting `git diff` matches the archive's
// want_diff.txt.
func TestVulncheck(t *testing.T) {
	cases, err := filepath.Glob("testcases/*.txtar")
	if err != nil {
		t.Fatal(err)
	}
	// The sibling foo.db.txtar vendored databases aren't test cases.
	cases = slices.DeleteFunc(cases, func(p string) bool { return strings.HasSuffix(p, ".db.txtar") })
	if len(cases) == 0 {
		t.Fatal("no testcases/*.txtar files found")
	}

	// The binary is built once and reused by every case. govulncheck is not built
	// here, because the program installs its own.
	govulncheckApply := filepath.Join(t.TempDir(), "govulncheck-apply")
	run(t, ".", "go", "build", "-o", govulncheckApply, "github.com/netflix-skunkworks/govulncheck-apply")

	for _, path := range cases {
		name := strings.TrimSuffix(filepath.Base(path), ".txtar")
		t.Run(name, func(t *testing.T) {
			// Each case gets its own repository and database under t.TempDir(),
			// and the go command locks the caches they share, so the cases only
			// contend for CPU. The binary above outlives them: a parallel subtest
			// signals its parent before the parent's cleanups run.
			t.Parallel()

			archive, err := txtar.ParseFile(path)
			if err != nil {
				t.Fatal(err)
			}

			d := directives(t, archive.Comment)
			if d["skip"] == "true" {
				t.Skip("disabled by 'skip: true' directive")
			}

			wantDiff, ok := take(archive, wantDiffFile)
			if !ok {
				t.Fatalf("%s has no %s", path, wantDiffFile)
			}
			wantReport, hasReport := take(archive, wantReportFile)
			// An empty want_diff.txt is how a case says the run must change
			// nothing, which on its own would also pass if the run did nothing at
			// all. Such a case has to assert the report too.
			if wantDiff == "" && !hasReport {
				t.Fatalf("%s asserts nothing: %s is empty and there is no %s", path, wantDiffFile, wantReportFile)
			}

			fsys, err := txtar.FS(archive)
			if err != nil {
				t.Fatal(err)
			}

			repo := t.TempDir()
			if err := os.CopyFS(repo, fsys); err != nil {
				t.Fatal(err)
			}
			gitInit(t, repo)

			// Scanning the vendored DB keeps findings deterministic and offline.
			env := []string{"GOTOOLCHAIN=" + Toolchain(d)}
			db := "file://" + loadDB(t, path)
			gotReport := runEnv(t, repo, env, govulncheckApply, "-db", db)

			run(t, repo, "git", "add", "-A")
			gotDiff := run(t, repo, "git", "-c", "core.pager=cat", "diff", "--cached")
			if gotDiff != wantDiff {
				t.Errorf("git diff --cached =\n%s\nwant:\n%s", gotDiff, wantDiff)
			}
			if hasReport && gotReport != wantReport {
				t.Errorf("report =\n%s\nwant:\n%s", gotReport, wantReport)
			}
		})
	}
}

// directives is Directives with the parse error reported as a test failure.
func directives(t *testing.T, comment []byte) map[string]string {
	t.Helper()
	d, err := Directives(comment)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// loadDB extracts the test's sibling foo.db.txtar database into a temp dir.
func loadDB(t *testing.T, txtarPath string) string {
	t.Helper()
	ar, err := txtar.ParseFile(strings.TrimSuffix(txtarPath, ".txtar") + ".db.txtar")
	if err != nil {
		t.Fatal(err)
	}
	fsys, err := txtar.FS(ar)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.CopyFS(dir, fsys); err != nil {
		t.Fatal(err)
	}
	return dir
}

// take removes the named file from the archive, returning its contents and
// whether it was there at all.
func take(archive *txtar.Archive, name string) (string, bool) {
	i := slices.IndexFunc(archive.Files, func(f txtar.File) bool { return f.Name == name })
	if i < 0 {
		return "", false
	}
	data := archive.Files[i].Data
	archive.Files = slices.Delete(archive.Files, i, i+1)
	return string(data), true
}

// gitInit commits the fixture so a later `git diff` has a baseline.
func gitInit(t *testing.T, dir string) {
	t.Helper()
	run(t, dir, "git", "init", "-q")
	run(t, dir, "git", "add", "-A")
	run(t, dir, "git", "-c", "user.email=test@example.com", "-c", "user.name=test", "commit", "-qm", "fixture")
}

// run executes a command in dir, failing the test on error, and returns stdout.
func run(t *testing.T, dir, name string, args ...string) string {
	t.Helper()
	return runEnv(t, dir, nil, name, args...)
}

// runEnv is run with extra environment variables.
func runEnv(t *testing.T, dir string, env []string, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, stderr.String())
	}
	return stdout.String()
}
