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
	"cmp"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
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

// Scenarios builds the command in the calling test's own directory and runs it
// over every testcases/*.txtar beside it, asserting the `git diff` each archive's
// want_diff.txt says the run should produce, and what a want_report.md says it
// should print.
//
// A scenario with a sibling foo.db.txtar is scanned against that vulnerability
// database rather than the live vuln.go.dev, passed as -db, so findings are
// deterministic and offline. A command that does not scan has no such sibling and
// is given no flags.
//
// The command is expected to exit 0 unless the case carries an `exit` directive.
// A case that requires a non-zero exit still asserts its diff: a run can fail and
// have changed files, and what the two together mean is the point of such a case.
func Scenarios(t *testing.T) {
	cases, err := filepath.Glob("testcases/*.txtar")
	if err != nil {
		t.Fatal(err)
	}
	// The sibling foo.db.txtar vendored databases aren't test cases.
	cases = slices.DeleteFunc(cases, func(p string) bool { return strings.HasSuffix(p, ".db.txtar") })
	if len(cases) == 0 {
		t.Fatal("no testcases/*.txtar files found")
	}

	// The binary is built once and reused by every case, and named after the
	// directory it was built from so that a failure says which command failed.
	// govulncheck is not built here, because modfix installs its own.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	command := filepath.Join(t.TempDir(), filepath.Base(wd))
	run(t, ".", "go", "build", "-o", command, ".")

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

			var args []string
			if db := loadDB(t, path); db != "" {
				args = append(args, "-db", "file://"+db)
			}
			gotReport, gotStderr, gotExit := runCommand(t, repo, []string{"GOTOOLCHAIN=" + Toolchain(d)}, command, args...)
			if got, want := strconv.Itoa(gotExit), cmp.Or(d["exit"], "0"); got != want {
				t.Errorf("%s exited %s, want %s\n%s", filepath.Base(command), got, want, gotStderr)
			}

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

// directives is [Directives] with the parse error reported as a test failure.
func directives(t *testing.T, comment []byte) map[string]string {
	t.Helper()
	d, err := Directives(comment)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// loadDB extracts a scenario's sibling foo.db.txtar vulnerability database into a
// temp dir, or returns "" for a scenario that has none.
func loadDB(t *testing.T, txtarPath string) string {
	t.Helper()
	name := strings.TrimSuffix(txtarPath, ".txtar") + ".db.txtar"
	if _, err := os.Stat(name); errors.Is(err, fs.ErrNotExist) {
		return ""
	}
	ar, err := txtar.ParseFile(name)
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

// runCommand runs a command in dir with extra environment variables, returning its
// stdout, its stderr and its exit code. A non-zero exit is the caller's to judge
// rather than a failure here, because a scenario can require one.
func runCommand(t *testing.T, dir string, env []string, name string, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil && !errors.As(err, new(*exec.ExitError)) {
		// The command never ran at all, which no scenario asks for.
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, stderr.String())
	}
	return stdout.String(), stderr.String(), cmd.ProcessState.ExitCode()
}

// run executes a command in dir, failing the test on a non-zero exit, and returns
// stdout.
func run(t *testing.T, dir, name string, args ...string) string {
	t.Helper()
	stdout, stderr, exit := runCommand(t, dir, nil, name, args...)
	if exit != 0 {
		t.Fatalf("%s %s: exit %d\n%s", name, strings.Join(args, " "), exit, stderr)
	}
	return stdout
}
