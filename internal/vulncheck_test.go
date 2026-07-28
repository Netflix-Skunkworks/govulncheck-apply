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

// wantDiffFile is the txtar entry holding the expected `git diff`.
const wantDiffFile = "want_diff.txt"

// TestVulncheck pipes govulncheck into govulncheck-apply against each txtar
// repository in testcases/ and asserts the resulting `git diff` matches the
// archive's want_diff.txt.
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

	// Build govulncheck-apply and govulncheck once, reused by every case.
	govulncheckApply := filepath.Join(t.TempDir(), "govulncheck-apply")
	run(t, ".", "go", "build", "-o", govulncheckApply, "github.com/netflix-skunkworks/govulncheck-apply")
	govulncheck := buildGovulncheck(t)

	for _, path := range cases {
		name := strings.TrimSuffix(filepath.Base(path), ".txtar")
		t.Run(name, func(t *testing.T) {
			archive, err := txtar.ParseFile(path)
			if err != nil {
				t.Fatal(err)
			}

			d := directives(t, archive.Comment)
			if d["skip"] == "true" {
				t.Skip("disabled by 'skip: true' directive")
			}

			// Split want_diff.txt (the expected output) from the files that
			// make up the repository under test.
			want, ok := take(archive, wantDiffFile)
			if !ok {
				t.Fatalf("%s has no %s", path, wantDiffFile)
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

			// Scan against the vendored DB for deterministic findings; a
			// gotoolchain directive sets the toolchain whose standard library
			// govulncheck analyzes.
			db := loadDB(t, path)
			toolchain := d["gotoolchain"]
			if toolchain == "" {
				toolchain = "local"
			}
			scan := "GOTOOLCHAIN=" + toolchain + " '" + govulncheck + "' -db file://" + db + " -json ./... | '" + govulncheckApply + "'"
			run(t, repo, "bash", "-c", scan)

			run(t, repo, "git", "add", "-A")
			got := run(t, repo, "git", "-c", "core.pager=cat", "diff", "--cached")

			if got != want {
				t.Errorf("diff mismatch\n--- want ---\n%s\n--- got ---\n%s", want, got)
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

// buildGovulncheck installs govulncheck once and returns the binary path. It's
// prebuilt (not `go run @version`) so a case can set GOTOOLCHAIN for the stdlib
// analysis without forcing that toolchain to also compile govulncheck.
func buildGovulncheck(t *testing.T) string {
	t.Helper()
	gobin := t.TempDir()
	cmd := exec.Command("go", "install", "golang.org/x/vuln/cmd/govulncheck@v1.6.0")
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOFLAGS=", "GOBIN="+gobin)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("install govulncheck: %v\n%s", err, out)
	}
	return filepath.Join(gobin, "govulncheck")
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

// take removes the named file from the archive and returns its contents.
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
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, stderr.String())
	}
	return stdout.String()
}
