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

// TestVulncheck runs the vulncheck bot's script (from vulncheck_adhoc.json)
// against each txtar repository in testcases/ and asserts the resulting
// `git diff` matches the archive's want_diff.txt.
func TestVulncheck(t *testing.T) {
	cases, err := filepath.Glob("testcases/*.txtar")
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("no testcases/*.txtar files found")
	}

	for _, path := range cases {
		name := strings.TrimSuffix(filepath.Base(path), ".txtar")
		t.Run(name, func(t *testing.T) {
			archive, err := txtar.ParseFile(path)
			if err != nil {
				t.Fatal(err)
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

			run(t, repo, "bash", "-c", script)

			run(t, repo, "git", "add", "-A")
			got := run(t, repo, "git", "-c", "core.pager=cat", "diff", "--cached")

			if got != want {
				t.Errorf("diff mismatch\n--- want ---\n%s\n--- got ---\n%s", want, got)
			}
		})
	}
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
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOFLAGS=-mod=mod")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, stderr.String())
	}
	return stdout.String()
}
