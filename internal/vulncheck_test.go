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
	// The sibling foo.db.txtar vendored databases aren't test cases.
	cases = slices.DeleteFunc(cases, func(p string) bool { return strings.HasSuffix(p, ".db.txtar") })
	if len(cases) == 0 {
		t.Fatal("no testcases/*.txtar files found")
	}

	// Build the applier and govulncheck once, reused by every case.
	applier := filepath.Join(t.TempDir(), "govulncheck-apply")
	run(t, ".", "go", "build", "-o", applier, "github.com/netflix-skunkworks/govulncheck-apply")
	govulncheck := buildGovulncheck(t)

	for _, path := range cases {
		name := strings.TrimSuffix(filepath.Base(path), ".txtar")
		t.Run(name, func(t *testing.T) {
			archive, err := txtar.ParseFile(path)
			if err != nil {
				t.Fatal(err)
			}

			if directives(archive.Comment)["skip"] == "true" {
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
			// gotoolchain directive pins the toolchain the stdlib is analyzed against.
			db := loadDB(t, path)
			toolchain := directives(archive.Comment)["gotoolchain"]
			if toolchain == "" {
				toolchain = "local"
			}
			scan := "GOTOOLCHAIN=" + toolchain + " '" + govulncheck + "' -db file://" + db + " -json ./... | '" + applier + "'"
			run(t, repo, "bash", "-c", scan)

			run(t, repo, "git", "add", "-A")
			got := run(t, repo, "git", "-c", "core.pager=cat", "diff", "--cached")

			if got != want {
				t.Errorf("diff mismatch\n--- want ---\n%s\n--- got ---\n%s", want, got)
			}
		})
	}
}

// directives parses the leading "key: value" lines of a txtar archive comment
// (e.g. description and skip). Parsing stops at the first blank or
// non-directive line, so the free-form description prose below is ignored.
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

// buildGovulncheck installs govulncheck once and returns the binary path. It's
// prebuilt (not `go run @version`) so a case can pin GOTOOLCHAIN for the stdlib
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
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOFLAGS=-mod=mod")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, stderr.String())
	}
	return stdout.String()
}
