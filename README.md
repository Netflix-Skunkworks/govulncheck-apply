# govulncheck-apply

Reads a `govulncheck -json` stream on stdin and applies the reported fixes to the
`go.mod`(s) in the working directory: upgrades vulnerable modules and bumps the
`go` directive for standard-library vulns. If the main module has a vendor
directory, it is re-synced with `go mod vendor`.

## Usage

    go install github.com/netflix-skunkworks/govulncheck-apply@latest
    govulncheck -json ./... | govulncheck-apply

## Test case format

Each `internal/testcases/foo.txtar` is a repository to scan, plus a
`want_diff.txt` holding the `git diff` the run is expected to produce. Its
sibling `foo.db.txtar` is the vulnerability database to scan against.

In the archive comment, `#` lines describe the case and mean nothing to the
harness. Every other non-blank line is a `key: value` directive:

| Directive | Effect |
| --- | --- |
| `gotoolchain: go1.21.0` | `GOTOOLCHAIN` for the scan, setting the toolchain whose standard library govulncheck analyzes |
| `skip: true` | Skip the case |

A line that is neither fails the test, so a mistyped directive can't quietly
read as a comment.

## Reproduce a test scenario

`internal/cmd/repro` extracts an `internal/testcases/*.txtar` scenario into a
temp dir:

```sh
go run ./internal/cmd/repro -testcase vuln_xtext
cd <dir>
./govulncheck -db file://<dir>/govulncheck-db -json ./... | ./govulncheck-apply
```
