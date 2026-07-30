# govulncheck-apply

Runs `govulncheck` over the modules under the working directory and applies the
fixes it reports: upgrades vulnerable modules and bumps the `go` directive for
standard-library vulns. A module whose vendor directory is out of date afterwards
is re-synced with `go mod vendor`, and a `go.work` whose `go` directive ends up
below the modules it uses is raised with `go work use`.

Every `go.mod` under the working directory is a module to fix, except under
`vendor`, `testdata`, and the dot- and underscore-prefixed directories the go
command itself ignores.

## Usage

    go install github.com/netflix-skunkworks/govulncheck-apply@latest
    govulncheck-apply

A module is rescanned until a pass leaves its `go.mod` and `go.sum` alone, because
the version a fix selects can itself be vulnerable. Five passes in, a module that
is still changing is reported as an error, since the last scan then says nothing
about what is left to fix.

Files are edited in place, with no way back: run this on a clean checkout, and
recover from an interrupted run with `git checkout -- . && git clean -fd` rather
than by running it again.

`govulncheck` is installed into a temporary directory rather than taken from
`PATH`, at a version pinned in `scan.go`. It is built under a toolchain at least
as new as the highest `go` directive it will scan, because it type-checks with
the `go/types` compiled into it.

`-db` names a vulnerability database for `govulncheck` to scan against, for a
mirror or an offline copy. It defaults to `govulncheck`'s own default,
`https://vuln.go.dev`.

## Output

A summary of every module is printed to stdout as JSON. `unfixed` distinguishes a
vulnerability the database publishes no fix for from one where the fix was
applied and the scan still reported it, which a `replace` directive can cause.

```json
{
  "modules": [
    { "dir": ".", "fixed": ["GO-2021-0113"] },
    { "dir": "sub", "unfixed": [{ "osv": "GO-2020-0017", "reason": "no fix published" }] },
    { "dir": "broken", "error": "govulncheck: exit status 1" }
  ]
}
```

A module that cannot be scanned does not stop the others being remediated: its
error is reported here and on stderr, and the run still exits 0, because a failure
would be read as "nothing changed" by whatever commits the result. A failure
outside any one module — an unreadable directory, or `govulncheck` itself failing
to install — does exit non-zero.

## Test case format

Each `internal/testcases/foo.txtar` is a repository to scan, plus a
`want_diff.txt` holding the `git diff` the run is expected to produce. Its
sibling `foo.db.txtar` is the vulnerability database to scan against. A case may
also carry a `want_summary.json` holding the summary the run should print.

In the archive comment, `#` lines describe the case and mean nothing to the
harness. Every other non-blank line is a `key: value` directive:

| Directive | Effect |
| --- | --- |
| `gotoolchain: go1.21.0` | `GOTOOLCHAIN` floor for the run, setting the toolchain whose standard library `govulncheck` analyzes. A floor rather than a pin, so a module raised past it can still be scanned |
| `skip: true` | Skip the case |

A line that is neither fails the test, so a mistyped directive can't quietly
read as a comment.

## Reproduce a test scenario

`internal/cmd/repro` extracts an `internal/testcases/*.txtar` scenario into a
temp dir:

```sh
go run ./internal/cmd/repro -testcase vuln_xtext
cd <dir>
./govulncheck-apply -db file://<dir>/govulncheck-db
```
