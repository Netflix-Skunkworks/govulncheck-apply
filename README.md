# govulncheck-apply

Reads a `govulncheck -json` stream on stdin and applies the reported fixes to the
`go.mod`(s) in the working directory: upgrades vulnerable modules and bumps the
`go` directive for standard-library vulns.

## Usage

    go install github.com/netflix-skunkworks/govulncheck-apply@latest
    govulncheck -json ./... | govulncheck-apply

## Reproduce a test scenario

`internal/cmd/repro` extracts an `internal/testcases/*.txtar` scenario into a
temp dir:

```sh
go run ./internal/cmd/repro -testcase vuln_xtext
cd <dir>
./govulncheck -db file://<dir>/govulncheck-db -json ./... | ./govulncheck-apply
```
