# govulncheck-apply

govulncheck-apply provides an implementation of
https://github.com/golang/go/issues/79896 which runs govulncheck and applies the
fixes.

To run it on your repo, run:

```sh
go install github.com/netflix-skunkworks/govulncheck-apply/cmd/modfix@latest
modfix
```

Also included is a program to bump Dockerfile `FROM golang:<ver>` declarations,
and a simple program to update Go versions in yml files.

```sh
go install github.com/netflix-skunkworks/govulncheck-apply/cmd/modfix@latest
go install github.com/netflix-skunkworks/govulncheck-apply/cmd/dockerfilefix@latest
go install github.com/netflix-skunkworks/govulncheck-apply/cmd/ymlfix@latest

modfix > report.md
dockerfilefix
ymlfix -path .tool-versions.goVersion config.yml
```

All edits to Go files (`go.mod`, `vendor/`, `go.work`, etc) are made with
standard Go tools, like `go mod edit`, `go mod tidy`, `go work use`, and so on.

## Features and quirks

There are several interesting cases that this program has to handle. See
[`./cmd/modfix/testcases`](https://github.com/Netflix-Skunkworks/govulncheck-apply/tree/main/cmd/modfix/testcases)
for a listing. You can also "test out" any of those testcases locally by
running:

```sh
go run ./internal/cmd/repro --testcase <testcase>
# ex: go run ./internal/cmd/repro --testcase vuln_four
```

An exhaustive list of scenarios that this program fixes, to highlight that it
has to do quite a bit more than just `govulncheck`, `go fix`, `go mod tidy`:

- When an update bumps a dependency to a version that itself has a (different)
vulnerability, iterate.
- When there are multiple modules, visit each and remediate.
- When files or dependencies are built only on some operating systems, scan
under each of linux, windows and darwin, because GOOS is a build constraint and
a scan only reaches what the files it admits import. An operating system a
module does not target is passed over rather than failing it.
- When there are replace statements, bump their versions too.
- When go.work files are present, ignore them and treat go.mod files as if they
were externally imported (go.work files can hide security issues, since
govulncheck uses the go.work version instead of the actually declared go.mod
version that a user importing the module would get).
- When one module requires a lower fix version than a preceding module required,
it's resolvable (using `require`, which enforces sets of minimums, instead of
`go get`, which could result in asking it to downgrade).
- etc.
