# govulncheck-apply

Three commands that carry a repository past the Go vulnerabilities `govulncheck`
reports. `modfix` does the remediating; `dockerfilefix` and `ymlfix` catch up the
files a remediation leaves behind, so run `modfix` first.

    go install github.com/netflix-skunkworks/govulncheck-apply/cmd/modfix@latest
    go install github.com/netflix-skunkworks/govulncheck-apply/cmd/dockerfilefix@latest
    go install github.com/netflix-skunkworks/govulncheck-apply/cmd/ymlfix@latest

    modfix > report.md
    dockerfilefix
    ymlfix -path .tool-versions.goVersion config.yml

Each only ever raises a version, never lowers one, and names on stdout what it
changed. All three edit in place with no way back: run them on a clean checkout and
recover with `git checkout -- . && git clean -fd` rather than by running them again.

Every `go.mod` under the working directory is a module, except under `vendor`,
`testdata`, and the dot- and underscore-prefixed directories the go command
ignores.

Up to v0.7.0 there was one command at the module root, so
`go install …/govulncheck-apply@latest` no longer resolves; `cmd/modfix` is where
it went.

## modfix

Runs `govulncheck` over every module and applies what it reports: upgrades
vulnerable modules, and raises the `go` directive for standard-library vulns. A
stale vendor directory is re-synced with `go mod vendor`, and a `go.work` left
below the modules it uses is raised with `go work use`.

A module is rescanned until a pass leaves its `go.mod` and `go.sum` alone, because
the version a fix selects can itself be vulnerable; one still changing after five
passes is reported as an error.

`govulncheck` is installed to a temp dir at a version pinned in
`cmd/modfix/scan.go`, built under a toolchain at least as new as the highest `go`
directive it will scan. `-db` points it at another vulnerability database.

Every advisory any pass reported is printed as markdown, ready for a pull request
description, and nothing at all when there is nothing to report. Each advisory gets
its own line, and what `govulncheck` prints under that heading is folded away behind
it — laid out as `govulncheck` lays it out, in a code block so the indentation
survives and no symbol is read as markdown:

````markdown
govulncheck found 2 vulnerabilities; this PR fixes 2:

**[GO-2021-0113](https://pkg.go.dev/vuln/GO-2021-0113)**: Out-of-bounds read in golang.org/x/text

<details>
<summary>Details</summary>

```
  Module: golang.org/x/text
    Found in: golang.org/x/text@v0.3.5
    Fixed in: golang.org/x/text@v0.3.7
    Selected: golang.org/x/text@v0.3.8
    Example traces found:
      #1: main.go:12:28: foo.main calls language.Parse
      #2: sub/lib.go:9:14: sub.Tag calls grpc.ClientConn.Invoke, which eventually calls language.Parse
```

</details>

**[GO-2024-2687](https://pkg.go.dev/vuln/GO-2024-2687)**: Improper header parsing in net/http

<details>
<summary>Details</summary>

```
  Standard library
    Found in: net/http@go1.21.0
    Fixed in: net/http@go1.21.9
    Example traces found: none. There is no path from your code to this
      vulnerability. It was remediated because it is in your dependency tree,
      where a scanner that does not tree-shake would alert on it regardless.
```

</details>
````

The heading, the link and the advisory's prose stay outside the fold, so the list
reads without opening anything.

A standard-library advisory reads `Standard library` in place of the module, and
names the package at a toolchain version — `net/http@go1.21.9` — as `govulncheck`
does. The heading counts what was found against what was fixed, and names the two
ways one can be left behind — no fix published yet, or one published that the
upgrade could not take, which a `replace` directive can cause — only when they
happened, so the numbers always account for the whole. Two lines are not `govulncheck`'s: `Selected`, which appears only where
minimal version selection landed above the version that fixes the advisory so the
entry does not disagree with the diff, and `Fixed in` reading `no fix published` or
carrying `(fix did not take)` where the advisory survived the upgrade, which a
`replace` directive can cause.

`govulncheck` reports a finding per reachable symbol, so one advisory can carry a
dozen traces. They are ordered by the symbol reached rather than by the call site the
sentence starts at, which is how `govulncheck` orders its own, so the same advisory
reads the same in both reports. Two that differ only in frames no sentence names are
written once. An
advisory nothing in the module reaches says so, and why it was remediated anyway:
being in the dependency tree is enough for a scanner that does not tree-shake to
alert on it.

A module that cannot be scanned is listed at the end and on stderr, and the run
still exits 0, because a failure reads as "nothing changed" to whatever commits the
result.

## dockerfilefix

Raises the `golang` image tag in every Dockerfile to the `go` directive of the
module it builds — the nearest one above it, since an image builds one module. The
official images set `GOTOOLCHAIN=local`, so a directive above the image's Go fails
`go mod download` inside it.

```diff
-FROM --platform={{ .Target.Platform }} docker.io/golang:1.21 AS builder
+FROM --platform={{ .Target.Platform }} docker.io/golang:1.21.9 AS builder
```

Only the version is rewritten, so a registry prefix, a `--platform` flag and a
suffix such as `-alpine` all survive. `golang:1` and `golang:latest` name no
version to raise and are left alone.

## ymlfix

Raises a version recorded in a YAML file, for CI that builds with a toolchain its
own configuration names rather than with the `go` directive.

    ymlfix -path .tool-versions.goVersion config.yml
    ymlfix -path .lint.golangci-version -version v2.4.0 config.yml

`-path` addresses a key, not a file: the mapping keys that reach the version,
separated by dots, the way `yq` names one. The file is the argument after it.

```yaml
tool-versions:
  buf: 1.28.1
  goVersion: 1.21                          # -path .tool-versions.goVersion
lint:
  golangci-version: v2.1.0@sha256:ea84d1   # -path .lint.golangci-version
```

Without `-version` the version raised to is the highest `go` directive in the
repository. With it, that version is used instead, for something whose version is
not a Go version — a pinned linter, whose releases have to be looked up somewhere
this knows nothing about. A module version and a Go version cannot be ordered
against each other, so asking is an error rather than a quiet no-op.

Only the version's own bytes are rewritten, never the document re-emitted, so
comments, blank lines, key order and flow mappings all survive. A digest is written
over along with the version it belonged to. A `-path` reaching no version leaves
the file alone.

## Tests

Each command has its own scenarios in `cmd/<command>/testcases`. A `foo.txtar` is a
repository to run that command over, with a `want_diff.txt` holding the `git diff`
it should produce and, optionally, a `want_report.md` holding what it should print.
A sibling `foo.db.txtar` is a vulnerability database passed as `-db`; only `modfix`
scans, so only its scenarios carry one.

`internal.Scenarios` is the shared harness. It builds the command in the directory
the test itself lives in, so a scenario is only ever run by the command beside it.

An archive comment holds `#` prose and `key: value` directives: `gotoolchain:
go1.21.0` sets the `GOTOOLCHAIN` floor for the run, and `skip: true` skips the
case. A line that is neither fails the test, so a mistyped directive cannot quietly
read as a comment.

`internal/cmd/repro` extracts a `modfix` scenario into a temp dir to run by hand,
and prints the commands to run there:

```sh
go run ./internal/cmd/repro -testcase vuln_xtext
```
