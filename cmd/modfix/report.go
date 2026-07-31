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

package main

import (
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
	"unicode"
)

// stdlib is the module path govulncheck reports a standard-library vulnerability
// against. Its versions are Go versions.
const stdlib = "stdlib"

// vuln is what the scans of one module said about one advisory: the advisory
// itself, the version of the vulnerable module found, the version that fixes it,
// and every call that reaches it.
type vuln struct {
	osv           string
	url           string
	summary       string    // the advisory's own one-line prose, if it publishes one
	module        string    // the vulnerable module's path, or stdlib
	pkg           string    // the vulnerable package, where a finding named one
	found         string    // the version of it the first scan found
	selected      string    // the version the run left selected, empty if unchanged
	fixedIn       string    // the version that fixes it, empty if none is published
	traces        [][]frame // the calls that reach it, empty if the module makes none
	stillReported bool      // whether the last pass reported it again
}

// The two ways a vulnerability can be left behind: the database publishes no
// fixed version, or raising the requirement to it did not shake the vulnerable
// version out of the build list, which usually means a replace directive is
// holding it there.
const (
	noFix       = "no fix published"
	fixNotTaken = "fix did not take"
)

// moduleReport is one module's outcome. A module that could not be scanned, or
// that never settled, carries an error and no vulnerabilities: a run that stopped
// partway cannot say what it fixed.
type moduleReport struct {
	dir   string
	vulns []vuln
	err   string
}

// withError records why a module was given up on. One module that cannot be
// remediated must not stop the others, so this is reported rather than returned.
func (m moduleReport) withError(err error) moduleReport {
	fmt.Fprintf(os.Stderr, "giving up on %s: %v\n", m.dir, err)
	m.err = err.Error()
	return m
}

// report writes every module's outcome as markdown, for a pull request
// description or a build log to carry as it is. Nothing is written when there is
// nothing to say, so that a caller can test the output for emptiness.
//
// The layout is govulncheck's own, an entry per advisory rather than a row: a
// summary and a call trace are each a sentence, and a table of sentences is wider
// than a pull request shows without scrolling.
func report(w io.Writer, modules []moduleReport) error {
	var out, failures strings.Builder
	found := 0
	for _, m := range modules {
		if m.err != "" {
			fmt.Fprintf(&failures, "- `%s`: %s\n", oneLine(m.dir), oneLine(m.err))
			continue
		}
		for _, v := range m.vulns {
			found++
			if found > 1 {
				out.WriteString("\n")
			}
			out.WriteString(entry(found, v))
		}
	}
	if out.Len() == 0 && failures.Len() == 0 {
		return nil
	}
	if failures.Len() > 0 {
		if out.Len() > 0 {
			out.WriteString("\n")
		}
		out.WriteString("Modules that could not be remediated:\n\n")
		out.WriteString(failures.String())
	}
	_, err := io.WriteString(w, out.String())
	return err
}

// entry renders one advisory, numbered across the whole report the way
// govulncheck numbers its own. Which module of the repository reported it is not
// named: almost every repository has one, and a call trace names a file, which
// places the entry in a repository that has more than one.
func entry(n int, v vuln) string {
	var b strings.Builder
	fmt.Fprintf(&b, "#### Vulnerability #%d: %s\n", n, advisory(v))
	if v.summary != "" {
		fmt.Fprintf(&b, "\n%s\n", oneLine(v.summary))
	}
	b.WriteString("\n")
	if v.module == stdlib {
		b.WriteString("- Standard library\n")
	} else {
		fmt.Fprintf(&b, "- Module: `%s`\n", oneLine(v.module))
	}
	fmt.Fprintf(&b, "- Found in: `%s`\n", oneLine(at(v, v.found)))
	fmt.Fprintf(&b, "- Fixed in: %s\n", fixedIn(v))
	// The version that fixes an advisory is a minimum, so minimal version selection
	// can land above it, and naming only the minimum next to a diff that says
	// otherwise reads as a mistake.
	if v.selected != "" && v.selected != v.found && v.selected != v.fixedIn {
		fmt.Fprintf(&b, "- Selected: `%s`\n", oneLine(at(v, v.selected)))
	}
	b.WriteString(traces(v.traces))
	return b.String()
}

// fixedIn says what became of the advisory: the version that fixes it, that no
// version does, or that one does and the upgrade did not shake the vulnerable
// version out of the build list anyway.
func fixedIn(v vuln) string {
	if v.fixedIn == "" {
		return noFix
	}
	in := "`" + oneLine(at(v, v.fixedIn)) + "`"
	if v.stillReported {
		in += " (" + fixNotTaken + ")"
	}
	return in
}

// at names what carries the vulnerability at one of its versions, as govulncheck
// writes it.
func at(v vuln, version string) string {
	return vulnerableModule(v) + "@" + toolchainName(v.module, version)
}

// traces renders the calls that reach the vulnerable symbol, folded away because
// one advisory can be reached a dozen ways and the list is longer than the entry
// it belongs to. Nothing is written for an advisory the module only carries.
func traces(traces [][]frame) string {
	var reached []string
	for _, trace := range traces {
		if call := callSite(trace); call != "" {
			reached = append(reached, call)
		}
	}
	if len(reached) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\n<details>\n<summary>%d example trace", len(reached))
	if len(reached) > 1 {
		b.WriteString("s")
	}
	b.WriteString("</summary>\n\n")
	for i, call := range reached {
		// Wrapped whole, so that a receiver's star or an underscore in a symbol is
		// not read as markdown.
		fmt.Fprintf(&b, "%d. `%s`\n", i+1, call)
	}
	b.WriteString("\n</details>\n")
	return b.String()
}

// vulnerableModule names what carries the vulnerability. For the standard library
// that is a package, as govulncheck's own report has it: crypto/tls tells a reader
// what to look at, where stdlib only tells them which version moved.
func vulnerableModule(v vuln) string {
	if v.module == stdlib && v.pkg != "" {
		return v.pkg
	}
	return v.module
}

// toolchainName renders the version of the vulnerable module. govulncheck reports
// the standard library's as a semver, where a toolchain name is what a reader of a
// go directive recognizes.
func toolchainName(module, v string) string {
	if module != stdlib || v == "" {
		return v
	}
	return "go" + strings.TrimPrefix(v, "v")
}

// advisory links the OSV id to the entry the database gave a URL for, so that a
// reader can reach the advisory itself without a line of its own for the address.
func advisory(v vuln) string {
	if v.url == "" {
		return oneLine(v.osv)
	}
	return "[" + oneLine(v.osv) + "](" + oneLine(v.url) + ")"
}

// oneLine folds text onto a single line, so that it cannot break out of the bullet
// or heading it is written into. An advisory's summary and a go command's error are
// the two that arrive spanning lines.
func oneLine(text string) string {
	return strings.Join(strings.Fields(text), " ")
}

// callSite renders how a module's own code reaches a vulnerable symbol, in
// govulncheck's own words. The last frame of the trace is the call in that code,
// trace[0] is the symbol it reaches, and the frame between them is what it calls
// to get there. Only the called-function granularity carries the positions, so the
// coarser findings render as nothing.
//
// What the caller reaches for is named rather than left out, because naming only
// the two ends reads as a call that is not there: it is grpc.ClientConn.Invoke that
// reaches the vulnerable symbol, not the protobuf method that called it.
func callSite(trace []frame) string {
	if len(trace) < 2 {
		return ""
	}
	caller := trace[len(trace)-1]
	if caller.Position == nil || !caller.Position.IsValid() {
		return ""
	}
	if len(trace) == 2 {
		return fmt.Sprintf("%s: %s calls %s", caller.Position, symbol(caller), symbol(trace[0]))
	}
	return fmt.Sprintf("%s: %s calls %s, which eventually calls %s",
		caller.Position, symbol(caller), symbol(trace[len(trace)-2]), symbol(trace[0]))
}

// symbol names a frame's function the way govulncheck's own report does, so that
// a reader of both sees the same names. A pointer receiver is written without the
// star, as a call on it reads.
func symbol(f frame) string {
	// A closure arrives as the function it is declared in, suffixed.
	name, _, _ := strings.Cut(f.Function, "$")
	if f.Receiver != "" {
		name = strings.TrimPrefix(f.Receiver, "*") + "." + name
	}
	if f.Package != "" {
		name = packageName(f.Package) + "." + name
	}
	return name
}

// packageName is the name a package is imported under, which is not always the
// last element of its import path: a major version suffix names the directory
// above it, and the rest of a name that is not an identifier is dropped, so
// github.com/dgrijalva/jwt-go reads as jwt. This is goimports' heuristic, by way
// of govulncheck, which keeps its copy in an internal package.
func packageName(importPath string) string {
	base := path.Base(importPath)
	if major, err := strconv.Atoi(strings.TrimPrefix(base, "v")); err == nil && major > 0 {
		if dir := path.Dir(importPath); dir != "." {
			base = path.Base(dir)
		}
	}
	base = strings.TrimPrefix(base, "go-")
	if i := strings.IndexFunc(base, notIdentifier); i >= 0 {
		base = base[:i]
	}
	return base
}

// notIdentifier reports whether r cannot appear in a Go identifier.
func notIdentifier(r rune) bool {
	return r != '_' && !unicode.IsLetter(r) && !unicode.IsDigit(r)
}
