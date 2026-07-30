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
// and the trace to the call that reaches it.
type vuln struct {
	osv           string
	url           string
	summary       string  // the advisory's own one-line prose, if it publishes one
	module        string  // the vulnerable module's path, or stdlib
	pkg           string  // the vulnerable package, where a finding named one
	found         string  // the version of it the first scan found
	selected      string  // the version the run left selected, empty if unchanged
	fixedIn       string  // the version that fixes it, empty if none is published
	trace         []frame // the call that reaches it, empty if the module makes none
	stillReported bool    // whether the last pass reported it again
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

// tableHeader is written once, before the first row there is to write. The
// advisory's prose is not a column of its own: a sentence per row made the table
// wider than a pull request shows without scrolling, so it rides along as the
// link's title instead.
const tableHeader = "| Advisory | Dependency | Fixed in | Reached from |\n" +
	"| --- | --- | --- | --- |\n"

// report writes every module's outcome as one markdown table, for a pull request
// description or a build log to carry as it is. Nothing is written when there is
// nothing to say, so that a caller can test the output for emptiness rather than
// paste an empty table.
func report(w io.Writer, modules []moduleReport) error {
	var table, failures strings.Builder
	for _, m := range modules {
		if m.err != "" {
			fmt.Fprintf(&failures, "- `%s`: %s\n", cell(m.dir), cell(m.err))
			continue
		}
		for _, v := range m.vulns {
			if table.Len() == 0 {
				table.WriteString(tableHeader)
			}
			table.WriteString(row(v))
		}
	}
	if table.Len() == 0 && failures.Len() == 0 {
		return nil
	}
	if failures.Len() > 0 {
		if table.Len() > 0 {
			table.WriteString("\n")
		}
		table.WriteString("Modules that could not be remediated:\n\n")
		table.WriteString(failures.String())
	}
	_, err := io.WriteString(w, table.String())
	return err
}

// row renders one advisory. Which module of the repository reported it is not a
// column: almost every repository has one, and a column of repeated "." earns no
// room. A call site names a file, which places the row in a repository that has
// more than one.
//
// The version that fixes the advisory carries what became of it, so that the
// exception is stated where a reader is already looking for the version rather
// than in a column of repeated "fixed".
func row(v vuln) string {
	fixedIn := toolchainName(v.module, v.fixedIn)
	switch {
	case v.fixedIn == "":
		fixedIn = noFix
	case v.stillReported:
		fixedIn += " (" + fixNotTaken + ")"
	}
	reached := callSite(v.trace)
	if reached == "" {
		reached = "not called"
	}
	return fmt.Sprintf("| %s | %s | %s | %s |\n",
		advisory(v), cell(vulnerableModule(v)+"@"+upgrade(v)),
		cell(fixedIn), cell(reached))
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

// upgrade renders what happened to the version of the vulnerable module: the one
// the scan found, and the one the run went on to select where those differ. The
// version that fixes an advisory is a minimum, so minimal version selection can
// land above it, and reporting only the minimum next to a diff that names a higher
// version reads as a mistake.
func upgrade(v vuln) string {
	found := toolchainName(v.module, v.found)
	if v.selected == "" || v.selected == v.found {
		return found
	}
	return found + " → " + toolchainName(v.module, v.selected)
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

// advisory links the OSV id to the entry the database gave a URL for, titled with
// the advisory's own prose so that a reader can have it without the table growing
// a column for it.
func advisory(v vuln) string {
	if v.url == "" {
		return cell(v.osv)
	}
	link := "[" + cell(v.osv) + "](" + cell(v.url)
	if v.summary != "" {
		// A title is quoted, so the quotes in it cannot be.
		link += ` "` + strings.ReplaceAll(cell(v.summary), `"`, "'") + `"`
	}
	return link + ")"
}

// cell makes text safe to sit in a markdown table: a pipe would start a column,
// and a newline would end the row. An advisory's summary and a go command's error
// are the two that carry either.
func cell(text string) string {
	text = strings.ReplaceAll(text, "|", `\|`)
	return strings.Join(strings.Fields(text), " ")
}

// callSite renders how a module's own code reaches a vulnerable symbol. The last
// frame of the trace is the call in that code, trace[0] is the symbol it reaches,
// and the frame between them is what it calls to get there. Only the
// called-function granularity carries the positions, so the coarser findings
// render as nothing.
//
// The frames in between are stood for by an ellipsis rather than dropped, because
// naming only the two ends reads as a call that is not there: it is
// `grpc.ClientConn.Invoke` that reaches the vulnerable symbol, not the protobuf
// method that called it. govulncheck's own report says "which eventually calls"
// for the same reason.
func callSite(trace []frame) string {
	if len(trace) < 2 {
		return ""
	}
	caller := trace[len(trace)-1]
	if caller.Position == nil || !caller.Position.IsValid() {
		return ""
	}
	reached := []string{symbol(caller)}
	if len(trace) > 2 {
		reached = append(reached, symbol(trace[len(trace)-2]))
	}
	if len(trace) > 3 {
		reached = append(reached, "…")
	}
	reached = append(reached, symbol(trace[0]))
	return fmt.Sprintf("%s %s", caller.Position, strings.Join(reached, " → "))
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
