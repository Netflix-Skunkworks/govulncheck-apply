// Copyright 2026 Netflix, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

package main

import (
	"fmt"
	"io"
	"path"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

const stdlib = "stdlib"

// vuln is what the scans of one module said about one govulncheck advisory.
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

// report writes every advisory a run found as markdown.
func report(w io.Writer, all []vuln) error {
	if len(all) == 0 {
		return nil
	}
	entries := make([]string, 0, len(all))
	for _, v := range all {
		entries = append(entries, entry(v))
	}
	_, err := fmt.Fprintf(w, "%s\n\n%s", heading(all), strings.Join(entries, "\n"))
	return err
}

// heading counts what the run found against what it left, so that a reader sees
// at a glance whether anything is outstanding.
func heading(all []vuln) string {
	fixed, unfixable, stuck := 0, 0, 0
	for _, v := range all {
		switch {
		case !v.stillReported:
			fixed++
		case v.fixedIn == "":
			unfixable++
		default:
			stuck++
		}
	}
	said := []string{fmt.Sprintf("this PR fixes %d", fixed)}
	if unfixable > 0 {
		said = append(said, fmt.Sprintf("%d %s not have a fix ready yet", unfixable, agree(unfixable, "does", "do")))
	}
	if stuck > 0 {
		said = append(said, fmt.Sprintf("%d unable to fix", stuck))
	}
	return fmt.Sprintf("govulncheck found %d %s; %s:",
		len(all), agree(len(all), "vulnerability", "vulnerabilities"), strings.Join(said, ", "))
}

// agree picks the form of a word that goes with a count.
func agree(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// entry renders one advisory.
func entry(v vuln) string {
	var b strings.Builder
	fmt.Fprintf(&b, "**%s**", advisory(v))
	if v.summary != "" {
		fmt.Fprintf(&b, ": %s", oneLine(v.summary))
	}
	b.WriteString("\n\n<details>\n<summary>Details</summary>\n\n```\n")
	if v.module == stdlib {
		b.WriteString("  Standard library\n")
	} else {
		fmt.Fprintf(&b, "  Module: %s\n", oneLine(v.module))
	}
	fmt.Fprintf(&b, "    Found in: %s\n", oneLine(at(v, v.found)))
	fmt.Fprintf(&b, "    Fixed in: %s\n", fixedIn(v))
	// The version that fixes an advisory is a minimum, so minimal version
	// selection can land above it, and naming only the minimum next to a diff
	// that says otherwise reads as a mistake. govulncheck has no line for this,
	// so it gets one in the same shape as the two above.
	if v.selected != "" && v.selected != v.found && v.selected != v.fixedIn {
		fmt.Fprintf(&b, "    Selected: %s\n", oneLine(at(v, v.selected)))
	}
	b.WriteString(traces(v.traces))
	b.WriteString("```\n\n</details>\n")
	return b.String()
}

func fixedIn(v vuln) string {
	if v.fixedIn == "" {
		return noFix
	}
	in := at(v, v.fixedIn)
	if v.stillReported {
		in += " (" + fixNotTaken + ")"
	}
	return in
}

func at(v vuln, version string) string {
	return vulnerableModule(v) + "@" + toolchainName(v.module, version)
}

const noTraces = `    Example traces found: none. The scan reports which packages hold the
      vulnerability rather than which calls reach it, so whether your code
      reaches this one is not known here. It was remediated either way.
`

// traces renders the calls that reach the vulnerable symbol, numbered as
// govulncheck numbers them, or [noTraces] where the scan named no call.
func traces(traces [][]frame) string {
	type call struct{ reaches, sentence string }
	var reached []call
	seen := map[string]bool{}
	for _, trace := range traces {
		sentence := callSite(trace)
		if sentence == "" || seen[sentence] {
			continue
		}
		seen[sentence] = true
		reached = append(reached, call{symbol(trace[0]), sentence})
	}
	if len(reached) == 0 {
		return noTraces
	}
	// Ordered by the symbol reached rather than by the sentence, which starts
	// at the call site: govulncheck orders its own this way, and the same
	// advisory should read the same in both reports.
	slices.SortFunc(reached, func(a, b call) int {
		if c := strings.Compare(a.reaches, b.reaches); c != 0 {
			return c
		}
		return strings.Compare(a.sentence, b.sentence)
	})
	var b strings.Builder
	b.WriteString("    Example traces found:\n")
	for i, call := range reached {
		fmt.Fprintf(&b, "      #%d: %s\n", i+1, call.sentence)
	}
	return b.String()
}

// vulnerableModule names what carries the vulnerability. For the standard
// library that is a package, as govulncheck's own report has it: crypto/tls
// tells a reader what to look at, where stdlib only tells them which version
// moved.
func vulnerableModule(v vuln) string {
	if v.module == stdlib && v.pkg != "" {
		return v.pkg
	}
	return v.module
}

// toolchainName renders the version of the vulnerable module. govulncheck
// reports the standard library's as a semver, where a toolchain name is what a
// reader of a go directive recognizes.
func toolchainName(module, v string) string {
	if module != stdlib || v == "" {
		return v
	}
	return "go" + strings.TrimPrefix(v, "v")
}

// advisory links the OSV id to the entry the database gave a URL for, so that a
// reader can reach the advisory itself without a line of its own for the
// address.
func advisory(v vuln) string {
	if v.url == "" {
		return oneLine(v.osv)
	}
	return "[" + oneLine(v.osv) + "](" + oneLine(v.url) + ")"
}

// oneLine folds text onto a single line, so that it cannot break out of the
// entry's first line or the code block under it. An advisory's summary is what
// arrives spanning lines.
func oneLine(text string) string {
	return strings.Join(strings.Fields(text), " ")
}

// callSite renders how a module's own code reaches a vulnerable symbol, in
// govulncheck's own words. The last frame of the trace is the call in that
// code, trace[0] is the symbol it reaches, and the frame between them is what
// it calls to get there. Only the called-function granularity carries the
// positions, so the coarser findings render as nothing.
//
// What the caller reaches for is named rather than left out, because naming
// only the two ends reads as a call that is not there: it is
// grpc.ClientConn.Invoke that reaches the vulnerable symbol, not the protobuf
// method that called it.
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

// symbol names a frame's function the way govulncheck's own report does, so
// that a reader of both sees the same names. A pointer receiver is written
// without the star, as a call on it reads.
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
// github.com/dgrijalva/jwt-go reads as jwt. This is goimports' heuristic, by
// way of govulncheck, which keeps its copy in an internal package.
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
