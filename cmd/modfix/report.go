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
	"strings"
)

const stdlib = "stdlib"

// vuln is what the scans of one module said about one govulncheck advisory.
type vuln struct {
	osv           string
	url           string
	summary       string // the advisory's own one-line prose, if it publishes one
	module        string // the vulnerable module's path, or stdlib
	pkg           string // the vulnerable package, where a finding named one
	found         string // the version of it the first scan found
	selected      string // the version the run left selected, empty if unchanged
	fixedIn       string // the version that fixes it, empty if none is published
	stillReported bool   // whether the last pass reported it again
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

// entry renders one advisory as a title over the versions of the module it is
// against. Those are indented four spaces, which markdown reads as a code
// block, so a module path and its versions come out in a monospace font.
func entry(v vuln) string {
	var b strings.Builder
	fmt.Fprintf(&b, "**%s**", advisory(v))
	if v.summary != "" {
		fmt.Fprintf(&b, ": %s", oneLine(v.summary))
	}
	fmt.Fprintf(&b, "\n\n    %s\n", oneLine(versions(v)))
	return b.String()
}

// versions names the vulnerable module, the version the scan found, and where
// the run left it.
func versions(v vuln) string {
	module, found := vulnerableModule(v), toolchainName(v.module, v.found)
	var noted []string
	// The version that fixes an advisory is a minimum, so minimal version
	// selection can land above it, and naming only the minimum next to a diff
	// that says otherwise reads as a mistake. An advisory with no fix of its own
	// needs this too, because another advisory's fix can raise the same module.
	if v.selected != "" && v.selected != v.found && v.selected != v.fixedIn {
		noted = append(noted, "selected "+toolchainName(v.module, v.selected))
	}
	var line string
	if v.fixedIn == "" {
		line = fmt.Sprintf("%s %s, %s", module, found, noFix)
	} else {
		line = fmt.Sprintf("%s %s -> %s", module, found, toolchainName(v.module, v.fixedIn))
		if v.stillReported {
			noted = append(noted, fixNotTaken)
		}
	}
	if len(noted) == 0 {
		return line
	}
	return fmt.Sprintf("%s (%s)", line, strings.Join(noted, ", "))
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
