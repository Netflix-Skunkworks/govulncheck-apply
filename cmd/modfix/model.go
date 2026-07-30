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

import "go/token"

// message is a single entry in the govulncheck -json stream. Entries other than
// findings and advisories decode to nil fields and are skipped.
type message struct {
	Finding *finding `json:"finding"`
	OSV     *osv     `json:"osv"`
}

// osv is the advisory a finding names. govulncheck emits it once, the first time
// a finding refers to it, either side of the findings themselves.
type osv struct {
	ID               string `json:"id"`
	Summary          string `json:"summary"`
	DatabaseSpecific struct {
		URL string `json:"url"`
	} `json:"database_specific"`
}

// finding reports one vulnerable module in the dependency graph. govulncheck
// emits a finding per trace granularity (module, package, called function), so
// the same OSV can appear several times with an identical module and fix.
// FixedVersion is empty when the database publishes no fix for the OSV.
type finding struct {
	OSV          string  `json:"osv"`
	FixedVersion string  `json:"fixed_version"`
	Trace        []frame `json:"trace"`
}

// frame is one step of a finding's call trace. trace[0] is the vulnerable module,
// and at the called-function granularity the frames run outwards from the
// vulnerable symbol to the call in the scanned module's own code.
type frame struct {
	Module   string `json:"module"`
	Version  string `json:"version"`
	Package  string `json:"package"`
	Function string `json:"function"`
	Receiver string `json:"receiver"`
	// Position is govulncheck's own, which is field for field go/token's, so its
	// String and IsValid render and validate a frame the way govulncheck does.
	Position *token.Position `json:"position"`
}
