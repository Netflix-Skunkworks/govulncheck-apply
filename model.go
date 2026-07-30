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

// message is a single entry in the govulncheck -json stream. Entries other than
// findings decode to a nil Finding and are skipped.
type message struct {
	Finding *finding `json:"finding"`
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

// frame is one step of a finding's call trace; trace[0] is the vulnerable module.
type frame struct {
	Module string `json:"module"`
}
