package main

// message is a single entry in the govulncheck -json stream. The stream mixes
// several entry types (config, SBOM, progress, osv, finding); we only care
// about findings, so every other type decodes to a nil Finding and is skipped.
type message struct {
	Finding *finding `json:"finding"`
}

// finding reports one vulnerable module in the dependency graph. govulncheck
// emits a finding per trace granularity (module, package, called function), so
// the same OSV can appear several times with an identical module and fix.
type finding struct {
	OSV          string  `json:"osv"`
	FixedVersion string  `json:"fixed_version"`
	Trace        []frame `json:"trace"`
}

// frame is one step of a finding's call trace; trace[0] is the vulnerable module.
type frame struct {
	Module string `json:"module"`
}
