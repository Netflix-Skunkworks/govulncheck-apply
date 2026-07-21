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

// Command govulncheck-apply reads a `govulncheck -json` stream on stdin and
// applies the identified fixes to the `go.mod`s in your working directory.
//
//	govulncheck -json ./... | go tool github.com/netflix-skunkworks/govulncheck-apply
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

func main() {
	dec := json.NewDecoder(os.Stdin)
	seen := map[string]bool{}
	decoded := false
	for {
		var msg message
		if err := dec.Decode(&msg); err == io.EOF {
			break
		} else if err != nil {
			// A parse failure on the very first entry almost always means the
			// input isn't the JSON stream at all (e.g. `-json` was forgotten,
			// so this is govulncheck's plain-text output).
			if decoded {
				fmt.Fprintln(os.Stderr, err)
			} else {
				fmt.Fprintln(os.Stderr, "input could not be parsed. did you pass govulncheck -json output to this program? the error was:", err)
			}
			os.Exit(1)
		}
		decoded = true

		f := msg.Finding
		if f == nil || len(f.Trace) == 0 || seen[f.OSV] {
			continue
		}
		seen[f.OSV] = true

		mod := f.Trace[0]
		fmt.Printf("Your code is affected by %s, found in %s@%s, fixed in %s@%s\n", f.OSV, mod.Module, mod.Version, mod.Module, f.FixedVersion)
	}
}
