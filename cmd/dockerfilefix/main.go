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

// Command dockerfilefix raises the golang image tag in every Dockerfile under the
// working directory to the go directive of the module that Dockerfile builds.
//
//	go install github.com/netflix-skunkworks/govulncheck-apply/cmd/dockerfilefix@latest
//	dockerfilefix
//
// A builder stage declares its own Go, and the official golang images set
// GOTOOLCHAIN=local, so a go directive above the image's Go fails `go mod
// download` inside the image. Running this after modfix, which raises a go
// directive to fix a standard-library vulnerability, leaves the images building
// their modules again.
//
// A tag is only ever raised: an image already past the go directive builds the
// module as it is. Files are edited in place, and each one edited is named on
// stdout.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/netflix-skunkworks/govulncheck-apply/internal/gomod"
)

// fromGolang matches an official golang image on a FROM line, up to and including
// the version its tag starts with. A tag naming only a major, such as golang:1,
// already follows the newest release, so a minor is required too.
var fromGolang = regexp.MustCompile(`(?m)^FROM\s.*?\bgolang:\d+\.\d+(?:\.\d+)?`)

func main() {
	rewritten, err := raise()
	// Named before the error is reported, because a walk that stopped partway has
	// already rewritten these and whatever commits the result has to know.
	for _, path := range rewritten {
		fmt.Println(path)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// raise rewrites every Dockerfile under the working directory that names a golang
// image below the go directive of the module it builds, and returns the ones it
// rewrote, in slash-separated form. A failure part way through returns what had
// been rewritten by then.
func raise() ([]string, error) {
	dirs, err := gomod.Modules(".")
	if err != nil {
		return nil, err
	}
	// Every module's go directive is read before the Dockerfiles are, so that
	// several Dockerfiles under one module do not each re-read its go.mod. A
	// module declaring no directive is left out: its images have nothing to be
	// raised to.
	directives := make(map[string]string, len(dirs))
	for _, dir := range dirs {
		mod, err := gomod.Read(dir)
		if err != nil {
			return nil, err
		}
		if mod.Go != nil {
			directives[dir] = gomod.FullVersion(mod.Go.Version)
		}
	}

	var rewritten []string
	err = gomod.Walk(".", func(path string) error {
		if !strings.HasPrefix(filepath.Base(path), "Dockerfile") {
			return nil
		}
		version, ok := directives[module(path, dirs)]
		if !ok {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		dockerfile := string(data)
		raised := raiseTags(dockerfile, version)
		if raised == dockerfile {
			return nil
		}
		if err := os.WriteFile(path, []byte(raised), 0o644); err != nil {
			return err
		}
		rewritten = append(rewritten, filepath.ToSlash(path))
		return nil
	})
	return rewritten, err
}

// module returns the directory of the module a file belongs to: the innermost of
// the module directories it sits under, since a Dockerfile builds one module
// rather than every module in the repository. dirs is [gomod.Modules]' order,
// outermost first, and the answer is "" for a file under none of them.
func module(path string, dirs []string) string {
	var innermost string
	for _, dir := range dirs {
		if rel, err := filepath.Rel(dir, path); err == nil && !strings.HasPrefix(rel, "..") {
			innermost = dir
		}
	}
	return innermost
}

// raiseTags returns the Dockerfile with every golang image tag below version
// raised to it. Only the version itself is rewritten, so a registry prefix, a
// --platform flag and a tag suffix such as -alpine all come through as they were.
//
// A tag naming no patch, such as golang:1.24, follows that line's newest patch
// release, and [gomod.Higher] orders it as the oldest release it can resolve to:
// enough for a module on go 1.24.0, and not enough for one on go 1.24.3.
func raiseTags(dockerfile, version string) string {
	return fromGolang.ReplaceAllStringFunc(dockerfile, func(from string) string {
		// The match ends at the version, so its last colon is the one separating
		// the image from its tag, whatever a registry prefix holds.
		tag := strings.LastIndex(from, ":") + 1
		if !gomod.Higher(version, from[tag:]) {
			return from
		}
		return from[:tag] + version
	})
}
