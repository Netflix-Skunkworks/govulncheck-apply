// Command repro reproduces a txtar testcase by creawting the directory and
// files in a temp dir.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path"

	"golang.org/x/tools/txtar"
)

var testcase = flag.String("testcase", "", "ex: vuln_xtext")

func main() {
	ctx := context.Background()
	flag.Parse()
	if err := run(ctx); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run(_ context.Context) error {
	if *testcase == "" {
		return fmt.Errorf("no --testcase passed")
	}
	path := path.Join("internal", "testcases", *testcase+".txtar")
	archive, err := txtar.ParseFile(path)
	if err != nil {
		return fmt.Errorf("unable to parse file %q: %v", path, err)
	}
	fsys, err := txtar.FS(archive)
	if err != nil {
		return fmt.Errorf("unable to create FS from txtar: %v", err)
	}
	dir, err := os.MkdirTemp("", "repro")
	if err != nil {
		return fmt.Errorf("unable to create temp dir: %v", err)
	}
	if err := os.CopyFS(dir, fsys); err != nil {
		return fmt.Errorf("unable to copy txtar FS to %q: %v", dir, err)
	}
	fmt.Printf("repro created at %q\n", dir)
	return nil
}
