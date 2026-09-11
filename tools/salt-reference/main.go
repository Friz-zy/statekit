// Command salt-reference indexes the pinned SaltStack revision into a
// machine-readable catalog and migration coverage report.
//
// Outputs (relative to -out and -lock):
//
//	docs/catalog/exec/<module>.yaml    execution module inventory
//	docs/catalog/states/<module>.yaml  state module inventory
//	docs/catalog/index.yaml            summary index
//	docs/catalog/coverage.yaml         migration coverage vs StateKit
//	references/salt.lock               pinned repository/commit/version
//
// Reference: plans/init.md sections 20-21, 30.
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	salt := flag.String("salt", "saltstack", "path to the vendored Salt tree")
	out := flag.String("out", "docs/catalog", "catalog output directory")
	lock := flag.String("lock", "references/salt.lock", "salt lock file path")
	src := flag.String("src", ".", "StateKit repository root for implemented-function detection")
	flag.Parse()

	if err := run(*salt, *out, *lock, *src); err != nil {
		fmt.Fprintf(os.Stderr, "salt-reference: %v\n", err)
		os.Exit(1)
	}
}

func run(saltDir, outDir, lockPath, srcRoot string) error {
	ref, err := resolveReference(saltDir, lockPath)
	if err != nil {
		return err
	}
	execDocs, stateDocs, err := scanSaltTree(saltDir)
	if err != nil {
		return err
	}
	impl, err := detectImplemented(srcRoot)
	if err != nil {
		return err
	}
	cov := buildCoverage(ref, execDocs, stateDocs, impl)
	if err := writeCatalog(outDir, ref, execDocs, stateDocs, cov, impl); err != nil {
		return err
	}
	if err := writeSaltLock(lockPath, ref); err != nil {
		return err
	}
	fmt.Printf("indexed %d exec modules (%d functions), %d state modules (%d functions) at %s (%s)\n",
		len(execDocs), countFunctions(execDocs), len(stateDocs), countFunctions(stateDocs),
		ref.Commit[:12], ref.Version)
	fmt.Printf("coverage: exec relevant=%d implemented=%d; states relevant=%d implemented=%d\n",
		cov.Execution.RelevantFunctions, cov.Execution.Implemented,
		cov.State.RelevantFunctions, cov.State.Implemented)
	return nil
}
