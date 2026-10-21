// argusctl is an operator tool for checks that must not depend on the hub.
//
// `argusctl audit verify` re-verifies the audit log's hash chain straight
// against Postgres, so a compromised or misbehaving hub cannot vouch for its
// own audit trail. Installing, upgrading and enrolling are Helm's job (the
// hub and agent charts); argusctl does none of them.
package main

import (
	"fmt"
	"os"

	"argus/internal/buildinfo"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "version", "--version":
		fmt.Printf("argusctl %s\n", buildinfo.Version())
	case "audit":
		if len(os.Args) < 3 || os.Args[2] != "verify" {
			usage()
			os.Exit(1)
		}
		runAuditVerify(os.Args[3:])
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: argusctl audit verify [--database-url <postgres-url>]")
	fmt.Fprintln(os.Stderr, "       argusctl version")
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "argusctl: "+format+"\n", args...)
	os.Exit(1)
}
