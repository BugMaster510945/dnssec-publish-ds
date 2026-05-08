package main

import (
	"os"

	"gitlab.syshawk.com/planchon/dnssec-publish-ds/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
