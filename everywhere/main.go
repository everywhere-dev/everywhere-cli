package main

import (
	"fmt"
	"os"

	"github.com/everywhere-dev/everywhere-cli/cmd"
)

var version = "0.1.1"

func main() {
	root := cmd.NewRootCmd()
	root.Version = version

	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
