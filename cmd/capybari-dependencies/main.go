// Command capybari-dependencies runs this capability on its own.
package main

import (
	dependencies "github.com/capybari-repo/capybari-analyzer-dependencies"
	"github.com/capybari-repo/capybari-core/standalone"
)

var version = "dev"

func main() { standalone.Main(version, dependencies.New()) }
