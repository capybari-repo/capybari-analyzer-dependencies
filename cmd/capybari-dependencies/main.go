// Command capybari-dependencies runs this capability on its own.
package main

import (
	dependencies "github.com/capybari/capybari-analyzer-dependencies"
	"github.com/capybari/capybari-core/standalone"
)

var version = "dev"

func main() { standalone.Main(version, dependencies.New()) }
