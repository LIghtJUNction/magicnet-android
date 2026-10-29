package main

import (
	"magicnet.local/rebuild/internal/magicnet"
	"os"
)

func main() { os.Exit(magicnet.Main(os.Args[1:])) }
