package main

import (
	cfgpkg "github.com/dropDatabas3/hellojohn/cmd/hjctl/cfg"
)

// Config is a type alias for the canonical cfg.Config.
// root.go uses this type; it delegates to the shared cfg package to avoid
// duplicate struct definitions between package main and package commands.
type Config = cfgpkg.Config

// loadConfig reads the config file. Returns zero Config if not found.
func loadConfig() (Config, error) {
	return cfgpkg.Load()
}

// saveConfig writes the config file with 0600 permissions.
func saveConfig(c Config) error {
	return cfgpkg.Save(c)
}
