//go:build windows

package commands

import "os"

// platformTermSignals is empty on Windows because SIGTERM is not a real
// signal there; process termination is handled by the OS directly.
var platformTermSignals = []os.Signal{}
