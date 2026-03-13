//go:build !windows

package commands

import (
	"os"
	"syscall"
)

// platformTermSignals contains OS-specific termination signals to handle.
// On Unix, SIGTERM is the standard graceful-stop signal sent by hjctl local stop.
var platformTermSignals = []os.Signal{syscall.SIGTERM}
