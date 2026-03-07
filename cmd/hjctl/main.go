package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/dropDatabas3/hellojohn/cmd/hjctl/client"
)

// exitCodeForError maps well-known error patterns to semantic exit codes.
// 0 = success, 1 = general error, 2 = not found, 3 = auth error, 4 = conflict.
func exitCodeForError(err error) int {
	if err == nil {
		return 0
	}
	var ae *client.APIError
	if errors.As(err, &ae) {
		switch ae.Status {
		case 404:
			return 2
		case 401, 403:
			return 3
		case 409:
			return 4
		}
	}
	return 1
}

func main() {
	// CLI-20: propagate OS signals (Ctrl+C) through cmd.Context() in all commands.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(exitCodeForError(err))
	}
}
