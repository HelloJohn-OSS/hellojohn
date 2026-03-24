package commands

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/localruntime"
	"github.com/spf13/cobra"
)

func newLocalConnectCmd() *cobra.Command {
	var (
		profile  string
		token    string
		cloudURL string
		baseURL  string
	)

	cmd := &cobra.Command{
		Use:   "connect",
		Short: "Connect local runtime to HelloJohn Cloud tunnel",
		RunE: func(cmd *cobra.Command, args []string) error {
			profile = localProfile(profile)

			// Auto-detect the running server URL from saved state so that a
			// port override (e.g. 8081 when 8080 was occupied) is respected.
			// An explicit --base-url flag always takes precedence.
			if !cmd.Flags().Changed("base-url") {
				if serverState, err := localruntime.ReadState[localruntime.ServerState](localruntime.ServerStateFile()); err == nil && serverState.BaseURL != "" {
					baseURL = serverState.BaseURL
				}
			}
			if strings.TrimSpace(baseURL) == "" {
				baseURL = "http://localhost:8080"
			}

			profileValues := map[string]string{}
			if values, err := localruntime.LoadProfile(profile); err == nil {
				profileValues = values
			}

			token = pickTunnelSetting(token, profileValues["HELLOJOHN_TUNNEL_TOKEN"], os.Getenv("HELLOJOHN_TUNNEL_TOKEN"))
			if strings.TrimSpace(token) == "" {
				return localActionError(
					"Tunnel token not found.",
					fmt.Sprintf("HELLOJOHN_TUNNEL_TOKEN is not set in %s", localruntime.EnvFile(profile)),
					"hjctl local env set HELLOJOHN_TUNNEL_TOKEN=hjtun_your_token_here",
					"or pass --token hjtun_... directly",
				)
			}

			cloudURL = pickTunnelSetting(cloudURL, profileValues["HELLOJOHN_CLOUD_URL"], os.Getenv("HELLOJOHN_CLOUD_URL"))
			if strings.TrimSpace(cloudURL) == "" {
				return localActionError(
					"Cloud URL not found.",
					fmt.Sprintf("HELLOJOHN_CLOUD_URL is not set in %s", localruntime.EnvFile(profile)),
					"hjctl local env set HELLOJOHN_CLOUD_URL=https://cloud.hellojohn.com",
					"or pass --cloud-url directly",
				)
			}

			alive, pid, err := localruntime.IsAlive(localruntime.TunnelPIDFile())
			if err != nil {
				return err
			}
			if alive {
				fmt.Fprintf(cmd.OutOrStdout(), "Tunnel is already running (pid %d).\n", pid)
				fmt.Fprintln(cmd.OutOrStdout(), "Run `hjctl local tunnel status` for details.")
				return nil
			}

			if err := probeHealth(baseURL); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "Warning: local server not reachable at %s. Tunnel will still connect.\n", baseURL)
			}

			hjctlPath, err := hjctlBinary()
			if err != nil {
				return localActionError(
					"Could not locate hjctl binary.",
					err.Error(),
					"Ensure hjctl is installed and in PATH.",
				)
			}

			workerArgs := []string{
				"_tunnel-worker",
				"--cloud-url", cloudURL,
				"--base-url", baseURL,
				"--state-file", localruntime.TunnelStateFile(),
				"--quiet",
			}

			workerEnvValues := make(map[string]string, len(profileValues)+1)
			for key, value := range profileValues {
				workerEnvValues[key] = value
			}
			workerEnvValues["HELLOJOHN_TUNNEL_TOKEN"] = token

			state := localruntime.TunnelState{
				ProcessState: localruntime.ProcessState{
					PID:       0,
					StartedAt: time.Now().UTC(),
					Profile:   profile,
				},
				CloudURL:    cloudURL,
				TokenPrefix: tunnelTokenPrefix(token),
				Connected:   false,
			}
			if err := localruntime.WriteState(localruntime.TunnelStateFile(), state); err != nil {
				return err
			}

			pid, err = localruntime.Spawn(
				hjctlPath,
				workerArgs,
				mapToEnv(workerEnvValues),
				localruntime.TunnelPIDFile(),
				localruntime.TunnelLogFile(),
			)
			if err != nil {
				_ = os.Remove(localruntime.TunnelStateFile())
				return err
			}

			if err := waitForTunnelConnection(cmd, 5*time.Second); err != nil {
				return localActionError(
					"Tunnel connection could not be confirmed.",
					err.Error(),
					"hjctl local tunnel logs --follow",
					"hjctl local tunnel status",
				)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Tunnel connected (pid %d) to %s\n", pid, cloudURL)
			printNextSteps(cmd.OutOrStdout(), []string{
				"hjctl local tunnel status",
				"hjctl local tunnel logs --follow",
				"hjctl local stop --tunnel-only",
			})
			return nil
		},
	}

	cmd.Flags().StringVar(&profile, "profile", defaultLocalProfile, "Local runtime profile name")
	cmd.Flags().StringVar(&token, "token", "", "Tunnel token")
	cmd.Flags().StringVar(&cloudURL, "cloud-url", "", "HelloJohn Cloud URL")
	// Default is empty so that Changed("base-url") reliably detects explicit use.
	// When not set, RunE reads the port from the saved server state file.
	cmd.Flags().StringVar(&baseURL, "base-url", "", "Local server base URL (default: auto-detected from running server state)")
	return cmd
}

func newLocalTunnelCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tunnel",
		Short: "Manage tunnel process",
	}
	cmd.AddCommand(newLocalTunnelStatusCmd())
	cmd.AddCommand(newLocalTunnelStartCmd())
	cmd.AddCommand(newLocalTunnelStopCmd())
	cmd.AddCommand(newLocalTunnelLogsCmd())
	return cmd
}

// newLocalTunnelStartCmd is an alias for `hjctl local connect` exposed under
// the `tunnel` subcommand group so that the intuitive `hjctl local tunnel start`
// just works.
func newLocalTunnelStartCmd() *cobra.Command {
	inner := newLocalConnectCmd()
	inner.Use = "start"
	inner.Short = "Connect tunnel to HelloJohn Cloud (alias for: hjctl local connect)"
	return inner
}

func newLocalTunnelStatusCmd() *cobra.Command {
	var profile string

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show tunnel status",
		RunE: func(cmd *cobra.Command, args []string) error {
			_ = localProfile(profile)
			alive, pid, err := localruntime.IsAlive(localruntime.TunnelPIDFile())
			if err != nil {
				return err
			}
			if !alive {
				fmt.Fprintln(cmd.OutOrStdout(), "Tunnel is stopped.")
				return nil
			}

			state, err := localruntime.ReadState[localruntime.TunnelState](localruntime.TunnelStateFile())
			if err != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "Tunnel running (pid %d). State unavailable.\n", pid)
				return nil
			}

			status := "running (reconnecting)"
			if state.Connected {
				status = "connected"
			}
			uptime := "unknown"
			if !state.StartedAt.IsZero() {
				uptime = time.Since(state.StartedAt).Round(time.Second).String()
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Tunnel: %s\n", status)
			fmt.Fprintf(cmd.OutOrStdout(), "  PID: %d\n", pid)
			fmt.Fprintf(cmd.OutOrStdout(), "  Uptime: %s\n", uptime)
			if strings.TrimSpace(state.CloudURL) != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "  Cloud URL: %s\n", state.CloudURL)
			}
			if strings.TrimSpace(state.TokenPrefix) != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "  Token Prefix: %s\n", state.TokenPrefix)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&profile, "profile", defaultLocalProfile, "Local runtime profile name")
	return cmd
}

func newLocalTunnelStopCmd() *cobra.Command {
	var profile string

	cmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop tunnel process",
		RunE: func(cmd *cobra.Command, args []string) error {
			_ = localProfile(profile)
			if err := localruntime.StopProcess(localruntime.TunnelPIDFile(), localruntime.TunnelStateFile(), 5*time.Second); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Tunnel stopped.")
			return nil
		},
	}

	cmd.Flags().StringVar(&profile, "profile", defaultLocalProfile, "Local runtime profile name")
	return cmd
}

func newLocalTunnelLogsCmd() *cobra.Command {
	var (
		profile string
		follow  bool
		tail    int
	)

	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Show tunnel logs",
		RunE: func(cmd *cobra.Command, args []string) error {
			_ = localProfile(profile)
			logFile := localruntime.TunnelLogFile()
			if err := streamLogFile(cmd.Context(), logFile, tail, follow, cmd.OutOrStdout()); err != nil {
				if errors.Is(err, os.ErrNotExist) {
					return localActionError(
						"Tunnel log file not found.",
						fmt.Sprintf("%s does not exist.", logFile),
						"Run: hjctl local connect --token hjtun_...",
					)
				}
				return err
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&profile, "profile", defaultLocalProfile, "Local runtime profile name")
	cmd.Flags().BoolVar(&follow, "follow", false, "Follow logs")
	cmd.Flags().IntVar(&tail, "tail", defaultLogTail, "Number of lines to show")
	return cmd
}

func pickTunnelSetting(primary string, secondary string, fallback string) string {
	if value := strings.TrimSpace(primary); value != "" {
		return value
	}
	if value := strings.TrimSpace(secondary); value != "" {
		return value
	}
	return strings.TrimSpace(fallback)
}

func tunnelTokenPrefix(token string) string {
	token = strings.TrimSpace(token)
	if len(token) <= 12 {
		return token
	}
	return token[:12]
}

func waitForTunnelConnection(cmd *cobra.Command, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		select {
		case <-cmd.Context().Done():
			return cmd.Context().Err()
		default:
		}

		state, err := localruntime.ReadState[localruntime.TunnelState](localruntime.TunnelStateFile())
		if err == nil && state.Connected {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("worker did not set connected=true within %s", timeout)
}
