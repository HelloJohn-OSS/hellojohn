package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dropDatabas3/hellojohn/cmd/hjctl/cfg"
	"github.com/dropDatabas3/hellojohn/internal/localruntime"
	"github.com/spf13/cobra"
)

const (
	defaultLocalProfile = "default"
	defaultLogTail      = 200
)

// NewLocalCmd creates `hjctl local` command group.
func NewLocalCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "local",
		Short: "Manage local runtime (server and tunnel)",
	}

	cmd.AddCommand(newLocalInitCmd())
	cmd.AddCommand(newLocalStartCmd())
	cmd.AddCommand(newLocalStopCmd())
	cmd.AddCommand(newLocalStatusCmd())
	cmd.AddCommand(newLocalLogsCmd())
	cmd.AddCommand(newLocalConnectCmd())
	cmd.AddCommand(newLocalTunnelCmd())
	cmd.AddCommand(NewLocalEnvCmd())

	return cmd
}

func newLocalInitCmd() *cobra.Command {
	var (
		profile string
		force   bool
	)

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize local runtime profile",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := localruntime.InitProfile(profile, force); err != nil {
				return localActionError(
					"Could not initialize local profile.",
					err.Error(),
					fmt.Sprintf("Run: hjctl local init --profile %s --force", localProfile(profile)),
				)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Profile initialized: %s\n", localruntime.EnvFile(profile))
			printNextSteps(cmd.OutOrStdout(), []string{
				"hjctl local env list",
				"hjctl local start",
			})
			return nil
		},
	}

	cmd.Flags().StringVar(&profile, "profile", defaultLocalProfile, "Local runtime profile name")
	cmd.Flags().BoolVar(&force, "force", false, "Overwrite existing profile file")
	return cmd
}

func newLocalStartCmd() *cobra.Command {
	var (
		profile    string
		port       int
		foreground bool
	)

	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start local HelloJohn server",
		RunE: func(cmd *cobra.Command, args []string) error {
			profile = localProfile(profile)

			envValues, err := localruntime.LoadProfile(profile)
			if err != nil {
				return localActionError(
					"Profile not found.",
					err.Error(),
					fmt.Sprintf("Run: hjctl local init --profile %s", profile),
				)
			}

			if validationErr := validateStartProfile(profile); validationErr != nil {
				return validationErr
			}

			serverAlive, pid, err := localruntime.IsAlive(localruntime.ServerPIDFile())
			if err != nil {
				return err
			}
			if serverAlive {
				fmt.Fprintf(cmd.OutOrStdout(), "hellojohn is already running (pid %d).\n", pid)
				fmt.Fprintln(cmd.OutOrStdout(), "Run `hjctl local status` for details.")
				return nil
			}

			baseURL, resolvedPort, err := resolveServerBaseURL(envValues, port)
			if err != nil {
				return localActionError(
					"Invalid BASE_URL in profile.",
					err.Error(),
					fmt.Sprintf("Run: hjctl local env set BASE_URL=http://localhost:%d", 8080),
				)
			}

			binary, err := hellojohnBinary()
			if err != nil {
				return localActionError(
					"Could not locate hellojohn binary.",
					err.Error(),
					"Install or add `hellojohn` to PATH.",
				)
			}

			serverArgs := []string{"--port", strconv.Itoa(resolvedPort)}
			env := mapToEnv(envValues)
			env = append(env, "BASE_URL="+baseURL)
			env = append(env, "V2_SERVER_ADDR=:"+strconv.Itoa(resolvedPort))

			if foreground {
				run := exec.CommandContext(cmd.Context(), binary, serverArgs...)
				run.Env = append(os.Environ(), env...)
				run.Stdin = os.Stdin
				run.Stdout = cmd.OutOrStdout()
				run.Stderr = cmd.ErrOrStderr()
				return run.Run()
			}

			if err := os.MkdirAll(localruntime.RunDir(), 0o755); err != nil {
				return fmt.Errorf("create run dir: %w", err)
			}

			pid, err = localruntime.Spawn(
				binary,
				serverArgs,
				env,
				localruntime.ServerPIDFile(),
				localruntime.ServerLogFile(),
			)
			if err != nil {
				return err
			}

			state := localruntime.ServerState{
				ProcessState: localruntime.ProcessState{
					PID:       pid,
					StartedAt: time.Now().UTC(),
					Profile:   profile,
				},
				Port:    resolvedPort,
				BaseURL: baseURL,
			}
			if err := localruntime.WriteState(localruntime.ServerStateFile(), state); err != nil {
				_ = localruntime.StopProcess(localruntime.ServerPIDFile(), localruntime.ServerStateFile(), 2*time.Second)
				return err
			}

			if err := waitForHealth(cmd.Context(), baseURL, 5, 2*time.Second); err != nil {
				return localActionError(
					"Server health check timed out.",
					fmt.Sprintf("hellojohn (pid %d) did not respond on %s after 8s (5 probes, 2s apart).", pid, baseURL),
					"hjctl local logs --tail 50",
				)
			}

			// Provision an admin API key if one is not already configured.
			// The tunnel worker needs it to authenticate requests to the local server.
			bootstrapLocalAPIKey(cmd.OutOrStdout(), baseURL, profile)

			fmt.Fprintf(cmd.OutOrStdout(), "Server started (pid %d) at %s\n", pid, baseURL)
			steps := []string{
				"hjctl local status",
				"hjctl local logs --follow",
				"hjctl local stop",
			}

			tunnelAlive, _, _ := localruntime.IsAlive(localruntime.TunnelPIDFile())
			if !tunnelAlive {
				steps = append(steps, "hjctl local connect --token hjtun_...")
			}
			printNextSteps(cmd.OutOrStdout(), steps)
			return nil
		},
	}

	cmd.Flags().StringVar(&profile, "profile", defaultLocalProfile, "Local runtime profile name")
	cmd.Flags().IntVar(&port, "port", 0, "Server port override")
	cmd.Flags().BoolVar(&foreground, "foreground", false, "Run server in foreground")
	return cmd
}

func newLocalStopCmd() *cobra.Command {
	var (
		profile    string
		serverOnly bool
		tunnelOnly bool
	)

	cmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop local runtime processes",
		RunE: func(cmd *cobra.Command, args []string) error {
			_ = localProfile(profile)
			if serverOnly && tunnelOnly {
				return fmt.Errorf("--server-only and --tunnel-only cannot be used together")
			}

			stopped := make([]string, 0, 2)
			if !tunnelOnly {
				if err := localruntime.StopProcess(localruntime.ServerPIDFile(), localruntime.ServerStateFile(), 5*time.Second); err != nil {
					return err
				}
				stopped = append(stopped, "server")
			}
			if !serverOnly {
				if err := localruntime.StopProcess(localruntime.TunnelPIDFile(), localruntime.TunnelStateFile(), 5*time.Second); err != nil {
					return err
				}
				stopped = append(stopped, "tunnel")
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Stopped: %s\n", strings.Join(stopped, ", "))
			return nil
		},
	}

	// --profile is accepted for forward compatibility but stop currently targets
	// the default run-directory paths regardless of profile.
	cmd.Flags().StringVar(&profile, "profile", defaultLocalProfile, "Local runtime profile name (reserved; currently targets default paths)")
	cmd.Flags().BoolVar(&serverOnly, "server-only", false, "Stop only server process")
	cmd.Flags().BoolVar(&tunnelOnly, "tunnel-only", false, "Stop only tunnel process")
	return cmd
}

func newLocalStatusCmd() *cobra.Command {
	var profile string

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show local runtime status",
		RunE: func(cmd *cobra.Command, args []string) error {
			profile = localProfile(profile)

			serverAlive, serverPID, err := localruntime.IsAlive(localruntime.ServerPIDFile())
			if err != nil {
				return err
			}
			tunnelAlive, tunnelPID, err := localruntime.IsAlive(localruntime.TunnelPIDFile())
			if err != nil {
				return err
			}

			serverState, _ := localruntime.ReadState[localruntime.ServerState](localruntime.ServerStateFile())
			tunnelState, _ := localruntime.ReadState[localruntime.TunnelState](localruntime.TunnelStateFile())

			fmt.Fprintf(cmd.OutOrStdout(), "Local runtime status (profile: %s)\n", profile)
			if serverAlive {
				status := "healthy"
				targetURL := strings.TrimSpace(serverState.BaseURL)
				if targetURL == "" {
					targetURL = "http://localhost:8080"
				}
				if err := probeHealth(targetURL); err != nil {
					status = "unhealthy"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "  Server : running (pid %d) - %s - %s\n", serverPID, targetURL, status)
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "  Server : stopped")
			}

			if tunnelAlive {
				tunnelStatus := "running"
				if tunnelState.Connected {
					tunnelStatus = "connected"
				} else {
					tunnelStatus = "running (reconnecting)"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "  Tunnel : %s (pid %d)\n", tunnelStatus, tunnelPID)
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "  Tunnel : stopped")
			}

			// Warn if the auto-generated credentials file still exists.
			envValues, _ := localruntime.LoadProfile(profile)
			fsRoot := strings.TrimSpace(envValues["FS_ROOT"])
			if fsRoot == "" {
				fsRoot = "data"
			}
			credPath := filepath.Join(fsRoot, "initial-credentials.txt")
			if _, statErr := os.Stat(credPath); statErr == nil {
				fmt.Fprintln(cmd.OutOrStdout(), "")
				fmt.Fprintln(cmd.OutOrStdout(), "  ⚠  Initial admin credentials file found: "+credPath)
				fmt.Fprintln(cmd.OutOrStdout(), "     Log in and delete this file once you have set a secure password.")
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&profile, "profile", defaultLocalProfile, "Local runtime profile name")
	return cmd
}

func newLocalLogsCmd() *cobra.Command {
	var (
		profile string
		follow  bool
		tail    int
	)

	cmd := &cobra.Command{
		Use:   "logs",
		Short: "Show local server logs",
		RunE: func(cmd *cobra.Command, args []string) error {
			_ = localProfile(profile)
			logFile := localruntime.ServerLogFile()
			if err := streamLogFile(cmd.Context(), logFile, tail, follow, cmd.OutOrStdout()); err != nil {
				if errors.Is(err, os.ErrNotExist) {
					return localActionError(
						"Server log file not found.",
						fmt.Sprintf("%s does not exist.", logFile),
						"Run: hjctl local start",
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

func validateStartProfile(profile string) error {
	validationErrs := localruntime.ValidateProfile(profile)
	if len(validationErrs) == 0 {
		return nil
	}

	first := validationErrs[0]
	return localActionError(
		"Profile validation failed.",
		fmt.Sprintf("%s: %s", first.Key, first.Message),
		"Run: hjctl local env validate",
		fmt.Sprintf("Run: hjctl local init --profile %s --force", profile),
	)
}

// healthClient is shared across all health probes to avoid per-call allocation.
var healthClient = &http.Client{Timeout: 2 * time.Second}

func waitForHealth(ctx context.Context, baseURL string, retries int, wait time.Duration) error {
	var lastErr error
	for i := 0; i < retries; i++ {
		if err := probeHealth(baseURL); err == nil {
			return nil
		} else {
			lastErr = err
		}

		// Skip wait after the last attempt so the caller gets the error immediately.
		if i < retries-1 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
		}
	}
	if lastErr == nil {
		lastErr = errors.New("health probe failed")
	}
	return lastErr
}

func probeHealth(baseURL string) error {
	healthURL := strings.TrimRight(baseURL, "/") + "/health"
	req, err := http.NewRequest(http.MethodGet, healthURL, nil)
	if err != nil {
		return err
	}
	resp, err := healthClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}
	return nil
}

func resolveServerBaseURL(values map[string]string, overridePort int) (string, int, error) {
	raw := strings.TrimSpace(values["BASE_URL"])
	if raw == "" {
		raw = "http://localhost:8080"
	}

	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" {
		return "", 0, fmt.Errorf("invalid BASE_URL %q", raw)
	}
	hostname := parsed.Hostname()
	if hostname == "" {
		hostname = "localhost"
	}

	port := overridePort
	if port <= 0 {
		port = inferPort(parsed)
	}

	parsed.Host = net.JoinHostPort(hostname, strconv.Itoa(port))
	return parsed.String(), port, nil
}

func inferPort(target *url.URL) int {
	if p := target.Port(); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			return parsed
		}
	}
	switch strings.ToLower(target.Scheme) {
	case "https":
		return 443
	case "http":
		return 80
	default:
		return 8080
	}
}

func printNextSteps(w io.Writer, steps []string) {
	if len(steps) == 0 {
		return
	}
	fmt.Fprintln(w, "Next steps:")
	for _, step := range steps {
		fmt.Fprintf(w, "  - %s\n", step)
	}
}

func localProfile(profile string) string {
	profile = strings.TrimSpace(profile)
	if profile == "" {
		return defaultLocalProfile
	}
	return profile
}

func mapToEnv(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, fmt.Sprintf("%s=%s", key, values[key]))
	}
	return out
}

// bootstrapLocalAPIKey provisions an admin API key for the running server if none
// is configured. It authenticates with the admin credentials from the profile and
// stores the generated key in:
//   - ~/.hjctl/config.yaml  (read by localAPIKey() as fallback)
//   - profile env HELLOJOHN_API_KEY  (inherited by the tunnel worker subprocess)
//
// Failures are non-fatal — the user can provision a key manually via:
//
//	hjctl admin api-keys create --scope admin
//	hjctl config set api-key <token>
func bootstrapLocalAPIKey(out io.Writer, baseURL, profile string) {
	// Skip if already configured.
	if key := strings.TrimSpace(os.Getenv("HELLOJOHN_API_KEY")); key != "" {
		return
	}
	c, _ := cfg.Load()
	if strings.TrimSpace(c.APIKey) != "" {
		return
	}
	profileValues, err := localruntime.LoadProfile(profile)
	if err != nil {
		return
	}
	if strings.TrimSpace(profileValues["HELLOJOHN_API_KEY"]) != "" {
		return
	}
	email := strings.TrimSpace(profileValues["HELLOJOHN_ADMIN_EMAIL"])
	password := strings.TrimSpace(profileValues["HELLOJOHN_ADMIN_PASSWORD"])
	if email == "" || password == "" {
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}
	base := strings.TrimRight(baseURL, "/")

	// Step 1: login with admin credentials to get a short-lived JWT.
	loginBody, _ := json.Marshal(map[string]string{"email": email, "password": password})
	loginResp, err := client.Post(base+"/v2/admin/login", "application/json", bytes.NewReader(loginBody))
	if err != nil || loginResp.StatusCode != http.StatusOK {
		return
	}
	defer loginResp.Body.Close()
	var loginResult struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(loginResp.Body).Decode(&loginResult); err != nil || loginResult.AccessToken == "" {
		return
	}

	// Step 2: create a non-expiring admin API key.
	keyBody, _ := json.Marshal(map[string]string{"name": "hjctl-local", "scope": "admin"})
	keyReq, _ := http.NewRequest(http.MethodPost, base+"/v2/admin/api-keys", bytes.NewReader(keyBody))
	keyReq.Header.Set("Content-Type", "application/json")
	keyReq.Header.Set("Authorization", "Bearer "+loginResult.AccessToken)
	keyResp, err := client.Do(keyReq)
	if err != nil || keyResp.StatusCode != http.StatusCreated {
		return
	}
	defer keyResp.Body.Close()
	var keyResult struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := json.NewDecoder(keyResp.Body).Decode(&keyResult); err != nil {
		return
	}
	rawKey := strings.TrimSpace(keyResult.Data.Token)
	if rawKey == "" {
		return
	}

	// Persist to ~/.hjctl/config.yaml so localAPIKey() finds it via cfg.Load().
	// Also persist BaseURL so commands like `hjctl auth login` work without
	// requiring an explicit --base-url when the port differs from 8080.
	c.APIKey = rawKey
	if strings.TrimSpace(c.BaseURL) == "" {
		c.BaseURL = base
	}
	_ = cfg.Save(c)

	// Persist to profile env so the tunnel worker subprocess inherits it directly.
	_ = localruntime.WriteProfile(profile, map[string]string{"HELLOJOHN_API_KEY": rawKey})

	fmt.Fprintln(out, "  API key provisioned for tunnel authentication.")
}

// hellojohnBinary resolves the server binary path.
// Search order:
// 1) ~/.hellojohn/bin/hellojohn
// 2) sibling of current hjctl binary
// 3) PATH (hellojohn, then service)
func hellojohnBinary() (string, error) {
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}

	candidates := []string{
		filepath.Join(localruntime.BinDir(), "hellojohn"+ext),
	}

	if exePath, err := os.Executable(); err == nil {
		dir := filepath.Dir(exePath)
		candidates = append(candidates, filepath.Join(dir, "hellojohn"+ext))
	}

	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}

	if path, err := exec.LookPath("hellojohn"); err == nil {
		return path, nil
	}
	if path, err := exec.LookPath("service"); err == nil {
		return path, nil
	}
	return "", fmt.Errorf("`hellojohn` not found in ~/.hellojohn/bin or PATH")
}

// hjctlBinary resolves the current hjctl binary path.
func hjctlBinary() (string, error) {
	if exePath, err := os.Executable(); err == nil && strings.TrimSpace(exePath) != "" {
		return exePath, nil
	}
	path, err := exec.LookPath("hjctl")
	if err != nil {
		return "", err
	}
	return path, nil
}

func localActionError(what string, cause string, actions ...string) error {
	var b strings.Builder
	b.WriteString("x " + what)
	if strings.TrimSpace(cause) != "" {
		b.WriteString("\n  Cause: " + strings.TrimSpace(cause))
	}
	if len(actions) > 0 {
		b.WriteString("\n  Action: " + strings.TrimSpace(actions[0]))
		for _, action := range actions[1:] {
			b.WriteString("\n          " + strings.TrimSpace(action))
		}
	}
	return errors.New(b.String())
}

func streamLogFile(ctx context.Context, path string, tail int, follow bool, out io.Writer) error {
	offset, err := printLogTail(path, tail, out)
	if err != nil {
		return err
	}
	if !follow {
		return nil
	}

	ticker := time.NewTicker(400 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			info, err := os.Stat(path)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				return err
			}
			if info.Size() < offset {
				offset = 0
			}
			if info.Size() == offset {
				continue
			}

			fh, err := os.Open(path)
			if err != nil {
				return err
			}
			if _, err := fh.Seek(offset, io.SeekStart); err != nil {
				_ = fh.Close()
				return err
			}
			n, err := io.Copy(out, fh)
			_ = fh.Close()
			if err != nil {
				return err
			}
			offset += n
		}
	}
}

func printLogTail(path string, tail int, out io.Writer) (int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}

	normalized := strings.ReplaceAll(string(data), "\r\n", "\n")
	lines := strings.Split(normalized, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	if tail < 0 {
		tail = 0
	}
	if tail > 0 && len(lines) > tail {
		lines = lines[len(lines)-tail:]
	}

	for _, line := range lines {
		fmt.Fprintln(out, line)
	}
	return int64(len(data)), nil
}
