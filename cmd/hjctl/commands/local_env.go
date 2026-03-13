package commands

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strings"

	"github.com/dropDatabas3/hellojohn/internal/localruntime"
	"github.com/spf13/cobra"
)

var envAssignmentKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

var knownLocalProfileKeys = map[string]struct{}{
	"SIGNING_MASTER_KEY":     {},
	"SECRETBOX_MASTER_KEY":   {},
	"APP_ENV":                {},
	"BASE_URL":               {},
	"UI_BASE_URL":            {},
	"FS_ROOT":                {},
	"CORS_ORIGINS":           {},
	"FS_ADMIN_ENABLE":        {},
	"HELLOJOHN_CLOUD_URL":    {},
	"HELLOJOHN_TUNNEL_TOKEN": {},
}

// NewLocalEnvCmd creates `hjctl local env`.
func NewLocalEnvCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "env",
		Short: "Manage local runtime profile variables",
	}

	cmd.AddCommand(newLocalEnvListCmd())
	cmd.AddCommand(newLocalEnvGetCmd())
	cmd.AddCommand(newLocalEnvSetCmd())
	cmd.AddCommand(newLocalEnvUnsetCmd())
	cmd.AddCommand(newLocalEnvEditCmd())
	cmd.AddCommand(newLocalEnvValidateCmd())
	return cmd
}

func newLocalEnvListCmd() *cobra.Command {
	var profile string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List profile variables",
		RunE: func(cmd *cobra.Command, args []string) error {
			entries, err := localruntime.ListProfileEntries(localProfile(profile))
			if err != nil {
				return localActionError(
					"Profile not found.",
					err.Error(),
					fmt.Sprintf("Run: hjctl local init --profile %s", localProfile(profile)),
				)
			}

			if len(entries) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "(no entries)")
				return nil
			}

			fmt.Fprintln(cmd.OutOrStdout(), "STATE      KEY=VALUE")
			fmt.Fprintln(cmd.OutOrStdout(), "---------  ------------------------------------------------------------")
			for _, entry := range entries {
				state := "commented"
				if entry.Active {
					state = "active"
				}
				value := entry.Value
				if localruntime.RedactValue(entry.Key, value) {
					value = "***REDACTED***"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%-9s  %s=%s\n", state, entry.Key, value)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&profile, "profile", defaultLocalProfile, "Local runtime profile name")
	return cmd
}

func newLocalEnvGetCmd() *cobra.Command {
	var (
		profile string
		reveal  bool
	)

	cmd := &cobra.Command{
		Use:   "get <KEY>",
		Short: "Get one profile variable",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			key := strings.TrimSpace(args[0])
			values, err := localruntime.LoadProfile(localProfile(profile))
			if err != nil {
				return localActionError(
					"Profile not found.",
					err.Error(),
					fmt.Sprintf("Run: hjctl local init --profile %s", localProfile(profile)),
				)
			}

			value, ok := values[key]
			if !ok {
				return localActionError(
					"Environment key not found.",
					fmt.Sprintf("%s is not set in %s", key, localruntime.EnvFile(localProfile(profile))),
					fmt.Sprintf("Run: hjctl local env set %s=<VALUE>", key),
				)
			}

			if localruntime.RedactValue(key, value) && !reveal {
				fmt.Fprintln(cmd.OutOrStdout(), "***REDACTED*** (use --reveal to show)")
				return nil
			}

			fmt.Fprintln(cmd.OutOrStdout(), value)
			return nil
		},
	}

	cmd.Flags().StringVar(&profile, "profile", defaultLocalProfile, "Local runtime profile name")
	cmd.Flags().BoolVar(&reveal, "reveal", false, "Show secret value without redaction")
	return cmd
}

func newLocalEnvSetCmd() *cobra.Command {
	var profile string

	cmd := &cobra.Command{
		Use:   "set <KEY>=<VALUE>",
		Short: "Set or update a profile variable",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			key, value, err := parseEnvSetArg(args[0])
			if err != nil {
				return err
			}

			if err := localruntime.WriteProfile(localProfile(profile), map[string]string{key: value}); err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "OK %s set in %s\n", key, localruntime.EnvFile(localProfile(profile)))
			return nil
		},
	}

	cmd.Flags().StringVar(&profile, "profile", defaultLocalProfile, "Local runtime profile name")
	return cmd
}

func newLocalEnvUnsetCmd() *cobra.Command {
	var profile string

	cmd := &cobra.Command{
		Use:   "unset <KEY>",
		Short: "Remove a key from profile file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			key := strings.TrimSpace(args[0])
			if !envAssignmentKeyPattern.MatchString(key) {
				return fmt.Errorf("invalid env key %q", key)
			}

			if err := localruntime.UnsetProfileKeys(localProfile(profile), key); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "OK %s removed from %s\n", key, localruntime.EnvFile(localProfile(profile)))
			return nil
		},
	}

	cmd.Flags().StringVar(&profile, "profile", defaultLocalProfile, "Local runtime profile name")
	return cmd
}

func newLocalEnvEditCmd() *cobra.Command {
	var profile string

	cmd := &cobra.Command{
		Use:   "edit",
		Short: "Open profile file in your editor",
		RunE: func(cmd *cobra.Command, args []string) error {
			profile = localProfile(profile)
			path := localruntime.EnvFile(profile)
			if _, err := os.Stat(path); err != nil {
				return localActionError(
					"Profile file not found.",
					err.Error(),
					fmt.Sprintf("Run: hjctl local init --profile %s", profile),
				)
			}

			editor, editorArgs := resolveEditor()
			runArgs := append(editorArgs, path)
			editCmd := exec.CommandContext(cmd.Context(), editor, runArgs...)
			editCmd.Stdin = os.Stdin
			editCmd.Stdout = cmd.OutOrStdout()
			editCmd.Stderr = cmd.ErrOrStderr()
			return editCmd.Run()
		},
	}

	cmd.Flags().StringVar(&profile, "profile", defaultLocalProfile, "Local runtime profile name")
	return cmd
}

func newLocalEnvValidateCmd() *cobra.Command {
	var profile string

	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate profile values",
		RunE: func(cmd *cobra.Command, args []string) error {
			profile = localProfile(profile)
			validationErrs := localruntime.ValidateProfile(profile)
			if len(validationErrs) == 1 && validationErrs[0].Key == "PROFILE" {
				return localActionError(
					"Profile not found.",
					validationErrs[0].Message,
					fmt.Sprintf("Run: hjctl local init --profile %s", profile),
				)
			}

			values, err := localruntime.LoadProfile(profile)
			if err != nil {
				return localActionError(
					"Profile not found.",
					err.Error(),
					fmt.Sprintf("Run: hjctl local init --profile %s", profile),
				)
			}

			errByKey := make(map[string]string, len(validationErrs))
			for _, item := range validationErrs {
				errByKey[item.Key] = item.Message
			}

			keys := make([]string, 0, len(values))
			for key := range values {
				keys = append(keys, key)
			}
			for key := range errByKey {
				if _, exists := values[key]; !exists {
					keys = append(keys, key)
				}
			}
			sort.Strings(keys)

			fmt.Fprintln(cmd.OutOrStdout(), "KEY                         STATUS             NOTE")
			fmt.Fprintln(cmd.OutOrStdout(), "--------------------------  -----------------  ------------------------------")

			invalidCount := 0
			for _, key := range keys {
				if note, hasErr := errByKey[key]; hasErr {
					invalidCount++
					fmt.Fprintf(cmd.OutOrStdout(), "%-26s  %-17s  %s\n", key, "invalid", note)
					continue
				}
				if _, known := knownLocalProfileKeys[key]; known {
					fmt.Fprintf(cmd.OutOrStdout(), "%-26s  %-17s  %s\n", key, "ok", "-")
					continue
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%-26s  %-17s  %s\n", key, "custom (unknown)", "non-blocking")
			}

			if invalidCount > 0 {
				return fmt.Errorf("profile validation failed with %d issue(s)", invalidCount)
			}

			fmt.Fprintln(cmd.OutOrStdout(), "Profile validation: OK")
			return nil
		},
	}

	cmd.Flags().StringVar(&profile, "profile", defaultLocalProfile, "Local runtime profile name")
	return cmd
}

func parseEnvSetArg(raw string) (string, string, error) {
	idx := strings.Index(raw, "=")
	if idx <= 0 {
		return "", "", fmt.Errorf("expected KEY=VALUE format")
	}
	key := strings.TrimSpace(raw[:idx])
	value := raw[idx+1:] // preserve intentional leading/trailing spaces
	if !envAssignmentKeyPattern.MatchString(key) {
		return "", "", fmt.Errorf("invalid env key %q", key)
	}
	return key, value, nil
}

func resolveEditor() (string, []string) {
	if editor := strings.TrimSpace(os.Getenv("EDITOR")); editor != "" {
		parts := strings.Fields(editor)
		if len(parts) > 0 {
			return parts[0], parts[1:]
		}
	}
	if editor := strings.TrimSpace(os.Getenv("VISUAL")); editor != "" {
		parts := strings.Fields(editor)
		if len(parts) > 0 {
			return parts[0], parts[1:]
		}
	}

	if runtime.GOOS == "windows" {
		return "notepad", nil
	}
	if path, err := exec.LookPath("nano"); err == nil {
		return path, nil
	}
	return "vi", nil
}
