package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/localruntime"
	"github.com/gorilla/websocket"
	"github.com/spf13/cobra"
)

const (
	tunnelTypeRequest   = "request"
	tunnelTypeResponse  = "response"
	tunnelTypeHeartbeat = "heartbeat"

	maxTunnelFrameBytes    = 4 * 1024 * 1024
	maxTunnelHTTPBodyBytes = 4 * 1024 * 1024
	tunnelWriteQueueSize   = 128
)

type tunnelEnvelope struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

type tunnelReq struct {
	ID      string              `json:"id"`
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Query   string              `json:"query,omitempty"`
	Headers map[string][]string `json:"headers,omitempty"`
	Body    []byte              `json:"body,omitempty"`
}

type tunnelResp struct {
	RequestID string              `json:"request_id"`
	Status    int                 `json:"status"`
	Headers   map[string][]string `json:"headers,omitempty"`
	Body      []byte              `json:"body,omitempty"`
}

type tunnelHeartbeat struct {
	Timestamp time.Time `json:"ts"`
}

type tunnelOutgoingFrame struct {
	messageType int
	payload     []byte
}

// NewTunnelWorkerCmd creates hidden `hjctl _tunnel-worker` command.
func NewTunnelWorkerCmd() *cobra.Command {
	var (
		token     string
		cloudURL  string
		baseURL   string
		stateFile string
		quiet     bool
	)

	cmd := &cobra.Command{
		Use:    "_tunnel-worker",
		Short:  "Internal tunnel worker process",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(token) == "" {
				token = strings.TrimSpace(os.Getenv("HELLOJOHN_TUNNEL_TOKEN"))
			}
			if strings.TrimSpace(token) == "" {
				return fmt.Errorf("--token is required (or HELLOJOHN_TUNNEL_TOKEN)")
			}
			if strings.TrimSpace(cloudURL) == "" {
				return fmt.Errorf("--cloud-url is required")
			}
			if strings.TrimSpace(baseURL) == "" {
				baseURL = "http://localhost:8080"
			}
			if strings.TrimSpace(stateFile) == "" {
				stateFile = localruntime.TunnelStateFile()
			}

			wsURL := toWSURL(cloudURL) + "/v2/cloud/tunnel/connect"
			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, append([]os.Signal{os.Interrupt}, platformTermSignals...)...)
			return runTunnelConnectLoop(cmd, wsURL, token, baseURL, stateFile, sigCh, quiet)
		},
	}

	cmd.Flags().StringVar(&token, "token", "", "Tunnel token (hjtun_...)")
	cmd.Flags().StringVar(&cloudURL, "cloud-url", "", "HelloJohn cloud relay URL")
	cmd.Flags().StringVar(&baseURL, "base-url", "http://localhost:8080", "Local HelloJohn server URL")
	cmd.Flags().StringVar(&stateFile, "state-file", localruntime.TunnelStateFile(), "Tunnel state file path")
	cmd.Flags().BoolVar(&quiet, "quiet", false, "Suppress informational output")

	return cmd
}

func runTunnelConnectLoop(cmd *cobra.Command, wsURL, token, localURL, stateFile string, sigCh <-chan os.Signal, quiet bool) error {
	backoff := time.Second
	const maxBackoff = 30 * time.Second

	for {
		select {
		case <-sigCh:
			_ = setTunnelConnected(stateFile, false)
			if !quiet {
				fmt.Fprintln(cmd.OutOrStdout(), "\nTunnel disconnected.")
			}
			return nil
		default:
		}

		err := runTunnelSession(cmd, wsURL, token, localURL, stateFile, sigCh, quiet)
		if err == nil {
			return nil
		}

		_ = setTunnelConnected(stateFile, false)
		if !quiet {
			fmt.Fprintf(cmd.ErrOrStderr(), "Tunnel connection lost: %v\n", err)
			fmt.Fprintf(cmd.ErrOrStderr(), "Reconnecting in %s...\n", backoff)
		}

		select {
		case <-sigCh:
			_ = setTunnelConnected(stateFile, false)
			return nil
		case <-time.After(backoff):
		}

		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func runTunnelSession(cmd *cobra.Command, wsURL, token, localURL, stateFile string, sigCh <-chan os.Signal, quiet bool) error {
	dialer := websocket.Dialer{HandshakeTimeout: 15 * time.Second}
	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)

	conn, _, err := dialer.Dial(wsURL, header)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	defer setTunnelConnected(stateFile, false)
	conn.SetReadLimit(maxTunnelFrameBytes)

	sessionCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	writeCh := make(chan tunnelOutgoingFrame, tunnelWriteQueueSize)
	writeErrCh := make(chan error, 1)
	go writeTunnelLoop(sessionCtx, conn, writeCh, writeErrCh)

	if err := setTunnelConnected(stateFile, true); err != nil && !quiet {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not update tunnel state: %v\n", err)
	}

	if !quiet {
		fmt.Fprintln(cmd.OutOrStdout(), "Tunnel connected. Waiting for requests...")
	}

	readErrCh := make(chan error, 1)
	go func() {
		readErrCh <- readTunnelLoop(sessionCtx, conn, localURL, writeCh)
	}()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sigCh:
			_ = enqueueTunnelFrame(sessionCtx, writeCh, tunnelOutgoingFrame{
				messageType: websocket.CloseMessage,
				payload:     websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			})
			return nil
		case err := <-readErrCh:
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		case err := <-writeErrCh:
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		case <-ticker.C:
			hb, _ := json.Marshal(tunnelHeartbeat{Timestamp: time.Now().UTC()})
			payload, _ := json.Marshal(tunnelEnvelope{Type: tunnelTypeHeartbeat, Payload: hb})
			if err := enqueueTunnelFrame(sessionCtx, writeCh, tunnelOutgoingFrame{
				messageType: websocket.TextMessage,
				payload:     payload,
			}); err != nil {
				return fmt.Errorf("heartbeat queue: %w", err)
			}
		}
	}
}

func readTunnelLoop(ctx context.Context, conn *websocket.Conn, localURL string, writeCh chan<- tunnelOutgoingFrame) error {
	httpClient := &http.Client{Timeout: 30 * time.Second}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		_, raw, err := conn.ReadMessage()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("read: %w", err)
		}

		var env tunnelEnvelope
		if err := json.Unmarshal(raw, &env); err != nil {
			continue
		}
		if env.Type != tunnelTypeRequest {
			continue
		}

		var req tunnelReq
		if err := json.Unmarshal(env.Payload, &req); err != nil {
			continue
		}

		// Handle each forwarded request concurrently while preserving single-writer
		// semantics through enqueueTunnelFrame -> writeTunnelLoop.
		go func(r tunnelReq) {
			resp := forwardToLocal(httpClient, localURL, r)
			payload, _ := json.Marshal(resp)
			frame, _ := json.Marshal(tunnelEnvelope{Type: tunnelTypeResponse, Payload: payload})
			_ = enqueueTunnelFrame(ctx, writeCh, tunnelOutgoingFrame{
				messageType: websocket.TextMessage,
				payload:     frame,
			})
		}(req)
	}
}

func forwardToLocal(client *http.Client, localURL string, req tunnelReq) tunnelResp {
	target := strings.TrimRight(localURL, "/") + "/" + strings.TrimLeft(req.Path, "/")
	if req.Query != "" {
		target += "?" + req.Query
	}

	httpReq, err := http.NewRequest(req.Method, target, bytes.NewReader(req.Body))
	if err != nil {
		return tunnelResp{
			RequestID: req.ID,
			Status:    http.StatusBadGateway,
			Body:      []byte(`{"error":"failed to create request"}`),
		}
	}
	for key, vals := range req.Headers {
		for _, value := range vals {
			httpReq.Header.Add(key, value)
		}
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return tunnelResp{
			RequestID: req.ID,
			Status:    http.StatusBadGateway,
			Body:      []byte(`{"error":"upstream unreachable"}`),
		}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxTunnelHTTPBodyBytes))
	headers := make(map[string][]string, len(resp.Header))
	for key, value := range resp.Header {
		headers[key] = value
	}

	return tunnelResp{
		RequestID: req.ID,
		Status:    resp.StatusCode,
		Headers:   headers,
		Body:      body,
	}
}

func setTunnelConnected(stateFile string, connected bool) error {
	state, err := localruntime.ReadState[localruntime.TunnelState](stateFile)
	if err != nil {
		state = localruntime.TunnelState{
			ProcessState: localruntime.ProcessState{
				StartedAt: time.Now().UTC(),
			},
		}
	}
	state.PID = os.Getpid()
	if state.StartedAt.IsZero() {
		state.StartedAt = time.Now().UTC()
	}
	state.Connected = connected
	return localruntime.WriteState(stateFile, state)
}

func toWSURL(raw string) string {
	raw = strings.TrimRight(raw, "/")
	if strings.HasPrefix(raw, "https://") {
		return "wss://" + strings.TrimPrefix(raw, "https://")
	}
	if strings.HasPrefix(raw, "http://") {
		return "ws://" + strings.TrimPrefix(raw, "http://")
	}
	return raw
}

func writeTunnelLoop(ctx context.Context, conn *websocket.Conn, writeCh <-chan tunnelOutgoingFrame, writeErrCh chan<- error) {
	for {
		select {
		case <-ctx.Done():
			return
		case frame := <-writeCh:
			if err := conn.WriteMessage(frame.messageType, frame.payload); err != nil {
				select {
				case writeErrCh <- fmt.Errorf("write: %w", err):
				default:
				}
				return
			}
		}
	}
}

func enqueueTunnelFrame(ctx context.Context, writeCh chan<- tunnelOutgoingFrame, frame tunnelOutgoingFrame) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case writeCh <- frame:
		return nil
	}
}
