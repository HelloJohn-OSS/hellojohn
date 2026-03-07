package cluster

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	appmetrics "github.com/dropDatabas3/hellojohn/internal/observability/raft"
	"github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb"
)

// membershipTimeout es el timeout por defecto para operaciones de membership (AddVoter, RemoveServer).
const membershipTimeout = 10 * time.Second

// Node es un wrapper liviano alrededor de *raft.Raft
// que provee helpers de Apply/Leader/Close y un constructor
// que inicializa stores (BoltDB), snapshots y transporte TCP.
type Node struct {
	r            *raft.Raft
	applyTimeout time.Duration
	id           raft.ServerID
	addr         raft.ServerAddress
	peers        map[string]string // nodeID -> raftAddr
	membershipMu sync.Mutex        // protege operaciones de membership (AddVoter, RemoveServer)
}

type NodeOptions struct {
	NodeID   string            // Identidad de este nodo (cfg.Cluster.NodeID)
	RaftAddr string            // host:port para transporte Raft (cfg.Cluster.RaftAddr)
	RaftDir  string            // Directorio de datos de Raft (CONTROL_PLANE_FS_ROOT/raft)
	FSM      raft.FSM          // Implementación de FSM
	Peers    map[string]string // Conjunto estático de peers (nodeID->raftAddr). Si >1, bootstrap estático en 1 nodo.
	// BootstrapPreferred: si true, este nodo intentará ser el bootstrapper inicial cuando no hay estado.
	// Úsese solo en un nodo. Si es false, se elige el de menor NodeID.
	BootstrapPreferred bool

	// DisableBootstrap: si true, este nodo NO hará bootstrap aunque no tenga estado previo.
	// Útil para nodos que van a unirse dinámicamente a un cluster existente ("join-only" mode).
	DisableBootstrap bool

	// TLS (optional). If enabled, create a TLS stream layer with mTLS.
	RaftTLSEnable     bool
	RaftTLSCertFile   string
	RaftTLSKeyFile    string
	RaftTLSCAFile     string
	RaftTLSServerName string
}

func NewNode(opts NodeOptions) (*Node, error) {
	if opts.NodeID == "" || opts.RaftAddr == "" || opts.RaftDir == "" || opts.FSM == nil {
		return nil, errors.New("invalid NodeOptions")
	}
	if err := os.MkdirAll(opts.RaftDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir raft dir: %w", err)
	}

	// Stores: log + stable en la misma Bolt DB.
	boltPath := filepath.Join(opts.RaftDir, "raft.db")
	boltStore, err := raftboltdb.NewBoltStore(boltPath)
	if err != nil {
		return nil, fmt.Errorf("bolt store: %w", err)
	}
	logStore := boltStore
	stableStore := boltStore

	// Snapshots en disco (retenemos 2).
	snapStore, err := raft.NewFileSnapshotStore(opts.RaftDir, 2, os.Stdout)
	if err != nil {
		return nil, fmt.Errorf("snapshot store: %w", err)
	}

	// Transporte: TCP plano o TLS mTLS si está habilitado
	var trans *raft.NetworkTransport
	if opts.RaftTLSEnable {
		bundle, err := loadTLSBundle(opts.RaftTLSCertFile, opts.RaftTLSKeyFile, opts.RaftTLSCAFile, opts.RaftTLSServerName)
		if err != nil {
			return nil, fmt.Errorf("raft tls: %w", err)
		}
		ln, err := tls.Listen("tcp", opts.RaftAddr, bundle.server)
		if err != nil {
			return nil, fmt.Errorf("tls listen: %w", err)
		}
		stream := &tlsStream{ln: ln, cfg: bundle.client}
		trans = raft.NewNetworkTransport(stream, 3, 10*time.Second, os.Stdout)
	} else {
		plain, err := raft.NewTCPTransport(opts.RaftAddr, nil, 3, 10*time.Second, os.Stdout)
		if err != nil {
			return nil, fmt.Errorf("tcp transport: %w", err)
		}
		trans = plain
	}

	// Config
	cfg := raft.DefaultConfig()
	cfg.LocalID = raft.ServerID(opts.NodeID)
	// Notas: thresholds por defecto; afinaremos en pasos siguientes.

	// New Raft
	r, err := raft.NewRaft(cfg, opts.FSM, logStore, stableStore, snapStore, trans)
	if err != nil {
		return nil, fmt.Errorf("new raft: %w", err)
	}

	// Leadership change counter (metrics)
	go func(ch <-chan bool) {
		for v := range ch {
			if v {
				appmetrics.RaftLeadershipChanges.Inc()
			}
		}
	}(r.LeaderCh())

	// Bootstrap si no hay estado previo
	hasState, err := raft.HasExistingState(logStore, stableStore, snapStore)
	if err != nil {
		return nil, fmt.Errorf("check state: %w", err)
	}
	if !hasState {
		// Join-only mode: si DisableBootstrap está activo, no hacemos bootstrap.
		// El nodo esperará a ser agregado dinámicamente al cluster por el leader.
		if opts.DisableBootstrap {
			log.Printf("[cluster] join-only mode: skipping bootstrap id=%s addr=%s", opts.NodeID, opts.RaftAddr)
		} else {
			peerCount := len(opts.Peers)
			if peerCount <= 1 {
				// Single node default bootstrap
				conf := raft.Configuration{Servers: []raft.Server{{ID: cfg.LocalID, Address: trans.LocalAddr()}}}
				if err := r.BootstrapCluster(conf).Error(); err != nil {
					return nil, fmt.Errorf("bootstrap: %w", err)
				}
				log.Printf("[cluster] bootstrapped single-node cluster: id=%s addr=%s", opts.NodeID, opts.RaftAddr)
			} else {
				// Static bootstrap on a single, deterministic node (smallest NodeID)
				smallest := opts.NodeID
				for k := range opts.Peers {
					if k < smallest {
						smallest = k
					}
				}
				// Decide bootstrapper: prefer explicit flag if set; else pick smallest
				shouldBootstrap := false
				if opts.BootstrapPreferred {
					shouldBootstrap = true
				} else if opts.NodeID == smallest {
					shouldBootstrap = true
				}
				if shouldBootstrap {
					// Build full server list from peers
					var servers []raft.Server
					for id, addr := range opts.Peers {
						servers = append(servers, raft.Server{ID: raft.ServerID(id), Address: raft.ServerAddress(addr)})
					}
					conf := raft.Configuration{Servers: servers}
					if err := r.BootstrapCluster(conf).Error(); err != nil {
						return nil, fmt.Errorf("bootstrap(static): %w", err)
					}
					log.Printf("[cluster] bootstrapped static cluster(%d). leader-candidate id=%s addr=%s", len(servers), opts.NodeID, opts.RaftAddr)
				} else {
					log.Printf("[cluster] waiting to join static cluster. local id=%s addr=%s bootstrap=%s", opts.NodeID, opts.RaftAddr, smallest)
					// No bootstrap here; leader will contact us using transport as we are in the config
				}
			}
		}
	}

	// Track raft log file size periodically (if Bolt file exists)
	go func() {
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for range t.C {
			if st, err := os.Stat(boltPath); err == nil {
				appmetrics.RaftLogSizeBytes.Set(float64(st.Size()))
			}
		}
	}()

	return &Node{r: r, applyTimeout: 5 * time.Second, id: cfg.LocalID, addr: trans.LocalAddr(), peers: opts.Peers}, nil
}

// Apply serializa la mutación y espera commit o timeout.
func (n *Node) Apply(ctx context.Context, m Mutation) (uint64, error) {
	if n == nil || n.r == nil {
		return 0, errors.New("raft not initialized")
	}
	buf, err := json.Marshal(m)
	if err != nil {
		return 0, err
	}
	return n.ApplyBytes(ctx, buf)
}

// ApplyBytes envía bytes raw al Raft log (sin re-serializar).
// Use esto cuando ya tenés JSON pre-serializado.
func (n *Node) ApplyBytes(ctx context.Context, data []byte) (uint64, error) {
	if n == nil || n.r == nil {
		return 0, errors.New("raft not initialized")
	}
	start := time.Now()
	fut := n.r.Apply(data, n.applyTimeout)

	// Respetar cancelación de ctx mientras esperamos el futuro.
	done := make(chan struct{})
	var applyErr error
	var index uint64
	go func() {
		applyErr = fut.Error()
		index = fut.Index()
		close(done)
	}()

	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-done:
		elapsed := time.Since(start).Milliseconds()
		appmetrics.RaftApplyLatency.Observe(float64(elapsed))
		return index, applyErr
	}
}

// ─── TLS helpers ───

type tlsBundle struct {
	server *tls.Config
	client *tls.Config
}

func loadTLSBundle(certFile, keyFile, caFile, serverName string) (*tlsBundle, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("invalid CA file")
	}
	server := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
	}
	client := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
		ServerName:   serverName,
	}
	return &tlsBundle{server: server, client: client}, nil
}

type tlsStream struct {
	ln  net.Listener
	cfg *tls.Config
}

func (t *tlsStream) Dial(address raft.ServerAddress, timeout time.Duration) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout}
	return tls.DialWithDialer(d, "tcp", string(address), t.cfg)
}
func (t *tlsStream) Accept() (net.Conn, error) { return t.ln.Accept() }
func (t *tlsStream) Close() error              { return t.ln.Close() }
func (t *tlsStream) Addr() net.Addr            { return t.ln.Addr() }

func (n *Node) IsLeader() bool {
	if n == nil || n.r == nil {
		return false
	}
	return n.r.State() == raft.Leader
}

func (n *Node) LeaderID() string {
	if n == nil || n.r == nil {
		return ""
	}
	addr, id := n.r.LeaderWithID()
	if id != "" {
		return string(id)
	}
	return string(addr)
}

func (n *Node) LeaderCh() <-chan bool {
	if n == nil || n.r == nil {
		return nil
	}
	return n.r.LeaderCh()
}

func (n *Node) NodeID() string {
	if n == nil {
		return ""
	}
	return string(n.id)
}
func (n *Node) RaftAddr() string {
	if n == nil {
		return ""
	}
	return string(n.addr)
}
func (n *Node) KnownPeers() int {
	if n == nil || n.peers == nil {
		return 0
	}
	return len(n.peers)
}
func (n *Node) PeerMap() map[string]string { return n.peers }

func (n *Node) Close() error {
	if n == nil || n.r == nil {
		return nil
	}
	f := n.r.Shutdown()
	return f.Error()
}

// Stats expone métricas de Raft del nodo embebido.
// Devuelve un mapa de strings tal como lo produce raft.Raft.Stats().
func (n *Node) Stats() map[string]string {
	if n == nil || n.r == nil {
		return map[string]string{}
	}
	return n.r.Stats()
}

// ─── Membership helpers ───

// GetConfiguration devuelve la configuración actual del cluster Raft.
// Respeta ctx.Done() mientras espera el future.
func (n *Node) GetConfiguration(ctx context.Context) (raft.Configuration, error) {
	if n == nil || n.r == nil {
		return raft.Configuration{}, errors.New("raft not initialized")
	}
	fut := n.r.GetConfiguration()

	done := make(chan struct{})
	var err error
	go func() {
		err = fut.Error()
		close(done)
	}()

	select {
	case <-ctx.Done():
		return raft.Configuration{}, ctx.Err()
	case <-done:
		if err != nil {
			return raft.Configuration{}, err
		}
		return fut.Configuration(), nil
	}
}

// AddVoter agrega un nodo votante al cluster.
// Comportamiento idempotente:
//   - Si el server ya existe con la misma dirección, retorna nil.
//   - Si el server existe con dirección distinta, primero se remueve y luego se agrega con la nueva dirección.
//     (Esto maneja el caso de un nodo que cambió de IP/puerto, ej. reinicio con nueva dirección.)
func (n *Node) AddVoter(ctx context.Context, id, addr string) error {
	if n == nil || n.r == nil {
		return errors.New("raft not initialized")
	}
	if id == "" {
		return errors.New("id cannot be empty")
	}
	if addr == "" {
		return errors.New("addr cannot be empty")
	}

	n.membershipMu.Lock()
	defer n.membershipMu.Unlock()

	// Leer configuración actual para verificar idempotencia
	config, err := n.GetConfiguration(ctx)
	if err != nil {
		return fmt.Errorf("get configuration: %w", err)
	}

	serverID := raft.ServerID(id)
	serverAddr := raft.ServerAddress(addr)

	// Buscar si el server ya existe
	for _, srv := range config.Servers {
		if srv.ID == serverID {
			if srv.Address == serverAddr {
				// Idempotente: ya existe con la misma dirección
				return nil
			}
			// Existe pero con dirección diferente: removemos primero y agregamos con nueva dirección.
			// Estrategia documentada: esto permite que un nodo cambie de dirección sin errores de duplicado.
			if err := n.removeServerLocked(ctx, id); err != nil {
				return fmt.Errorf("remove server before re-add: %w", err)
			}
			break
		}
	}

	// Agregar nuevo voter
	fut := n.r.AddVoter(serverID, serverAddr, 0, membershipTimeout)

	done := make(chan struct{})
	var addErr error
	go func() {
		addErr = fut.Error()
		close(done)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return addErr
	}
}

// RemoveServer remueve un nodo del cluster.
// Idempotente: si el server no existe, retorna nil.
func (n *Node) RemoveServer(ctx context.Context, id string) error {
	if n == nil || n.r == nil {
		return errors.New("raft not initialized")
	}
	if id == "" {
		return errors.New("id cannot be empty")
	}

	n.membershipMu.Lock()
	defer n.membershipMu.Unlock()

	return n.removeServerLocked(ctx, id)
}

// removeServerLocked es la implementación interna que asume que membershipMu ya está bloqueado.
func (n *Node) removeServerLocked(ctx context.Context, id string) error {
	// Leer configuración actual para verificar idempotencia
	config, err := n.GetConfiguration(ctx)
	if err != nil {
		return fmt.Errorf("get configuration: %w", err)
	}

	serverID := raft.ServerID(id)

	// Verificar si el server existe
	found := false
	for _, srv := range config.Servers {
		if srv.ID == serverID {
			found = true
			break
		}
	}
	if !found {
		// Idempotente: no existe, nada que hacer
		return nil
	}

	fut := n.r.RemoveServer(serverID, 0, membershipTimeout)

	done := make(chan struct{})
	var removeErr error
	go func() {
		removeErr = fut.Error()
		close(done)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return removeErr
	}
}
