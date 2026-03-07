# Cluster - Raft Consensus Layer

> Infraestructura Raft para replicación de estado entre nodos HelloJohn

## Propósito

Provee un wrapper sobre Hashicorp Raft para:
- **Replicación de estado**: Mutaciones del Control Plane se replican a todos los nodos
- **Alta disponibilidad**: Elección automática de líder
- **Tolerancia a fallos**: Logs persistentes en BoltDB
- **Seguridad**: Soporte TLS mutuo (mTLS) para comunicación inter-nodo

## Estructura

```
internal/cluster/
├── types.go    # MutationType, Mutation (19 líneas)
└── node.go     # Node wrapper + TLS (486 líneas)
```

## Componentes Principales

| Componente | Descripción |
|------------|-------------|
| `Node` | Wrapper de `*raft.Raft` con helpers |
| `Mutation` | Operación a replicar (type + payload JSON) |
| `NodeOptions` | Configuración de nodo |
| `tlsBundle` | Config TLS para mTLS |

## Interface de Node

```go
// Operaciones de replicación
func (n *Node) Apply(ctx, mutation) (uint64, error)
func (n *Node) ApplyBytes(ctx, data) (uint64, error)

// Estado
func (n *Node) IsLeader() bool
func (n *Node) LeaderID() string
func (n *Node) NodeID() string
func (n *Node) Stats() map[string]string

// Membership dinámico
func (n *Node) AddVoter(ctx, id, addr) error
func (n *Node) RemoveServer(ctx, id) error
func (n *Node) GetConfiguration(ctx) (Configuration, error)

// Lifecycle
func (n *Node) Close() error
```

## Configuración

```go
opts := cluster.NodeOptions{
    NodeID:   "node-1",
    RaftAddr: "10.0.0.1:7000",
    RaftDir:  "/data/raft",
    FSM:      myFSM,
    Peers:    map[string]string{"node-1": "10.0.0.1:7000"},
    
    // TLS opcional
    RaftTLSEnable:   true,
    RaftTLSCertFile: "/certs/node.crt",
    RaftTLSKeyFile:  "/certs/node.key",
    RaftTLSCAFile:   "/certs/ca.crt",
}
node, err := cluster.NewNode(opts)
```

## Almacenamiento

| Componente | Backend | Notas |
|------------|---------|-------|
| Log Store | BoltDB | `raft.db` en RaftDir |
| Stable Store | BoltDB | Misma DB |
| Snapshots | FileSnapshot | 2 retenidos |

## Modos de Bootstrap

| Modo | Condición | Comportamiento |
|------|-----------|----------------|
| Single-node | 1 peer | Bootstrap automático |
| Static cluster | N peers | Nodo con menor ID bootstrapea |
| Join-only | `DisableBootstrap=true` | Espera ser agregado por leader |
| Preferred | `BootstrapPreferred=true` | Este nodo es bootstrapper |

## Seguridad (TLS)

- **mTLS**: Certificados cliente y servidor mutuamente verificados
- **CA Pool**: Verificación contra CA propia
- **Min TLS 1.2**

## Métricas

Expone métricas Prometheus via `internal/observability/raft`:
- `raft_leadership_changes` - Counter de cambios de líder
- `raft_log_size_bytes` - Tamaño del log BoltDB
- `raft_apply_latency` - Latencia de Apply en ms

## Dependencias

### Externas
- `github.com/hashicorp/raft` - Implementación Raft
- `github.com/hashicorp/raft-boltdb` - Storage

### Internas
- `internal/observability/raft` - Métricas

## Ver También

- [internal/store/cluster](../store/cluster/README.md) - Uso de Raft en DAL
- [internal/controlplane](../controlplane/README.md) - FSM implementation
