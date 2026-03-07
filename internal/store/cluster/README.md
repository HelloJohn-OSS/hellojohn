# Store Cluster (Raft FSM)

> Implementación de la Máquina de Estados Finitos (FSM) para el consenso Raft V2.

## Descripción General

Este paquete implementa la lógica de replicación para el **Control Plane** (Tenants, Clients, Keys, Scopes). Utiliza [HashiCorp Raft](https://github.com/hashicorp/raft) para mantener la consistencia entre nodos del clúster.

La arquitectura desacopla la lógica de consenso (`FSM`) de la lógica de aplicación (`Applier`), permitiendo testear la máquina de estados sin levantar un servidor Raft real.

## Componentes

### 1. Finite State Machine (`FSM`)

-   **Responsabilidad**: Recibir logs confirmados (committed) por Raft y aplicarlos localmente.
-   **Determinismo**: Solo aplica cambios, no genera IDs, timestamps ni claves aleatorias. Todo eso debe venir pre-calculado en el payload de la mutación.
-   **Snapshots**: Genera snapshots comprimiendo (`tar.gz`) los directorios `tenants/` y `keys/` del FileSystem.

### 2. Applier

-   **Responsabilidad**: Traducir las mutaciones genéricas (`Mutation`) a llamadas concretas a los repositorios (`store.Access`).
-   **Operaciones**:
    -   `Client`: Upsert/Delete.
    -   `Tenant`: Upsert/Delete.
    -   `Scope`: Upsert/Delete.
    -   `Key`: Rotate (escritura directa de archivos JSON).

### 3. Tipos de Mutación (`types.go`)

Catálogo estricto de operaciones permitidas:

-   `client.create`, `client.update`, `client.delete`
-   `tenant.create`, `tenant.update`, `tenant.delete`
-   `scope.create`, `scope.delete`
-   `key.rotate`

## Flujo de Replicación

1.  **Líder**: Recibe petición API -> Valida -> Genera IDs/Secrets -> Crea `Mutation` -> `raft.Apply()`.
2.  **Raft**: Replica log a seguidores -> Quourum alcanzado -> Commit.
3.  **FSM (Todos los nodos)**: Recibe `Apply(log)` -> Deserializa `Mutation` -> Llama `Applier`.
4.  **Applier**: Escribe cambios en el disco local (`data/tenants/...`).

## Snapshots y Restore

El sistema de snapshots es **basado en archivos**:

-   **Snapshot**: Lee recursivamente `data/tenants` y `data/keys`, crea un tarball en memoria/disco y lo envía al sink de Raft.
-   **Restore**: Recibe el tarball, lo descomprime en `restore.tmp`, valida la estructura y realiza un **swap atómico** de los directorios.

Esto asegura que si un nodo se queda muy atrás o inicia desde cero, puede sincronizarse copiando el estado completo del sistema de archivos.
