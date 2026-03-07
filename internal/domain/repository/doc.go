// Package repository define las interfaces de repositorio de dominio.
//
// Estas interfaces representan contratos de negocio, independientes del
// almacenamiento subyacente (PostgreSQL, MongoDB, FileSystem, etc.).
//
// Las implementaciones concretas viven en internal/store/v2/adapters/.
//
// Arquitectura:
//
//	┌─────────────────────────────────────────────────────┐
//	│           Services / Controllers                    │
//	└─────────────────────────────────────────────────────┘
//	                        │
//	                        ▼
//	┌─────────────────────────────────────────────────────┐
//	│        domain/repository (interfaces)               │
//	│  UserRepository, ClientRepository, TokenRepository  │
//	└─────────────────────────────────────────────────────┘
//	                        │
//	         ┌──────────────┼──────────────┐
//	         ▼              ▼              ▼
//	┌─────────────┐  ┌─────────────┐  ┌─────────────┐
//	│  adapters/  │  │  adapters/  │  │  adapters/  │
//	│     pg      │  │     fs      │  │    noop     │
//	└─────────────┘  └─────────────┘  └─────────────┘
//
// Convenciones:
//   - TenantID se pasa explícitamente en métodos que lo requieren
//   - Context siempre es el primer parámetro
//   - Errores de dominio están en errors.go
package repository
