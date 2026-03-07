// Package mongo implementa el adapter MongoDB (placeholder).
package mongo

import (
	"context"
	"fmt"

	store "github.com/dropDatabas3/hellojohn/internal/store"
)

func init() {
	store.RegisterAdapter(&mongoAdapter{})
}

type mongoAdapter struct{}

func (a *mongoAdapter) Name() string { return "mongo" }

func (a *mongoAdapter) Connect(ctx context.Context, cfg store.AdapterConfig) (store.AdapterConnection, error) {
	// TODO: Implementar usando go.mongodb.org/mongo-driver/mongo
	return nil, fmt.Errorf("mongo adapter not yet implemented")
}
