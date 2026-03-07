// Package admin contiene controllers administrativos V2.
package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	httperrors "github.com/dropDatabas3/hellojohn/internal/http/errors"
	svc "github.com/dropDatabas3/hellojohn/internal/http/services/admin"
	"github.com/dropDatabas3/hellojohn/internal/observability/logger"
	"go.uber.org/zap"
)

// ClusterController maneja operaciones de cluster.
type ClusterController struct {
	service svc.ClusterService
}

// NewClusterController crea un nuevo ClusterController.
func NewClusterController(service svc.ClusterService) *ClusterController {
	return &ClusterController{
		service: service,
	}
}

// GetNodes lista todos los nodos del cluster.
// GET /v2/admin/cluster/nodes
func (c *ClusterController) GetNodes(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("ClusterController.GetNodes"))

	// Llamar al servicio
	nodes, err := c.service.GetNodes(ctx)
	if err != nil {
		c.writeError(w, log, err)
		return
	}

	// Responder
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(admin.ClusterNodesResponse{
		Nodes: nodes,
	})
}

// GetStats obtiene estadísticas del cluster.
// GET /v2/admin/cluster/stats
func (c *ClusterController) GetStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("ClusterController.GetStats"))

	// Llamar al servicio
	stats, err := c.service.GetStats(ctx)
	if err != nil {
		c.writeError(w, log, err)
		return
	}

	// Responder
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(admin.ClusterStatsResponse{
		Stats: stats,
	})
}

// AddNode agrega un nodo al cluster.
// POST /v2/admin/cluster/nodes
func (c *ClusterController) AddNode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("ClusterController.AddNode"))

	// Parsear body
	var req admin.AddNodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Warn("invalid json", logger.Err(err))
		httperrors.WriteError(w, httperrors.ErrInvalidJSON)
		return
	}

	// Llamar al servicio
	if err := c.service.AddNode(ctx, req); err != nil {
		c.writeError(w, log, err)
		return
	}

	// Responder
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "node added successfully",
	})
}

// RemoveNode elimina un nodo del cluster.
// DELETE /v2/admin/cluster/nodes/{id}
func (c *ClusterController) RemoveNode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logger.From(ctx).With(logger.Layer("controller"), logger.Op("ClusterController.RemoveNode"))

	// Extraer nodeID del path
	// Formato: /v2/admin/cluster/nodes/{id}
	path := r.URL.Path
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 5 {
		httperrors.WriteError(w, httperrors.ErrNotFound)
		return
	}
	nodeID := parts[4] // v2, admin, cluster, nodes, {id}

	if nodeID == "" {
		httperrors.WriteError(w, httperrors.ErrNotFound)
		return
	}

	// Llamar al servicio
	if err := c.service.RemoveNode(ctx, nodeID); err != nil {
		c.writeError(w, log, err)
		return
	}

	// Responder
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "node removed successfully",
	})
}

// ─── Error Handling ───

func (c *ClusterController) writeError(w http.ResponseWriter, log *zap.Logger, err error) {
	// Errores específicos de cluster
	if errors.Is(err, svc.ErrClusterNotEnabled) {
		httperrors.WriteError(w, httperrors.ErrServiceUnavailable.WithDetail("cluster mode not enabled"))
		return
	}

	// Errores de liderazgo
	if strings.Contains(err.Error(), "leader node") {
		httperrors.WriteError(w, httperrors.ErrConflict.WithDetail(err.Error()))
		return
	}

	// Errores de validación
	if strings.Contains(err.Error(), "required") || strings.Contains(err.Error(), "invalid") {
		httperrors.WriteError(w, httperrors.ErrBadRequest.WithDetail(err.Error()))
		return
	}

	// Error genérico
	log.Error("cluster operation failed", logger.Err(err))
	httperrors.WriteError(w, httperrors.ErrInternalServerError)
}
