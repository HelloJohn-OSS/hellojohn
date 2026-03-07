package admin

import (
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	dto "github.com/dropDatabas3/hellojohn/internal/http/dto/admin"
	store "github.com/dropDatabas3/hellojohn/internal/store"
)

const exportUsersPageSize = 1000

// ExportService expone export de usuarios en formato JSON streaming.
type ExportService interface {
	ExportUsers(ctx context.Context, tenantID string, w io.Writer) error
}

// ExportDeps contiene dependencias del servicio de export.
type ExportDeps struct {
	DAL store.DataAccessLayer
}

type exportService struct {
	deps ExportDeps
}

// NewExportService crea el servicio de export.
func NewExportService(deps ExportDeps) ExportService {
	return &exportService{deps: deps}
}

func (s *exportService) ExportUsers(ctx context.Context, tenantRef string, w io.Writer) error {
	tda, err := s.deps.DAL.ForTenant(ctx, tenantRef)
	if err != nil {
		return err
	}
	if err := tda.RequireDB(); err != nil {
		return err
	}

	if _, err := w.Write([]byte(`{"users":[`)); err != nil {
		return err
	}

	offset := 0
	first := true

	for {
		users, err := tda.Users().List(ctx, tda.ID(), repository.ListUsersFilter{
			Limit:  exportUsersPageSize,
			Offset: offset,
		})
		if err != nil {
			return err
		}
		if len(users) == 0 {
			break
		}

		for i := range users {
			out := dto.UserExportRecord{
				ID:            users[i].ID,
				Email:         users[i].Email,
				Name:          users[i].Name,
				EmailVerified: users[i].EmailVerified,
				Disabled:      users[i].DisabledAt != nil,
				CreatedAt:     users[i].CreatedAt.Format(time.RFC3339),
			}
			if len(users[i].CustomFields) > 0 {
				out.CustomFields = toInterfaceMap(users[i].CustomFields)
			}

			raw, err := json.Marshal(out)
			if err != nil {
				return err
			}

			if !first {
				if _, err := w.Write([]byte(",")); err != nil {
					return err
				}
			}
			first = false

			if _, err := w.Write(raw); err != nil {
				return err
			}
		}

		offset += len(users)
		if len(users) < exportUsersPageSize {
			break
		}
	}

	_, err = w.Write([]byte("]}\n"))
	return err
}

func toInterfaceMap(in map[string]any) map[string]interface{} {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
