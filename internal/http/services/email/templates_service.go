package email

import "context"

// TemplatesService permite separar templates/rendering si hace falta.
type TemplatesService interface {
	Render(ctx context.Context, templateName string, data any) (subject string, html string, text string, err error)
}
