package emailv2

import (
	"context"

	"github.com/dropDatabas3/hellojohn/internal/store"
)

// senderProvider mantiene compatibilidad con el constructor histÃ³rico.
// Internamente delega en SenderFactory.
type senderProvider struct {
	factory *SenderFactory
}

// NewSenderProvider crea un SenderProvider compatible con la API anterior.
// Usa el fallback de 5 niveles definido en SenderFactory.
func NewSenderProvider(dal store.DataAccessLayer, masterKey string, systemSMTP SystemSMTPConfig) SenderProvider {
	systemEmail := SystemEmailConfig{}
	if systemSMTP.IsConfigured() {
		systemEmail = SystemEmailConfig{
			Provider:  string(ProviderKindSMTP),
			FromEmail: systemSMTP.From,
			SMTP:      systemSMTP,
		}
	}
	return &senderProvider{
		factory: NewSenderFactory(
			dal,
			masterKey,
			systemEmail,
			dal.ConfigAccess().SystemSettings(),
		),
	}
}

func (p *senderProvider) GetSender(ctx context.Context, tenantSlugOrID string) (Sender, error) {
	return p.factory.GetSender(ctx, tenantSlugOrID)
}
