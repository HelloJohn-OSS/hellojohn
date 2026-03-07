package webauthn

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	"github.com/go-webauthn/webauthn/protocol"
	gowa "github.com/go-webauthn/webauthn/webauthn"
)

// waUser implementa la interfaz webauthn.User requerida por la libreria.
type waUser struct {
	id          []byte
	name        string
	displayName string
	credentials []gowa.Credential
}

func (u *waUser) WebAuthnID() []byte                     { return u.id }
func (u *waUser) WebAuthnName() string                   { return u.name }
func (u *waUser) WebAuthnDisplayName() string            { return u.displayName }
func (u *waUser) WebAuthnCredentials() []gowa.Credential { return u.credentials }

func toGoWACredentials(creds []repository.WebAuthnCredential) []gowa.Credential {
	out := make([]gowa.Credential, 0, len(creds))
	for _, c := range creds {
		transports := make([]protocol.AuthenticatorTransport, 0, len(c.Transports))
		for _, t := range c.Transports {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}
			transports = append(transports, protocol.AuthenticatorTransport(t))
		}

		out = append(out, gowa.Credential{
			ID:              c.CredentialID,
			PublicKey:       c.PublicKey,
			AttestationType: "none",
			Transport:       transports,
			Flags: gowa.CredentialFlags{
				UserVerified:   c.UserVerified,
				BackupEligible: c.BackupEligible,
				BackupState:    c.BackupState,
			},
			Authenticator: gowa.Authenticator{
				SignCount: c.SignCount,
			},
		})
	}
	return out
}

func transportsToStrings(transports []protocol.AuthenticatorTransport) []string {
	out := make([]string, 0, len(transports))
	for _, t := range transports {
		s := strings.TrimSpace(string(t))
		if s == "" {
			continue
		}
		out = append(out, s)
	}
	return out
}

func parseCredentialCreation(bodyJSON []byte) (*protocol.ParsedCredentialCreationData, error) {
	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, fmt.Errorf("parse credential creation response: %w", err)
	}
	return parsed, nil
}

func parseCredentialAssertion(bodyJSON []byte) (*protocol.ParsedCredentialAssertionData, error) {
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, fmt.Errorf("parse credential assertion response: %w", err)
	}
	return parsed, nil
}
