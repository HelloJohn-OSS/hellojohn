package webauthn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/dropDatabas3/hellojohn/internal/cache"
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	"github.com/go-webauthn/webauthn/protocol"
	gowa "github.com/go-webauthn/webauthn/webauthn"
)

const challengeTTL = 5 * time.Minute

// Config representa la configuracion de relying party por tenant.
type Config struct {
	RPID          string
	RPOrigins     []string
	RPDisplayName string
}

// Service orquesta ceremonias de WebAuthn.
type Service struct {
	cache cache.Client
	repo  repository.WebAuthnRepository
	cfg   Config
}

// New crea una nueva instancia del servicio de WebAuthn.
func New(cfg Config, repo repository.WebAuthnRepository, cacheClient cache.Client) *Service {
	return &Service{
		cache: cacheClient,
		repo:  repo,
		cfg:   cfg,
	}
}

func (s *Service) newWA() (*gowa.WebAuthn, error) {
	return gowa.New(&gowa.Config{
		RPID:          s.cfg.RPID,
		RPOrigins:     s.cfg.RPOrigins,
		RPDisplayName: s.cfg.RPDisplayName,
	})
}

// BeginRegistration inicia la ceremonia de registro.
func (s *Service) BeginRegistration(ctx context.Context, tenantSlug, tenantID, userID, userName, userDisplayName string) ([]byte, string, error) {
	w, err := s.newWA()
	if err != nil {
		return nil, "", fmt.Errorf("webauthn init: %w", err)
	}

	existing, err := s.repo.GetByUserID(ctx, tenantID, userID)
	if err != nil {
		return nil, "", fmt.Errorf("get credentials: %w", err)
	}

	user := &waUser{
		id:          []byte(userID),
		name:        userName,
		displayName: userDisplayName,
		credentials: toGoWACredentials(existing),
	}

	options, sessionData, err := w.BeginRegistration(user,
		gowa.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationPreferred,
		}),
	)
	if err != nil {
		return nil, "", fmt.Errorf("begin registration: %w", err)
	}

	sessionID := fmt.Sprintf("%s:%d", userID, time.Now().UnixNano())
	sessionJSON, err := json.Marshal(sessionData)
	if err != nil {
		return nil, "", fmt.Errorf("marshal registration session: %w", err)
	}
	cacheKey := fmt.Sprintf("webauthn:%s:reg:%s", tenantSlug, sessionID)
	if err := s.cache.Set(ctx, cacheKey, string(sessionJSON), challengeTTL); err != nil {
		return nil, "", fmt.Errorf("cache registration session: %w", err)
	}

	optionsJSON, err := json.Marshal(options)
	if err != nil {
		return nil, "", fmt.Errorf("marshal registration options: %w", err)
	}
	return optionsJSON, sessionID, nil
}

// FinishRegistration completa la ceremonia de registro.
func (s *Service) FinishRegistration(ctx context.Context, tenantSlug, tenantID, userID, sessionID string, bodyJSON []byte, credentialName string) error {
	w, err := s.newWA()
	if err != nil {
		return fmt.Errorf("webauthn init: %w", err)
	}

	cacheKey := fmt.Sprintf("webauthn:%s:reg:%s", tenantSlug, sessionID)
	sessionJSON, err := s.cache.GetDel(ctx, cacheKey)
	if cache.IsNotFound(err) {
		return ErrChallengeExpiredOrNotFound
	}
	if err != nil {
		return fmt.Errorf("cache get registration session: %w", err)
	}

	var sessionData gowa.SessionData
	if err := json.Unmarshal([]byte(sessionJSON), &sessionData); err != nil {
		return fmt.Errorf("unmarshal registration session: %w", err)
	}
	if string(sessionData.UserID) != userID {
		return ErrSessionUserMismatch
	}

	existing, err := s.repo.GetByUserID(ctx, tenantID, userID)
	if err != nil {
		return fmt.Errorf("get credentials: %w", err)
	}
	user := &waUser{
		id:          []byte(userID),
		credentials: toGoWACredentials(existing),
	}

	parsedResponse, err := parseCredentialCreation(bodyJSON)
	if err != nil {
		return err
	}

	cred, err := w.CreateCredential(user, sessionData, parsedResponse)
	if err != nil {
		return fmt.Errorf("create credential: %w", err)
	}

	name := credentialName
	if name == "" {
		name = "Passkey"
	}

	return s.repo.Create(ctx, tenantID, repository.WebAuthnCredential{
		TenantID:       tenantID,
		UserID:         userID,
		CredentialID:   cred.ID,
		PublicKey:      cred.PublicKey,
		AAGUID:         fmt.Sprintf("%x", cred.Authenticator.AAGUID),
		SignCount:      cred.Authenticator.SignCount,
		Transports:     transportsToStrings(cred.Transport),
		UserVerified:   cred.Flags.UserVerified,
		BackupEligible: cred.Flags.BackupEligible,
		BackupState:    cred.Flags.BackupState,
		Name:           name,
	})
}

// BeginLogin inicia la ceremonia de autenticacion.
func (s *Service) BeginLogin(ctx context.Context, tenantSlug, tenantID, userID string) ([]byte, string, error) {
	w, err := s.newWA()
	if err != nil {
		return nil, "", fmt.Errorf("webauthn init: %w", err)
	}

	creds, err := s.repo.GetByUserID(ctx, tenantID, userID)
	if err != nil {
		return nil, "", fmt.Errorf("get credentials: %w", err)
	}
	if len(creds) == 0 {
		return nil, "", ErrNoCredentialsRegistered
	}

	user := &waUser{
		id:          []byte(userID),
		credentials: toGoWACredentials(creds),
	}

	options, sessionData, err := w.BeginLogin(user)
	if err != nil {
		return nil, "", fmt.Errorf("begin login: %w", err)
	}

	sessionID := fmt.Sprintf("%s:%d", userID, time.Now().UnixNano())
	sessionJSON, err := json.Marshal(sessionData)
	if err != nil {
		return nil, "", fmt.Errorf("marshal login session: %w", err)
	}
	cacheKey := fmt.Sprintf("webauthn:%s:login:%s", tenantSlug, sessionID)
	if err := s.cache.Set(ctx, cacheKey, string(sessionJSON), challengeTTL); err != nil {
		return nil, "", fmt.Errorf("cache login session: %w", err)
	}

	optionsJSON, err := json.Marshal(options)
	if err != nil {
		return nil, "", fmt.Errorf("marshal login options: %w", err)
	}
	return optionsJSON, sessionID, nil
}

// FinishLogin valida la firma y retorna el userID autenticado.
func (s *Service) FinishLogin(ctx context.Context, tenantSlug, tenantID, userID, sessionID string, bodyJSON []byte) (string, error) {
	w, err := s.newWA()
	if err != nil {
		return "", fmt.Errorf("webauthn init: %w", err)
	}

	cacheKey := fmt.Sprintf("webauthn:%s:login:%s", tenantSlug, sessionID)
	sessionJSON, err := s.cache.GetDel(ctx, cacheKey)
	if cache.IsNotFound(err) {
		return "", ErrChallengeExpiredOrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("cache get login session: %w", err)
	}

	var sessionData gowa.SessionData
	if err := json.Unmarshal([]byte(sessionJSON), &sessionData); err != nil {
		return "", fmt.Errorf("unmarshal login session: %w", err)
	}
	if string(sessionData.UserID) != userID {
		return "", ErrSessionUserMismatch
	}

	creds, err := s.repo.GetByUserID(ctx, tenantID, userID)
	if err != nil {
		return "", fmt.Errorf("get credentials: %w", err)
	}
	if len(creds) == 0 {
		return "", ErrNoCredentialsRegistered
	}

	user := &waUser{
		id:          []byte(userID),
		credentials: toGoWACredentials(creds),
	}

	parsedResponse, err := parseCredentialAssertion(bodyJSON)
	if err != nil {
		return "", err
	}

	cred, err := w.ValidateLogin(user, sessionData, parsedResponse)
	if err != nil {
		return "", fmt.Errorf("validate login: %w", err)
	}
	if cred.Authenticator.CloneWarning {
		return "", ErrPotentialCredentialClone
	}

	if err := s.repo.UpdateSignCount(ctx, tenantID, cred.ID, cred.Authenticator.SignCount); err != nil {
		return "", fmt.Errorf("update sign count: %w", err)
	}
	if err := s.repo.UpdateLastUsed(ctx, tenantID, cred.ID); err != nil {
		return "", fmt.Errorf("update last used: %w", err)
	}

	return userID, nil
}

var (
	ErrChallengeExpiredOrNotFound = errors.New("webauthn: challenge expired or not found")
	ErrNoCredentialsRegistered    = errors.New("webauthn: no credentials registered for this user")
	ErrSessionUserMismatch        = errors.New("webauthn: session user mismatch")
	ErrPotentialCredentialClone   = errors.New("webauthn: credential clone warning")
)
