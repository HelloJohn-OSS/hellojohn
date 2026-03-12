package admin

import (
	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	"github.com/dropDatabas3/hellojohn/internal/security/secretbox"
)

// EncryptTenantSecrets encrypts sensitive fields in the settings using secretbox.
// It modifies the settings in place.
// It clears the plain text password fields after encryption.
// Note: masterKeyHex parameter is kept for signature compatibility but not used - secretbox uses global key.
func encryptTenantSecrets(s *repository.TenantSettings, masterKeyHex string) error {
	if s == nil {
		return nil
	}

	// SMTP
	if s.SMTP != nil && s.SMTP.Password != "" {
		enc, err := secretbox.Encrypt(s.SMTP.Password)
		if err != nil {
			return err
		}
		s.SMTP.PasswordEnc = enc
		s.SMTP.Password = "" // Clear plain
	}

	// EmailProvider
	if s.EmailProvider != nil {
		if s.EmailProvider.APIKey != "" {
			enc, err := secretbox.Encrypt(s.EmailProvider.APIKey)
			if err != nil {
				return err
			}
			s.EmailProvider.APIKeyEnc = enc
			s.EmailProvider.APIKey = ""
		}
		if s.EmailProvider.SMTPPassword != "" {
			enc, err := secretbox.Encrypt(s.EmailProvider.SMTPPassword)
			if err != nil {
				return err
			}
			s.EmailProvider.SMTPPasswordEnc = enc
			s.EmailProvider.SMTPPassword = ""
		}
	}

	// UserDB
	if s.UserDB != nil && s.UserDB.DSN != "" {
		enc, err := secretbox.Encrypt(s.UserDB.DSN)
		if err != nil {
			return err
		}
		s.UserDB.DSNEnc = enc
		s.UserDB.DSN = ""
	}

	// Cache
	if s.Cache != nil && s.Cache.Password != "" {
		enc, err := secretbox.Encrypt(s.Cache.Password)
		if err != nil {
			return err
		}
		s.Cache.PassEnc = enc
		s.Cache.Password = ""
	}

	// Social Providers
	if sp := s.SocialProviders; sp != nil {
		// Preserve existing encrypted secrets by default.
		// New encrypted values are only produced from plain-text inputs (*Secret).
		// Request-provided *Enc values are filtered upstream during DTO merge.

		if sp.GoogleSecret != "" {
			enc, err := secretbox.Encrypt(sp.GoogleSecret)
			if err != nil {
				return err
			}
			sp.GoogleSecretEnc = enc
			sp.GoogleSecret = ""
		}
		if sp.GitHubSecret != "" {
			enc, err := secretbox.Encrypt(sp.GitHubSecret)
			if err != nil {
				return err
			}
			sp.GitHubSecretEnc = enc
			sp.GitHubSecret = ""
		}
		if sp.FacebookSecret != "" {
			enc, err := secretbox.Encrypt(sp.FacebookSecret)
			if err != nil {
				return err
			}
			sp.FacebookSecretEnc = enc
			sp.FacebookSecret = ""
		}
		if sp.DiscordSecret != "" {
			enc, err := secretbox.Encrypt(sp.DiscordSecret)
			if err != nil {
				return err
			}
			sp.DiscordSecretEnc = enc
			sp.DiscordSecret = ""
		}
		if sp.MicrosoftSecret != "" {
			enc, err := secretbox.Encrypt(sp.MicrosoftSecret)
			if err != nil {
				return err
			}
			sp.MicrosoftSecretEnc = enc
			sp.MicrosoftSecret = ""
		}
		if sp.LinkedInSecret != "" {
			enc, err := secretbox.Encrypt(sp.LinkedInSecret)
			if err != nil {
				return err
			}
			sp.LinkedInSecretEnc = enc
			sp.LinkedInSecret = ""
		}
		if sp.ApplePrivateKeyEnc == "" && len(sp.AppleKeyID) > 0 {
			// Apple uses P8 private key, not a simple secret
			// ApplePrivateKeyEnc is handled separately if needed
		}

	}

	// Bot Protection
	if bp := s.BotProtection; bp != nil && bp.TurnstileSecretKey != "" {
		enc, err := secretbox.Encrypt(bp.TurnstileSecretKey)
		if err != nil {
			return err
		}
		bp.TurnstileSecretEnc = enc
		bp.TurnstileSecretKey = "" // Clear plain
	}

	// Tenant MFA SMS provider secrets
	if s.MFA != nil && s.MFA.SMS != nil {
		sms := s.MFA.SMS
		if sms.TwilioAccountSID != "" {
			enc, err := secretbox.Encrypt(sms.TwilioAccountSID)
			if err != nil {
				return err
			}
			sms.TwilioAccountSIDEnc = enc
			sms.TwilioAccountSID = ""
		}
		if sms.TwilioAuthToken != "" {
			enc, err := secretbox.Encrypt(sms.TwilioAuthToken)
			if err != nil {
				return err
			}
			sms.TwilioAuthTokenEnc = enc
			sms.TwilioAuthToken = ""
		}
		if sms.VonageAPIKey != "" {
			enc, err := secretbox.Encrypt(sms.VonageAPIKey)
			if err != nil {
				return err
			}
			sms.VonageAPIKeyEnc = enc
			sms.VonageAPIKey = ""
		}
		if sms.VonageAPISecret != "" {
			enc, err := secretbox.Encrypt(sms.VonageAPISecret)
			if err != nil {
				return err
			}
			sms.VonageAPISecretEnc = enc
			sms.VonageAPISecret = ""
		}
	}

	return nil
}
