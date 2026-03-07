package bootstrap

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/dropDatabas3/hellojohn/internal/domain/repository"
	"github.com/dropDatabas3/hellojohn/internal/security/password"
	store "github.com/dropDatabas3/hellojohn/internal/store"
	"golang.org/x/term"
)

// AdminBootstrapConfig holds configuration for admin bootstrap
type AdminBootstrapConfig struct {
	DAL           store.DataAccessLayer
	SkipPrompt    bool   // Skip interactive prompts (for testing)
	AdminEmail    string // Pre-filled email (optional)
	AdminPassword string // Pre-filled password (optional)
}

// CheckAndCreateAdmin checks if there are any admin users in the system.
// If no admins exist, it prompts the user to create one interactively.
// This uses the AdminRepository in the Control Plane (FS), no tenant required.
func CheckAndCreateAdmin(ctx context.Context, cfg AdminBootstrapConfig) error {
	// 1. Check if we have any admins in the system (via ConfigAccess)
	hasAdmin, err := hasExistingAdmin(ctx, cfg.DAL)
	if err != nil {
		return fmt.Errorf("failed to check for existing admins: %w", err)
	}

	if hasAdmin {
		fmt.Println("✅ Admin user detected. Skipping bootstrap.")
		return nil
	}

	// 2. No admins found - prompt for creation
	fmt.Println("\n⚠️  No admin users found in the system.")
	fmt.Println("📋 Let's create the first admin user to get started.")
	fmt.Println()

	if cfg.SkipPrompt {
		// Non-interactive mode (testing)
		if cfg.AdminEmail == "" || cfg.AdminPassword == "" {
			return fmt.Errorf("SkipPrompt=true requires AdminEmail and AdminPassword")
		}
		return createAdminUser(ctx, cfg.DAL, cfg.AdminEmail, cfg.AdminPassword)
	}

	// 3. Interactive prompt
	email, password, err := promptAdminCredentials()
	if err != nil {
		return fmt.Errorf("failed to prompt admin credentials: %w", err)
	}

	// 4. Create admin user
	if err := createAdminUser(ctx, cfg.DAL, email, password); err != nil {
		return fmt.Errorf("failed to create admin user: %w", err)
	}

	fmt.Println("\n✅ Admin user created successfully!")
	fmt.Printf("   Email: %s\n", email)
	fmt.Printf("   You can now login at: /v2/auth/login\n\n")

	return nil
}

// hasExistingAdmin checks if there's at least one admin user in the system
// Uses AdminRepository from ConfigAccess (Control Plane)
func hasExistingAdmin(ctx context.Context, dal store.DataAccessLayer) (bool, error) {
	// Acceder al ConfigAccess (Control Plane)
	configAccess := dal.ConfigAccess()
	adminRepo := configAccess.Admins()

	if adminRepo == nil {
		// Si no hay AdminRepository, asumir que no hay admins
		return false, nil
	}

	// Listar admins (límite 1 solo para verificar)
	admins, err := adminRepo.List(ctx, repository.AdminFilter{
		Limit: 1,
	})
	if err != nil {
		return false, err
	}

	return len(admins) > 0, nil
}

// createAdminUser creates a new admin user in the Control Plane (FS)
// No requiere tenant - es un admin global del sistema
func createAdminUser(ctx context.Context, dal store.DataAccessLayer, email, plainPassword string) error {
	// 1. Acceder al ConfigAccess (Control Plane)
	configAccess := dal.ConfigAccess()
	adminRepo := configAccess.Admins()

	if adminRepo == nil {
		return fmt.Errorf("AdminRepository not available (FS adapter not initialized)")
	}

	// 2. Validar que el email no exista
	existingAdmin, err := adminRepo.GetByEmail(ctx, email)
	if err != nil && !repository.IsNotFound(err) {
		return fmt.Errorf("failed to check existing admin: %w", err)
	}
	if existingAdmin != nil {
		return fmt.Errorf("admin with email '%s' already exists", email)
	}

	// 3. Hash del password usando argon2id
	passwordHash, err := password.Hash(password.Default, plainPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// 4. Crear admin global
	admin, err := adminRepo.Create(ctx, repository.CreateAdminInput{
		Email:        email,
		PasswordHash: passwordHash,
		Name:         "", // Vacío por defecto, puede actualizarse después
		Type:         repository.AdminTypeGlobal,
		CreatedBy:    nil, // Primer admin, creado por bootstrap
	})
	if err != nil {
		return fmt.Errorf("failed to create admin: %w", err)
	}

	fmt.Printf("\n📝 Admin created with ID: %s\n", admin.ID)
	fmt.Printf("   Type: %s (full system access)\n", admin.Type)
	fmt.Printf("   Email: %s\n\n", admin.Email)

	// 5. Opcional: Agregar al ADMIN_SUBS env para compatibilidad
	// (si el sistema usa ADMIN_SUBS para verificar permisos)
	adminSubs := os.Getenv("ADMIN_SUBS")
	if adminSubs == "" {
		fmt.Printf("💡 TIP: You can add this admin ID to your .env file for faster checks:\n")
		fmt.Printf("   ADMIN_SUBS=%s\n\n", admin.ID)
	}

	return nil
}

// promptAdminCredentials prompts the user for email and password interactively
func promptAdminCredentials() (email, password string, err error) {
	reader := bufio.NewReader(os.Stdin)

	// Prompt for email
	fmt.Print("Admin Email: ")
	email, err = reader.ReadString('\n')
	if err != nil {
		return "", "", err
	}
	email = strings.TrimSpace(email)

	if email == "" {
		return "", "", fmt.Errorf("email cannot be empty")
	}

	// Validate email format (basic)
	if !strings.Contains(email, "@") {
		return "", "", fmt.Errorf("invalid email format")
	}

	// Prompt for password (hidden input)
	fmt.Print("Admin Password (min 10 chars): ")
	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", "", err
	}
	password = string(passwordBytes)
	fmt.Println() // New line after hidden input

	if len(password) < 10 {
		return "", "", fmt.Errorf("password must be at least 10 characters")
	}

	// Confirm password
	fmt.Print("Confirm Password: ")
	confirmBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", "", err
	}
	confirm := string(confirmBytes)
	fmt.Println() // New line after hidden input

	if password != confirm {
		return "", "", fmt.Errorf("passwords do not match")
	}

	return email, password, nil
}

// ShouldRunBootstrap checks if admin bootstrap should run
// Returns true if no admins exist in the system
func ShouldRunBootstrap(ctx context.Context, dal store.DataAccessLayer) bool {
	// Check if any admins exist
	hasAdmin, err := hasExistingAdmin(ctx, dal)
	if err != nil {
		// On error, skip bootstrap (conservative)
		return false
	}

	return !hasAdmin
}
