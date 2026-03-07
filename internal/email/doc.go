// Package emailv2 proporciona servicios de email usando Store V2 DAL.
//
// Arquitectura:
//
//	┌─────────────────────────────────────────────────────────────────┐
//	│                         HTTP Handlers                           │
//	└───────────────────────────┬─────────────────────────────────────┘
//	                            │
//	                            ▼
//	┌─────────────────────────────────────────────────────────────────┐
//	│                       Email Service                             │
//	│  emailv2.NewService(cfg)                                        │
//	│    - SendVerificationEmail(ctx, req)                            │
//	│    - SendPasswordResetEmail(ctx, req)                           │
//	│    - SendNotificationEmail(ctx, req)                            │
//	│    - TestSMTP(ctx, tenant, email, override)                     │
//	└───────────────────────────┬─────────────────────────────────────┘
//	                            │
//	                            ▼
//	┌─────────────────────────────────────────────────────────────────┐
//	│                     SenderProvider                              │
//	│  Resuelve configuración SMTP por tenant via Store V2 DAL        │
//	└───────────────────────────┬─────────────────────────────────────┘
//	                            │
//	                            ▼
//	┌─────────────────────────────────────────────────────────────────┐
//	│                       Store V2 DAL                              │
//	│  dal.ConfigAccess().Tenants().GetBySlug/GetByID(...)            │
//	└─────────────────────────────────────────────────────────────────┘
package emailv2
