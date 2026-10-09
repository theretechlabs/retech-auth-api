package dto

import "github.com/google/uuid"

// AuthenticateRequest representa a requisição de autenticação
type AuthenticateRequest struct {
	Email           string `json:"email"`
	Password        string `json:"password"`
	ApplicationCode string `json:"application_code"` // Código da aplicação (ex: "retech-fin-admin")
}

// AuthenticateResponse representa a resposta de autenticação
type AuthenticateResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	User         UserDTO `json:"user"`
}

// RefreshTokenRequest representa a requisição de renovação de token
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// LogoutRequest revoga o refresh token (all=true: todos do usuário na aplicação)
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token"`
	All          bool   `json:"all,omitempty"`
}

// UserDTO representa os dados do usuário para resposta
type UserDTO struct {
	ID    uuid.UUID `json:"id"`
	Email string    `json:"email"`
	Name  string    `json:"name"`
}

// MeResponse representa a resposta do endpoint /me
type MeResponse struct {
	User        UserDTO           `json:"user"`
	Application ApplicationDTO    `json:"application"`
	Roles       []RoleDTO         `json:"roles"`
	Permissions []PermissionDTO   `json:"permissions"`
	Abilities   []AbilityDTO      `json:"abilities"` // Formato CASL
}

// ApplicationDTO representa os dados da aplicação
type ApplicationDTO struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Code        string    `json:"code"`
	Description string    `json:"description"`
}

// RoleDTO representa os dados de uma role
type RoleDTO struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Code        string    `json:"code"`
	Description string    `json:"description"`
}

// PermissionDTO representa os dados de uma permissão
type PermissionDTO struct {
	ID          uuid.UUID  `json:"id"`
	Code        string     `json:"code"`        // Código único da permissão (ex: "admin.users.view")
	Subject     string     `json:"subject"`
	Action      string     `json:"action"`
	Conditions  *string    `json:"conditions,omitempty"`
	Description string     `json:"description"`
}

// AbilityDTO representa uma habilidade no formato CASL
type AbilityDTO struct {
	Action     string                 `json:"action"`
	Subject    string                 `json:"subject"`
	Conditions map[string]interface{} `json:"conditions,omitempty"`
}

// ErrorResponse representa uma resposta de erro
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Code    int    `json:"code"`
}

