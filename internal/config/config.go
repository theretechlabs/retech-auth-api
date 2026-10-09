package config

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

// Config armazena todas as configurações da aplicação
type Config struct {
	Server          ServerConfig
	Database        DatabaseConfig
	JWT             JWTConfig
	CORS            CORSConfig
	Docs            DocsConfig
	RateLimit       RateLimitConfig
	BootstrapSecret string
	// HMACRequireNonce exige X-Nonce nas rotas internas (HMAC_REQUIRE_NONCE).
	// false = transição (clientes sem nonce ainda passam).
	HMACRequireNonce bool
}

// RateLimitConfig: eventos por minuto por chave (0 = desligado). Em memória,
// por instância.
type RateLimitConfig struct {
	LoginPerIP      int // RATE_LIMIT_LOGIN_PER_MINUTE (por IP)
	LoginPerEmail   int // RATE_LIMIT_LOGIN_PER_EMAIL_PER_MINUTE
	RefreshPerIP    int // RATE_LIMIT_REFRESH_PER_MINUTE
	PasswordResetIP int // RATE_LIMIT_PASSWORD_RESET_PER_MINUTE (por IP)
}

// ServerConfig armazena as configurações do servidor
type ServerConfig struct {
	Port string
	Env  string
}

// DatabaseConfig armazena as configurações do banco de dados
type DatabaseConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	DBName   string
	SSLMode  string
}

// JWTConfig armazena as configurações do JWT
type JWTConfig struct {
	RSAKeysDir             string // Diretório para armazenar chaves RSA
	ExpirationHours        int
	ExpirationMinutes      int // opcional (JWT_EXPIRATION_MINUTES); > 0 prevalece sobre ExpirationHours
	RefreshExpirationHours int
	// Issuer é o claim `iss` (JWT_ISSUER, opcional; padrão "retech-auth-api").
	Issuer string
}

// AccessTokenTTL é a validade do access token. Consumidores que renovam
// server-side (gateways de sessão do CashFlowfy e do MeuFin) permitem tokens
// curtos (15 min): um JWT vazado vale pouco.
func (j JWTConfig) AccessTokenTTL() time.Duration {
	if j.ExpirationMinutes > 0 {
		return time.Duration(j.ExpirationMinutes) * time.Minute
	}
	return time.Duration(j.ExpirationHours) * time.Hour
}

// RefreshTokenTTL é a validade do refresh token.
func (j JWTConfig) RefreshTokenTTL() time.Duration {
	return time.Duration(j.RefreshExpirationHours) * time.Hour
}

// CORSConfig armazena as configurações do CORS
type CORSConfig struct {
	AllowedOrigins []string
}

// DocsConfig armazena as configurações da página de documentação
type DocsConfig struct {
	Enabled          bool
	Title            string
	Description      string
	Version          string
	SpecURL          string
	APIBaseURL       string
	VersionLinks     string
	HeroSupportEmail string
	HeroSupportURL   string
	HeroLicense      string
}

// Load carrega as configurações da aplicação
func Load() (*Config, error) {
	// Carrega o arquivo .env se existir (silenciosamente)
	_ = godotenv.Load()

	log.Println("🔍 Carregando configurações obrigatórias...")

	// Valida que todas as ENVs obrigatórias existem ANTES de criar o config
	if err := validateRequiredEnvs(); err != nil {
		return nil, err
	}

	config := &Config{
		Server: ServerConfig{
			Port: getEnvRequired("PORT"),
			Env:  getEnvRequired("ENV"),
		},
		Database: DatabaseConfig{
			Host:     getEnvRequired("DB_HOST"),
			Port:     getEnvRequired("DB_PORT"),
			User:     getEnvRequired("DB_USER"),
			Password: getEnvRequired("DB_PASSWORD"),
			DBName:   getEnvRequired("DB_NAME"),
			SSLMode:  getEnvRequired("DB_SSLMODE"),
		},
		JWT: JWTConfig{
			RSAKeysDir:             getEnvRequired("JWT_RSA_KEYS_DIR"),
			ExpirationHours:        getEnvAsIntRequired("JWT_EXPIRATION_HOURS"),
			ExpirationMinutes:      getEnvAsIntOptional("JWT_EXPIRATION_MINUTES", 0),
			RefreshExpirationHours: getEnvAsIntRequired("JWT_REFRESH_EXPIRATION_HOURS"),
			Issuer:                 strings.TrimSpace(os.Getenv("JWT_ISSUER")),
		},
		RateLimit: RateLimitConfig{
			LoginPerIP:      getEnvAsIntOptional("RATE_LIMIT_LOGIN_PER_MINUTE", 20),
			LoginPerEmail:   getEnvAsIntOptional("RATE_LIMIT_LOGIN_PER_EMAIL_PER_MINUTE", 10),
			RefreshPerIP:    getEnvAsIntOptional("RATE_LIMIT_REFRESH_PER_MINUTE", 60),
			PasswordResetIP: getEnvAsIntOptional("RATE_LIMIT_PASSWORD_RESET_PER_MINUTE", 5),
		},
		CORS: CORSConfig{
			AllowedOrigins: getEnvAsSliceRequired("CORS_ALLOWED_ORIGINS"),
		},
		Docs: DocsConfig{
			Enabled:          getEnvAsBoolRequired("DOCS_ENABLED"),
			Title:            getEnvRequired("DOCS_TITLE"),
			Description:      getEnvRequired("DOCS_DESCRIPTION"),
			Version:          getEnvRequired("DOCS_VERSION"),
			SpecURL:          getEnvRequired("DOCS_SPEC_URL"),
			APIBaseURL:       getEnvRequired("DOCS_API_BASE_URL"),
			VersionLinks:     getEnvRequired("DOCS_VERSION_LINKS"),
			HeroSupportEmail: getEnvRequired("DOCS_HERO_SUPPORT_EMAIL"),
			HeroSupportURL:   getEnvRequired("DOCS_HERO_SUPPORT_URL"),
			HeroLicense:      getEnvRequired("DOCS_HERO_LICENSE"),
		},
		BootstrapSecret:  getEnvRequired("BOOTSTRAP_SECRET"),
		HMACRequireNonce: getEnvAsBoolOptional("HMAC_REQUIRE_NONCE", false),
	}

	// Valida valores específicos
	if err := config.Validate(); err != nil {
		return nil, err
	}

	log.Println("✅ Todas as configurações carregadas com sucesso!")
	return config, nil
}

// validateRequiredEnvs valida que todas as ENVs obrigatórias existem
func validateRequiredEnvs() error {
	required := []string{
		"PORT",
		"ENV",
		"DB_HOST",
		"DB_PORT",
		"DB_USER",
		"DB_PASSWORD",
		"DB_NAME",
		"DB_SSLMODE",
		"JWT_RSA_KEYS_DIR",
		"JWT_EXPIRATION_HOURS",
		"JWT_REFRESH_EXPIRATION_HOURS",
		"CORS_ALLOWED_ORIGINS",
		"DOCS_ENABLED",
		"DOCS_TITLE",
		"DOCS_DESCRIPTION",
		"DOCS_VERSION",
		"DOCS_SPEC_URL",
		"DOCS_API_BASE_URL",
		"DOCS_VERSION_LINKS",
		"DOCS_HERO_SUPPORT_EMAIL",
		"DOCS_HERO_SUPPORT_URL",
		"DOCS_HERO_LICENSE",
		"BOOTSTRAP_SECRET",
	}

	var missing []string
	for _, key := range required {
		if os.Getenv(key) == "" {
			missing = append(missing, key)
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf(
			"❌ Variáveis de ambiente obrigatórias não encontradas:\n  - %s\n\n"+
				"💡 Solução:\n"+
				"  - Desenvolvimento: copie .env.example para .env ou use 'make dev'\n"+
				"  - Produção: Configure todas as variáveis no Railway\n"+
				"  - Detalhes: copie .env.example para .env e ajuste os valores",
			strings.Join(missing, "\n  - "),
		)
	}

	return nil
}

// Validate valida valores específicos das configurações
func (c *Config) Validate() error {
	// Valida ambiente
	validEnvs := map[string]bool{
		"development": true,
		"staging":     true,
		"production":  true,
	}
	if !validEnvs[c.Server.Env] {
		return fmt.Errorf("ENV deve ser: development, staging ou production (atual: %s)", c.Server.Env)
	}

	// JWT_RSA_KEYS_DIR já é validado como obrigatório em validateRequiredEnvs()
	// Validação adicional: diretório deve ser acessível
	if c.JWT.RSAKeysDir == "" {
		return fmt.Errorf("JWT_RSA_KEYS_DIR é obrigatório e não pode estar vazio")
	}

	// Valida expiração dos tokens
	if c.JWT.ExpirationHours < 1 {
		return fmt.Errorf("JWT_EXPIRATION_HOURS deve ser >= 1 (atual: %d)", c.JWT.ExpirationHours)
	}
	if c.JWT.RefreshExpirationHours < 1 {
		return fmt.Errorf("JWT_REFRESH_EXPIRATION_HOURS deve ser >= 1 (atual: %d)", c.JWT.RefreshExpirationHours)
	}
	if c.JWT.ExpirationMinutes < 0 {
		return fmt.Errorf("JWT_EXPIRATION_MINUTES deve ser >= 0 (atual: %d)", c.JWT.ExpirationMinutes)
	}
	if c.JWT.RefreshTokenTTL() <= c.JWT.AccessTokenTTL() {
		return fmt.Errorf("JWT_REFRESH_EXPIRATION_HOURS (%dh) deve ser maior que a validade do access token (%s)",
			c.JWT.RefreshExpirationHours, c.JWT.AccessTokenTTL())
	}

	// Valida SSL em produção
	if c.Server.Env == "production" && c.Database.SSLMode == "disable" {
		log.Println("⚠️  AVISO: DB_SSLMODE=disable em produção não é recomendado!")
	}

	return nil
}

// GetDSN retorna a string de conexão do banco de dados
func (c *Config) GetDSN() string {
	return fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		c.Database.Host,
		c.Database.Port,
		c.Database.User,
		c.Database.Password,
		c.Database.DBName,
		c.Database.SSLMode,
	)
}

// getEnvRequired obtém uma variável de ambiente obrigatória
func getEnvRequired(key string) string {
	value := os.Getenv(key)
	if value == "" {
		// Não deveria chegar aqui por causa do validateRequiredEnvs
		panic(fmt.Sprintf("Variável de ambiente obrigatória não encontrada: %s", key))
	}
	return value
}

// getEnvAsIntRequired obtém uma variável de ambiente obrigatória como int
func getEnvAsIntRequired(key string) int {
	valueStr := getEnvRequired(key)
	value, err := strconv.Atoi(valueStr)
	if err != nil {
		panic(fmt.Sprintf("Variável %s deve ser um número inteiro (atual: %s)", key, valueStr))
	}
	return value
}

// getEnvAsIntOptional obtém uma variável opcional como int (default se ausente/vazia).
func getEnvAsIntOptional(key string, def int) int {
	valueStr := strings.TrimSpace(os.Getenv(key))
	if valueStr == "" {
		return def
	}
	value, err := strconv.Atoi(valueStr)
	if err != nil {
		panic(fmt.Sprintf("Variável %s deve ser um número inteiro (atual: %s)", key, valueStr))
	}
	return value
}

// getEnvAsSliceRequired obtém uma variável de ambiente obrigatória como slice
func getEnvAsSliceRequired(key string) []string {
	valueStr := getEnvRequired(key)
	return strings.Split(valueStr, ",")
}

// getEnvAsBoolOptional obtém uma variável opcional como bool (default se ausente/vazia).
func getEnvAsBoolOptional(key string, def bool) bool {
	valueStr := strings.TrimSpace(os.Getenv(key))
	if valueStr == "" {
		return def
	}
	value, err := strconv.ParseBool(valueStr)
	if err != nil {
		panic(fmt.Sprintf("Variável %s deve ser um valor booleano (true/false) (atual: %s)", key, valueStr))
	}
	return value
}

// getEnvAsBoolRequired obtém uma variável de ambiente obrigatória como bool
func getEnvAsBoolRequired(key string) bool {
	valueStr := getEnvRequired(key)
	value, err := strconv.ParseBool(valueStr)
	if err != nil {
		panic(fmt.Sprintf("Variável %s deve ser um valor booleano (true/false) (atual: %s)", key, valueStr))
	}
	return value
}
