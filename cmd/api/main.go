package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/theretech/retech-auth-api/internal/application/service"
	"github.com/theretech/retech-auth-api/internal/application/usecase"
	"github.com/theretech/retech-auth-api/internal/config"
	"github.com/theretech/retech-auth-api/internal/infrastructure/database"
	"github.com/theretech/retech-auth-api/internal/infrastructure/http/handler"
	"github.com/theretech/retech-auth-api/internal/infrastructure/http/middleware"
	"github.com/theretech/retech-auth-api/internal/infrastructure/http/router"
	"github.com/theretech/retech-auth-api/internal/infrastructure/migration"
	"github.com/theretech/retech-auth-api/internal/infrastructure/repository"
)

type responseWriter struct {
	http.ResponseWriter
	written bool
	size    int
}

func (w *responseWriter) Written() bool {
	return w.written
}

func (w *responseWriter) WriteHeaderNow() {
	if !w.written {
		w.written = true
	}
}

func (w *responseWriter) Write(data []byte) (int, error) {
	w.WriteHeaderNow()
	n, err := w.ResponseWriter.Write(data)
	w.size += n
	return n, err
}

func (w *responseWriter) WriteString(s string) (int, error) {
	w.WriteHeaderNow()
	n, err := w.ResponseWriter.Write([]byte(s))
	w.size += n
	return n, err
}

func (w *responseWriter) WriteHeader(code int) {
	w.WriteHeaderNow()
	w.ResponseWriter.WriteHeader(code)
}

func (w *responseWriter) Size() int {
	return w.size
}

func (w *responseWriter) Status() int {
	return 200
}

func (w *responseWriter) CloseNotify() <-chan bool {
	if cn, ok := w.ResponseWriter.(http.CloseNotifier); ok {
		return cn.CloseNotify()
	}
	return nil
}

func (w *responseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, fmt.Errorf("http.Hijacker interface is not supported")
}

func (w *responseWriter) Pusher() http.Pusher {
	if pusher, ok := w.ResponseWriter.(http.Pusher); ok {
		return pusher
	}
	return nil
}

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Erro ao carregar configurações: %v", err)
	}

	db, err := database.NewPostgresConnection(cfg.GetDSN())
	if err != nil {
		log.Fatalf("Erro ao conectar ao banco de dados: %v", err)
	}
	defer db.Close()

	log.Println("✅ Conectado ao banco de dados com sucesso!")

	log.Println("🔄 Verificando migrations pendentes...")
	migrator := migration.NewMigrator(db)
	if err := migrator.Up(); err != nil {
		log.Fatalf("Erro ao aplicar migrations: %v", err)
	}
	log.Println("✅ Migrations verificadas e aplicadas!")

	userRepo := repository.NewPostgresUserRepository(db)
	appRepo := repository.NewPostgresApplicationRepository(db)
	authRepo := repository.NewPostgresAuthRepository(db)

	hashService := service.NewHashService()

	// Inicializa serviço de chaves RSA
	rsaKeyService, err := service.NewRSAKeyService(cfg.JWT.RSAKeysDir)
	if err != nil {
		log.Fatalf("Erro ao inicializar serviço de chaves RSA: %v", err)
	}
	log.Printf("✅ Serviço de chaves RSA inicializado (diretório: %s)", cfg.JWT.RSAKeysDir)
	log.Printf("🔑 Key ID atual: %s", rsaKeyService.GetCurrentKeyID())

	// Inicializa serviço JWT com chaves RSA
	jwtService := service.NewJWTService(
		rsaKeyService,
		cfg.JWT.AccessTokenTTL(),
		cfg.JWT.RefreshTokenTTL(),
		cfg.JWT.Issuer,
	)
	log.Printf("⏱️ Validade dos tokens: access=%s refresh=%s", cfg.JWT.AccessTokenTTL(), cfg.JWT.RefreshTokenTTL())

	refreshTokenRepo := repository.NewPostgresRefreshTokenRepository(db)
	// Manutenção: refresh tokens expirados saem do banco (a tabela não cresce sem limite).
	go func() {
		purge := func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			if n, err := refreshTokenRepo.DeleteExpired(ctx, time.Now().Add(-24*time.Hour)); err != nil {
				log.Printf("⚠️ purge de refresh tokens falhou: %v", err)
			} else if n > 0 {
				log.Printf("🧹 refresh tokens expirados removidos: %d", n)
			}
		}
		purge()
		for range time.Tick(time.Hour) {
			purge()
		}
	}()

	authenticateUseCase := usecase.NewAuthenticateUseCase(authRepo, refreshTokenRepo, hashService, jwtService)
	refreshTokenUseCase := usecase.NewRefreshTokenUseCase(userRepo, authRepo, refreshTokenRepo, jwtService)
	logoutUseCase := usecase.NewLogoutUseCase(refreshTokenRepo, jwtService)
	getUserInfoUseCase := usecase.NewGetUserInfoUseCase(userRepo, authRepo, appRepo)
	listUsersUseCase := usecase.NewListUsersUseCase(userRepo, authRepo)
	userManagementUseCase := usecase.NewUserManagementUseCase(userRepo, authRepo, appRepo, hashService)
	managementUseCase := usecase.NewManagementUseCase(appRepo, authRepo, userRepo, hashService)
	passwordResetRepo := repository.NewPostgresPasswordResetRepository(db)
	passwordResetUseCase := usecase.NewPasswordResetUseCase(userRepo, passwordResetRepo, hashService)

	// Rate limit (por instância, em memória): brute force de senha, de refresh e de reset.
	loginByIP := middleware.NewRateLimiter(cfg.RateLimit.LoginPerIP, time.Minute)
	loginByEmail := middleware.NewRateLimiter(cfg.RateLimit.LoginPerEmail, time.Minute)
	refreshByIP := middleware.NewRateLimiter(cfg.RateLimit.RefreshPerIP, time.Minute)
	resetByIP := middleware.NewRateLimiter(cfg.RateLimit.PasswordResetIP, time.Minute)
	log.Printf("🚦 Rate limit/min: login ip=%d email=%d, refresh ip=%d, password-reset ip=%d (0 = desligado)",
		cfg.RateLimit.LoginPerIP, cfg.RateLimit.LoginPerEmail, cfg.RateLimit.RefreshPerIP, cfg.RateLimit.PasswordResetIP)

	authHandler := handler.NewAuthHandler(
		authenticateUseCase,
		refreshTokenUseCase,
		logoutUseCase,
		getUserInfoUseCase,
		jwtService,
		db,
		loginByEmail,
	)
	userHandler := handler.NewUserHandler(listUsersUseCase, userManagementUseCase)
	managementHandler := handler.NewManagementHandler(managementUseCase)
	passwordResetHandler := handler.NewPasswordResetHandler(passwordResetUseCase)

	authMiddleware := middleware.NewAuthMiddleware(jwtService)
	syncMiddleware := middleware.NewSyncMiddleware(cfg.BootstrapSecret)
	corsMiddleware := middleware.NewCORSMiddleware(cfg.CORS.AllowedOrigins)

	docsHandler := handler.NewDocsHandler(cfg.Docs)

	apiVersions := []router.APIVersion{
		{
			Prefix: "/v1",
			Register: func(r *gin.RouterGroup) {
				r.GET("/health", authHandler.Health)
				r.POST("/authenticate", middleware.RateLimit(loginByIP, middleware.KeyByClientIP), authHandler.Authenticate)
				r.POST("/account/authenticate", middleware.RateLimit(loginByIP, middleware.KeyByClientIP), authHandler.Authenticate) // Alias para compatibilidade
				r.POST("/refresh", middleware.RateLimit(refreshByIP, middleware.KeyByClientIP), authHandler.RefreshToken)
				r.POST("/logout", middleware.RateLimit(refreshByIP, middleware.KeyByClientIP), authHandler.Logout)

				protected := r.Group("")
				protected.Use(authMiddleware.Authenticate())
				protected.GET("/me", authHandler.Me)

				protected.GET("/users", userHandler.ListUsers)
				protected.POST("/users", userHandler.CreateUser)
				protected.GET("/users/:id", userHandler.GetUser)
				protected.PUT("/users/:id", userHandler.UpdateUser)
				protected.DELETE("/users/:id", userHandler.DeleteUser)
				protected.PUT("/users/:id/roles", userHandler.UpdateUserRoles)
				protected.PATCH("/users/:id/status", userHandler.UpdateUserStatus)
				protected.POST("/users/:id/password/change", userHandler.ChangePassword)
				protected.POST("/users/:id/password/reset", userHandler.ResetPassword)

				protected.GET("/applications", managementHandler.ListApplications)
				protected.POST("/applications", managementHandler.CreateApplication)
				// /sync é rota interna: exige HMAC com BOOTSTRAP_SECRET (sem fallback JWT)
				r.POST("/applications/sync", syncMiddleware.AuthenticateSync(), managementHandler.SyncManifest)

				// Fluxo "esqueci a senha" — consumido por serviços internos via HMAC
				// (quem envia o e-mail é o serviço do produto, ex.: retech-meufin-api)
				r.POST("/password-reset/request", middleware.RateLimit(resetByIP, middleware.KeyByClientIP), syncMiddleware.AuthenticateSync(), passwordResetHandler.Request)
				r.POST("/password-reset/confirm", middleware.RateLimit(resetByIP, middleware.KeyByClientIP), syncMiddleware.AuthenticateSync(), passwordResetHandler.Confirm)
				protected.GET("/applications/:id", managementHandler.GetApplication)
				protected.PUT("/applications/:id", managementHandler.UpdateApplication)
				protected.DELETE("/applications/:id", managementHandler.DeleteApplication)

				protected.GET("/roles", managementHandler.ListRoles)
				protected.POST("/roles", managementHandler.CreateRole)
				protected.GET("/roles/:id", managementHandler.GetRole)
				protected.PUT("/roles/:id", managementHandler.UpdateRole)
				protected.PUT("/roles/:id/permissions", managementHandler.UpdateRolePermissions)
				protected.DELETE("/roles/:id", managementHandler.DeleteRole)

				protected.GET("/permissions", managementHandler.ListPermissions)
				protected.POST("/permissions", managementHandler.CreatePermission)
				protected.PUT("/permissions/:id", managementHandler.UpdatePermission)
				protected.DELETE("/permissions/:id", managementHandler.DeletePermission)
			},
		},
	}

	httpHandler := router.SetupServer(apiVersions, docsHandler, authHandler, "/v1")

	corsHandler := func(w http.ResponseWriter, r *http.Request) {
		ginCtx, _ := gin.CreateTestContext(w)
		ginCtx.Request = r
		ginCtx.Writer = &responseWriter{ResponseWriter: w}
		corsMiddleware(ginCtx)
		if !ginCtx.IsAborted() {
			httpHandler.ServeHTTP(w, r)
		}
	}

	// Railway e outros serviços esperam que o servidor escute em 0.0.0.0 (todas as interfaces)
	// No Go, usar ":" + porta já escuta em todas as interfaces (0.0.0.0)
	addr := fmt.Sprintf("0.0.0.0:%s", cfg.Server.Port)
	server := &http.Server{
		Addr:              addr,
		Handler:           http.HandlerFunc(corsHandler),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	log.Printf("🚀 Servidor iniciado na porta %s (escutando em 0.0.0.0:%s)", cfg.Server.Port, cfg.Server.Port)
	log.Printf("📝 Ambiente: %s", cfg.Server.Env)
	log.Printf("🔗 Health check: http://0.0.0.0:%s/health", cfg.Server.Port)
	log.Printf("🔗 Health check (v1): http://0.0.0.0:%s/v1/health", cfg.Server.Port)
	log.Printf("📚 Documentação: http://0.0.0.0:%s/docs", cfg.Server.Port)
	log.Printf("📚 Documentação (v1): http://0.0.0.0:%s/docs/v1", cfg.Server.Port)

	// Graceful shutdown: SIGTERM/SIGINT (deploy no Railway) drena as conexões em
	// vez de matar o processo — sem isso cada deploy é reportado como "crash".
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 1)
	go func() { errCh <- server.ListenAndServe() }()
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Erro ao iniciar servidor: %v", err)
		}
	case <-ctx.Done():
		log.Println("🛑 Sinal recebido, encerrando com graça...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("⚠️ Shutdown forçado: %v", err)
		}
		log.Println("👋 Servidor encerrado")
	}
}
