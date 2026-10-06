package main

import (
	"flag"
	"log"
	"os"
	"strconv"

	_ "github.com/lib/pq"
	"github.com/theretech/retech-auth-api/internal/config"
	"github.com/theretech/retech-auth-api/internal/infrastructure/database"
	"github.com/theretech/retech-auth-api/internal/infrastructure/migration"
)

func main() {
	upCmd := flag.NewFlagSet("up", flag.ExitOnError)
	downCmd := flag.NewFlagSet("down", flag.ExitOnError)
	statusCmd := flag.NewFlagSet("status", flag.ExitOnError)

	downVersion := downCmd.Int("version", 0, "Versão específica para reverter (0 = última)")

	if len(os.Args) < 2 {
		log.Println("Uso: go run cmd/migrate/main.go [up|down|status]")
		log.Println("")
		log.Println("Comandos:")
		log.Println("  up        - Aplica todas as migrations pendentes")
		log.Println("  down      - Reverte migrations (use -version=N para reverter até uma versão específica)")
		log.Println("  status    - Mostra o status de todas as migrations")
		os.Exit(1)
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Erro ao carregar configurações: %v", err)
	}

	db, err := database.NewPostgresConnection(cfg.GetDSN())
	if err != nil {
		log.Fatalf("Erro ao conectar ao banco de dados: %v", err)
	}
	defer db.Close()

	migrator := migration.NewMigrator(db)

	switch os.Args[1] {
	case "up":
		_ = upCmd.Parse(os.Args[2:])
		if err := migrator.Up(); err != nil {
			log.Fatalf("Erro ao executar migrations: %v", err)
		}
		log.Println("✅ Migrations executadas com sucesso!")

	case "down":
		_ = downCmd.Parse(os.Args[2:])
		version := *downVersion
		if len(downCmd.Args()) > 0 {
			v, err := strconv.Atoi(downCmd.Args()[0])
			if err == nil {
				version = v
			}
		}
		if err := migrator.Down(version); err != nil {
			log.Fatalf("Erro ao reverter migrations: %v", err)
		}
		log.Println("✅ Migrations revertidas com sucesso!")

	case "status":
		_ = statusCmd.Parse(os.Args[2:])
		if err := migrator.Status(); err != nil {
			log.Fatalf("Erro ao verificar status: %v", err)
		}

	default:
		log.Fatalf("Comando inválido: %s. Use 'up', 'down' ou 'status'", os.Args[1])
	}
}
