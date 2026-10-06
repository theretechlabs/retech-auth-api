package migration

import (
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	_ "github.com/lib/pq" // driver PostgreSQL registrado via side effect
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

type Migration struct {
	Version int
	Name    string
	Up      string
	Down    string
}

type Migrator struct {
	db *sql.DB
}

func NewMigrator(db *sql.DB) *Migrator {
	return &Migrator{db: db}
}

func (m *Migrator) Initialize() error {
	query := `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			name VARCHAR(255) NOT NULL,
			applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
	`
	_, err := m.db.Exec(query)
	if err != nil {
		return fmt.Errorf("erro ao criar tabela schema_migrations: %w", err)
	}
	return nil
}

func (m *Migrator) GetAppliedMigrations() (map[int]bool, error) {
	applied := make(map[int]bool)
	
	rows, err := m.db.Query("SELECT version FROM schema_migrations ORDER BY version")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var version int
		if err := rows.Scan(&version); err != nil {
			return nil, err
		}
		applied[version] = true
	}

	return applied, rows.Err()
}

func (m *Migrator) LoadMigrations() ([]Migration, error) {
	var migrations []Migration

	err := fs.WalkDir(migrationsFS, "migrations", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() || !strings.HasSuffix(path, ".sql") {
			return nil
		}

		filename := filepath.Base(path)
		name := strings.TrimSuffix(filename, ".sql")
		
		parts := strings.SplitN(name, "_", 2)
		if len(parts) != 2 {
			return nil
		}

		version, err := strconv.Atoi(parts[0])
		if err != nil {
			return nil
		}

		content, err := migrationsFS.ReadFile(path)
		if err != nil {
			return err
		}

		upDown := strings.Split(string(content), "-- +goose Down")
		if len(upDown) != 2 {
			return fmt.Errorf("migration %s não contém separador -- +goose Down", filename)
		}

		migration := Migration{
			Version: version,
			Name:    parts[1],
			Up:      strings.TrimSpace(strings.TrimPrefix(upDown[0], "-- +goose Up")),
			Down:    strings.TrimSpace(upDown[1]),
		}

		migrations = append(migrations, migration)
		return nil
	})

	if err != nil {
		return nil, err
	}

	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})

	return migrations, nil
}

func (m *Migrator) Up() error {
	if err := m.Initialize(); err != nil {
		return err
	}

	applied, err := m.GetAppliedMigrations()
	if err != nil {
		return err
	}

	migrations, err := m.LoadMigrations()
	if err != nil {
		return err
	}

	for _, migration := range migrations {
		if applied[migration.Version] {
			log.Printf("⏭️  Migration %03d_%s já aplicada, pulando...", migration.Version, migration.Name)
			continue
		}

		log.Printf("⬆️  Aplicando migration %03d_%s...", migration.Version, migration.Name)

		tx, err := m.db.Begin()
		if err != nil {
			return fmt.Errorf("erro ao iniciar transação: %w", err)
		}

		if _, err := tx.Exec(migration.Up); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("erro ao executar migration %03d_%s: %w", migration.Version, migration.Name, err)
		}

		_, err = tx.Exec(
			"INSERT INTO schema_migrations (version, name) VALUES ($1, $2)",
			migration.Version,
			migration.Name,
		)
		if err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("erro ao registrar migration %03d_%s: %w", migration.Version, migration.Name, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("erro ao commitar migration %03d_%s: %w", migration.Version, migration.Name, err)
		}

		log.Printf("✅ Migration %03d_%s aplicada com sucesso", migration.Version, migration.Name)
	}

	return nil
}

func (m *Migrator) Down(version int) error {
	if err := m.Initialize(); err != nil {
		return err
	}

	applied, err := m.GetAppliedMigrations()
	if err != nil {
		return err
	}

	migrations, err := m.LoadMigrations()
	if err != nil {
		return err
	}

	for i := len(migrations) - 1; i >= 0; i-- {
		migration := migrations[i]
		
		if !applied[migration.Version] {
			continue
		}

		if version > 0 && migration.Version <= version {
			break
		}

		log.Printf("⬇️  Revertendo migration %03d_%s...", migration.Version, migration.Name)

		tx, err := m.db.Begin()
		if err != nil {
			return fmt.Errorf("erro ao iniciar transação: %w", err)
		}

		if _, err := tx.Exec(migration.Down); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("erro ao reverter migration %03d_%s: %w", migration.Version, migration.Name, err)
		}

		_, err = tx.Exec("DELETE FROM schema_migrations WHERE version = $1", migration.Version)
		if err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("erro ao remover registro da migration %03d_%s: %w", migration.Version, migration.Name, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("erro ao commitar reversão da migration %03d_%s: %w", migration.Version, migration.Name, err)
		}

		log.Printf("✅ Migration %03d_%s revertida com sucesso", migration.Version, migration.Name)

		if version > 0 {
			break
		}
	}

	return nil
}

func (m *Migrator) Status() error {
	if err := m.Initialize(); err != nil {
		return err
	}

	applied, err := m.GetAppliedMigrations()
	if err != nil {
		return err
	}

	migrations, err := m.LoadMigrations()
	if err != nil {
		return err
	}

	fmt.Println("\n📊 Status das Migrations:")
	fmt.Println(strings.Repeat("-", 80))
	fmt.Printf("%-10s %-50s %-10s\n", "Version", "Name", "Status")
	fmt.Println(strings.Repeat("-", 80))

	for _, migration := range migrations {
		status := "❌ Pendente"
		if applied[migration.Version] {
			status = "✅ Aplicada"
		}
		fmt.Printf("%-10d %-50s %-10s\n", migration.Version, migration.Name, status)
	}

	fmt.Println(strings.Repeat("-", 80))
	return nil
}

