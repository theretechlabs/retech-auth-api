package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/theretech/retech-auth-api/internal/domain/entity"
	"github.com/theretech/retech-auth-api/internal/domain/repository"
)

type postgresAuthRepository struct {
	db *sql.DB
}

// NewPostgresAuthRepository cria uma nova instância de PostgresAuthRepository
func NewPostgresAuthRepository(db *sql.DB) repository.AuthRepository {
	return &postgresAuthRepository{db: db}
}

func (r *postgresAuthRepository) GetUserApplications(ctx context.Context, userID uuid.UUID) ([]*entity.Application, error) {
	query := `
		SELECT a.id, a.name, a.code, a.description, a.active, a.created_at, a.updated_at
		FROM applications a
		INNER JOIN user_applications ua ON ua.application_id = a.id
		WHERE ua.user_id = $1 AND ua.active = true AND a.active = true
		ORDER BY a.name
	`
	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var apps []*entity.Application
	for rows.Next() {
		app := &entity.Application{}
		if err := rows.Scan(
			&app.ID, &app.Name, &app.Code, &app.Description, &app.Active,
			&app.CreatedAt, &app.UpdatedAt,
		); err != nil {
			return nil, err
		}
		apps = append(apps, app)
	}

	return apps, rows.Err()
}

func (r *postgresAuthRepository) GetUserPermissions(ctx context.Context, userID, applicationID uuid.UUID) ([]*repository.PermissionInfo, error) {
	query := `
		SELECT 
			p.id, p.application_id, COALESCE(p.code, p.subject || '.' || p.action) as code, p.subject, p.action, p.conditions, p.description,
			p.active, p.created_at, p.updated_at,
			r.id, r.application_id, r.name, r.code, r.description, COALESCE(r.system, false) as system, r.active, r.created_at, r.updated_at,
			a.id, a.name, a.code, a.description, a.active, a.created_at, a.updated_at
		FROM permissions p
		INNER JOIN role_permissions rp ON rp.permission_id = p.id
		INNER JOIN roles r ON r.id = rp.role_id
		INNER JOIN user_roles ur ON ur.role_id = r.id
		INNER JOIN user_applications ua ON ua.id = ur.user_application_id
		INNER JOIN applications a ON a.id = r.application_id
		WHERE ua.user_id = $1 
			AND r.application_id = $2
			AND ua.active = true
			AND ur.active = true
			AND rp.active = true
			AND p.active = true
			AND r.active = true
		ORDER BY p.subject, p.action
	`
	rows, err := r.db.QueryContext(ctx, query, userID, applicationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var permissions []*repository.PermissionInfo
	for rows.Next() {
		perm := &entity.Permission{}
		role := &entity.Role{}
		app := &entity.Application{}

		if err := rows.Scan(
			&perm.ID, &perm.ApplicationID, &perm.Code, &perm.Subject, &perm.Action, &perm.Conditions,
			&perm.Description, &perm.Active, &perm.CreatedAt, &perm.UpdatedAt,
			&role.ID, &role.ApplicationID, &role.Name, &role.Code, &role.Description, &role.System,
			&role.Active, &role.CreatedAt, &role.UpdatedAt,
			&app.ID, &app.Name, &app.Code, &app.Description, &app.Active,
			&app.CreatedAt, &app.UpdatedAt,
		); err != nil {
			return nil, err
		}

		permissions = append(permissions, &repository.PermissionInfo{
			Permission:  perm,
			Role:        role,
			Application: app,
		})
	}

	return permissions, rows.Err()
}

func (r *postgresAuthRepository) GetUserRoles(ctx context.Context, userID, applicationID uuid.UUID) ([]*entity.Role, error) {
	query := `
		SELECT r.id, r.application_id, r.name, r.code, r.description, COALESCE(r.system, false) as system, r.active, r.created_at, r.updated_at
		FROM roles r
		INNER JOIN user_roles ur ON ur.role_id = r.id
		INNER JOIN user_applications ua ON ua.id = ur.user_application_id
		WHERE ua.user_id = $1 
			AND r.application_id = $2
			AND ua.active = true
			AND ur.active = true
			AND r.active = true
		ORDER BY r.name
	`
	rows, err := r.db.QueryContext(ctx, query, userID, applicationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []*entity.Role
	for rows.Next() {
		role := &entity.Role{}
		if err := rows.Scan(
			&role.ID, &role.ApplicationID, &role.Name, &role.Code, &role.Description, &role.System,
			&role.Active, &role.CreatedAt, &role.UpdatedAt,
		); err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}

	return roles, rows.Err()
}

func (r *postgresAuthRepository) CreateUserApplication(ctx context.Context, userApp *entity.UserApplication) error {
	query := `
		INSERT INTO user_applications (id, user_id, application_id, tenant_id, active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := r.db.ExecContext(
		ctx, query,
		userApp.ID, userApp.UserID, userApp.ApplicationID, userApp.TenantID, userApp.Active,
		userApp.CreatedAt, userApp.UpdatedAt,
	)
	return err
}

func (r *postgresAuthRepository) AssignRoleToUser(ctx context.Context, userRole *entity.UserRole) error {
	query := `
		INSERT INTO user_roles (id, user_application_id, role_id, active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err := r.db.ExecContext(
		ctx, query,
		userRole.ID, userRole.UserApplicationID, userRole.RoleID, userRole.Active,
		userRole.CreatedAt, userRole.UpdatedAt,
	)
	return err
}

func (r *postgresAuthRepository) CreateRole(ctx context.Context, role *entity.Role) error {
	query := `
		INSERT INTO roles (id, application_id, name, code, description, system, active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	_, err := r.db.ExecContext(
		ctx, query,
		role.ID, role.ApplicationID, role.Name, role.Code, role.Description,
		role.System, role.Active, role.CreatedAt, role.UpdatedAt,
	)
	return err
}

func (r *postgresAuthRepository) CreatePermission(ctx context.Context, permission *entity.Permission) error {
	query := `
		INSERT INTO permissions (id, application_id, code, subject, action, conditions, description, active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`
	_, err := r.db.ExecContext(
		ctx, query,
		permission.ID, permission.ApplicationID, permission.Code, permission.Subject, permission.Action,
		permission.Conditions, permission.Description, permission.Active,
		permission.CreatedAt, permission.UpdatedAt,
	)
	return err
}

func (r *postgresAuthRepository) AssignPermissionToRole(ctx context.Context, rolePermission *entity.RolePermission) error {
	query := `
		INSERT INTO role_permissions (id, role_id, permission_id, active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err := r.db.ExecContext(
		ctx, query,
		rolePermission.ID, rolePermission.RoleID, rolePermission.PermissionID,
		rolePermission.Active, rolePermission.CreatedAt, rolePermission.UpdatedAt,
	)
	return err
}

func (r *postgresAuthRepository) FindUserByEmailAndApplication(ctx context.Context, email string, applicationCode string) (*entity.User, *entity.Application, *entity.UserApplication, error) {
	query := `
		SELECT
			u.id, u.email, u.password, u.name, u.active, COALESCE(u.version, 1) as version, u.created_at, u.updated_at,
			a.id, a.name, a.code, a.description, a.active, a.created_at, a.updated_at,
			ua.id, ua.tenant_id, ua.active, ua.created_at, ua.updated_at
		FROM users u
		INNER JOIN user_applications ua ON ua.user_id = u.id
		INNER JOIN applications a ON a.id = ua.application_id
		WHERE u.email = $1 AND a.code = $2 AND ua.active = true
	`
	user := &entity.User{}
	app := &entity.Application{}
	userApp := &entity.UserApplication{}

	err := r.db.QueryRowContext(ctx, query, email, applicationCode).Scan(
		&user.ID, &user.Email, &user.Password, &user.Name, &user.Active,
		&user.Version, &user.CreatedAt, &user.UpdatedAt,
		&app.ID, &app.Name, &app.Code, &app.Description, &app.Active,
		&app.CreatedAt, &app.UpdatedAt,
		&userApp.ID, &userApp.TenantID, &userApp.Active, &userApp.CreatedAt, &userApp.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, nil, errors.New("usuário ou aplicação não encontrados")
		}
		return nil, nil, nil, err
	}

	userApp.UserID = user.ID
	userApp.ApplicationID = app.ID

	return user, app, userApp, nil
}

func (r *postgresAuthRepository) FindUserApplication(ctx context.Context, userID, applicationID uuid.UUID) (*entity.UserApplication, error) {
	query := `
		SELECT id, user_id, application_id, tenant_id, active, created_at, updated_at
		FROM user_applications
		WHERE user_id = $1 AND application_id = $2 AND active = true
	`
	ua := &entity.UserApplication{}
	err := r.db.QueryRowContext(ctx, query, userID, applicationID).Scan(
		&ua.ID, &ua.UserID, &ua.ApplicationID, &ua.TenantID, &ua.Active, &ua.CreatedAt, &ua.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("vínculo usuário-aplicação não encontrado")
		}
		return nil, err
	}
	return ua, nil
}

// GetRolesByApplication retorna todas as roles de uma aplicação (com filtro opcional de active)
func (r *postgresAuthRepository) GetRolesByApplication(ctx context.Context, applicationID uuid.UUID, active *bool) ([]*entity.Role, error) {
	query := `
		SELECT id, application_id, name, code, description, COALESCE(system, false) as system, active, created_at, updated_at
		FROM roles
		WHERE application_id = $1
	`
	args := []interface{}{applicationID}
	argCount := 1

	// Adicionar filtro de active se fornecido
	if active != nil {
		argCount++
		query += fmt.Sprintf(" AND active = $%d", argCount)
		args = append(args, *active)
	}

	query += " ORDER BY created_at DESC"

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var roles []*entity.Role
	for rows.Next() {
		role := &entity.Role{}
		if err := rows.Scan(&role.ID, &role.ApplicationID, &role.Name, &role.Code, &role.Description, &role.System, &role.Active, &role.CreatedAt, &role.UpdatedAt); err != nil {
			return nil, err
		}
		roles = append(roles, role)
	}

	return roles, rows.Err()
}

// GetRole busca uma role por ID
func (r *postgresAuthRepository) GetRole(ctx context.Context, roleID uuid.UUID) (*entity.Role, error) {
	query := `
		SELECT id, application_id, name, code, description, COALESCE(system, false) as system, active, created_at, updated_at
		FROM roles
		WHERE id = $1
	`
	role := &entity.Role{}
	err := r.db.QueryRowContext(ctx, query, roleID).Scan(&role.ID, &role.ApplicationID, &role.Name, &role.Code, &role.Description, &role.System, &role.Active, &role.CreatedAt, &role.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("role não encontrada")
		}
		return nil, err
	}
	return role, nil
}

// UpdateRole atualiza uma role
func (r *postgresAuthRepository) UpdateRole(ctx context.Context, role *entity.Role) error {
	query := `
		UPDATE roles
		SET name = $2, description = $3, active = $4, updated_at = $5
		WHERE id = $1
	`
	_, err := r.db.ExecContext(ctx, query, role.ID, role.Name, role.Description, role.Active, role.UpdatedAt)
	return err
}

// GetRolePermissions retorna todas as permissions de uma role
func (r *postgresAuthRepository) GetRolePermissions(ctx context.Context, roleID uuid.UUID) ([]*entity.Permission, error) {
	query := `
		SELECT p.id, p.application_id, COALESCE(p.code, p.subject || '.' || p.action) as code, p.subject, p.action, p.conditions, p.description, p.active, p.created_at, p.updated_at
		FROM permissions p
		INNER JOIN role_permissions rp ON p.id = rp.permission_id
		WHERE rp.role_id = $1 AND rp.active = true AND p.active = true
		ORDER BY p.created_at DESC
	`
	rows, err := r.db.QueryContext(ctx, query, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var permissions []*entity.Permission
	for rows.Next() {
		perm := &entity.Permission{}
		if err := rows.Scan(&perm.ID, &perm.ApplicationID, &perm.Code, &perm.Subject, &perm.Action, &perm.Conditions, &perm.Description, &perm.Active, &perm.CreatedAt, &perm.UpdatedAt); err != nil {
			return nil, err
		}
		permissions = append(permissions, perm)
	}

	return permissions, rows.Err()
}

// GetPermissionsByApplication retorna todas as permissions de uma aplicação
func (r *postgresAuthRepository) GetPermissionsByApplication(ctx context.Context, applicationID uuid.UUID) ([]*entity.Permission, error) {
	query := `
		SELECT id, application_id, COALESCE(code, subject || '.' || action) as code, subject, action, conditions, description, active, created_at, updated_at
		FROM permissions
		WHERE application_id = $1
		ORDER BY created_at DESC
	`
	rows, err := r.db.QueryContext(ctx, query, applicationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var permissions []*entity.Permission
	for rows.Next() {
		perm := &entity.Permission{}
		if err := rows.Scan(&perm.ID, &perm.ApplicationID, &perm.Code, &perm.Subject, &perm.Action, &perm.Conditions, &perm.Description, &perm.Active, &perm.CreatedAt, &perm.UpdatedAt); err != nil {
			return nil, err
		}
		permissions = append(permissions, perm)
	}

	return permissions, rows.Err()
}

// GetPermission busca uma permission por ID
func (r *postgresAuthRepository) GetPermission(ctx context.Context, permissionID uuid.UUID) (*entity.Permission, error) {
	query := `
		SELECT id, application_id, COALESCE(code, subject || '.' || action) as code, subject, action, conditions, description, active, created_at, updated_at
		FROM permissions
		WHERE id = $1
	`
	perm := &entity.Permission{}
	err := r.db.QueryRowContext(ctx, query, permissionID).Scan(&perm.ID, &perm.ApplicationID, &perm.Code, &perm.Subject, &perm.Action, &perm.Conditions, &perm.Description, &perm.Active, &perm.CreatedAt, &perm.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("permission não encontrada")
		}
		return nil, err
	}
	return perm, nil
}

// UpdatePermission atualiza uma permission
func (r *postgresAuthRepository) UpdatePermission(ctx context.Context, permission *entity.Permission) error {
	query := `
		UPDATE permissions
		SET description = $2, conditions = $3, active = $4, updated_at = $5
		WHERE id = $1
	`
	_, err := r.db.ExecContext(ctx, query, permission.ID, permission.Description, permission.Conditions, permission.Active, permission.UpdatedAt)
	return err
}

// RemoveRoleFromUser remove uma role de um usuário (soft delete)
func (r *postgresAuthRepository) RemoveRoleFromUser(ctx context.Context, userApplicationID, roleID uuid.UUID) error {
	query := `
		UPDATE user_roles
		SET active = false, updated_at = NOW()
		WHERE user_application_id = $1 AND role_id = $2
	`
	_, err := r.db.ExecContext(ctx, query, userApplicationID, roleID)
	return err
}

// GetUserApplicationID retorna o ID do vínculo user_application
func (r *postgresAuthRepository) GetUserApplicationID(ctx context.Context, userID, applicationID uuid.UUID) (uuid.UUID, error) {
	query := `
		SELECT id
		FROM user_applications
		WHERE user_id = $1 AND application_id = $2 AND active = true
	`
	var id uuid.UUID
	err := r.db.QueryRowContext(ctx, query, userID, applicationID).Scan(&id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return uuid.Nil, errors.New("vínculo usuário-aplicação não encontrado")
		}
		return uuid.Nil, err
	}
	return id, nil
}

// UpdateUserRoles atualiza as roles de um usuário (calcula diff e aplica)
func (r *postgresAuthRepository) UpdateUserRoles(ctx context.Context, userApplicationID uuid.UUID, roleIDs []uuid.UUID) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	// Desativa todas as roles atuais
	_, err = tx.ExecContext(ctx, `
		UPDATE user_roles
		SET active = false, updated_at = NOW()
		WHERE user_application_id = $1
	`, userApplicationID)
	if err != nil {
		return err
	}

	// Ativa ou cria as novas roles
	for _, roleID := range roleIDs {
		// Tenta atualizar se já existe
		result, err := tx.ExecContext(ctx, `
			UPDATE user_roles
			SET active = true, updated_at = NOW()
			WHERE user_application_id = $1 AND role_id = $2
		`, userApplicationID, roleID)
		if err != nil {
			return err
		}

		// Se não atualizou nenhuma linha, cria nova
		rows, _ := result.RowsAffected()
		if rows == 0 {
			userRole := entity.NewUserRole(userApplicationID, roleID)
			_, err = tx.ExecContext(ctx, `
				INSERT INTO user_roles (id, user_application_id, role_id, active, created_at, updated_at)
				VALUES ($1, $2, $3, $4, $5, $6)
			`, userRole.ID, userRole.UserApplicationID, userRole.RoleID, userRole.Active, userRole.CreatedAt, userRole.UpdatedAt)
			if err != nil {
				return err
			}
		}
	}

	return tx.Commit()
}

// GetPermissionByCode busca uma permission por code e application_id
func (r *postgresAuthRepository) GetPermissionByCode(ctx context.Context, applicationID uuid.UUID, code string) (*entity.Permission, error) {
	query := `
		SELECT id, application_id, COALESCE(code, subject || '.' || action) as code, subject, action, conditions, description, active, created_at, updated_at
		FROM permissions
		WHERE application_id = $1 AND COALESCE(code, subject || '.' || action) = $2
	`
	perm := &entity.Permission{}
	err := r.db.QueryRowContext(ctx, query, applicationID, code).Scan(&perm.ID, &perm.ApplicationID, &perm.Code, &perm.Subject, &perm.Action, &perm.Conditions, &perm.Description, &perm.Active, &perm.CreatedAt, &perm.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("permission não encontrada")
		}
		return nil, err
	}
	return perm, nil
}

// GetPermissionBySubjectAction busca uma permission por subject+action.
// Fallback do SyncManifest: rows criadas fora do sync (SQL manual) podem não
// ter code — a chave natural (application_id, subject, action) sempre existe.
func (r *postgresAuthRepository) GetPermissionBySubjectAction(ctx context.Context, applicationID uuid.UUID, subject, action string) (*entity.Permission, error) {
	query := `
		SELECT id, application_id, COALESCE(code, subject || ':' || action) as code, subject, action, conditions, description, active, created_at, updated_at
		FROM permissions
		WHERE application_id = $1 AND subject = $2 AND action = $3
	`
	perm := &entity.Permission{}
	err := r.db.QueryRowContext(ctx, query, applicationID, subject, action).Scan(&perm.ID, &perm.ApplicationID, &perm.Code, &perm.Subject, &perm.Action, &perm.Conditions, &perm.Description, &perm.Active, &perm.CreatedAt, &perm.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("permission não encontrada")
		}
		return nil, err
	}
	return perm, nil
}

// UpsertPermission cria ou atualiza uma permission por id (o chamador resolve
// o id via GetPermissionByCode/GetPermissionBySubjectAction). Também faz
// backfill do code em rows antigas sem ele.
func (r *postgresAuthRepository) UpsertPermission(ctx context.Context, permission *entity.Permission) error {
	query := `
		INSERT INTO permissions (id, application_id, code, subject, action, conditions, description, active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (id) DO UPDATE SET
			code = EXCLUDED.code,
			subject = EXCLUDED.subject,
			action = EXCLUDED.action,
			conditions = EXCLUDED.conditions,
			description = EXCLUDED.description,
			active = EXCLUDED.active,
			updated_at = EXCLUDED.updated_at
	`
	_, err := r.db.ExecContext(
		ctx, query,
		permission.ID, permission.ApplicationID, permission.Code, permission.Subject, permission.Action,
		permission.Conditions, permission.Description, permission.Active,
		permission.CreatedAt, permission.UpdatedAt,
	)
	return err
}

// GetRoleByCode busca uma role por code e application_id
func (r *postgresAuthRepository) GetRoleByCode(ctx context.Context, applicationID uuid.UUID, code string) (*entity.Role, error) {
	query := `
		SELECT id, application_id, name, code, description, COALESCE(system, false) as system, active, created_at, updated_at
		FROM roles
		WHERE application_id = $1 AND code = $2
	`
	role := &entity.Role{}
	err := r.db.QueryRowContext(ctx, query, applicationID, code).Scan(&role.ID, &role.ApplicationID, &role.Name, &role.Code, &role.Description, &role.System, &role.Active, &role.CreatedAt, &role.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("role não encontrada")
		}
		return nil, err
	}
	return role, nil
}

// UpsertRole cria ou atualiza uma role por application_id + code (apenas para roles base)
func (r *postgresAuthRepository) UpsertRole(ctx context.Context, role *entity.Role) error {
	query := `
		INSERT INTO roles (id, application_id, name, code, description, system, active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (application_id, code) DO UPDATE SET
			name = EXCLUDED.name,
			description = EXCLUDED.description,
			system = EXCLUDED.system,
			active = EXCLUDED.active,
			updated_at = EXCLUDED.updated_at
	`
	_, err := r.db.ExecContext(
		ctx, query,
		role.ID, role.ApplicationID, role.Name, role.Code, role.Description,
		role.System, role.Active, role.CreatedAt, role.UpdatedAt,
	)
	return err
}

// UpsertRolePermissions regenera os vínculos role_permissions (remove todos e cria novos)
func (r *postgresAuthRepository) UpsertRolePermissions(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	// Remove todos os vínculos atuais da role
	_, err = tx.ExecContext(ctx, `
		DELETE FROM role_permissions
		WHERE role_id = $1
	`, roleID)
	if err != nil {
		return err
	}

	// Cria novos vínculos
	for _, permID := range permissionIDs {
		rolePerm := entity.NewRolePermission(roleID, permID)
		_, err = tx.ExecContext(ctx, `
			INSERT INTO role_permissions (id, role_id, permission_id, active, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6)
		`, rolePerm.ID, rolePerm.RoleID, rolePerm.PermissionID, rolePerm.Active, rolePerm.CreatedAt, rolePerm.UpdatedAt)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// GetActiveUsersByRole retorna usuários ativos que possuem uma role específica
func (r *postgresAuthRepository) GetActiveUsersByRole(ctx context.Context, roleID, applicationID uuid.UUID) ([]*entity.User, error) {
	query := `
		SELECT DISTINCT u.id, u.email, u.password, u.name, u.active, COALESCE(u.version, 1) as version, u.created_at, u.updated_at
		FROM users u
		INNER JOIN user_applications ua ON u.id = ua.user_id
		INNER JOIN user_roles ur ON ua.id = ur.user_application_id
		WHERE ur.role_id = $1
			AND ua.application_id = $2
			AND u.active = true
			AND ua.active = true
			AND ur.active = true
		ORDER BY u.name
	`
	rows, err := r.db.QueryContext(ctx, query, roleID, applicationID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*entity.User
	for rows.Next() {
		user := &entity.User{}
		if err := rows.Scan(
			&user.ID, &user.Email, &user.Password, &user.Name, &user.Active,
			&user.Version, &user.CreatedAt, &user.UpdatedAt,
		); err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	return users, rows.Err()
}
