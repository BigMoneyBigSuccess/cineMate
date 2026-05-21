package postgres

import (
	"context"
	"database/sql"

	"github.com/BigMoneyBigSuccess/cineMate/auth-service/internal/core/domain"
	"github.com/BigMoneyBigSuccess/cineMate/auth-service/internal/core/ports"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

var _ ports.UserRepository = (*UserRepository)(nil)

type UserRepository struct {
	db *sql.DB
}

func NewUserRepository(db *sql.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) CreateUser(ctx context.Context, user domain.User) (uuid.UUID, error) {
	const query = `INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id`
	var id uuid.UUID
	if err := r.db.QueryRowContext(ctx, query, user.Email, user.Password).Scan(&id); err != nil {
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			return uuid.Nil, domain.ErrUserExists
		}
		return uuid.Nil, err
	}
	return id, nil
}

func (r *UserRepository) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	const query = `SELECT id, email, password, created_at FROM users WHERE email = $1 LIMIT 1`
	var user domain.User
	row := r.db.QueryRowContext(ctx, query, email)
	if err := row.Scan(&user.ID, &user.Email, &user.Password, &user.CreatedAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &user, nil
}
