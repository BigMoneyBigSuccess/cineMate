package repository

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/BigMoneyBigSuccess/cineMate/auth/internal/model"
)

type UserRepository struct {
	pool *pgxpool.Pool
}

func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	return &UserRepository{pool: pool}
}

func (r *UserRepository) CreateUser(email, password string) error {
	ctx := context.Background()
	const q = `INSERT INTO users (email, password) VALUES ($1, $2)`
	_, err := r.pool.Exec(ctx, q, email, password)
	return err
}

func (r *UserRepository) GetUserByEmail(email string) (*model.User, error) {
	ctx := context.Background()
	const q = `SELECT id, email, password FROM users WHERE email = $1 LIMIT 1`
	var u model.User
	row := r.pool.QueryRow(ctx, q, email)
	if err := row.Scan(&u.ID, &u.Email, &u.Password); err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &u, nil
}
