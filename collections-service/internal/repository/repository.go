package repository

import (
	"context"

	"github.com/BigMoneyBigSuccess/cineMate/collections/internal/model"
	"github.com/jackc/pgx/v5/pgxpool"
)

type CollectionsRepository struct {
	pool *pgxpool.Pool
}

func NewCollectionsRepository(pool *pgxpool.Pool) *CollectionsRepository {
	return &CollectionsRepository{pool: pool}
}

func (r *CollectionsRepository) AddMovie(userID string, ctype model.CollectionType, item model.Movie) error {
	query := `
		INSERT INTO collection_items (user_id, type, movie_id, rating, review)
		VALUES ($1, $2, $3, $4, $5)
	`

	_, err := r.pool.Exec(context.Background(), query, userID, ctype, item.ID, item.Rating, item.Review)
	return err
}

func (r *CollectionsRepository) GetCollection(userID string, ctype model.CollectionType) ([]model.Movie, error) {
	query := `SELECT movie_id, rating, review FROM collection_items WHERE user_id = $1 AND type = $2`

	rows, err := r.pool.Query(context.Background(), query, userID, ctype)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []model.Movie
	for rows.Next() {
		var item model.Movie
		if err := rows.Scan(&item.ID, &item.Rating, &item.Review); err != nil {
			return nil, err
		}
		items = append(items, item)
	}

	return items, nil
}

func (r *CollectionsRepository) RemoveMovie(userID string, ctype model.CollectionType, movieID int64) error {
	query := `DELETE FROM collection_items WHERE user_id = $1 AND type = $2 AND movie_id = $3`
	_, err := r.pool.Exec(context.Background(), query, userID, ctype, movieID)
	return err
}
