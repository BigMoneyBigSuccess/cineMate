package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/domain"
	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/ports"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type FeedbackRepository struct {
	db *pgxpool.Pool
}

func NewFeedbackRepository(db *pgxpool.Pool) *FeedbackRepository {
	return &FeedbackRepository{db: db}
}

func (r *FeedbackRepository) UpsertFeedback(ctx context.Context, feedback domain.MovieFeedback) error {
	const q = `
		INSERT INTO movie_feedback
		    (feedback_id, user_id, movie_id, rating, title, content, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
		ON CONFLICT (user_id, movie_id) DO UPDATE
			SET rating     = EXCLUDED.rating,
			    title      = EXCLUDED.title,
			    content    = EXCLUDED.content,
			    updated_at = NOW()`

	_, err := r.db.Exec(ctx, q,
		feedback.FeedbackID, feedback.UserID, feedback.MovieID,
		feedback.Rating, feedback.Title, feedback.Content,
	)
	if err != nil {
		return fmt.Errorf("upsert feedback: %w", err)
	}
	return nil
}

func (r *FeedbackRepository) RemoveFeedback(ctx context.Context, feedbackID uuid.UUID) error {
	const q = `DELETE FROM movie_feedback WHERE feedback_id = $1`
	_, err := r.db.Exec(ctx, q, feedbackID)
	if err != nil {
		return fmt.Errorf("remove feedback: %w", err)
	}
	return nil
}

func (r *FeedbackRepository) ListFeedbackByUser(ctx context.Context, userID uuid.UUID) ([]domain.MovieFeedback, error) {
	const q = `
		SELECT feedback_id, user_id, movie_id, rating, title, content
		FROM movie_feedback
		WHERE user_id = $1
		ORDER BY created_at DESC`

	rows, err := r.db.Query(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("list feedback by user: %w", err)
	}
	defer rows.Close()

	var result []domain.MovieFeedback
	for rows.Next() {
		var f domain.MovieFeedback
		if err := rows.Scan(
			&f.FeedbackID, &f.UserID, &f.MovieID,
			&f.Rating, &f.Title, &f.Content,
		); err != nil {
			return nil, fmt.Errorf("scan feedback row: %w", err)
		}
		result = append(result, f)
	}
	return result, rows.Err()
}

func (r *FeedbackRepository) GetFeedbackByID(ctx context.Context, feedbackID uuid.UUID) (domain.MovieFeedback, error) {
	const q = `
		SELECT feedback_id, user_id, movie_id, rating, title, content
		FROM movie_feedback
		WHERE feedback_id = $1`

	var f domain.MovieFeedback
	err := r.db.QueryRow(ctx, q, feedbackID).Scan(
		&f.FeedbackID, &f.UserID, &f.MovieID,
		&f.Rating, &f.Title, &f.Content,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.MovieFeedback{}, domain.ErrInvalidMovieFeedback
	}
	if err != nil {
		return domain.MovieFeedback{}, fmt.Errorf("get feedback by id: %w", err)
	}
	return f, nil
}

var _ ports.FeedbackRepository = (*FeedbackRepository)(nil)
