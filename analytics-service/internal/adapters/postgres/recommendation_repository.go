package postgres

import (
	"context"
	"fmt"

	"analytics/internal/core/domain"
	"analytics/internal/core/ports"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type RecommendationRepository struct {
	db *pgxpool.Pool
}

func NewRecommendationRepository(db *pgxpool.Pool) *RecommendationRepository {
	return &RecommendationRepository{db: db}
}

func (r *RecommendationRepository) SaveRecommendationsBatch(ctx context.Context, recommendations []domain.MovieRecommendation) error {
	if len(recommendations) == 0 {
		return nil
	}

	const q = `
		INSERT INTO movie_recommendations
		    (recommendation_id, session_id, user_id, movie_id, rank, strategy, interaction, generated_at)
		VALUES ($1, $2, $3, $4, $5, $6::recommendation_strategy, $7::interaction_type, $8)`

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	batch := &pgx.Batch{}
	for _, rec := range recommendations {
		batch.Queue(q,
			rec.RecommendationID, rec.SessionID, rec.UserID, rec.MovieID,
			rec.Rank,
			string(rec.Strategy),
			string(rec.Interaction),
			rec.GeneratedAt,
		)
	}

	br := tx.SendBatch(ctx, batch)
	for range recommendations {
		if _, err := br.Exec(); err != nil {
			br.Close()
			return fmt.Errorf("insert recommendation: %w", err)
		}
	}
	if err := br.Close(); err != nil {
		return fmt.Errorf("close batch: %w", err)
	}

	return tx.Commit(ctx)
}

func (r *RecommendationRepository) MarkInteraction(ctx context.Context, recommendationID uuid.UUID, interaction domain.InteractionType) error {
	const q = `
		UPDATE movie_recommendations
		SET interaction = $1::interaction_type
		WHERE recommendation_id = $2`

	_, err := r.db.Exec(ctx, q, string(interaction), recommendationID)
	if err != nil {
		return fmt.Errorf("mark interaction: %w", err)
	}
	return nil
}

func (r *RecommendationRepository) ListRecommendationsByUser(ctx context.Context, userID uuid.UUID, filter ports.RecommendationHistoryFilter) ([]domain.MovieRecommendation, error) {
	q := `
		SELECT recommendation_id, session_id, user_id, movie_id, rank, strategy, interaction, generated_at
		FROM movie_recommendations
		WHERE user_id = $1
		ORDER BY generated_at DESC`

	args := []any{userID}

	if filter.Limit > 0 {
		args = append(args, filter.Limit)
		q += fmt.Sprintf(" LIMIT $%d", len(args))
	}
	if filter.Offset > 0 {
		args = append(args, filter.Offset)
		q += fmt.Sprintf(" OFFSET $%d", len(args))
	}

	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list recommendations by user: %w", err)
	}
	defer rows.Close()

	var result []domain.MovieRecommendation
	for rows.Next() {
		var (
			rec         domain.MovieRecommendation
			strategy    string
			interaction string
		)
		if err := rows.Scan(
			&rec.RecommendationID, &rec.SessionID, &rec.UserID, &rec.MovieID,
			&rec.Rank, &strategy, &interaction, &rec.GeneratedAt,
		); err != nil {
			return nil, fmt.Errorf("scan recommendation row: %w", err)
		}
		rec.Strategy = domain.RecommendationStrategy(strategy)
		rec.Interaction = domain.InteractionType(interaction)
		result = append(result, rec)
	}
	return result, rows.Err()
}

func (r *RecommendationRepository) ResetRecommendationsByUser(ctx context.Context, userID uuid.UUID) error {
	const q = `DELETE FROM movie_recommendations WHERE user_id = $1`
	_, err := r.db.Exec(ctx, q, userID)
	if err != nil {
		return fmt.Errorf("reset recommendations: %w", err)
	}
	return nil
}

var _ ports.RecommendationRepository = (*RecommendationRepository)(nil)
