package usecase

import (
	"context"

	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/domain"
	"github.com/BigMoneyBigSucces/cineMate/analytics-service/internal/core/ports"

	"github.com/google/uuid"
)

type UserProfileUseCase struct {
	profileRepo  ports.UserProfileRepository
	feedbackRepo ports.FeedbackRepository
	catalog      ports.MovieRepository
}

func NewUserProfileUseCase(
	profileRepo ports.UserProfileRepository,
	feedbackRepo ports.FeedbackRepository,
	catalog ports.MovieRepository,
) *UserProfileUseCase {
	return &UserProfileUseCase{
		profileRepo:  profileRepo,
		feedbackRepo: feedbackRepo,
		catalog:      catalog,
	}
}

func (uc *UserProfileUseCase) GetOrCreateProfile(ctx context.Context, userID uuid.UUID) (domain.UserPreferenceProfile, error) {
	if userID == uuid.Nil {
		return domain.UserPreferenceProfile{}, domain.ErrInvalidUserReference
	}
	return uc.profileRepo.GetOrCreateProfileByUserID(ctx, userID)
}

func (uc *UserProfileUseCase) RemoveProfile(ctx context.Context, userID uuid.UUID) error {
	if userID == uuid.Nil {
		return domain.ErrInvalidUserReference
	}
	return uc.profileRepo.RemoveProfile(ctx, userID)
}

// RebuildProfileFromFeedback recomputes the preference profile from all stored
// feedback. Genres, actors, and directors are collected from movies the user
// rated at or above the liked threshold; AverageRating spans all rated movies.
func (uc *UserProfileUseCase) RebuildProfileFromFeedback(ctx context.Context, userID uuid.UUID) error {
	if userID == uuid.Nil {
		return domain.ErrInvalidUserReference
	}
	feedbacks, err := uc.feedbackRepo.ListFeedbackByUser(ctx, userID)
	if err != nil {
		return err
	}
	if len(feedbacks) == 0 {
		return uc.profileRepo.UpsertProfile(ctx, domain.NewEmptyUserPreferenceProfile(userID))
	}

	const likedThreshold = 7

	var totalRating float32
	genreSet := make(map[uuid.UUID]domain.Genre)
	actorSet := make(map[uuid.UUID]domain.Person)
	directorSet := make(map[uuid.UUID]domain.Person)

	for _, fb := range feedbacks {
		totalRating += float32(fb.Rating)
		if fb.Rating < likedThreshold {
			continue
		}
		snapshot, err := uc.catalog.GetMovieByID(ctx, fb.MovieID)
		if err != nil || snapshot == nil {
			continue
		}
		for _, g := range snapshot.Genres {
			genreSet[g.ID] = g
		}
		for _, a := range snapshot.Actors {
			actorSet[a.ID] = a
		}
		for _, d := range snapshot.Directors {
			directorSet[d.ID] = d
		}
	}

	profile := domain.UserPreferenceProfile{
		UserID:        userID,
		AverageRating: totalRating / float32(len(feedbacks)),
	}
	for _, g := range genreSet {
		profile.PreferredGenres = append(profile.PreferredGenres, g)
	}
	for _, a := range actorSet {
		profile.PreferredActors = append(profile.PreferredActors, a)
	}
	for _, d := range directorSet {
		profile.PreferredDirectors = append(profile.PreferredDirectors, d)
	}

	return uc.profileRepo.UpsertProfile(ctx, profile)
}
