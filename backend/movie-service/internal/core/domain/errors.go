package domain

import "errors"

var (
	ErrInvalidMovie  = errors.New("invalid movie")
	ErrInvalidPerson = errors.New("invalid person")
	ErrInvalidGenre  = errors.New("invalid genre")
	ErrMovieNotFound = errors.New("movie not found")
)
