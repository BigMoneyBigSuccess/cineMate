package domain

import "errors"

var (
	ErrProfileNotFound = errors.New("profile not found")
	ErrAlreadyFollows  = errors.New("already following")
	ErrNotFollowing    = errors.New("not following")
	ErrUsernameTaken   = errors.New("username already taken")
)
