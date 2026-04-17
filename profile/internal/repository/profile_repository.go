package repository

type ProfileRepository interface {
	GetByUserID(userID int64) (username, name, bio, avatarURL string, err error)
	Update(userID int64, username, name, bio, avatarURL string) error
	ExistsByUsername(username string) (bool, error)
}
