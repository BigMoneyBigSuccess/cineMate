package repository

type AuthRepository interface {
	CreateUser(email, passwordHash string) error
	GetUserCredentialsByEmail(email string) (userID int64, passwordHash string, err error)
	ExistsByEmail(email string) (bool, error)
}
