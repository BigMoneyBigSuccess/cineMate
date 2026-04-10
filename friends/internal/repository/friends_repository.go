package repository

type FriendRow struct {
	UserID   int64
	Username string
	Name     string
}

type FriendsRepository interface {
	CreateFriendRequest(userID, friendID int64) error
	AcceptFriendRequest(requestID int64) error
	GetFriendsByUserID(userID int64) ([]FriendRow, error)
}
