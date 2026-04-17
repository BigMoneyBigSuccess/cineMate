package handler

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/BigMoneyBigSuccess/cineMate/friends/internal/service"
)

type FriendsHandler struct {
	service *service.FriendsService
}

type SendFriendRequestBody struct {
	UserID   int64 `json:"user_id"`
	FriendID int64 `json:"friend_id"`
}

func NewFriendsHandler(s *service.FriendsService) *FriendsHandler {
	return &FriendsHandler{service: s}
}

func (h *FriendsHandler) SendFriendRequest(c *gin.Context) {
	var req SendFriendRequestBody
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	err := h.service.SendFriendRequest(req.UserID, req.FriendID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "friend request sent"})
}

func (h *FriendsHandler) AcceptFriendRequest(c *gin.Context) {
	idParam := c.Param("requestId")
	requestID, err := strconv.ParseInt(idParam, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request id"})
		return
	}

	err = h.service.AcceptFriendRequest(requestID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "friend request accepted"})
}

func (h *FriendsHandler) GetFriends(c *gin.Context) {
	idParam := c.Param("id")
	userID, err := strconv.ParseInt(idParam, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}

	friends, err := h.service.GetFriends(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"friends": friends})
}
