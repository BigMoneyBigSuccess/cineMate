package handler

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/BigMoneyBigSuccess/cineMate/user_collection/internal/service"
)

type UserCollectionHandler struct {
	service *service.UserCollectionService
}

type MovieActionRequest struct {
	UserID  int64 `json:"user_id"`
	MovieID int64 `json:"movie_id"`
}

type RateMovieRequest struct {
	UserID  int64 `json:"user_id"`
	MovieID int64 `json:"movie_id"`
	Rating  int32 `json:"rating"`
}

type ReviewMovieRequest struct {
	UserID  int64  `json:"user_id"`
	MovieID int64  `json:"movie_id"`
	Review  string `json:"review"`
}

func NewUserCollectionHandler(s *service.UserCollectionService) *UserCollectionHandler {
	return &UserCollectionHandler{service: s}
}

func (h *UserCollectionHandler) AddToWatchlist(c *gin.Context) {
	var req MovieActionRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if err := h.service.AddToWatchlist(req.UserID, req.MovieID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "movie added to watchlist"})
}

func (h *UserCollectionHandler) MarkAsWatched(c *gin.Context) {
	var req MovieActionRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if err := h.service.MarkAsWatched(req.UserID, req.MovieID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "movie marked as watched"})
}

func (h *UserCollectionHandler) RateMovie(c *gin.Context) {
	var req RateMovieRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if err := h.service.RateMovie(req.UserID, req.MovieID, req.Rating); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "movie rated"})
}

func (h *UserCollectionHandler) ReviewMovie(c *gin.Context) {
	var req ReviewMovieRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
		return
	}

	if err := h.service.ReviewMovie(req.UserID, req.MovieID, req.Review); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "review added"})
}

func (h *UserCollectionHandler) GetUserCollection(c *gin.Context) {
	idParam := c.Param("id")
	userID, err := strconv.ParseInt(idParam, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}

	items, err := h.service.GetUserCollection(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"items": items})
}
