package handler

import (
	"net/http"

	"github.com/BigMoneyBigSuccess/cineMate/collections/internal/model"
	"github.com/BigMoneyBigSuccess/cineMate/collections/internal/service"
	"github.com/gin-gonic/gin"
)

type CollectionsHandler struct {
	service *service.CollectionsService
}

func NewHandler(service *service.CollectionsService) *CollectionsHandler {
	return &CollectionsHandler{service: service}
}

func (h *CollectionsHandler) AddMovie(c *gin.Context) {
	userID := c.GetString("user_id") // используем user_id из контекста, который был установлен в middleware

	var req struct {
		Type  model.CollectionType `json:"type"`
		Movie model.Movie          `json:"movie"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := h.service.AddMovie(userID, req.Type, req.Movie)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *CollectionsHandler) GetCollection(c *gin.Context) {
	userID := c.GetString("user_id")
	typeParam := c.Param("type")

	items, err := h.service.GetCollection(userID, model.CollectionType(typeParam))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, items)
}

func (h *CollectionsHandler) RemoveMovie(c *gin.Context) {
	userID := c.GetString("user_id")
	typeParam := c.Param("type")

	var req struct {
		MovieID int64 `json:"movie_id"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := h.service.RemoveMovie(userID, model.CollectionType(typeParam), req.MovieID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "deleted"})
}
