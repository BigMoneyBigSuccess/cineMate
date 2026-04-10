package handler

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/BigMoneyBigSuccess/cineMate/movie_collection/internal/service"
)

type MovieCollectionHandler struct {
	service *service.MovieCollectionService
}

func NewMovieCollectionHandler(s *service.MovieCollectionService) *MovieCollectionHandler {
	return &MovieCollectionHandler{service: s}
}

func (h *MovieCollectionHandler) GetMovieCollections(c *gin.Context) {
	idParam := c.Param("id")
	movieID, err := strconv.ParseInt(idParam, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid movie id"})
		return
	}

	items, err := h.service.GetMovieCollections(movieID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"items": items})
}
