package main

import (
	"github.com/BigMoneyBigSuccess/cineMate/collections/internal/handler"
	"github.com/BigMoneyBigSuccess/cineMate/collections/internal/repository"
	"github.com/BigMoneyBigSuccess/cineMate/collections/internal/service"
	"github.com/gin-gonic/gin"
)

func setupRouter(handler *handler.CollectionsHandler) *gin.Engine {
	r := gin.Default()

	// Middleware для аутентификации (JWT)
	r.Use(func(c *gin.Context) {
		// TODO: Реализовать JWT аутентификацию и извлекать user_id из токена

		c.Next()
	})

	r.POST("/collections", handler.AddMovie)
	r.GET("/collections/:type", handler.GetCollection)
	r.DELETE("/collections/:type", handler.RemoveMovie)

	return r
}

func main() {
	repo := repository.NewCollectionsRepository(nil) // TODO: Инициализировать пул соединений с базой данных
	service := service.NewCollectionService(repo)
	handler := handler.NewHandler(service)

	r := setupRouter(handler)
	r.Run(":8080")
}
