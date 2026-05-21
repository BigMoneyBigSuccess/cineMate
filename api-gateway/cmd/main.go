package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	httpadapter "github.com/BigMoneyBigSuccess/cineMate/api-gateway/internal/adapters/http"
	"github.com/BigMoneyBigSuccess/cineMate/clients"
	"github.com/BigMoneyBigSuccess/cineMate/api-gateway/internal/config"
	"strings"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	cfg, err := config.Load(resolveConfigPath())
	if err != nil {
		return err
	}

	authClient, err := clients.NewAuthClient(cfg.Auth.Host, cfg.Auth.Port)
	if err != nil {
		return fmt.Errorf("init auth client: %w", err)
	}
	defer authClient.Close()

	movieClient, err := clients.NewMovieClient(cfg.Movies.Host, cfg.Movies.Port)
	if err != nil {
		return fmt.Errorf("init movie client: %w", err)
	}
	defer movieClient.Close()

	socialClient, err := clients.NewSocialClient(cfg.Social.Host, cfg.Social.Port)
	if err != nil {
		return fmt.Errorf("init social client: %w", err)
	}
	defer socialClient.Close()

	
	authHandler := httpadapter.NewAuthHandler(authClient)
	movieHandler := httpadapter.NewMovieHandler(movieClient)
	movieAdminHandler := httpadapter.NewMovieAdminHandler(movieClient)
	socialHandler := httpadapter.NewSocialHandler(socialClient)

	
	mux := http.NewServeMux()

	
	mux.HandleFunc("/auth/register", authHandler.Register)
	mux.HandleFunc("/auth/login", authHandler.Login)

	
	authMiddleware := httpadapter.AuthMiddleware(authClient, true)

	
	mux.HandleFunc("/api/v1/movies", movieHandler.ListMovies)
	
	mux.HandleFunc("/api/v1/movies/", movieHandler.GetMovieByID)

	
	mux.Handle("/api/v1/watchlist", authMiddleware(http.HandlerFunc(movieHandler.GetWatchlist)))
	mux.Handle("/api/v1/watchlist/", authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			movieHandler.AddMovieToWatchlist(w, r)
		case http.MethodDelete:
			movieHandler.RemoveMovieFromWatchlist(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})))

	
	mux.HandleFunc("/api/v1/users/search", socialHandler.SearchUsers)

	mux.HandleFunc("/api/v1/users/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/profile"):
			if r.Method == http.MethodPut {
				socialHandler.UpdateProfile(w, r)
			} else {
				socialHandler.GetProfile(w, r)
			}
		case strings.HasSuffix(path, "/follow"):
			if r.Method == http.MethodPost {
				socialHandler.FollowUser(w, r)
			} else {
				socialHandler.UnfollowUser(w, r)
			}
		case strings.HasSuffix(path, "/followers"):
			socialHandler.GetFollowers(w, r)
		case strings.HasSuffix(path, "/following"):
			socialHandler.GetFollowing(w, r)
		case strings.HasSuffix(path, "/watchlist"):
			movieHandler.GetUserWatchlistByID(w, r)
		case strings.HasSuffix(path, "/is-following"):
			socialHandler.IsFollowing(w, r)
		default:
			http.NotFound(w, r)
		}
	})

	mux.Handle("/api/v1/admin/movies", authMiddleware(http.HandlerFunc(movieAdminHandler.UpsertMovie)))
	mux.Handle("/api/v1/admin/movies/", authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/archive"):
			movieAdminHandler.ArchiveMovie(w, r)
		default:
			movieAdminHandler.RemoveMovie(w, r)
		}
	})))

	handler := httpadapter.CORSMiddleware(mux)

	
	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	
	go func() {
		log.Printf("API Gateway listening on %s", server.Addr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("server error: %v", err)
		}
	}()

	
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("server shutdown: %w", err)
	}

	log.Println("API Gateway shutdown successfully")
	return nil
}

func resolveConfigPath() string {
	configPath := flag.String("config", "", "path to config file")
	flag.Parse()

	if *configPath != "" {
		return *configPath
	}

	
	defaultPaths := []string{
		"./configs/config.local.yaml",
		"./configs/config.docker.yaml",
		"/etc/api-gateway/config.yaml",
	}

	for _, path := range defaultPaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return defaultPaths[0] 
}
