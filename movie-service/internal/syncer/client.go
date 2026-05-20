package syncer

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
)

const Source = "kinopoisk"

// Client is a rate-limited HTTP client for the Kinopoisk Unofficial API.
// It spaces requests evenly across the day to stay within the daily budget.
// The first request fires immediately; subsequent requests wait for a token.
type Client struct {
	httpClient *http.Client
	baseURL    string
	apiKey     string
	ticker     *time.Ticker
	tokens     chan struct{}
	done       chan struct{}
}

func NewClient(baseURL, apiKey string, dailyBudget int) *Client {
	interval := time.Duration(int64(24*time.Hour) / int64(dailyBudget))
	tokens := make(chan struct{}, 1)
	tokens <- struct{}{} // first request fires immediately
	c := &Client{
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
			Transport: &http.Transport{
				DisableKeepAlives: true,
				DialContext: (&net.Dialer{
					Timeout: 30 * time.Second,
				}).DialContext,
				TLSHandshakeTimeout: 30 * time.Second,
			},
		},
		baseURL: baseURL,
		apiKey:  apiKey,
		ticker:  time.NewTicker(interval),
		tokens:  tokens,
		done:    make(chan struct{}),
	}
	go c.refill()
	return c
}

func (c *Client) refill() {
	for {
		select {
		case <-c.ticker.C:
			select {
			case c.tokens <- struct{}{}:
			default: // discard if a token is already waiting
			}
		case <-c.done:
			return
		}
	}
}

func (c *Client) Stop() {
	c.ticker.Stop()
	close(c.done)
}

// FilmsPage is the response from GET /api/v2.2/films.
type FilmsPage struct {
	Total      int        `json:"total"`
	TotalPages int        `json:"totalPages"`
	Items      []FilmItem `json:"items"`
}

type FilmItem struct {
	KinopoiskID  int          `json:"kinopoiskId"`
	NameRu       string       `json:"nameRu"`
	NameOriginal *string      `json:"nameOriginal"`
	Countries    []CountryDTO `json:"countries"`
	Genres       []GenreDTO   `json:"genres"`
	RatingImdb   *float32     `json:"ratingImdb"`
	Year         *int         `json:"year"`
}

// FilmDetail is the response from GET /api/v2.2/films/{id}.
type FilmDetail struct {
	Description *string `json:"description"`
}

type CountryDTO struct {
	Country string `json:"country"`
}

type GenreDTO struct {
	Genre string `json:"genre"`
}

// StaffMember is one entry from GET /api/v1/staff?filmId={id}.
type StaffMember struct {
	NameRu        string `json:"nameRu"`
	NameEn        string `json:"nameEn"`
	ProfessionKey string `json:"professionKey"`
}

// GetFilmsPage fetches a page of films ordered by vote count.
func (c *Client) GetFilmsPage(ctx context.Context, page int) (*FilmsPage, error) {
	if err := c.wait(ctx); err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/api/v2.2/films?page=%d&order=NUM_VOTE&type=FILM", c.baseURL, page)
	var result FilmsPage
	if err := c.get(ctx, url, &result); err != nil {
		return nil, fmt.Errorf("get films page %d: %w", page, err)
	}
	return &result, nil
}

// GetFilmDetail fetches the full detail for a single film (used for description).
func (c *Client) GetFilmDetail(ctx context.Context, filmID int) (*FilmDetail, error) {
	if err := c.wait(ctx); err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/api/v2.2/films/%d", c.baseURL, filmID)
	var result FilmDetail
	if err := c.get(ctx, url, &result); err != nil {
		return nil, fmt.Errorf("get film detail %d: %w", filmID, err)
	}
	return &result, nil
}

// GetStaff fetches the cast and crew for a film.
func (c *Client) GetStaff(ctx context.Context, filmID int) ([]StaffMember, error) {
	if err := c.wait(ctx); err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/api/v1/staff?filmId=%d", c.baseURL, filmID)
	var result []StaffMember
	if err := c.get(ctx, url, &result); err != nil {
		return nil, fmt.Errorf("get staff for film %d: %w", filmID, err)
	}
	return result, nil
}

func (c *Client) wait(ctx context.Context) error {
	select {
	case <-c.tokens:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Client) get(ctx context.Context, url string, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-KEY", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	return json.NewDecoder(resp.Body).Decode(target)
}
