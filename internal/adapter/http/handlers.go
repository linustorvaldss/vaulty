package httpapi

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/linustorvaldss/vaulty/internal/domain"
	"github.com/linustorvaldss/vaulty/internal/service"
)

type Handlers struct {
	service *service.Service
}

type CreateUserRequest struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

type CreateProjectRequest struct {
	UserID      string `json:"user_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type CreateSecretRequest struct {
	ProjectID string `json:"project_id"`
	Key       string `json:"key"`
	Value     string `json:"value"`
	Type      string `json:"type"`
}

func NewHandlers(service *service.Service) *Handlers {
	return &Handlers{service: service}
}

func (h *Handlers) RegisterRoutes(router *gin.Engine) {
	router.GET("/health", h.health)
	router.GET("/users", h.listUsers)
	router.POST("/users", h.createUser)
	router.GET("/projects", h.listProjects)
	router.POST("/projects", h.createProject)
	router.GET("/secrets", h.listSecrets)
	router.POST("/secrets", h.createSecret)
}

func (h *Handlers) health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
	})
}

func (h *Handlers) listUsers(c *gin.Context) {
	users, err := h.service.ListUsers()
	if err != nil {
		writeStoreError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"users": users,
	})
}

func (h *Handlers) createUser(c *gin.Context) {
	var request CreateUserRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}

	user, err := h.service.CreateUser(request.Name, request.Email)
	if err != nil {
		writeStoreError(c, err)
		return
	}

	c.JSON(http.StatusCreated, user)
}

func (h *Handlers) listProjects(c *gin.Context) {
	projects, err := h.service.ListProjects()
	if err != nil {
		writeStoreError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"projects": projects,
	})
}

func (h *Handlers) createProject(c *gin.Context) {
	var request CreateProjectRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}

	userID, err := uuid.Parse(request.UserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user_id"})
		return
	}

	project, err := h.service.CreateProject(userID, request.Name, request.Description)
	if err != nil {
		writeStoreError(c, err)
		return
	}

	c.JSON(http.StatusCreated, project)
}

func (h *Handlers) listSecrets(c *gin.Context) {
	projectID := uuid.Nil
	if rawID := c.Query("project_id"); rawID != "" {
		parsedID, err := uuid.Parse(rawID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid project_id"})
			return
		}
		projectID = parsedID
	}

	secrets, err := h.service.ListSecrets(projectID)
	if err != nil {
		writeStoreError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"secrets": secrets,
	})
}

func (h *Handlers) createSecret(c *gin.Context) {
	var request CreateSecretRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid payload"})
		return
	}

	projectID, err := uuid.Parse(request.ProjectID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid project_id"})
		return
	}

	secret, err := h.service.CreateSecret(projectID, request.Key, request.Value, request.Type)
	if err != nil {
		writeStoreError(c, err)
		return
	}

	c.JSON(http.StatusCreated, secret)
}

func writeStoreError(c *gin.Context, err error) {
	switch err {
	case domain.ErrValidation:
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing required fields"})
	case domain.ErrDuplicate:
		c.JSON(http.StatusConflict, gin.H{"error": "resource already exists"})
	case domain.ErrNotFound:
		c.JSON(http.StatusNotFound, gin.H{"error": "resource not found"})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "unexpected error"})
	}
}
