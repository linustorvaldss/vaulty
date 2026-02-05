package port

import (
	"github.com/google/uuid"

	"github.com/linustorvaldss/vaulty/internal/domain"
)

type UserRepository interface {
	CreateUser(name, email string) (domain.User, error)
	ListUsers() ([]domain.User, error)
	GetUser(id uuid.UUID) (domain.User, error)
}

type ProjectRepository interface {
	CreateProject(userID uuid.UUID, name, description string) (domain.Project, error)
	ListProjects() ([]domain.Project, error)
	GetProject(id uuid.UUID) (domain.Project, error)
}

type SecretRepository interface {
	CreateSecret(projectID uuid.UUID, key, value, secretType string) (domain.Secret, error)
	ListSecrets(projectID uuid.UUID) ([]domain.Secret, error)
}
