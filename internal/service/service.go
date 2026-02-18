package service

import (
	"github.com/google/uuid"

	"github.com/linustorvaldss/vaulty/internal/domain"
	"github.com/linustorvaldss/vaulty/internal/port"
)

type Service struct {
	users    port.UserRepository
	projects port.ProjectRepository
	secrets  port.SecretRepository
}

func NewService(users port.UserRepository, projects port.ProjectRepository, secrets port.SecretRepository) *Service {
	return &Service{
		users:    users,
		projects: projects,
		secrets:  secrets,
	}
}

func (s *Service) CreateUser(name, email string) (domain.User, error) {
	return s.users.CreateUser(name, email)
}

func (s *Service) ListUsers() ([]domain.User, error) {
	return s.users.ListUsers()
}

func (s *Service) CreateProject(userID uuid.UUID, name, description string) (domain.Project, error) {
	if _, err := s.users.GetUser(userID); err != nil {
		return domain.Project{}, err
	}
	return s.projects.CreateProject(userID, name, description)
}

func (s *Service) ListProjects() ([]domain.Project, error) {
	return s.projects.ListProjects()
}

func (s *Service) CreateSecret(projectID uuid.UUID, key, value, secretType string) (domain.Secret, error) {
	if _, err := s.projects.GetProject(projectID); err != nil {
		return domain.Secret{}, err
	}
	return s.secrets.CreateSecret(projectID, key, value, secretType)
}

func (s *Service) ListSecrets(projectID uuid.UUID) ([]domain.Secret, error) {
	return s.secrets.ListSecrets(projectID)
}
