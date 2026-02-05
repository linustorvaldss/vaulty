package memory

import (
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/linustorvaldss/vaulty/internal/domain"
)

type Store struct {
	mu            sync.RWMutex
	users         map[uuid.UUID]domain.User
	projects      map[uuid.UUID]domain.Project
	secrets       map[uuid.UUID]domain.Secret
	emailIndex    map[string]uuid.UUID
	projectByName map[string]uuid.UUID
}

func NewStore() *Store {
	return &Store{
		users:         make(map[uuid.UUID]domain.User),
		projects:      make(map[uuid.UUID]domain.Project),
		secrets:       make(map[uuid.UUID]domain.Secret),
		emailIndex:    make(map[string]uuid.UUID),
		projectByName: make(map[string]uuid.UUID),
	}
}

func (s *Store) CreateUser(name, email string) (domain.User, error) {
	if name == "" || email == "" {
		return domain.User{}, domain.ErrValidation
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.emailIndex[email]; exists {
		return domain.User{}, domain.ErrDuplicate
	}

	user := domain.User{
		ID:        uuid.New(),
		Name:      name,
		Email:     email,
		CreatedAt: time.Now().UTC(),
	}

	s.users[user.ID] = user
	s.emailIndex[email] = user.ID
	return user, nil
}

func (s *Store) ListUsers() ([]domain.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	users := make([]domain.User, 0, len(s.users))
	for _, user := range s.users {
		users = append(users, user)
	}
	return users, nil
}

func (s *Store) GetUser(id uuid.UUID) (domain.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, ok := s.users[id]
	if !ok {
		return domain.User{}, domain.ErrNotFound
	}
	return user, nil
}

func (s *Store) CreateProject(userID uuid.UUID, name, description string) (domain.Project, error) {
	if userID == uuid.Nil || name == "" {
		return domain.Project{}, domain.ErrValidation
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.projectByName[name]; exists {
		return domain.Project{}, domain.ErrDuplicate
	}

	project := domain.Project{
		ID:          uuid.New(),
		UserID:      userID,
		Name:        name,
		Description: description,
		CreatedAt:   time.Now().UTC(),
	}

	s.projects[project.ID] = project
	s.projectByName[name] = project.ID
	return project, nil
}

func (s *Store) ListProjects() ([]domain.Project, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	projects := make([]domain.Project, 0, len(s.projects))
	for _, project := range s.projects {
		projects = append(projects, project)
	}
	return projects, nil
}

func (s *Store) GetProject(id uuid.UUID) (domain.Project, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	project, ok := s.projects[id]
	if !ok {
		return domain.Project{}, domain.ErrNotFound
	}
	return project, nil
}

func (s *Store) CreateSecret(projectID uuid.UUID, key, value, secretType string) (domain.Secret, error) {
	if projectID == uuid.Nil || key == "" || value == "" || secretType == "" {
		return domain.Secret{}, domain.ErrValidation
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	secret := domain.Secret{
		ID:        uuid.New(),
		ProjectID: projectID,
		Key:       key,
		Value:     value,
		Type:      secretType,
		CreatedAt: time.Now().UTC(),
	}

	s.secrets[secret.ID] = secret
	return secret, nil
}

func (s *Store) ListSecrets(projectID uuid.UUID) ([]domain.Secret, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	secrets := make([]domain.Secret, 0, len(s.secrets))
	for _, secret := range s.secrets {
		if projectID != uuid.Nil && secret.ProjectID != projectID {
			continue
		}
		secrets = append(secrets, secret)
	}
	return secrets, nil
}
