package service

import (
	"context"
	"strings"

	"github.com/linustorvaldss/vaulty/internal/domain"
	"github.com/linustorvaldss/vaulty/internal/port"
)

type ProjectInput struct {
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	Description string `json:"description"`
	// Environments to create; defaults to development, staging, production.
	Environments []string `json:"environments"`
}

type ProjectView struct {
	domain.Project
	Environments []domain.Environment `json:"environments"`
}

func (s *Service) CreateProject(ctx context.Context, sc *Scope, in ProjectInput) (*ProjectView, error) {
	if err := sc.can(domain.RoleMember, true); err != nil {
		return nil, err
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" {
		return nil, domain.Invalid("name is required")
	}
	slug := domain.Slugify(in.Slug)
	if slug == "" {
		slug = domain.Slugify(in.Name)
	}
	if slug == "" {
		return nil, domain.Invalid("name must contain letters or digits")
	}
	envs := in.Environments
	if len(envs) == 0 {
		envs = domain.DefaultEnvironments
	}

	t := now()
	view := &ProjectView{Project: domain.Project{
		ID: newID(), TenantID: sc.TenantID(), Name: in.Name, Slug: slug,
		Description: in.Description, CreatedBy: sc.UserID(), CreatedAt: t, UpdatedAt: t,
	}}
	err := s.Store.WithTx(ctx, func(tx port.Store) error {
		if err := tx.Projects().Create(ctx, &view.Project); err != nil {
			return err
		}
		seen := map[string]bool{}
		for _, name := range envs {
			env, err := newEnvironment(sc, view.ID, name)
			if err != nil {
				return err
			}
			if seen[env.Slug] {
				continue
			}
			seen[env.Slug] = true
			if err := tx.Environments().Create(ctx, env); err != nil {
				return err
			}
			view.Environments = append(view.Environments, *env)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return view, nil
}

func newEnvironment(sc *Scope, projectID, name string) (*domain.Environment, error) {
	name = strings.TrimSpace(name)
	slug := domain.Slugify(name)
	if slug == "" {
		return nil, domain.Invalid("invalid environment name %q", name)
	}
	return &domain.Environment{ID: newID(), TenantID: sc.TenantID(), ProjectID: projectID, Name: name, Slug: slug, CreatedAt: now()}, nil
}

func (s *Service) ListProjects(ctx context.Context, sc *Scope) ([]domain.Project, error) {
	if err := sc.can(domain.RoleViewer, false); err != nil {
		return nil, err
	}
	return s.Store.Projects().List(ctx, sc.TenantID())
}

func (s *Service) GetProject(ctx context.Context, sc *Scope, ref string) (*ProjectView, error) {
	if err := sc.can(domain.RoleViewer, false); err != nil {
		return nil, err
	}
	p, err := s.Store.Projects().Get(ctx, sc.TenantID(), ref)
	if err != nil {
		return nil, err
	}
	envs, err := s.Store.Environments().List(ctx, sc.TenantID(), p.ID)
	if err != nil {
		return nil, err
	}
	return &ProjectView{Project: *p, Environments: envs}, nil
}

type ProjectPatch struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
}

func (s *Service) UpdateProject(ctx context.Context, sc *Scope, ref string, in ProjectPatch) (*domain.Project, error) {
	if err := sc.can(domain.RoleMember, true); err != nil {
		return nil, err
	}
	p, err := s.Store.Projects().Get(ctx, sc.TenantID(), ref)
	if err != nil {
		return nil, err
	}
	if in.Name != nil {
		if strings.TrimSpace(*in.Name) == "" {
			return nil, domain.Invalid("name cannot be empty")
		}
		p.Name = strings.TrimSpace(*in.Name)
	}
	if in.Description != nil {
		p.Description = *in.Description
	}
	p.UpdatedAt = now()
	return p, s.Store.Projects().Update(ctx, p)
}

// DeleteProject removes the project, its environments and every secret value.
func (s *Service) DeleteProject(ctx context.Context, sc *Scope, ref string) error {
	if err := sc.can(domain.RoleAdmin, true); err != nil {
		return err
	}
	p, err := s.Store.Projects().Get(ctx, sc.TenantID(), ref)
	if err != nil {
		return err
	}
	secrets, err := s.Store.Secrets().ListByProject(ctx, sc.TenantID(), p.ID)
	if err != nil {
		return err
	}
	for _, sec := range secrets {
		if err := s.deleteSecret(ctx, &sec); err != nil {
			return err
		}
	}
	return s.Store.Projects().Delete(ctx, sc.TenantID(), p.ID)
}

// ---------- Environments ----------

func (s *Service) ListEnvironments(ctx context.Context, sc *Scope, projectRef string) ([]domain.Environment, error) {
	v, err := s.GetProject(ctx, sc, projectRef)
	if err != nil {
		return nil, err
	}
	return v.Environments, nil
}

func (s *Service) CreateEnvironment(ctx context.Context, sc *Scope, projectRef, name string) (*domain.Environment, error) {
	if err := sc.can(domain.RoleMember, true); err != nil {
		return nil, err
	}
	p, err := s.Store.Projects().Get(ctx, sc.TenantID(), projectRef)
	if err != nil {
		return nil, err
	}
	env, err := newEnvironment(sc, p.ID, name)
	if err != nil {
		return nil, err
	}
	return env, s.Store.Environments().Create(ctx, env)
}

func (s *Service) DeleteEnvironment(ctx context.Context, sc *Scope, projectRef, envRef string) error {
	if err := sc.can(domain.RoleAdmin, true); err != nil {
		return err
	}
	_, env, err := s.resolveEnv(ctx, sc, projectRef, envRef)
	if err != nil {
		return err
	}
	secrets, err := s.Store.Secrets().List(ctx, sc.TenantID(), env.ID)
	if err != nil {
		return err
	}
	for _, sec := range secrets {
		if err := s.deleteSecret(ctx, &sec); err != nil {
			return err
		}
	}
	return s.Store.Environments().Delete(ctx, sc.TenantID(), env.ID)
}

func (s *Service) resolveEnv(ctx context.Context, sc *Scope, projectRef, envRef string) (*domain.Project, *domain.Environment, error) {
	p, err := s.Store.Projects().Get(ctx, sc.TenantID(), projectRef)
	if err != nil {
		return nil, nil, err
	}
	env, err := s.Store.Environments().Get(ctx, sc.TenantID(), p.ID, envRef)
	if err != nil {
		return nil, nil, err
	}
	return p, env, nil
}
