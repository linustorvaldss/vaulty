package service

import (
	"context"
	"sort"

	"github.com/linustorvaldss/vaulty/internal/domain"
	"github.com/linustorvaldss/vaulty/internal/parser"
	"github.com/linustorvaldss/vaulty/internal/port"
)

func vaultRef(s *domain.Secret) port.VaultRef {
	return port.VaultRef{TenantID: s.TenantID, ProjectID: s.ProjectID, EnvironmentID: s.EnvironmentID, SecretID: s.ID, Key: s.Key}
}

type SecretInput struct {
	Key         string  `json:"key"`
	Value       *string `json:"value"`
	Type        string  `json:"type"`
	Description *string `json:"description"`
}

// ListSecrets returns metadata; values are included only when reveal is true.
func (s *Service) ListSecrets(ctx context.Context, sc *Scope, projectRef, envRef string, reveal bool) ([]domain.Secret, error) {
	if err := sc.can(domain.RoleViewer, false); err != nil {
		return nil, err
	}
	_, env, err := s.resolveEnv(ctx, sc, projectRef, envRef)
	if err != nil {
		return nil, err
	}
	secrets, err := s.Store.Secrets().List(ctx, sc.TenantID(), env.ID)
	if err != nil {
		return nil, err
	}
	if reveal && len(secrets) > 0 {
		if err := s.fillValues(ctx, secrets); err != nil {
			return nil, err
		}
	}
	return secrets, nil
}

func (s *Service) fillValues(ctx context.Context, secrets []domain.Secret) error {
	refs := make([]port.VaultRef, len(secrets))
	for i := range secrets {
		refs[i] = vaultRef(&secrets[i])
	}
	values, err := s.Vault.GetMany(ctx, refs)
	if err != nil {
		return err
	}
	for i := range secrets {
		if v, ok := values[secrets[i].ID]; ok {
			secrets[i].Value = &v
		}
	}
	return nil
}

func (s *Service) GetSecret(ctx context.Context, sc *Scope, projectRef, envRef, key string) (*domain.Secret, error) {
	if err := sc.can(domain.RoleViewer, false); err != nil {
		return nil, err
	}
	_, env, err := s.resolveEnv(ctx, sc, projectRef, envRef)
	if err != nil {
		return nil, err
	}
	sec, err := s.Store.Secrets().GetByKey(ctx, sc.TenantID(), env.ID, key)
	if err != nil {
		return nil, err
	}
	v, err := s.Vault.Get(ctx, vaultRef(sec))
	if err != nil {
		return nil, err
	}
	sec.Value = &v
	return sec, nil
}

// CreateSecret fails with Conflict if the key already exists.
func (s *Service) CreateSecret(ctx context.Context, sc *Scope, projectRef, envRef string, in SecretInput) (*domain.Secret, error) {
	if err := sc.can(domain.RoleMember, true); err != nil {
		return nil, err
	}
	if in.Value == nil {
		return nil, domain.Invalid("value is required")
	}
	_, env, err := s.resolveEnv(ctx, sc, projectRef, envRef)
	if err != nil {
		return nil, err
	}
	if _, err := s.Store.Secrets().GetByKey(ctx, sc.TenantID(), env.ID, in.Key); err == nil {
		return nil, domain.Conflict("secret %q already exists in %s", in.Key, env.Slug)
	}
	return s.createSecret(ctx, sc, env, in)
}

// UpsertSecret creates or updates key in the environment (PUT semantics).
func (s *Service) UpsertSecret(ctx context.Context, sc *Scope, projectRef, envRef string, in SecretInput) (*domain.Secret, bool, error) {
	if err := sc.can(domain.RoleMember, true); err != nil {
		return nil, false, err
	}
	_, env, err := s.resolveEnv(ctx, sc, projectRef, envRef)
	if err != nil {
		return nil, false, err
	}
	existing, err := s.Store.Secrets().GetByKey(ctx, sc.TenantID(), env.ID, in.Key)
	switch {
	case err == nil:
		sec, err := s.updateSecret(ctx, sc, existing, in)
		return sec, false, err
	case domain.KindOf(err) == domain.KindNotFound:
		if in.Value == nil {
			return nil, false, domain.Invalid("value is required")
		}
		sec, err := s.createSecret(ctx, sc, env, in)
		return sec, true, err
	default:
		return nil, false, err
	}
}

func (s *Service) createSecret(ctx context.Context, sc *Scope, env *domain.Environment, in SecretInput) (*domain.Secret, error) {
	if err := domain.ValidateSecretKey(in.Key); err != nil {
		return nil, err
	}
	if err := domain.ValidateSecretValue(in.Key, *in.Value); err != nil {
		return nil, err
	}
	if in.Type == "" {
		in.Type = "string"
	}
	if !domain.ValidSecretType(in.Type) {
		return nil, domain.Invalid("unknown secret type %q", in.Type)
	}
	t := now()
	sec := &domain.Secret{
		ID: newID(), TenantID: sc.TenantID(), ProjectID: env.ProjectID, EnvironmentID: env.ID,
		Key: in.Key, Type: in.Type, Version: 1,
		CreatedBy: sc.UserID(), UpdatedBy: sc.UserID(), CreatedAt: t, UpdatedAt: t,
	}
	if in.Description != nil {
		sec.Description = *in.Description
	}
	// Value first: a metadata row must never point at a missing value.
	if err := s.Vault.Put(ctx, vaultRef(sec), *in.Value); err != nil {
		return nil, err
	}
	if err := s.Store.Secrets().Create(ctx, sec); err != nil {
		if derr := s.Vault.Delete(context.WithoutCancel(ctx), vaultRef(sec)); derr != nil {
			s.Logger.Error("orphaned vault secret", "secret_id", sec.ID, "err", derr)
		}
		return nil, err
	}
	sec.Value = in.Value
	return sec, nil
}

func (s *Service) updateSecret(ctx context.Context, sc *Scope, sec *domain.Secret, in SecretInput) (*domain.Secret, error) {
	if in.Type != "" {
		if !domain.ValidSecretType(in.Type) {
			return nil, domain.Invalid("unknown secret type %q", in.Type)
		}
		sec.Type = in.Type
	}
	if in.Description != nil {
		sec.Description = *in.Description
	}
	if in.Value != nil {
		if err := domain.ValidateSecretValue(sec.Key, *in.Value); err != nil {
			return nil, err
		}
		if err := s.Vault.Put(ctx, vaultRef(sec), *in.Value); err != nil {
			return nil, err
		}
		sec.Version++
		sec.Value = in.Value
	}
	sec.UpdatedBy, sec.UpdatedAt = sc.UserID(), now()
	if err := s.Store.Secrets().Update(ctx, sec); err != nil {
		return nil, err
	}
	return sec, nil
}

func (s *Service) DeleteSecret(ctx context.Context, sc *Scope, projectRef, envRef, key string) error {
	if err := sc.can(domain.RoleMember, true); err != nil {
		return err
	}
	_, env, err := s.resolveEnv(ctx, sc, projectRef, envRef)
	if err != nil {
		return err
	}
	sec, err := s.Store.Secrets().GetByKey(ctx, sc.TenantID(), env.ID, key)
	if err != nil {
		return err
	}
	return s.deleteSecret(ctx, sec)
}

func (s *Service) deleteSecret(ctx context.Context, sec *domain.Secret) error {
	if err := s.Vault.Delete(ctx, vaultRef(sec)); err != nil && domain.KindOf(err) != domain.KindNotFound {
		return err
	}
	return s.Store.Secrets().Delete(ctx, sec.TenantID, sec.ID)
}

// ---------- Import (upload .env / json / xml / yaml / settings.json) ----------

type ImportStrategy string

const (
	ImportOverwrite ImportStrategy = "overwrite" // update existing keys
	ImportSkip      ImportStrategy = "skip"      // keep existing keys untouched
	ImportFail      ImportStrategy = "fail"      // abort if any key exists
)

type ImportInput struct {
	Data     []byte
	Filename string
	Format   parser.Format
	Strategy ImportStrategy
	DryRun   bool
	Options  parser.Options
}

type ImportItem struct {
	Key    string `json:"key"`
	Action string `json:"action"` // created, updated, unchanged, skipped, error
	Line   int    `json:"line,omitempty"`
	Error  string `json:"error,omitempty"`
}

type ImportResult struct {
	Format  parser.Format  `json:"format"`
	DryRun  bool           `json:"dry_run"`
	Items   []ImportItem   `json:"items"`
	Issues  []parser.Issue `json:"issues,omitempty"`
	Summary map[string]int `json:"summary"`
}

// ImportSecrets parses a file and stores each entry as an individual secret.
// Each key is processed independently: one failing key does not stop the rest.
func (s *Service) ImportSecrets(ctx context.Context, sc *Scope, projectRef, envRef string, in ImportInput) (*ImportResult, error) {
	if err := sc.can(domain.RoleMember, true); err != nil {
		return nil, err
	}
	if in.Strategy == "" {
		in.Strategy = ImportOverwrite
	}
	switch in.Strategy {
	case ImportOverwrite, ImportSkip, ImportFail:
	default:
		return nil, domain.Invalid("strategy must be overwrite, skip or fail")
	}
	_, env, err := s.resolveEnv(ctx, sc, projectRef, envRef)
	if err != nil {
		return nil, err
	}
	parsed, err := parser.Parse(in.Data, in.Format, in.Filename, in.Options)
	if err != nil {
		return nil, domain.Invalid("%v", err)
	}
	if len(parsed.Entries) == 0 {
		return nil, domain.Invalid("no secrets found in file (format: %s)", parsed.Format)
	}

	existing, err := s.Store.Secrets().List(ctx, sc.TenantID(), env.ID)
	if err != nil {
		return nil, err
	}
	byKey := make(map[string]*domain.Secret, len(existing))
	for i := range existing {
		byKey[existing[i].Key] = &existing[i]
	}
	// Load current values so unchanged keys don't create new versions.
	var current map[string]string
	if len(existing) > 0 && in.Strategy == ImportOverwrite {
		refs := make([]port.VaultRef, len(existing))
		for i := range existing {
			refs[i] = vaultRef(&existing[i])
		}
		if current, err = s.Vault.GetMany(ctx, refs); err != nil {
			return nil, err
		}
	}

	if in.Strategy == ImportFail {
		for _, e := range parsed.Entries {
			if _, ok := byKey[e.Key]; ok {
				return nil, domain.Conflict("secret %q already exists (strategy=fail)", e.Key)
			}
		}
	}

	res := &ImportResult{Format: parsed.Format, DryRun: in.DryRun, Issues: parsed.Issues, Summary: map[string]int{}}
	for _, e := range parsed.Entries {
		item := ImportItem{Key: e.Key, Line: e.Line}
		value := e.Value
		cur, exists := byKey[e.Key]
		switch {
		case domain.ValidateSecretKey(e.Key) != nil:
			item.Action, item.Error = "error", domain.ValidateSecretKey(e.Key).Error()
		case domain.ValidateSecretValue(e.Key, value) != nil:
			item.Action, item.Error = "error", domain.ValidateSecretValue(e.Key, value).Error()
		case exists && in.Strategy == ImportSkip:
			item.Action = "skipped"
		case exists && current != nil && current[cur.ID] == value:
			item.Action = "unchanged"
		case exists:
			item.Action = "updated"
			if !in.DryRun {
				if _, err := s.updateSecret(ctx, sc, cur, SecretInput{Value: &value}); err != nil {
					item.Action, item.Error = "error", err.Error()
				}
			}
		default:
			item.Action = "created"
			if !in.DryRun {
				if _, err := s.createSecret(ctx, sc, env, SecretInput{Key: e.Key, Value: &value}); err != nil {
					item.Action, item.Error = "error", err.Error()
				}
			}
		}
		res.Summary[item.Action]++
		res.Items = append(res.Items, item)
	}
	return res, nil
}

// ---------- Export (CLI pull) ----------

// ExportSecrets returns all secrets of an environment as parser entries.
func (s *Service) ExportSecrets(ctx context.Context, sc *Scope, projectRef, envRef string) ([]parser.Entry, error) {
	secrets, err := s.ListSecrets(ctx, sc, projectRef, envRef, true)
	if err != nil {
		return nil, err
	}
	return toEntries(secrets, nil), nil
}

func toEntries(secrets []domain.Secret, only map[string]bool) []parser.Entry {
	out := make([]parser.Entry, 0, len(secrets))
	for _, sec := range secrets {
		if sec.Value == nil || (only != nil && !only[sec.Key]) {
			continue
		}
		out = append(out, parser.Entry{Key: sec.Key, Value: *sec.Value})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}
