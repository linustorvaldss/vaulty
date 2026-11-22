// Package awssm stores secret values in AWS Secrets Manager, encrypted with a
// KMS customer managed key. Each Vaulty secret is one Secrets Manager secret
// named <prefix>/<tenant>/<project>/<environment>/<secret-id>.
//
// Tenants may connect their own AWS account (CloudConnection): Vaulty then
// assumes the given IAM role (with an external id) and writes to that
// account using the tenant's KMS key. Otherwise the platform account is used.
package awssm

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	smtypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/linustorvaldss/vaulty/internal/domain"
	"github.com/linustorvaldss/vaulty/internal/port"
)

type Config struct {
	// KMSKeyID is the platform CMK (key id, ARN or alias) used when the tenant
	// has no AWS connection. Empty = aws/secretsmanager managed key.
	KMSKeyID string
	// Prefix for secret names, e.g. "vaulty" or "vaulty-prod".
	Prefix string
	// ForceDelete deletes immediately instead of scheduling deletion.
	ForceDelete bool
	// RecoveryDays when ForceDelete is false (7-30).
	RecoveryDays int64
}

type target struct {
	sm       *secretsmanager.Client
	kmsKeyID string
	version  time.Time
}

type Vault struct {
	base   aws.Config
	cfg    Config
	clouds port.CloudConnectionRepository

	mu       sync.Mutex
	platform *target
	tenants  map[string]*target
}

var (
	_ port.SecretVault   = (*Vault)(nil)
	_ port.CloudVerifier = (*Verifier)(nil)
)

func New(base aws.Config, cfg Config, clouds port.CloudConnectionRepository) *Vault {
	if cfg.Prefix == "" {
		cfg.Prefix = "vaulty"
	}
	if cfg.RecoveryDays == 0 {
		cfg.RecoveryDays = 7
	}
	return &Vault{
		base: base, cfg: cfg, clouds: clouds,
		platform: &target{sm: secretsmanager.NewFromConfig(base), kmsKeyID: cfg.KMSKeyID},
		tenants:  map[string]*target{},
	}
}

// tenantConfig returns an aws.Config that assumes the tenant's role.
func tenantConfig(base aws.Config, c *domain.CloudConnection) aws.Config {
	cfg := base.Copy()
	cfg.Region = c.Region
	provider := stscreds.NewAssumeRoleProvider(sts.NewFromConfig(base), c.RoleARN, func(o *stscreds.AssumeRoleOptions) {
		o.ExternalID = aws.String(c.ExternalID)
		o.RoleSessionName = "vaulty-" + strings.ReplaceAll(c.TenantID, "-", "")[:16]
	})
	cfg.Credentials = aws.NewCredentialsCache(provider)
	return cfg
}

func (v *Vault) target(ctx context.Context, tenantID string) (*target, error) {
	conn, err := v.clouds.Get(ctx, tenantID, domain.CloudAWS)
	if domain.KindOf(err) == domain.KindNotFound {
		return v.platform, nil
	}
	if err != nil {
		return nil, err
	}
	if conn.Status != "verified" {
		return nil, domain.Unavailable(nil, "the workspace AWS connection is not verified; verify it before storing secrets")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if t, ok := v.tenants[tenantID]; ok && t.version.Equal(conn.UpdatedAt) {
		return t, nil
	}
	t := &target{sm: secretsmanager.NewFromConfig(tenantConfig(v.base, conn)), kmsKeyID: conn.KMSKeyID, version: conn.UpdatedAt}
	v.tenants[tenantID] = t
	return t, nil
}

func (v *Vault) name(ref port.VaultRef) string {
	return fmt.Sprintf("%s/%s/%s/%s/%s", v.cfg.Prefix, ref.TenantID, ref.ProjectID, ref.EnvironmentID, ref.SecretID)
}

func isNotFound(err error) bool {
	var nf *smtypes.ResourceNotFoundException
	return errors.As(err, &nf)
}

func wrap(err error, op string) error {
	if err == nil {
		return nil
	}
	if domain.KindOf(err) != "" {
		return err
	}
	return domain.Unavailable(err, "aws secrets manager %s failed", op)
}

func (v *Vault) Put(ctx context.Context, ref port.VaultRef, value string) error {
	t, err := v.target(ctx, ref.TenantID)
	if err != nil {
		return err
	}
	name := v.name(ref)
	_, err = t.sm.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{SecretId: &name, SecretString: &value})
	if err == nil || !isNotFound(err) {
		return wrap(err, "put")
	}
	in := &secretsmanager.CreateSecretInput{
		Name:         &name,
		SecretString: &value,
		Description:  aws.String("Managed by Vaulty"),
		Tags: []smtypes.Tag{
			{Key: aws.String("vaulty:tenant"), Value: aws.String(ref.TenantID)},
			{Key: aws.String("vaulty:project"), Value: aws.String(ref.ProjectID)},
			{Key: aws.String("vaulty:environment"), Value: aws.String(ref.EnvironmentID)},
			{Key: aws.String("vaulty:key"), Value: aws.String(tagValue(ref.Key))},
		},
	}
	if t.kmsKeyID != "" {
		in.KmsKeyId = &t.kmsKeyID
	}
	_, err = t.sm.CreateSecret(ctx, in)
	var exists *smtypes.ResourceExistsException
	if errors.As(err, &exists) { // concurrent create: fall back to a new version
		_, err = t.sm.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{SecretId: &name, SecretString: &value})
	}
	return wrap(err, "create")
}

// tagValue keeps tag values within AWS limits (256 chars).
func tagValue(s string) string {
	if len(s) > 256 {
		return s[:256]
	}
	return s
}

func (v *Vault) Get(ctx context.Context, ref port.VaultRef) (string, error) {
	t, err := v.target(ctx, ref.TenantID)
	if err != nil {
		return "", err
	}
	out, err := t.sm.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(v.name(ref))})
	if isNotFound(err) {
		return "", domain.NotFound("secret value not found")
	}
	if err != nil {
		return "", wrap(err, "get")
	}
	return aws.ToString(out.SecretString), nil
}

// GetMany uses BatchGetSecretValue (20 secrets per call).
func (v *Vault) GetMany(ctx context.Context, refs []port.VaultRef) (map[string]string, error) {
	out := make(map[string]string, len(refs))
	byTenant := map[string][]port.VaultRef{}
	for _, r := range refs {
		byTenant[r.TenantID] = append(byTenant[r.TenantID], r)
	}
	for tenantID, group := range byTenant {
		t, err := v.target(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		idByName := make(map[string]string, len(group))
		for _, r := range group {
			idByName[v.name(r)] = r.SecretID
		}
		for start := 0; start < len(group); start += 20 {
			end := min(start+20, len(group))
			names := make([]string, 0, end-start)
			for _, r := range group[start:end] {
				names = append(names, v.name(r))
			}
			res, err := t.sm.BatchGetSecretValue(ctx, &secretsmanager.BatchGetSecretValueInput{SecretIdList: names})
			if err != nil {
				return nil, wrap(err, "batch get")
			}
			for _, sv := range res.SecretValues {
				if id, ok := idByName[aws.ToString(sv.Name)]; ok {
					out[id] = aws.ToString(sv.SecretString)
				}
			}
			for _, e := range res.Errors {
				if aws.ToString(e.ErrorCode) != "ResourceNotFoundException" {
					return nil, domain.Unavailable(nil, "aws secrets manager: %s: %s", aws.ToString(e.ErrorCode), aws.ToString(e.Message))
				}
			}
		}
	}
	return out, nil
}

func (v *Vault) Delete(ctx context.Context, ref port.VaultRef) error {
	t, err := v.target(ctx, ref.TenantID)
	if err != nil {
		return err
	}
	in := &secretsmanager.DeleteSecretInput{SecretId: aws.String(v.name(ref))}
	if v.cfg.ForceDelete {
		in.ForceDeleteWithoutRecovery = aws.Bool(true)
	} else {
		in.RecoveryWindowInDays = aws.Int64(v.cfg.RecoveryDays)
	}
	_, err = t.sm.DeleteSecret(ctx, in)
	if isNotFound(err) {
		return nil
	}
	return wrap(err, "delete")
}

// ---------- Verifier ----------

// Verifier checks that Vaulty can assume a tenant's role and use its KMS key
// and Secrets Manager.
type Verifier struct {
	Base aws.Config
}

func (vf *Verifier) Verify(ctx context.Context, c *domain.CloudConnection) error {
	cfg := tenantConfig(vf.Base, c)
	if _, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); err != nil {
		return fmt.Errorf("cannot assume role %s (check trust policy and external id): %w", c.RoleARN, err)
	}
	if _, err := secretsmanager.NewFromConfig(cfg).ListSecrets(ctx, &secretsmanager.ListSecretsInput{MaxResults: aws.Int32(1)}); err != nil {
		return fmt.Errorf("role cannot access Secrets Manager in %s: %w", c.Region, err)
	}
	if c.KMSKeyID != "" {
		out, err := kms.NewFromConfig(cfg).DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: &c.KMSKeyID})
		if err != nil {
			return fmt.Errorf("role cannot describe KMS key %s: %w", c.KMSKeyID, err)
		}
		if out.KeyMetadata.KeyState != kmstypes.KeyStateEnabled {
			return fmt.Errorf("KMS key %s is %s", c.KMSKeyID, out.KeyMetadata.KeyState)
		}
	}
	return nil
}
