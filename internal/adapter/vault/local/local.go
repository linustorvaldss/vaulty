// Package local is a SecretVault for development and tests: values are
// encrypted with AES-256-GCM using a master key and stored in the database.
// Production deployments should use the awssm adapter.
package local

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/linustorvaldss/vaulty/internal/domain"
	"github.com/linustorvaldss/vaulty/internal/port"
)

type entry struct {
	SecretID   string `gorm:"primaryKey;size:36"`
	TenantID   string `gorm:"size:36;not null;index"`
	Nonce      []byte `gorm:"not null"`
	Ciphertext []byte `gorm:"not null"`
	UpdatedAt  time.Time
}

func (entry) TableName() string { return "local_vault_entries" }

type Vault struct {
	db   *gorm.DB
	aead cipher.AEAD
}

var _ port.SecretVault = (*Vault)(nil)

// New creates the vault. masterKey is a base64-encoded 32-byte key.
func New(db *gorm.DB, masterKey string) (*Vault, error) {
	key, err := base64.StdEncoding.DecodeString(masterKey)
	if err != nil || len(key) != 32 {
		return nil, errors.New("LOCAL_VAULT_KEY must be a base64-encoded 32-byte key (openssl rand -base64 32)")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if err := db.AutoMigrate(&entry{}); err != nil {
		return nil, err
	}
	return &Vault{db: db, aead: aead}, nil
}

// aad binds the ciphertext to its tenant and secret so rows cannot be swapped.
func aad(ref port.VaultRef) []byte { return []byte(ref.TenantID + "/" + ref.SecretID) }

func (v *Vault) Put(ctx context.Context, ref port.VaultRef, value string) error {
	nonce := make([]byte, v.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	e := entry{SecretID: ref.SecretID, TenantID: ref.TenantID, Nonce: nonce,
		Ciphertext: v.aead.Seal(nil, nonce, []byte(value), aad(ref)), UpdatedAt: time.Now().UTC()}
	return v.db.WithContext(ctx).Clauses(clause.OnConflict{UpdateAll: true}).Create(&e).Error
}

func (v *Vault) open(ref port.VaultRef, e entry) (string, error) {
	pt, err := v.aead.Open(nil, e.Nonce, e.Ciphertext, aad(ref))
	if err != nil {
		return "", fmt.Errorf("decrypt secret %s: %w", ref.SecretID, err)
	}
	return string(pt), nil
}

func (v *Vault) Get(ctx context.Context, ref port.VaultRef) (string, error) {
	var e entry
	err := v.db.WithContext(ctx).First(&e, "secret_id = ? AND tenant_id = ?", ref.SecretID, ref.TenantID).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", domain.NotFound("secret value not found")
	}
	if err != nil {
		return "", err
	}
	return v.open(ref, e)
}

func (v *Vault) GetMany(ctx context.Context, refs []port.VaultRef) (map[string]string, error) {
	out := make(map[string]string, len(refs))
	if len(refs) == 0 {
		return out, nil
	}
	byID := make(map[string]port.VaultRef, len(refs))
	ids := make([]string, len(refs))
	for i, r := range refs {
		byID[r.SecretID], ids[i] = r, r.SecretID
	}
	var rows []entry
	if err := v.db.WithContext(ctx).Where("secret_id IN ?", ids).Find(&rows).Error; err != nil {
		return nil, err
	}
	for _, e := range rows {
		ref := byID[e.SecretID]
		if e.TenantID != ref.TenantID {
			continue
		}
		val, err := v.open(ref, e)
		if err != nil {
			return nil, err
		}
		out[e.SecretID] = val
	}
	return out, nil
}

func (v *Vault) Delete(ctx context.Context, ref port.VaultRef) error {
	return v.db.WithContext(ctx).Delete(&entry{}, "secret_id = ? AND tenant_id = ?", ref.SecretID, ref.TenantID).Error
}
