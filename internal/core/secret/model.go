package secret

import (
	"time"

	// packages imports
	"github.com/google/uuid"

	// internal imports
	"github.com/linustorvaldss/vaulty/internal/core/project"
	"github.com/linustorvaldss/vaulty/internal/core/user"
)

// SecretType := enum defines the type of secret
type SecretType string


// TODO: define them or refactor the enum to varchar
const (
	SecretString SecretType = "string"
	SecretJSON   SecretType = "json"
	SecretFile   SecretType = "file"
	SecretToken  SecretType = "token"
	SecretEmail  SecretType = "email"
	SecretUUID   SecretType = "uuid"
)

type Secret struct {
	ID        uuid.UUID  `gorm:"type:uuid;primaryKey" json:"id"`
	ProjectID uuid.UUID  `gorm:"type:uuid;not null" json:"project_id"`
	Key       string     `gorm:"type:varchar;not null" json:"key"`
	Value     string     `gorm:"type:varchar;not null" json:"value"`
	Type      SecretType `gorm:"type:varchar(20)" json:"type"`
	Status    bool       `gorm:"default:true" json:"status"`
	CreatedBy uuid.UUID  `gorm:"type:uuid" json:"created_by"`
	UpdatedBy uuid.UUID  `gorm:"type:uuid" json:"updated_by"`
	CreatedAt time.Time  `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt time.Time  `gorm:"autoUpdateTime" json:"updated_at"`

	Project project.Project `gorm:"foreignKey:ProjectID" json:"-"`
	Creator user.User       `gorm:"foreignKey:CreatedBy" json:"-"`
	Updater *user.User      `gorm:"foreignKey:UpdatedBy" json:"-"`
}

// type CreateSecretRequest struct {
//     Key   string `json:"key"`
//     Value string `json:"value"`
// }

// type UpdateSecretRequest struct {
//     Value string `json:"value"`
// }
