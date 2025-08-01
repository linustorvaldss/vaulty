package user

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type User struct {
	ID               uuid.UUID      `gorm:"type:uuid;               primaryKey"             json:"id"`
	Name             string         `gorm:"type:varchar(255);       not null"               json:"name"`
	Email            string         `gorm:"type:varchar(255);       not null;unique"        json:"email"`
	EmailVerified    bool           `gorm:"default:false"                                   json:"email_verified"`
	AuthProviderName string         `gorm:"type:varchar(50)"                                json:"auth_provider_name"` // e.g., mail, github
	AuthProviderID   string         `gorm:"type:varchar(255)"                               json:"auth_provider_id"`
	Password         string         `gorm:"type:varchar"                                    json:"-"` // not serialized in JSON
	Status           bool           `gorm:"default:true"                                    json:"status"`
	CreatedAt        time.Time      `gorm:"autoCreateTime"                                  json:"created_at"`
	UpdatedAt        time.Time      `gorm:"autoUpdateTime"                                  json:"updated_at"`
	DeletedAt        gorm.DeletedAt `gorm:"index"                                          json:"-"`
}

// type CreateUserRequest struct {
// 	Name     string `json:"name"`
// 	Email    string `json:"email"`
// 	Password string `json:"password"`
// }

// type UpdateUserRequest struct {
// 	Value string `json:"value"`
// }
