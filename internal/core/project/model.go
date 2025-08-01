package project

import (
    "time"
	
	// packages imports
    "github.com/google/uuid"

	// internal imports
	"github.com/linustorvaldss/vaulty/internal/core/user"
)

type Project struct {

	ID          uuid.UUID `gorm:"type:uuid;primaryKey;not null" json:"id"`
    UserID      uuid.UUID `gorm:"type:uuid;not null" json:"user_id"`               // FK    
    Name        string    `gorm:"type:varchar(255);not null;unique" json:"name"`      
    Description string    `gorm:"type:text" json:"description"`                       
    CreatedBy   uuid.UUID `gorm:"type:uuid;not null" json:"created_by"`               // FK
    UpdatedBy   uuid.UUID `gorm:"type:uuid" json:"updated_by"`                        // FK
    CreatedAt   time.Time `gorm:"autoCreateTime" json:"created_at"`                   
    UpdatedAt   time.Time `gorm:"autoUpdateTime" json:"updated_at"`

	User       user.User `gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE" json:"-"`
    Creator    user.User `gorm:"foreignKey:CreatedBy" json:"-"`
    Updater    user.User `gorm:"foreignKey:UpdatedBy" json:"-"`

}

// type CreateProjectRequest struct {
//     Key   string `json:"key"`
//     Value string `json:"value"`
// }

// type UpdateProjectRequest struct {
//     Value string `json:"value"`
// }