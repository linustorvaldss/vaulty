package config

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func loadEnv() {
	if err := godotenv.Load(); err != nil {
		fmt.Println("Error loading .env file")
		fmt.Println(err)
	}
}

func InitDB() (*gorm.DB, error) {
	
	loadEnv()

	dsn := os.Getenv("POSTGRES_DSN")
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	
	if err != nil {
		fmt.Println("Failed to connect to the database:", err)
	} else {
		fmt.Println("Database connection established successfully")
	}
	
	return db, nil

}






