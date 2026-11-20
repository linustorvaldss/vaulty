package config

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// db.AutoMigrate(&user.User{}, &project.Project{})


// type Config struct {
// 	Env           Env               `yaml:"env" mapstructure:"env"`
// 	App           *AppConfig        `yaml:"app" mapstructure:"app"`
// 	HTTPServer    *HttpServerConfig `yaml:"http_server" mapstructure:"http_server"`
// 	MetricsServer *MetricsConfig    `yaml:"metrics_server" mapstructure:"metrics_server"`
// 	Log           *LogConfig        `yaml:"log" mapstructure:"log"`
// 	MySQL         *MySQLConfig      `yaml:"mysql" mapstructure:"mysql"`
// 	Redis         *RedisConfig      `yaml:"redis" mapstructure:"redis"`
// 	Postgre       *PostgreSQLConfig `yaml:"postgres" mapstructure:"postgres"`
// 	MongoDB       *MongoDBConfig    `yaml:"mongodb" mapstructure:"mongodb"`
// 	MigrationDir  string            `yaml:"migration_dir" mapstructure:"migration_dir"`
// }

func loadEnv() {
	if err := godotenv.Load(); err != nil {
		fmt.Println("Error loading .env file")
		fmt.Println(err)
	}
}

func InitDB() (*gorm.DB, error) {

// 	db.AutoMigrate(
//     &user.User{},
//     &project.Project{},
//     &secret.Secret{},
// )

	
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






