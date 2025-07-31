// load envs
// cors
//
// middleware
// init server

package main

import (
	"fmt"
	"net/http"
	"os"

	// "log"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	// "github.com/linustorvaldss/vaulty/config"
)

// Config holds environment configuration
type Config struct {
	Port string
	Env  string
}

// Load environment variables and return Config
func loadEnvs() Config {
	err := godotenv.Load()
	if err != nil {
		fmt.Printf("Error loading .env file: %v\n", err)
	}

	config := Config{
		Port: os.Getenv("PORT"),
		Env:  os.Getenv("ENV"),
	}

	fmt.Print("Port:", config.Port, "\n")
	fmt.Print("Environment:", config.Env, "\n")

	return config
}

// Setup CORS and other middleware
func setupMiddleware(router *gin.Engine) {
	router.Use(cors.Default())
}

func setupRoutes(router *gin.Engine) {

	router.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "Hello World",
		})
	})
}


func initServer() *gin.Engine {
	router := gin.Default()

	setupMiddleware(router)
	setupRoutes(router)

	return router
}

func main() {
	config := loadEnvs()
	router := initServer()
	router.Run(":" + config.Port)
}
