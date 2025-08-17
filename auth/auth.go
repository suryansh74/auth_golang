package auth

import (
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/suryansh74/auth_golang/auth/config"
	"github.com/suryansh74/auth_golang/auth/logger"
	"github.com/suryansh74/auth_golang/auth/models"
	"github.com/suryansh74/auth_golang/auth/routes"
	"gorm.io/gorm"
)

// AuthModule represents the authentication module
type AuthModule struct {
	DB *gorm.DB
}

// NewAuthModule creates a new auth module instance
func NewAuthModule(db *gorm.DB) *AuthModule {
	return &AuthModule{
		DB: db,
	}
}

// Setup initializes the authentication system
func (a *AuthModule) Setup(app *fiber.App) error {
	// Initialize logger
	logger.InitLogger()

	// Set the database connection
	config.AppConfig = &config.Config{
		DB: a.DB,
	}

	// Auto migrate database tables
	if err := a.DB.AutoMigrate(&models.User{}); err != nil {
		log.Printf("Failed to migrate database: %v", err)
		return err
	}

	// Setup routes
	routes.SetupRoutes(app)

	return nil
}

// SetupWithConfig is a convenience function for quick setup
func SetupWithConfig(app *fiber.App, db *gorm.DB) error {
	authModule := NewAuthModule(db)
	return authModule.Setup(app)
}
