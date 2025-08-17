package main

import (
	"jwt-auth-app/config"
	"jwt-auth-app/logger"
	"jwt-auth-app/models"
	"jwt-auth-app/routes"
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"go.uber.org/zap"
)

func main() {
	// Initialize logger
	logger.InitLogger()
	defer logger.Sync()

	// Initialize configuration
	config.InitConfig()

	// Drop existing users table to avoid migration conflicts (DEV ONLY)
	if err := config.AppConfig.DB.Exec("DROP TABLE IF EXISTS users").Error; err != nil {
		logger.Log.Warn("Failed to drop users table", zap.Error(err))
	} else {
		logger.Log.Info("Dropped existing users table")
	}

	// Auto migrate database tables
	if err := config.AppConfig.DB.AutoMigrate(&models.User{}); err != nil {
		log.Fatal("Failed to migrate database:", err)
	}

	// Create Fiber app
	app := fiber.New(fiber.Config{
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			code := fiber.StatusInternalServerError
			message := "Internal Server Error"

			if e, ok := err.(*fiber.Error); ok {
				code = e.Code
				message = e.Message
			}

			logger.Log.Error("Request error",
				zap.String("method", c.Method()),
				zap.String("path", c.Path()),
				zap.Int("status", code),
				zap.String("error", message))

			return c.Status(code).JSON(fiber.Map{
				"error":       true,
				"message":     message,
				"status_code": code,
			})
		},
	})

	// Middleware
	app.Use(cors.New())
	app.Use(recover.New())

	// Setup routes
	routes.SetupRoutes(app)

	// Health check
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status":  "OK",
			"message": "Server is running",
		})
	})

	logger.Log.Info("Server starting on port 3000")
	log.Fatal(app.Listen(":3000"))
}
