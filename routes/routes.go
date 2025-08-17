package routes

import (
	"jwt-auth-app/controllers"
	"jwt-auth-app/middlewares"

	"github.com/gofiber/fiber/v2"
)

func SetupRoutes(app *fiber.App) {
	api := app.Group("/api/v1")

	// Auth routes
	auth := api.Group("/auth")
	auth.Post("/register", controllers.Register)
	auth.Post("/login", controllers.Login)
	auth.Post("/logout", middlewares.AuthRequired, controllers.Logout)

	// Profile routes (protected)
	profile := api.Group("/profile", middlewares.AuthRequired)
	profile.Get("/", controllers.GetProfile)
	profile.Put("/", controllers.UpdateProfile)
}
