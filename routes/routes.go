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
	auth.Get("/verify-email", controllers.VerifyEmail)
	auth.Post("/login", controllers.Login)
	auth.Post("/forgot-password", controllers.ForgotPassword)
	auth.Post("/reset-password", controllers.ResetPassword)
	auth.Post("/logout", middlewares.AuthRequired, controllers.Logout)

	// Profile routes (protected)
	profile := api.Group("/profile", middlewares.AuthRequired)
	profile.Get("/", controllers.GetProfile)
	profile.Put("/", controllers.UpdateProfile)
}
