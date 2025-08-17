package controllers

import (
	"jwt-auth-app/config"
	"jwt-auth-app/logger"
	"jwt-auth-app/models"
	"jwt-auth-app/utils"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

var jwtSecret = []byte("your-secret-key") // In production, use environment variable

type RegisterRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=6"`
	Name     string `json:"name" validate:"required"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

func Register(c *fiber.Ctx) error {
	var req RegisterRequest
	if err := c.BodyParser(&req); err != nil {
		logger.Log.Error("Failed to parse register request", zap.Error(err))
		err := utils.NewError(fiber.StatusBadRequest, "Invalid request format")
		return utils.ErrorResponse(c, err)
	}

	// Check if user already exists
	var existingUser models.User
	if err := config.AppConfig.DB.Where("email = ?", req.Email).First(&existingUser).Error; err == nil {
		err := utils.NewError(fiber.StatusConflict, "User with this email already exists")
		return utils.ErrorResponse(c, err)
	}

	// Create new user
	user := models.User{
		Email:    req.Email,
		Password: req.Password,
		Name:     req.Name,
		IsLocked: true, // Automatically locked after registration
	}

	if err := user.HashPassword(); err != nil {
		logger.Log.Error("Failed to hash password", zap.Error(err))
		err := utils.NewError(fiber.StatusInternalServerError, "Failed to create user")
		return utils.ErrorResponse(c, err)
	}

	if err := config.AppConfig.DB.Create(&user).Error; err != nil {
		logger.Log.Error("Failed to create user", zap.Error(err))
		err := utils.NewError(fiber.StatusInternalServerError, "Failed to create user")
		return utils.ErrorResponse(c, err)
	}

	logger.Log.Info("User registered successfully",
		zap.String("email", user.Email),
		zap.Uint("user_id", user.ID))

	return utils.SuccessResponse(c, "User registered successfully. Account is locked.", fiber.Map{
		"user": fiber.Map{
			"id":        user.ID,
			"email":     user.Email,
			"name":      user.Name,
			"is_locked": user.IsLocked,
		},
	})
}

func Login(c *fiber.Ctx) error {
	var req LoginRequest
	if err := c.BodyParser(&req); err != nil {
		err := utils.NewError(fiber.StatusBadRequest, "Invalid request format")
		return utils.ErrorResponse(c, err)
	}

	var user models.User
	if err := config.AppConfig.DB.Where("email = ?", req.Email).First(&user).Error; err != nil {
		err := utils.NewError(fiber.StatusUnauthorized, "Invalid email or password")
		return utils.ErrorResponse(c, err)
	}

	if !user.CheckPassword(req.Password) {
		err := utils.NewError(fiber.StatusUnauthorized, "Invalid email or password")
		return utils.ErrorResponse(c, err)
	}

	// Check if user is already logged in
	if user.IsLoggedIn() {
		err := utils.NewError(fiber.StatusConflict, "User is already logged in, please log out first")
		return utils.ErrorResponse(c, err)
	}

	// Generate JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"email":   user.Email,
		"exp":     time.Now().Add(time.Hour * 24).Unix(),
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		logger.Log.Error("Failed to generate token", zap.Error(err))
		err := utils.NewError(fiber.StatusInternalServerError, "Failed to generate token")
		return utils.ErrorResponse(c, err)
	}

	// Store token in user record
	user.Token = tokenString
	if err := config.AppConfig.DB.Save(&user).Error; err != nil {
		logger.Log.Error("Failed to save token", zap.Error(err))
		err := utils.NewError(fiber.StatusInternalServerError, "Failed to login")
		return utils.ErrorResponse(c, err)
	}

	logger.Log.Info("User logged in successfully",
		zap.String("email", user.Email),
		zap.Uint("user_id", user.ID))

	return utils.SuccessResponse(c, "Login successful", fiber.Map{
		"token": tokenString,
		"user": fiber.Map{
			"id":        user.ID,
			"email":     user.Email,
			"name":      user.Name,
			"is_locked": user.IsLocked,
		},
	})
}

func Logout(c *fiber.Ctx) error {
	user := c.Locals("user").(*models.User)

	// Clear the token
	user.Token = ""
	if err := config.AppConfig.DB.Save(user).Error; err != nil {
		logger.Log.Error("Failed to logout user", zap.Error(err))
		err := utils.NewError(fiber.StatusInternalServerError, "Failed to logout")
		return utils.ErrorResponse(c, err)
	}

	logger.Log.Info("User logged out successfully",
		zap.String("email", user.Email),
		zap.Uint("user_id", user.ID))

	return utils.SuccessResponse(c, "Logged out successfully", nil)
}
