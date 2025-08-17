package controllers

import (
	"github.com/suryansh74/auth_golang/auth/config"
	"github.com/suryansh74/auth_golang/auth/logger"
	"github.com/suryansh74/auth_golang/auth/models"
	"github.com/suryansh74/auth_golang/auth/utils"

	"github.com/gofiber/fiber/v2"
	"go.uber.org/zap"
)

type UpdateProfileRequest struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

func GetProfile(c *fiber.Ctx) error {
	user := c.Locals("user").(*models.User)

	return utils.SuccessResponse(c, "Profile retrieved successfully", fiber.Map{
		"user": fiber.Map{
			"id":         user.ID,
			"email":      user.Email,
			"name":       user.Name,
			"is_locked":  user.IsLocked,
			"created_at": user.CreatedAt,
			"updated_at": user.UpdatedAt,
		},
	})
}

func UpdateProfile(c *fiber.Ctx) error {
	user := c.Locals("user").(*models.User)

	var req UpdateProfileRequest
	if err := c.BodyParser(&req); err != nil {
		err := utils.NewError(fiber.StatusBadRequest, "Invalid request format")
		return utils.ErrorResponse(c, err)
	}

	// Update user fields if provided
	if req.Name != "" {
		user.Name = req.Name
	}
	if req.Email != "" {
		// Check if email is already taken by another user
		var existingUser models.User
		if err := config.AppConfig.DB.Where("email = ? AND id != ?", req.Email, user.ID).First(&existingUser).Error; err == nil {
			err := utils.NewError(fiber.StatusConflict, "Email is already taken")
			return utils.ErrorResponse(c, err)
		}
		user.Email = req.Email
	}

	if err := config.AppConfig.DB.Save(user).Error; err != nil {
		logger.Log.Error("Failed to update profile", zap.Error(err))
		err := utils.NewError(fiber.StatusInternalServerError, "Failed to update profile")
		return utils.ErrorResponse(c, err)
	}

	logger.Log.Info("Profile updated successfully",
		zap.String("email", user.Email),
		zap.Uint("user_id", user.ID))

	return utils.SuccessResponse(c, "Profile updated successfully", fiber.Map{
		"user": fiber.Map{
			"id":         user.ID,
			"email":      user.Email,
			"name":       user.Name,
			"is_locked":  user.IsLocked,
			"updated_at": user.UpdatedAt,
		},
	})
}
