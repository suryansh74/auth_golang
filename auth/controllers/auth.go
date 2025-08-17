package controllers

import (
	"github.com/suryansh74/auth_golang/auth/config"
	"github.com/suryansh74/auth_golang/auth/logger"
	"github.com/suryansh74/auth_golang/auth/models"
	"github.com/suryansh74/auth_golang/auth/utils"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

var jwtSecret = []byte("your-secret-key")

type RegisterRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=6"`
	Name     string `json:"name" validate:"required"`
}

type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type ForgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email"`
}

type ResetPasswordRequest struct {
	NewPassword string `json:"new_password" validate:"required,min=6"`
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

	// Generate verification code
	verificationCode, err := utils.GenerateRandomCode()
	if err != nil {
		logger.Log.Error("Failed to generate verification code", zap.Error(err))
		err := utils.NewError(fiber.StatusInternalServerError, "Failed to create user")
		return utils.ErrorResponse(c, err)
	}

	// Create new user
	user := models.User{
		Email:                 req.Email,
		Password:              req.Password,
		Name:                  req.Name,
		IsLocked:              true,
		IsEmailVerified:       false,
		EmailVerificationCode: verificationCode,
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

	// Send verification email
	emailService := utils.NewEmailService()
	verificationLink := "http://localhost:3000/api/v1/auth/verify-email?code=" + verificationCode
	emailTemplate := utils.GetVerificationEmailTemplate(user.Name, verificationLink)

	if err := emailService.SendEmail(user.Email, "Please verify your email", emailTemplate); err != nil {
		logger.Log.Error("Failed to send verification email", zap.Error(err))
		// Don't fail registration if email fails, just log it
	}

	logger.Log.Info("User registered successfully",
		zap.String("email", user.Email),
		zap.Uint("user_id", user.ID))

	return utils.SuccessResponse(c, "User registered successfully. Please check your email to verify your account.", fiber.Map{
		"user": fiber.Map{
			"id":                user.ID,
			"email":             user.Email,
			"name":              user.Name,
			"is_locked":         user.IsLocked,
			"is_email_verified": user.IsEmailVerified,
		},
	})
}

func VerifyEmail(c *fiber.Ctx) error {
	code := c.Query("code")
	if code == "" {
		err := utils.NewError(fiber.StatusBadRequest, "Verification code is required")
		return utils.ErrorResponse(c, err)
	}

	var user models.User
	if err := config.AppConfig.DB.Where("email_verification_code = ?", code).First(&user).Error; err != nil {
		err := utils.NewError(fiber.StatusBadRequest, "Invalid verification code")
		return utils.ErrorResponse(c, err)
	}

	if user.IsEmailVerified {
		err := utils.NewError(fiber.StatusBadRequest, "Email is already verified")
		return utils.ErrorResponse(c, err)
	}

	// Verify email
	user.IsEmailVerified = true
	user.EmailVerificationCode = ""

	if err := config.AppConfig.DB.Save(&user).Error; err != nil {
		logger.Log.Error("Failed to verify email", zap.Error(err))
		err := utils.NewError(fiber.StatusInternalServerError, "Failed to verify email")
		return utils.ErrorResponse(c, err)
	}

	logger.Log.Info("Email verified successfully",
		zap.String("email", user.Email),
		zap.Uint("user_id", user.ID))

	return utils.SuccessResponse(c, "Email verified successfully", nil)
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

	if !user.IsEmailVerified {
		err := utils.NewError(fiber.StatusUnauthorized, "Please verify your email before logging in")
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
			"id":                user.ID,
			"email":             user.Email,
			"name":              user.Name,
			"is_locked":         user.IsLocked,
			"is_email_verified": user.IsEmailVerified,
		},
	})
}

func ForgotPassword(c *fiber.Ctx) error {
	var req ForgotPasswordRequest
	if err := c.BodyParser(&req); err != nil {
		err := utils.NewError(fiber.StatusBadRequest, "Invalid request format")
		return utils.ErrorResponse(c, err)
	}

	var user models.User
	if err := config.AppConfig.DB.Where("email = ?", req.Email).First(&user).Error; err != nil {
		// Don't reveal if email exists or not for security
		return utils.SuccessResponse(c, "If the email exists, a password reset link has been sent", nil)
	}

	// Generate reset code
	resetCode, err := utils.GenerateRandomCode()
	if err != nil {
		logger.Log.Error("Failed to generate reset code", zap.Error(err))
		err := utils.NewError(fiber.StatusInternalServerError, "Failed to process request")
		return utils.ErrorResponse(c, err)
	}

	// Set reset code and expiry (1 hour)
	expiry := time.Now().Add(time.Hour)
	user.PasswordResetCode = resetCode
	user.PasswordResetExpiry = &expiry

	if err := config.AppConfig.DB.Save(&user).Error; err != nil {
		logger.Log.Error("Failed to save reset code", zap.Error(err))
		err := utils.NewError(fiber.StatusInternalServerError, "Failed to process request")
		return utils.ErrorResponse(c, err)
	}

	// Send password reset email
	emailService := utils.NewEmailService()
	resetLink := "http://localhost:3000/api/v1/auth/reset-password?code=" + resetCode
	emailTemplate := utils.GetPasswordResetEmailTemplate(user.Name, resetLink)

	if err := emailService.SendEmail(user.Email, "Password Reset Request", emailTemplate); err != nil {
		logger.Log.Error("Failed to send reset email", zap.Error(err))
		err := utils.NewError(fiber.StatusInternalServerError, "Failed to send reset email")
		return utils.ErrorResponse(c, err)
	}

	logger.Log.Info("Password reset email sent",
		zap.String("email", user.Email),
		zap.Uint("user_id", user.ID))

	return utils.SuccessResponse(c, "Password reset link has been sent to your email", nil)
}

func ResetPassword(c *fiber.Ctx) error {
	code := c.Query("code")
	if code == "" {
		err := utils.NewError(fiber.StatusBadRequest, "Reset code is required")
		return utils.ErrorResponse(c, err)
	}

	var req ResetPasswordRequest
	if err := c.BodyParser(&req); err != nil {
		err := utils.NewError(fiber.StatusBadRequest, "Invalid request format")
		return utils.ErrorResponse(c, err)
	}

	var user models.User
	if err := config.AppConfig.DB.Where("password_reset_code = ?", code).First(&user).Error; err != nil {
		err := utils.NewError(fiber.StatusBadRequest, "Invalid reset code")
		return utils.ErrorResponse(c, err)
	}

	if !user.IsPasswordResetValid() {
		err := utils.NewError(fiber.StatusBadRequest, "Reset code has expired")
		return utils.ErrorResponse(c, err)
	}

	// Update password
	user.Password = req.NewPassword
	if err := user.HashPassword(); err != nil {
		logger.Log.Error("Failed to hash new password", zap.Error(err))
		err := utils.NewError(fiber.StatusInternalServerError, "Failed to reset password")
		return utils.ErrorResponse(c, err)
	}

	// Clear reset code and expiry, also clear any existing tokens
	user.PasswordResetCode = ""
	user.PasswordResetExpiry = nil
	user.Token = "" // Force re-login after password reset

	if err := config.AppConfig.DB.Save(&user).Error; err != nil {
		logger.Log.Error("Failed to save new password", zap.Error(err))
		err := utils.NewError(fiber.StatusInternalServerError, "Failed to reset password")
		return utils.ErrorResponse(c, err)
	}

	logger.Log.Info("Password reset successfully",
		zap.String("email", user.Email),
		zap.Uint("user_id", user.ID))

	return utils.SuccessResponse(c, "Password has been reset successfully. Please login with your new password.", nil)
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
