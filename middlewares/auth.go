package middlewares

import (
	"jwt-auth-app/config"
	"jwt-auth-app/logger"
	"jwt-auth-app/models"
	"jwt-auth-app/utils"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

var jwtSecret = []byte("your-secret-key") // In production, use environment variable

func AuthRequired(c *fiber.Ctx) error {
	authHeader := c.Get("Authorization")
	if authHeader == "" {
		err := utils.NewError(fiber.StatusUnauthorized, "Authorization header required")
		return utils.ErrorResponse(c, err)
	}

	tokenString := strings.Replace(authHeader, "Bearer ", "", 1)

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		logger.Log.Error("Invalid token",
			zap.String("token", tokenString),
			zap.Error(err))

		err := utils.NewError(fiber.StatusUnauthorized, "Please login again")
		return utils.ErrorResponse(c, err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		err := utils.NewError(fiber.StatusUnauthorized, "Invalid token claims")
		return utils.ErrorResponse(c, err)
	}

	userID := uint(claims["user_id"].(float64))

	var user models.User
	if err := config.AppConfig.DB.First(&user, userID).Error; err != nil {
		err := utils.NewError(fiber.StatusUnauthorized, "User not found")
		return utils.ErrorResponse(c, err)
	}

	// Check if token matches stored token
	if user.Token != tokenString {
		err := utils.NewError(fiber.StatusUnauthorized, "Please login again")
		return utils.ErrorResponse(c, err)
	}

	c.Locals("user", &user)
	return c.Next()
}
