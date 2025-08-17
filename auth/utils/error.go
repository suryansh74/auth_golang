package utils

import (
	"github.com/gofiber/fiber/v2"
)

type CustomError struct {
	StatusCode int    `json:"status_code"`
	Message    string `json:"message"`
}

func (e *CustomError) Error() string {
	return e.Message
}

func NewError(statusCode int, message string) *CustomError {
	return &CustomError{
		StatusCode: statusCode,
		Message:    message,
	}
}

func ErrorResponse(c *fiber.Ctx, err *CustomError) error {
	return c.Status(err.StatusCode).JSON(fiber.Map{
		"error":       true,
		"message":     err.Message,
		"status_code": err.StatusCode,
	})
}

func SuccessResponse(c *fiber.Ctx, message string, data interface{}) error {
	return c.JSON(fiber.Map{
		"error":   false,
		"message": message,
		"data":    data,
	})
}
