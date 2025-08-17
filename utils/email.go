package utils

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/smtp"
	"os"
	"time"

	"github.com/suryansh74/auth_golang/auth/logger"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

var jwtSecret = []byte("your-secret-key") // Use environment variable in production

type EmailService struct {
	Host     string
	Port     string
	Email    string
	Password string
}

func NewEmailService() *EmailService {
	return &EmailService{
		Host:     os.Getenv("MAIL_HOST"),
		Port:     os.Getenv("MAIL_PORT"),
		Email:    os.Getenv("MAIL_EMAIL"),
		Password: os.Getenv("MAIL_PASSWORD"),
	}
}

func (e *EmailService) SendEmail(to, subject, body string) error {
	auth := smtp.PlainAuth("", e.Email, e.Password, e.Host)

	msg := []byte("To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"Content-Type: text/html; charset=UTF-8\r\n" +
		"\r\n" +
		body + "\r\n")

	err := smtp.SendMail(e.Host+":"+e.Port, auth, e.Email, []string{to}, msg)
	if err != nil {
		logger.Log.Error("Failed to send email",
			zap.String("to", to),
			zap.String("subject", subject),
			zap.Error(err))
		return err
	}

	logger.Log.Info("Email sent successfully",
		zap.String("to", to),
		zap.String("subject", subject))

	return nil
}

func GenerateVerificationToken(email string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": email,
		"type":  "email_verification",
		"exp":   time.Now().Add(time.Hour * 24).Unix(), // 24 hours
	})

	return token.SignedString(jwtSecret)
}

func GenerateRandomCode() (string, error) {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func GetVerificationEmailTemplate(name, verificationLink string) string {
	return fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Email Verification</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #007bff; color: white; text-align: center; padding: 20px; }
        .content { padding: 20px; background-color: #f8f9fa; }
        .button { background-color: #28a745; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 20px 0; }
        .footer { text-align: center; color: #666; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Welcome %s!</h1>
        </div>
        <div class="content">
            <h2>Please verify your email address</h2>
            <p>Thank you for registering with our service. To complete your registration, please click the button below to verify your email address:</p>
            <a href="%s" class="button">Verify Email</a>
            <p>Or copy and paste this link into your browser:</p>
            <p style="word-break: break-all;">%s</p>
            <p><strong>This link will expire in 24 hours.</strong></p>
        </div>
        <div class="footer">
            <p>If you didn't create an account, please ignore this email.</p>
        </div>
    </div>
</body>
</html>`, name, verificationLink, verificationLink)
}

func GetPasswordResetEmailTemplate(name, resetLink string) string {
	return fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Password Reset</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #dc3545; color: white; text-align: center; padding: 20px; }
        .content { padding: 20px; background-color: #f8f9fa; }
        .button { background-color: #dc3545; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 20px 0; }
        .footer { text-align: center; color: #666; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Password Reset Request</h1>
        </div>
        <div class="content">
            <h2>Hello %s</h2>
            <p>You requested to reset your password. Click the button below to set a new password:</p>
            <a href="%s" class="button">Reset Password</a>
            <p>Or copy and paste this link into your browser:</p>
            <p style="word-break: break-all;">%s</p>
            <p><strong>This link will expire in 1 hour.</strong></p>
            <p>If you didn't request this password reset, please ignore this email.</p>
        </div>
        <div class="footer">
            <p>For security reasons, never share this link with anyone.</p>
        </div>
    </div>
</body>
</html>`, name, resetLink, resetLink)
}
