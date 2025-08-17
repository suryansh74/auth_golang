package models

import (
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type User struct {
	ID                    uint           `json:"id" gorm:"primaryKey"`
	Email                 string         `json:"email" gorm:"unique;not null"`
	Password              string         `json:"-" gorm:"not null"`
	Name                  string         `json:"name" gorm:"not null"`
	IsLocked              bool           `json:"is_locked" gorm:"default:true"`
	IsEmailVerified       bool           `json:"is_email_verified" gorm:"default:false"`
	EmailVerificationCode string         `json:"-"`
	PasswordResetCode     string         `json:"-"`
	PasswordResetExpiry   *time.Time     `json:"-"`
	Token                 string         `json:"-"`
	CreatedAt             time.Time      `json:"created_at"`
	UpdatedAt             time.Time      `json:"updated_at"`
	DeletedAt             gorm.DeletedAt `json:"-" gorm:"index"`
}

func (u *User) HashPassword() error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.Password = string(hashedPassword)
	return nil
}

func (u *User) CheckPassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
	return err == nil
}

func (u *User) IsLoggedIn() bool {
	return u.Token != ""
}

func (u *User) IsPasswordResetValid() bool {
	if u.PasswordResetExpiry == nil {
		return false
	}
	return time.Now().Before(*u.PasswordResetExpiry)
}
