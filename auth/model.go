package auth

import (
	"gorm.io/gorm"
)

type Auth struct {
	gorm.Model
	UserId   uint
	AuthUuid string
}

type Locker struct {
	gorm.Model
	UserId   uint
	Password string
}
