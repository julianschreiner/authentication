package auth

import (
	"gorm.io/gorm"
)

type AuthRepository interface {
	CreateAuth(auth *Auth) error
	DeleteAuth(auth *Auth) error
	GetByQuery(query *Auth) (*Auth, error)
	GetLockerEntry(uid uint) (*Locker, error)
	CreateLockerEntry(locker *Locker) error
}

type authRepo struct {
	db *gorm.DB
}

func NewAuthRepository(db *gorm.DB) AuthRepository {
	return authRepo{
		db: db,
	}
}

func (r authRepo) CreateAuth(auth *Auth) error {
	return r.db.Create(auth).Error // FIXME better error handling
}

func (r authRepo) DeleteAuth(auth *Auth) error {
	return r.db.Delete(auth).Error // FIXME better error handling
}

func (r authRepo) GetByQuery(query *Auth) (*Auth, error) {
	var a Auth
	return &a, r.db.Where(query).Take(&a).Error // FIXME better error handling
}

func (r authRepo) GetLockerEntry(uid uint) (*Locker, error) {
	var l Locker
	return &l, r.db.Where("user_id = ?", uid).Take(&l).Error
}

func (r authRepo) CreateLockerEntry(locker *Locker) error {
	return r.db.Create(locker).Error
}
