package auth

import (
	"authentication/security"
	user "authentication/user"
	"context"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
)

type AuthService interface {
	SignIn(ctx context.Context, email string, password string) (*security.Credentials, error)
	SignOut(ctx context.Context, refreshToken string) error
	Refresh(ctx context.Context, refreshToken string) (*security.Credentials, error)
	Register(ctx context.Context, email string, password string, forename string, surname string, dob string) (*security.Credentials, error)
}

type authService struct {
	authJwt        security.AuthJwt
	authRepository AuthRepository
	superGroup     *uint
	logger         *log.Logger
	userClient     user.UserClient
}

func NewAuthService(authJwt security.AuthJwt, authRepository AuthRepository, superGroup *uint, logger *log.Logger, userClient user.UserClient) AuthService {
	return &authService{
		authJwt:        authJwt,
		authRepository: authRepository,
		superGroup:     superGroup,
		logger:         logger,
		userClient:     userClient,
	}
}

func (s *authService) Register(ctx context.Context, email string, password string, forename string, surname string, dob string) (*security.Credentials, error) {
	// CHECK IF USER EXISTS
	u, err := s.userClient.GetActiveUserByEmail(email)
	if err != nil {
		return nil, errors.New("InvalidCredentialsError")
	}

	if u == nil {
		// CHECK IF PW IS SECURE
		ok := s.checkPassword(password)
		if !ok {
			return nil, errors.New("PasswordTooWeak")
		}

		// CREATE BCRYPT PW AND STORE INTO LOCKER
		pw, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return nil, errors.New("failed to generate bcrypt version of password")
		} else {
			// CREATE ENTRY IN USER SERVICE
			usr := &user.User{
				Email:    email,
				Forename: forename,
				Surname:  surname,
				Dob:      dob,
			}
			u, err := s.userClient.CreateUser(usr)
			if err != nil {
				return nil, errors.New("InvalidCredentialsError")
			}

			u.Password = string(pw)
			// save into locker
			newLockerEntry := Locker{
				UserId:   u.Id,
				Password: u.Password,
			}

			err = s.authRepository.CreateLockerEntry(&newLockerEntry)
			if err != nil {
				return nil, errors.New("Could not save new User to Locker")
			}

			// return creds
			cred, err := s.signIn(u)
			if err != nil {
				return nil, errors.New("InternalServerError")
			}
			return cred, nil
		}
	}

	return nil, nil
}

func (s *authService) checkPassword(password string) bool {
	/* TODO MORE FOR PASSWORD POLICY */
	if len(password) > 7 {
		return true
	}

	return false
}

func (s *authService) SignIn(ctx context.Context, email string, password string) (*security.Credentials, error) {
	// GET USER FROM USER SERVICE
	u, err := s.userClient.GetActiveUserByEmail(email)
	if err != nil {
		return nil, errors.New("InvalidCredentialsError")
	}

	locker, err := s.authRepository.GetLockerEntry(u.Id)
	if err != nil {
		return nil, errors.New("Could not find password for email: " + email)
	}

	err = bcrypt.CompareHashAndPassword([]byte(locker.Password), []byte(password))
	if err != nil {
		return nil, errors.New("Could not create Bcrypt version of password")
	}

	cred, err := s.signIn(u)
	if err != nil {
		return nil, errors.New("InternalServerError")
	}

	return cred, nil
}

func (s *authService) signIn(u *user.User) (*security.Credentials, error) {
	data := map[string]interface{}{
		"id":         u.Id,
		"email":      u.Email,
		"forename":   u.Forename,
		"surname":    u.Surname,
		"role":       u.Role,
		"active":     u.Active,
		"created_at": u.CreatedAt,
		"dob":        u.Dob,
	}
	if s.superGroup != nil && &u.Role == s.superGroup {
		data["permissions"] = []string{"*"}
	} else {
		data["permissions"] = []string{"-"}
	}

	cred, err := s.authJwt.Generate(u.Id, data)
	if err != nil {
		return nil, err
	}

	a := Auth{
		UserId:   u.Id,
		AuthUuid: cred.AuthId,
	}
	_ = s.authRepository.CreateAuth(&a)

	return cred, nil
}

func (s *authService) SignOut(ctx context.Context, refreshToken string) error {
	_, err := s.validateRefreshToken(ctx, refreshToken)
	return err
}

func (s *authService) Refresh(ctx context.Context, refreshToken string) (*security.Credentials, error) {
	auth, err := s.validateRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, err
	}

	u, err := s.userClient.GetActiveUserById(uint64(auth.UserId))
	if err != nil {
		return nil, err
	}

	cred, err := s.signIn(u)
	if err != nil {
		return nil, errors.New("InternalServerError")
	}

	return cred, nil
}

func (s *authService) validateRefreshToken(ctx context.Context, token string) (*Auth, error) {
	rawCookies := ctx.Value("cookie")
	if rawCookies != nil {
		header := http.Header{}
		header.Add("Cookie", rawCookies.(string))
		request := http.Request{Header: header}
		c, err := request.Cookie("refresh")
		if err == nil {
			token = c.Value
		}
	}

	claims, err := s.authJwt.ValidateRefresh(token)
	if err != nil {
		return nil, errors.New("UnauthorizedClaimError")
	}

	a := Auth{
		AuthUuid: claims["auth"].(string),
		UserId:   uint(claims["user"].(float64)),
	}
	authInDb, err := s.authRepository.GetByQuery(&a)
	if err != nil {
		return nil, errors.New("UnauthorizedTokenError")
	}

	_ = s.authRepository.DeleteAuth(authInDb)

	return &a, nil
}
