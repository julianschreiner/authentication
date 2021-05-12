package security

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"github.com/pascaldekloe/jwt"
	"github.com/twinj/uuid"
	"regexp"
	"strings"
	"time"
)

var (
	ErrTokenExpired     = errors.New("the token is expired")
	ErrAccessCountry    = errors.New("you are not permitted to access this country")
	ErrAccessPermission = errors.New("you do not have the permission")
	ErrTokenMissing     = errors.New("no token has been provided")
	ErrTokenInvalid     = errors.New("provided token is not valid")

	patternBearer = regexp.MustCompile("(?i)^(bearer ?)?([a-zA-Z0-9._-]+)$")
)

type AuthJwt interface {
	Generate(userId interface{}, customClaims map[string]interface{}) (*Credentials, error)
	ValidateRefresh(token string) (map[string]interface{}, error)
	ValidateAccess(token string) (map[string]interface{}, error)
	ValidateAccessBearer(ctx context.Context) (map[string]interface{}, error)
	HasPermission(claims map[string]interface{}, country string, permissions ...string) ([]string, error)
	HasRole(claims map[string]interface{}, role int) bool
}

type authJwt struct {
	refreshSecret []byte
	accessPrivate ed25519.PrivateKey
	accessPublic  ed25519.PublicKey
}

type Credentials struct {
	AccessToken  string
	RefreshToken string
	AuthId       string
}

func NewJwtSigner(accessPrivateHex, refreshSecret string) (*authJwt, error) {
	access, err := hex.DecodeString(accessPrivateHex)
	if err != nil {
		return nil, err
	}

	auth := authJwt{
		accessPrivate: access,
		refreshSecret: []byte(refreshSecret),
		accessPublic:  access[32:],
	}
	return &auth, nil
}

func NewJwtValidator(accessPublicHex string) (AuthJwt, error) {
	access, err := hex.DecodeString(accessPublicHex)
	if err != nil {
		return nil, err
	}

	return &authJwt{
		accessPublic: access,
	}, nil
}

func (j *authJwt) Generate(userId interface{}, customClaims map[string]interface{}) (*Credentials, error) {
	claims := jwt.Claims{}
	claims.Issued = jwt.NewNumericTime(time.Now().Round(time.Second))
	claims.Expires = jwt.NewNumericTime(time.Now().Add(5 * time.Minute).Round(time.Second))
	claims.Set = customClaims
	access, err := claims.EdDSASign(j.accessPrivate)
	if err != nil {
		return nil, err
	}

	authId := uuid.NewV4().String()
	claims = jwt.Claims{}
	claims.Issued = jwt.NewNumericTime(time.Now().Round(time.Second))
	claims.Expires = jwt.NewNumericTime(time.Now().Add(5 * time.Minute).Round(time.Second))
	claims.Set = map[string]interface{}{"user": userId, "auth": authId}
	refresh, err := claims.HMACSign(jwt.HS512, j.refreshSecret)
	if err != nil {
		return nil, err
	}

	return &Credentials{
		AccessToken:  string(access),
		RefreshToken: string(refresh),
		AuthId:       authId,
	}, nil
}

func (j *authJwt) ValidateRefresh(token string) (map[string]interface{}, error) {
	claims, err := jwt.HMACCheck([]byte(token), j.refreshSecret)
	if err != nil {
		return nil, err
	}
	if !claims.Valid(time.Now()) {
		return claims.Set, errors.New("token is expired")
	}

	return claims.Set, nil
}

func (j *authJwt) ValidateAccess(token string) (map[string]interface{}, error) {
	claims, err := jwt.EdDSACheck([]byte(token), j.accessPublic)
	if err != nil {
		return nil, err
	}
	if !claims.Valid(time.Now()) {
		return nil, ErrTokenExpired
	}

	return claims.Set, nil
}

func (j *authJwt) ValidateAccessBearer(ctx context.Context) (map[string]interface{}, error) {
	raw := ctx.Value("authorization")
	if raw == nil {
		return nil, ErrTokenMissing
	}
	matches := patternBearer.FindStringSubmatch(raw.(string))
	if matches == nil || len(matches) != 3 {
		return nil, ErrTokenInvalid
	}
	return j.ValidateAccess(matches[2])
}

func (j *authJwt) HasPermission(claims map[string]interface{}, country string, permissions ...string) ([]string, error) {
	result := make([]string, 0)

	raw, ok := claims["country"]
	if !ok {
		return nil, ErrAccessCountry
	}
	c, ok := raw.(string)
	if !ok {
		return nil, ErrAccessCountry
	}
	if country != "*" && (!strings.EqualFold(country, c) && c != "") {
		return nil, ErrAccessCountry
	}

	if len(permissions) == 0 {
		return result, nil
	}

	raw, ok = claims["permissions"]
	if !ok {
		return nil, ErrAccessPermission
	}
	granted, ok := raw.([]interface{})
	if !ok {
		return nil, ErrAccessPermission
	}
	for _, permission := range permissions {
		for _, p := range granted {
			if strings.EqualFold(permission, p.(string)) || p.(string) == "*" {
				result = append(result, permission)
				break
			}
		}
	}
	if len(result) == 0 {
		return nil, ErrAccessPermission
	}
	return result, nil
}

func (j *authJwt) HasRole(claims map[string]interface{}, role int) bool {
	raw, ok := claims["role"]
	if !ok {
		return false
	}
	r, ok := raw.(float64)
	if !ok {
		return false
	}
	return r == float64(role)
}
