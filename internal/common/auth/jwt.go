package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type JWT struct {
	secret   []byte
	issuer   string
	lifetime time.Duration
}

func NewJWT(secret []byte, issuer string, lifetime time.Duration) (*JWT, error) {
	return &JWT{
		secret:   secret,
		issuer:   issuer,
		lifetime: lifetime,
	}, nil
}

// Enforce interface implementation
var _ jwt.Claims = (*JWTClaims)(nil)

type JWTClaims struct {
	Subject   uuid.UUID `json:"sub"`
	Issuer    string    `json:"iss"`
	IssuedAt  time.Time `json:"iat"`
	ExpiresAt time.Time `json:"exp"`
	Groups    []string  `json:"groups"`
}

// GetAudience implements jwt.Claims.
func (j *JWTClaims) GetAudience() (jwt.ClaimStrings, error) {
	return jwt.ClaimStrings{}, nil
}

// GetExpirationTime implements jwt.Claims.
func (j *JWTClaims) GetExpirationTime() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(j.ExpiresAt), nil
}

// GetIssuedAt implements jwt.Claims.
func (j *JWTClaims) GetIssuedAt() (*jwt.NumericDate, error) {
	return jwt.NewNumericDate(j.IssuedAt), nil
}

// GetIssuer implements jwt.Claims.
func (j *JWTClaims) GetIssuer() (string, error) {
	return j.Issuer, nil
}

// GetNotBefore implements jwt.Claims.
func (j *JWTClaims) GetNotBefore() (*jwt.NumericDate, error) {
	return nil, nil
}

// GetSubject implements jwt.Claims.
func (j *JWTClaims) GetSubject() (string, error) {
	return j.Subject.String(), nil
}

func (j *JWT) GenerateToken(userID uuid.UUID, groups []string) (string, error) {
	now := time.Now()
	claims := &JWTClaims{
		Subject:   userID,
		Issuer:    j.issuer,
		IssuedAt:  now,
		ExpiresAt: now.Add(j.lifetime),
		Groups:    groups,
	}

	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return t.SignedString(j.secret)
}

func (j *JWT) ValidateToken(token string) (JWTClaims, error) {
	t, err := jwt.ParseWithClaims(token, &JWTClaims{},
		func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return j.secret, nil
		},
		jwt.WithIssuer(j.issuer),
	)
	if err != nil {
		return JWTClaims{}, err
	}

	if claims, ok := t.Claims.(*JWTClaims); ok {
		return *claims, nil
	}

	return JWTClaims{}, jwt.ErrTokenInvalidClaims
}
