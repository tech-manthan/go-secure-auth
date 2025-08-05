package myjwt

import (
	"crypto/rsa"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/tech-manthan/secure-auth/db"
	"github.com/tech-manthan/secure-auth/db/models"
)

const (
	privateKeyPath = "keys/app.rsa"
	publicKeyPath  = "keys/app.rsa.pub"
)

var (
	signKey   *rsa.PrivateKey
	verifyKey *rsa.PublicKey
)

func InitJWT() error {
	signBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return err
	}

	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)

	if err != nil {
		return err
	}

	verifyBytes, err := os.ReadFile(publicKeyPath)

	if err != nil {
		return err
	}

	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)

	if err != nil {
		return err
	}

	return nil
}

func CreateNewTokens(uuid string, role string) (authTokenString, refreshTokenString, csrfSecret string, err error) {

	csrfSecret, err = models.GenerateCSRFSecret()

	if err != nil {
		return
	}

	refreshTokenString, err = createRefreshTokenString(uuid, role, csrfSecret)

	if err != nil {
		return
	}

	authTokenString, err = createAuthTokenString(uuid, role, csrfSecret)

	if err != nil {
		return
	}

	return authTokenString, refreshTokenString, csrfSecret, nil
}

func CheckAndRefreshTokens() {

}

func RevokeRefreshToken(refreshToken string) error {
	return nil
}

func GradUUID() {

}

func createAuthTokenString(uuid, role, csrfSecret string) (authTokenString string, err error) {
	authTokenExpiration := time.Now().Add(models.AuthTokenValidTime)
	authClaims := models.TokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   uuid,
			ExpiresAt: jwt.NewNumericDate(authTokenExpiration),
		},
		Role: role,
		Csrf: csrfSecret,
	}
	authJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), authClaims)

	authTokenString, err = authJwt.SignedString(signKey)
	return
}

func createRefreshTokenString(uuid, role, csrfSecret string) (refreshTokenString string, err error) {
	refreshTokenExpiration := time.Now().Add(models.RefreshTokenValidTime)

	refreshJti, err := db.StoreRefreshToken()

	refreshClaims := models.TokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   uuid,
			ExpiresAt: jwt.NewNumericDate(refreshTokenExpiration),
			ID:        refreshJti,
		},
		Role: role,
		Csrf: csrfSecret,
	}
	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), refreshClaims)

	refreshTokenString, err = refreshJwt.SignedString(signKey)
	return
}

func updateRefreshTokenExpiry() {

}

func updateAuthTokenString() {

}

func updateRefreshTokenCsrf() {

}
