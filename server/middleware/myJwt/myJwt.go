package myjwt

import (
	"crypto/rsa"
	"errors"
	"log"
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
		return "", "", "", err
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

func CheckAndRefreshTokens(oldAuthToken, oldRefreshToken, oldCsrfToken string) (authTokenString, refreshTokenString, csrfTokenString string, err error) {
	if oldCsrfToken == "" {
		log.Println("No CSRF Token!")
		err = errors.New("Unauthorized")
		return
	}

	authToken, err := jwt.ParseWithClaims(oldAuthToken, &models.TokenClaims{}, func(t *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})

	if err != nil {
		return
	}

	authTokenClaims, ok := authToken.Claims.(*models.TokenClaims)

	if !ok {
		return
	}

	if oldCsrfToken != authTokenClaims.Csrf {
		log.Println("CSRF Token doesn't match jwt")
		err = errors.New("Unauthorized")
		return
	}

	if authToken.Valid {
		log.Println("Auth Token is Valid")
		csrfTokenString = authTokenClaims.Csrf
		refreshTokenString, err = updateRefreshTokenExpiry(oldRefreshToken)
		authTokenString = oldAuthToken
		return
	} else if errors.Is(err, jwt.ErrTokenExpired) {
		log.Println("Auth Token expired, need to refresh")

		authTokenString, csrfTokenString, err = updateAuthTokenString(oldRefreshToken, oldAuthToken)
		if err != nil {
			return
		}
		refreshTokenString, err = updateRefreshTokenExpiry(oldRefreshToken)
		if err != nil {
			return
		}

		refreshTokenString, err = updateRefreshTokenCsrf(refreshTokenString, csrfTokenString)

		return

	} else {
		log.Println("Auth Token invalid:", err)
		err = errors.New("Error in Auth Token")
		return
	}

}

func RevokeRefreshToken(refreshTokenString string) error {
	refreshToken, err := jwt.ParseWithClaims(refreshTokenString, &models.TokenClaims{}, func(t *jwt.Token) (any, error) {
		return verifyKey, nil
	})

	if err != nil {
		return err
	}

	refreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)

	if !ok {
		err = errors.New("Invalid Refresh Token")
		return err
	}

	db.DeleteRefreshToken(refreshTokenClaims.ID)

	return nil
}

func GradUUID(authTokenString string) (string, error) {
	authToken, err := jwt.ParseWithClaims(authTokenString, &models.TokenClaims{}, func(t *jwt.Token) (any, error) {
		return verifyKey, nil
	})

	if err != nil {
		return "", err
	}

	authTokenClaims, ok := authToken.Claims.(*models.TokenClaims)

	if !ok {
		err = errors.New("Invalid Auth Token")
		return "", err
	}

	return authTokenClaims.Subject, nil
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

	if err != nil {
		return "", err
	}

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

func updateRefreshTokenExpiry(oldRefreshTokenString string) (newRefreshTokenString string, err error) {

	refreshToken, err := jwt.ParseWithClaims(oldRefreshTokenString, &models.TokenClaims{}, func(t *jwt.Token) (any, error) {
		return verifyKey, nil
	})

	if err != nil {
		return
	}

	oldRefreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)

	if !ok {
		err = errors.New("Invalid Refresh Token")
		return
	}

	refreshTokenExpiration := time.Now().Add(models.RefreshTokenValidTime)

	refreshClaims := models.TokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        oldRefreshTokenClaims.ID,
			Subject:   oldRefreshTokenClaims.Subject,
			ExpiresAt: jwt.NewNumericDate(refreshTokenExpiration),
		},
		Role: oldRefreshTokenClaims.Role,
		Csrf: oldRefreshTokenClaims.Csrf,
	}

	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), refreshClaims)

	newRefreshTokenString, err = refreshJwt.SignedString(signKey)
	return
}

func updateAuthTokenString(oldAuthTokenString, refreshTokenString string) (authTokenString, csrfTokenString string, err error) {
	refreshToken, err := jwt.ParseWithClaims(refreshTokenString, &models.TokenClaims{}, func(t *jwt.Token) (any, error) {
		return verifyKey, nil
	})

	if err != nil {
		return
	}

	refreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)

	if !ok {
		err = errors.New("Invalid Refresh Token")
		return
	}

	if db.CheckRefreshToken(refreshTokenClaims.ID) {
		if refreshToken.Valid {
			oldAuthToken, err := jwt.ParseWithClaims(oldAuthTokenString, &models.TokenClaims{}, func(t *jwt.Token) (any, error) {
				return verifyKey, nil
			})

			if err != nil {
				return "", "", err
			}

			oldAuthTokenClaims, ok := oldAuthToken.Claims.(*models.TokenClaims)

			if !ok {
				err = errors.New("Invalid Refresh Token")
				return "", "", err
			}

			csrfTokenString, err := models.GenerateCSRFSecret()

			if err != nil {
				return "", "", err
			}

			authTokenString, err = createAuthTokenString(oldAuthTokenClaims.Subject, oldAuthTokenClaims.Role, csrfTokenString)

			if err != nil {
				return "", "", err
			}
		} else {
			db.DeleteRefreshToken(refreshTokenClaims.ID)
			err = errors.New("Unauthorized")
			return
		}
	} else {
		err = errors.New("Unauthorized")
		return
	}

	return "", "", errors.New("Unauthorized")
}

func updateRefreshTokenCsrf(oldRefreshTokenString, newCsrfSecret string) (refreshTokenString string, err error) {
	refreshToken, err := jwt.ParseWithClaims(oldRefreshTokenString, &models.TokenClaims{}, func(t *jwt.Token) (any, error) {
		return verifyKey, nil
	})

	if err != nil {
		return
	}

	oldRefreshTokenClaims, ok := refreshToken.Claims.(*models.TokenClaims)

	if !ok {
		err = errors.New("Invalid Refresh Token")
		return
	}

	refreshClaims := models.TokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        oldRefreshTokenClaims.ID,
			Subject:   oldRefreshTokenClaims.Subject,
			ExpiresAt: oldRefreshTokenClaims.ExpiresAt,
		},
		Role: oldRefreshTokenClaims.Role,
		Csrf: newCsrfSecret,
	}

	refreshJwt := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), refreshClaims)

	newRefreshTokenString, err := refreshJwt.SignedString(signKey)

	if err != nil {
		return "", err
	}
	return newRefreshTokenString, nil
}
