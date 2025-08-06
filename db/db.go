package db

import (
	"errors"

	"github.com/tech-manthan/secure-auth/db/models"
	"github.com/tech-manthan/secure-auth/randomstrings"
	"golang.org/x/crypto/bcrypt"
)

var users map[string]models.User
var refreshTokens map[string]string

func InitDB() {
	users = make(map[string]models.User)
	refreshTokens = make(map[string]string)
}

func StoreUser(username, password, role string) (uuid string, err error) {
	uuid, err = randomstrings.GenerateRandomString(32)

	if err != nil {
		return "", err
	}

	u := models.User{}

	for u != users[uuid] {
		uuid, err = randomstrings.GenerateRandomString(32)
		if err != nil {
			return "", err
		}
	}

	passwordHash, hashErr := generateBcryptHash(password)

	if hashErr != nil {
		return "", hashErr
	}

	users[uuid] = models.User{
		Username:     username,
		PasswordHash: passwordHash,
		Role:         role,
	}

	return uuid, nil
}

func DeleteUser(uuid string) {
	delete(users, uuid)
}

func FetchUserById(uuid string) (models.User, error) {
	u := users[uuid]
	blankUser := models.User{}

	if blankUser != u {
		return u, nil
	} else {
		return u, errors.New("User not found")
	}

}

func FetchUserByUsername(username string) (user models.User, uuid string, err error) {
	for k, v := range users {
		if v.Username == username {
			return v, k, nil
		}
	}

	return models.User{}, "", errors.New("User not found")
}

func StoreRefreshToken() (jti string, err error) {
	jti, err = randomstrings.GenerateRandomString(32)
	if err != nil {
		return "", err
	}

	for refreshTokens[jti] != "" {
		jti, err = randomstrings.GenerateRandomString(32)
		if err != nil {
			return "", err
		}
	}

	refreshTokens[jti] = "valid"

	return jti, nil
}

func DeleteRefreshToken(jti string) {
	delete(refreshTokens, jti)
}

func CheckRefreshToken(jti string) bool {
	return refreshTokens[jti] != "valid"
}

func LogUserIn(username string, password string) (models.User, string, error) {
	user, uuid, err := FetchUserByUsername(username)

	if err != nil {
		return models.User{}, "", err
	}
	return user, uuid, checkPasswordAgainstHash(user.PasswordHash, password)
}

func generateBcryptHash(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash[:]), err
}

func checkPasswordAgainstHash(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}
