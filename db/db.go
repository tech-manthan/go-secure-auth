package db

import (
	"errors"

	"github.com/tech-manthan/secure-auth/db/models"
)

var users = map[string]models.User{}

func InitDB() {

}

func StoreUser(username, password, role string) (uuid string, err error) {
	return
}

func DeleteUser() {

}

func FetchUserById() {

}

func FetchUserByUsername(username string) (user models.User, uuid string, err error) {
	for k, v := range users {
		if v.Username == username {
			return v, k, nil
		}
	}

	return models.User{}, "", errors.New("User not found")
}

func StoreRefreshToken() (string, error) {
	return "", nil
}

func DeleteRefreshToken() {

}

func CheckRefreshToken() bool {
	return true
}

func LogUserIn() {

}

func generateBcryptHash() {

}

func checkPasswordAgainstHash() error {
	return nil
}
