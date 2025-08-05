package randomstrings

import (
	"crypto/rand"
	"encoding/base64"
)

func GenerateRandomString(size int) (string, error) {

	b, err := generateRandomBytes(size)
	return base64.URLEncoding.EncodeToString(b), err
}

func generateRandomBytes(size int) ([]byte, error) {
	b := make([]byte, size)
	_, err := rand.Read(b)

	if err != nil {
		return nil, err
	}

	return b, nil
}
