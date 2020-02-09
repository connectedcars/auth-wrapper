package server

import (
	"crypto/rand"
)

// GenerateRamdomBytes from cryptographically secure source
func GenerateRamdomBytes(length int) (value []byte, err error) {
	randomBytes := make([]byte, length)
	_, err = rand.Read(randomBytes)
	if err != nil {
		return nil, err
	}
	return randomBytes, nil
}
