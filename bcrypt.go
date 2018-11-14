package bcrypt

import (
	jwt_lib "github.com/dgrijalva/jwt-go"
	"golang.org/x/crypto/bcrypt"
)

type Bcrypt struct {
	Name string
}

func (bpt *Bcrypt) Verify(signingString, signature string, key interface{}) error {

	keyBytes, ok := key.([]byte)
	if !ok {
		return jwt_lib.ErrInvalidKeyType
	}

	// Decode signature, for comparison
	sig, err := jwt_lib.DecodeSegment(signature)
	if err != nil {
		return err
	}

	err = bcrypt.CompareHashAndPassword([]byte(sig), []byte(signingString+string(keyBytes)))

	if err != nil {
		return jwt_lib.ErrSignatureInvalid
	}

	return nil
}

func (bpt *Bcrypt) Sign(signingString string, key interface{}) (string, error) {
	if keyBytes, ok := key.([]byte); ok {

		result, err := bcrypt.GenerateFromPassword([]byte(signingString+string(keyBytes)), bcrypt.DefaultCost)

		if err != nil {
			return "", jwt_lib.ErrSignatureInvalid
		}

		return jwt_lib.EncodeSegment(result), nil
	}
	return "", jwt_lib.ErrInvalidKeyType
}

func (bpt *Bcrypt) Alg() string {
	return bpt.Name
}