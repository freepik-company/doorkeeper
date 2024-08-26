package hmac

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"strconv"
	"strings"
	"time"
)

var (
	encryptionAlgorithmMap = map[string]func() hash.Hash{
		"md5":    md5.New,
		"sha1":   sha1.New,
		"sha256": sha256.New,
		"sha512": sha512.New,
	}
)

// generateHMAC TODO
func generateHMAC(tokenDigest, encryptionKey, encryptionAlgorithm string) (token []byte, err error) {
	// change encryption key to binary
	binaryEncryptionKey, err := hex.DecodeString(strings.TrimSpace(encryptionKey))
	if err != nil {
		return token, err
	}

	// check if provided algorithm exist
	if _, ok := encryptionAlgorithmMap[encryptionAlgorithm]; !ok {
		err = fmt.Errorf("invalid encryption algorithm '%s'", encryptionAlgorithm)
		return token, err
	}

	// generate HMAC token
	hmacHash := hmac.New(encryptionAlgorithmMap[encryptionAlgorithm], binaryEncryptionKey)
	_, err = hmacHash.Write([]byte(tokenDigest))
	if err != nil {
		return token, err
	}
	token = []byte(hex.EncodeToString(hmacHash.Sum(nil)))

	return token, err
}

// ValidateToken TODO
// token: exp={int}~hmac={hash}
func ValidateTokenUrl(token, encryptionKey, encryptionAlgorithm, url string) (isValid bool, err error) {
	// split token to get tokenDigest and HMAC
	tokenParts := strings.Split(token, "~hmac=")
	if len(tokenParts) != 2 {
		return isValid, err
	}
	tokenDigest := fmt.Sprintf("%s~url=%s", tokenParts[0], url)
	tokenHMAC := []byte(tokenParts[1])

	// check expiration time
	expPart := strings.TrimPrefix(strings.Split(tokenDigest, "~")[0], "exp=")
	exp, err := strconv.ParseInt(expPart, 10, 64)
	if err != nil {
		err = fmt.Errorf("invalid expiration time '%s'", expPart)
		return isValid, err
	}

	if time.Now().Unix() >= exp {
		err = fmt.Errorf("token has expired")
		return isValid, err
	}

	// generate HMAC with your local encription key to compare
	generatedHMAC, err := generateHMAC(tokenDigest, encryptionKey, encryptionAlgorithm)
	if err != nil {
		return isValid, err
	}

	// compare given with generated HMAC
	isValid = hmac.Equal(generatedHMAC, tokenHMAC)

	return isValid, err
}
