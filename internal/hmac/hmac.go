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
func ValidateTokenUrl(token, encryptionKey, encryptionAlgorithm, url string, mandatoryFields []string) (generatedHmac, receivedHmac string, err error) {
	tokenFields := map[string]string{}
	tokenParts := strings.Split(token, "~")
	for _, fieldv := range tokenParts {
		fieldParts := strings.SplitN(fieldv, "=", 2)
		if len(fieldParts) != 2 {
			continue
		}
		tokenFields[fieldParts[0]] = fieldParts[1]
	}

	for _, fv := range mandatoryFields {
		if _, ok := tokenFields[fv]; !ok {
			err = fmt.Errorf("mandatory field '%s' not found in hmac sign", fv)
			return generatedHmac, receivedHmac, err
		}
	}

	// split token to get tokenDigest and HMAC
	hmacTokenParts := strings.Split(token, "~hmac=")
	if len(hmacTokenParts) != 2 {
		err = fmt.Errorf("hmac sign without main 'hmac' field")
		return generatedHmac, receivedHmac, err
	}
	tokenDigest := fmt.Sprintf("%s~url=%s", hmacTokenParts[0], url)
	tokenHMAC := []byte(hmacTokenParts[1])

	// check expiration time
	expPart, ok := tokenFields["exp"]
	if !ok {
		err = fmt.Errorf("hmac sign without main 'exp' field")
		return generatedHmac, receivedHmac, err
	}
	exp, err := strconv.ParseInt(expPart, 10, 64)
	if err != nil {
		err = fmt.Errorf("invalid expiration time format '%s'", expPart)
		return generatedHmac, receivedHmac, err
	}

	if time.Now().Unix() >= exp {
		err = fmt.Errorf("hmac sign has expired")
		return generatedHmac, receivedHmac, err
	}

	// generate HMAC with your local encription key to compare
	generatedHMAC, err := generateHMAC(tokenDigest, encryptionKey, encryptionAlgorithm)
	if err != nil {
		return generatedHmac, receivedHmac, err
	}

	generatedHmac = string(generatedHMAC)
	receivedHmac = string(tokenHMAC)

	// compare given with generated HMAC
	if !hmac.Equal(generatedHMAC, tokenHMAC) {
		err = fmt.Errorf("invalid '%s' sign, result '%s' does not match", receivedHmac, generatedHMAC)
	}

	return generatedHmac, receivedHmac, err
}
