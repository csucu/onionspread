package common

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"strings"
)

const rendTimePeriodV2descValidity = 86400

// Base64ToHex decodes a base 64 string and returns its uppercase hex encoding
func Base64ToHex(identity string) (string, error) {
	if missingPadding := len(identity) % 4; missingPadding != 0 {
		identity += strings.Repeat("=", 4-missingPadding)
	}

	decoded, err := base64.StdEncoding.DecodeString(identity)
	if err != nil {
		return "", err
	}

	return strings.ToUpper(strings.TrimSpace(hex.EncodeToString(decoded))), nil
}

// CalculateDescriptorID computes the v2 descriptor ID
func CalculateDescriptorID(permanentID []byte, time int64, replica byte, deviation uint8,
	descriptorCookie string) ([]byte, error) {
	secretIDPart := getSecretID(permanentID, time, descriptorCookie, replica)

	h := sha1.New()
	h.Write(permanentID)
	h.Write(secretIDPart)

	descriptorID := make([]byte, 32)
	base32.StdEncoding.Encode(descriptorID, h.Sum(nil))

	return descriptorID, nil
}

//  time-period = (current-time + permanent-id-byte * 86400 / 256) / 86400
//  "permanent-id-byte" is the first unsigned) byte of the permanent identifier.
func getTimePeriod(time int64, deviation uint8, serviceID []byte) int64 {
	permanentIDByte := int64(serviceID[0])
	return (time+permanentIDByte*rendTimePeriodV2descValidity/256)/rendTimePeriodV2descValidity + int64(deviation)
}

// GetSecretID returns the secretID which is used to calculate the descriptor ID
// SecretIDPart = H(time-period | descriptor-cookie | replica)
func GetSecretID(serviceID []byte, time int64, descriptorCookie string, replica byte) []byte {
	src := getSecretID(serviceID, time, descriptorCookie, replica)
	dst := make([]byte, base32.StdEncoding.EncodedLen(len(src)))
	base32.StdEncoding.Encode(dst, src)

	return bytes.ToLower(dst)
}

// SecretIDPart = H(time-period | descriptor-cookie | replica)
func getSecretID(serviceID []byte, time int64, descriptorCookie string, replica byte) []byte {
	timePeriodBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(timePeriodBytes, uint32(getTimePeriod(time, 0, serviceID)))

	secretID := sha1.New()
	secretID.Write(timePeriodBytes)

	if descriptorCookie != "" {
		secretID.Write([]byte(descriptorCookie))
	}

	secretID.Write([]byte{replica})

	return secretID.Sum(nil)
}

// CalculatePermanentID returns permanentID given the permanentKey(public key)
func CalculatePermanentID(permanentKey rsa.PublicKey) ([]byte, error) {
	der, err := asn1.Marshal(permanentKey)
	if err != nil {
		return nil, err
	}

	hash := sha1.New()
	hash.Write(der)

	return hash.Sum(nil)[:10], nil
}

// CalculateOnionAddress returns the v2 onion address given the permanentID
func CalculateOnionAddress(permanentID []byte) string {
	return strings.ToLower(base32.StdEncoding.EncodeToString(permanentID))
}

//  DescriptorIDValidUntil calculates seconds until the descriptor ID changes
func DescriptorIDValidUntil(permanentID []byte, time int64) int64 {
	return rendTimePeriodV2descValidity - ((time + int64(permanentID[0])*rendTimePeriodV2descValidity/256) %
		rendTimePeriodV2descValidity)
}

// LoadKeysFromFile returns an rsa public/private key pair given pem encoded private key
func LoadKeysFromFile(filePath string) (*rsa.PublicKey, *rsa.PrivateKey, error) {
	privateKeyPem, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, nil, err
	}

	block, rest := pem.Decode(privateKeyPem)
	if len(rest) > 0 {
		return nil, nil, fmt.Errorf("failed to decode PEM, remaining data: %v", rest)
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse decoded private key")
	}

	publicKey, ok := privateKey.Public().(*rsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("failed to cast public key")
	}

	return publicKey, privateKey, nil
}
