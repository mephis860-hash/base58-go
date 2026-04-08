package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"encoding/base58"
)

// GenerateRandomPrivateKey generates a random 32-byte private key.
func GenerateRandomPrivateKey() ([]byte, error) {
	privateKey := make([]byte, 32)
	if _, err := rand.Read(privateKey); err != nil {
		return nil, err
	}
	return privateKey, nil
}

// EncodePrivateKeyToWIF encodes a private key to WIF format.
func EncodePrivateKeyToWIF(privateKey []byte) string {
	// Add version byte (0x80)
	versionedKey := append([]byte{0x80}, privateKey...)
	
	// Calculate SHA256 checksum
	checksum := sha256.Sum256(versionedKey)
	// Take the first 4 bytes as the checksum
	checksum = sha256.Sum256(checksum[:])
	versionedKey = append(versionedKey, checksum[:4]...)
	
	// Encode to base58
	return base58.Encode(versionedKey)
}

func main() {
	privateKey, err := GenerateRandomPrivateKey()
	if err != nil {
		fmt.Println("Error generating private key:", err)
		return
	}
	
	wif := EncodePrivateKeyToWIF(privateKey)
	fmt.Println("Private Key in WIF:", wif)
}