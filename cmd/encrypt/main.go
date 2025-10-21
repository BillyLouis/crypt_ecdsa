package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"

	"golang.org/x/crypto/sha3"
)

func main() {
	// Generate recipient's ECDSA key pair (public and private keys)
	recipientPriv, recipientPub := generateECDSAKeys()

	// Generate ephemeral ECDSA key pair for encryption
	ephemeralPriv, ephemeralPub := generateECDSAKeys()

	// Derive shared key from recipient's public key and ephemeral private key
	sharedKey := deriveSharedKey(recipientPub, ephemeralPriv)

	// Prompt the user to enter the message to encrypt
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter the message to encrypt: ")
	message, _ := reader.ReadString('\n')
	message = message[:len(message)-1] // Remove newline character

	// Encrypt the message
	encrypted, err := encrypt(message, sharedKey)
	if err != nil {
		fmt.Printf("Encryption failed: %v\n", err)
		return
	}

	// Display the encrypted message and ephemeral public key for use in decryption
	fmt.Printf("Encrypted message: %s\n", encrypted)
	fmt.Printf("Ephemeral Public Key X: %s\n", ephemeralPub.X.Text(16))
	fmt.Printf("Ephemeral Public Key Y: %s\n", ephemeralPub.Y.Text(16))
	fmt.Printf("Recipient Private Key (for decryption): %s\n", recipientPriv.D.Text(16)) // Display the recipient private key for decryption
}

func generateECDSAKeys() (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	// Generate a new ECDSA key pair using P256 curve
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return priv, &priv.PublicKey
}

func deriveSharedKey(pub *ecdsa.PublicKey, priv *ecdsa.PrivateKey) []byte {
	// Perform scalar multiplication to derive the shared secret
	x, _ := pub.ScalarMult(pub.X, pub.Y, priv.D.Bytes())

	// Hash the shared secret to get a 256-bit AES key
	hash := sha3.New256()
	hash.Write(x.Bytes())
	return hash.Sum(nil)
}

func encrypt(plaintext string, key []byte) (string, error) {
	// Convert plaintext to bytes
	plaintextBytes := []byte(plaintext)

	// Create an AES cipher using the derived shared key
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}

	// Use AES-GCM for encryption
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}

	// Generate a nonce for AES-GCM
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %v", err)
	}

	// Encrypt the message using Seal
	ciphertext := aesGCM.Seal(nonce, nonce, plaintextBytes, nil)

	// Return the encrypted message as a hex string
	return hex.EncodeToString(ciphertext), nil
}
