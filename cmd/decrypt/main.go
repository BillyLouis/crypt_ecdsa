package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"

	"golang.org/x/crypto/sha3"
)

func main() {
	// Prompt user to enter the encrypted message and ephemeral public key
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter the encrypted message (hex): ")
	encryptedText, _ := reader.ReadString('\n')
	encryptedText = encryptedText[:len(encryptedText)-1] // Remove newline character

	fmt.Print("Enter ephemeral public key X (hex): ")
	ephemeralPubXHex, _ := reader.ReadString('\n')
	ephemeralPubXHex = ephemeralPubXHex[:len(ephemeralPubXHex)-1] // Remove newline character

	fmt.Print("Enter ephemeral public key Y (hex): ")
	ephemeralPubYHex, _ := reader.ReadString('\n')
	ephemeralPubYHex = ephemeralPubYHex[:len(ephemeralPubYHex)-1] // Remove newline character

	fmt.Print("Enter recipient private key (hex): ")
	recipientPrivHex, _ := reader.ReadString('\n')
	recipientPrivHex = recipientPrivHex[:len(recipientPrivHex)-1] // Remove newline character

	// Convert the ephemeral public key X and Y and recipient private key from hex to big.Int
	ephemeralPubX := new(big.Int)
	ephemeralPubY := new(big.Int)
	recipientPriv := new(big.Int)

	ephemeralPubX.SetString(ephemeralPubXHex, 16)
	ephemeralPubY.SetString(ephemeralPubYHex, 16)
	recipientPriv.SetString(recipientPrivHex, 16)

	// Reconstruct the recipient's private key and ephemeral public key
	recipientPrivateKey := &ecdsa.PrivateKey{
		D: recipientPriv,
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
		},
	}
	ephemeralPub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     ephemeralPubX,
		Y:     ephemeralPubY,
	}

	// Derive the shared key from the ephemeral public key and recipient's private key
	sharedKey := deriveSharedKey(ephemeralPub, recipientPrivateKey)

	// Decrypt the message using the derived shared key
	decrypted, err := decrypt(encryptedText, sharedKey)
	if err != nil {
		fmt.Printf("Decryption failed: %v\n", err)
		return
	}
	fmt.Printf("Decrypted message: %s\n", decrypted)
}

func deriveSharedKey(pub *ecdsa.PublicKey, priv *ecdsa.PrivateKey) []byte {
	// Perform scalar multiplication to derive the shared secret
	x, _ := pub.ScalarMult(pub.X, pub.Y, priv.D.Bytes())

	// Hash the shared secret to derive a 256-bit AES key
	hash := sha3.New256()
	hash.Write(x.Bytes())
	return hash.Sum(nil)
}

func decrypt(encryptedHex string, key []byte) (string, error) {
	// Decode the encrypted message from hex
	enc, err := hex.DecodeString(encryptedHex)
	if err != nil {
		return "", fmt.Errorf("failed to decode encrypted message: %v", err)
	}

	// Create AES cipher using the shared key
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}

	// Use AES-GCM for decryption
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}

	nonceSize := aesGCM.NonceSize()

	// Ensure that the encrypted message length is valid
	if len(enc) < nonceSize {
		return "", fmt.Errorf("encrypted message too short")
	}

	// Separate the nonce and ciphertext
	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]

	// Decrypt the message using Open
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("message authentication failed: %v", err)
	}

	return string(plaintext), nil
}

/*
//======================== Decrypt 1 failed =============================

package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand" // Add rand for secure randomness
	"encoding/hex"
	"fmt"
	"math/big"
	"os"

	"golang.org/x/crypto/sha3"
)

// eaaf96f515f6ee3d0dfd4f71c3939cdbcc0185b44b1e01be858647df393b63eb45f7deb7a3e26d7bacfdd454ea
func main() {
	// Generate the recipient's ECDSA keys (same ones used for encryption)
	recipientPriv, _ := generateECDSAKeys()

	// Prompt user to enter the encrypted text and ephemeral public key
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter the encrypted message (hex): ")
	encryptedText, _ := reader.ReadString('\n')
	encryptedText = encryptedText[:len(encryptedText)-1] // Remove newline character

	fmt.Print("Enter ephemeral public key X (hex): ")
	ephemeralPubXHex, _ := reader.ReadString('\n')
	ephemeralPubXHex = ephemeralPubXHex[:len(ephemeralPubXHex)-1] // Remove newline character

	fmt.Print("Enter ephemeral public key Y (hex): ")
	ephemeralPubYHex, _ := reader.ReadString('\n')
	ephemeralPubYHex = ephemeralPubYHex[:len(ephemeralPubYHex)-1] // Remove newline character

	fmt.Println("Entered X:", ephemeralPubXHex)
	fmt.Println("Entered Y:", ephemeralPubYHex)

	// Convert ephemeral public key X and Y from hex to big.Int
	ephemeralPubX := new(big.Int)
	ephemeralPubY := new(big.Int)
	ephemeralPubX.SetString(ephemeralPubXHex, 16)
	ephemeralPubY.SetString(ephemeralPubYHex, 16)

	// Derive shared key from the ephemeral public key and recipient's private key
	sharedKey := deriveSharedKey(&ecdsa.PublicKey{Curve: elliptic.P256(), X: ephemeralPubX, Y: ephemeralPubY}, recipientPriv)

	// Decrypt the message using the derived shared key
	decrypted, err := decrypt(encryptedText, sharedKey)
	if err != nil {
		fmt.Printf("Decryption failed: %v\n", err)
		return
	}
	fmt.Printf("Decrypted message: %s\n", decrypted)
}

func generateECDSAKeys() (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	// Use rand.Reader as the source of randomness
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return priv, &priv.PublicKey
}

func deriveSharedKey(pub *ecdsa.PublicKey, priv *ecdsa.PrivateKey) []byte {
	x, _ := pub.ScalarMult(pub.X, pub.Y, priv.D.Bytes())
	hash := sha3.New256()
	hash.Write(x.Bytes())
	return hash.Sum(nil)
}

func decrypt(encryptedHex string, key []byte) (string, error) {
	// Decode the encrypted message from hex
	enc, err := hex.DecodeString(encryptedHex)
	if err != nil {
		return "", fmt.Errorf("failed to decode encrypted message: %v", err)
	}

	// Create AES cipher with the shared key
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}

	// Use AES-GCM for decryption
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %v", err)
	}

	nonceSize := aesGCM.NonceSize()

	// Check if the encrypted message length is valid
	if len(enc) < nonceSize {
		return "", fmt.Errorf("encrypted message too short")
	}

	// Separate the nonce and ciphertext
	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]

	// Decrypt the message
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("message authentication failed: %v", err)
	}

	return string(plaintext), nil
}

/*
//======================== Decrypt 2 failed =============================
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
	"math/big"
	"os"

	"golang.org/x/crypto/sha3"
)

func main() {
	// Generate the recipient's ECDSA keys (the same ones used for encryption)
	recipientPriv, _ := generateECDSAKeys()

	// Prompt user to enter the encrypted text and ephemeral public key
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter the encrypted message: ")
	encryptedText, _ := reader.ReadString('\n')
	encryptedText = encryptedText[:len(encryptedText)-1] // Remove newline character

	fmt.Print("Enter ephemeral public key (X in hex): ")
	ephemeralPubXHex, _ := reader.ReadString('\n')
	ephemeralPubXHex = ephemeralPubXHex[:len(ephemeralPubXHex)-1] // Remove newline character

	fmt.Print("Enter ephemeral public key (Y in hex): ")
	ephemeralPubYHex, _ := reader.ReadString('\n')
	ephemeralPubYHex = ephemeralPubYHex[:len(ephemeralPubYHex)-1] // Remove newline character

	// Convert ephemeral public key X and Y from hex to big.Int
	ephemeralPubX := new(big.Int)
	ephemeralPubY := new(big.Int)
	ephemeralPubX.SetString(ephemeralPubXHex, 16)
	ephemeralPubY.SetString(ephemeralPubYHex, 16)

	// Derive shared key from the ephemeral public key and recipient's private key
	sharedKey := deriveSharedKey(&ecdsa.PublicKey{Curve: elliptic.P256(), X: ephemeralPubX, Y: ephemeralPubY}, recipientPriv)

	// Decrypt the message using the derived shared key
	decrypted := decrypt(encryptedText, sharedKey)
	fmt.Printf("Decrypted message: %s\n", decrypted)
}

func generateECDSAKeys() (*ecdsa.PrivateKey, *ecdsa.PublicKey) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return priv, &priv.PublicKey
}

func deriveSharedKey(pub *ecdsa.PublicKey, priv *ecdsa.PrivateKey) []byte {
	x, _ := pub.ScalarMult(pub.X, pub.Y, priv.D.Bytes())
	hash := sha3.New256()
	hash.Write(x.Bytes())
	return hash.Sum(nil)
}

func decrypt(encryptedString string, key []byte) string {
	enc, _ := hex.DecodeString(encryptedString)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	nonceSize := aesGCM.NonceSize()
	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	return string(plaintext)
}
*/
