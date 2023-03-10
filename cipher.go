// Package for symmetric encryption with AES-256 GCM
package aes256gcm

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "crypto/sha256"
    "io"
)

type Cipher struct {
    key []byte
}

func NewCipher(key []byte) *Cipher {
    hKey := sha256.Sum256(key)
    return &Cipher{key: hKey[:]}
}

// Encrypt bytes.
func (c *Cipher) Encrypt(src []byte) ([]byte, error) {
    aesblock, err := aes.NewCipher(c.key)
    if err != nil {
        return nil, err
    }

    aesgcm, err := cipher.NewGCM(aesblock)
    if err != nil {
        return nil, err
    }

    nonce := make([]byte, aesgcm.NonceSize())
    _, err = io.ReadFull(rand.Reader, nonce)
    if err != nil {
        return nil, err
    }

    return aesgcm.Seal(nonce, nonce, src, nil), nil
}

// Decrypt bytes.
func (c *Cipher) Decrypt(dst []byte) ([]byte, error) {
    aesblock, err := aes.NewCipher(c.key)
    if err != nil {
        return nil, err
    }

    aesgcm, err := cipher.NewGCM(aesblock)
    if err != nil {
        return nil, err
    }

    nonceSize := aesgcm.NonceSize()
    nonce, dst := dst[:nonceSize], dst[nonceSize:]

    return aesgcm.Open(nil, nonce, dst, nil)
}
