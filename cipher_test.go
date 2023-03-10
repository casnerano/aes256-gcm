package aes256gcm

import (
    "bytes"
    "testing"
)

func TestCipher(t *testing.T) {
    tests := []struct {
        name    string
        rawText []byte
    }{
        {"Short text", []byte("Lorem")},
        {"Middle text", []byte("Lorem ipsum")},
        {"Large text", []byte("Lorem ipsum is placeholder text commonly used in the graphic")},
    }

    aes256gcm := NewCipher([]byte("example key"))

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            cipherText, err := aes256gcm.Encrypt(tt.rawText)
            if err != nil {
                t.Errorf("Encrypt() error = %v", err)
                return
            }
            rawText, err := aes256gcm.Decrypt(cipherText)
            if err != nil {
                t.Errorf("Decrypt() error = %v", err)
                return
            }

            if !bytes.Equal(tt.rawText, rawText) {
                t.Errorf("The decrypted text does not match the encrypted.")
            }
        })
    }
}
