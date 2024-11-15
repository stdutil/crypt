// Package crypt is a package for handling easy crypt handling
//
//	Author: Elizalde G. Baguinon
//	Created: October 17, 2019
package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	b64 "encoding/base64"
	"errors"
	"io"
)

type Crypt struct {
}

// Encrypt encrypts a string using AES
func (s *Crypt) Encrypt(plainText []byte, key []byte) ([]byte, error) {
	return Encrypt(plainText, key)
}

// Decrypt decrypts a string using AES
func (s *Crypt) Decrypt(cipherText []byte, key []byte) ([]byte, error) {
	return Decrypt(cipherText, key)
}

// EncodeText encodes plain text with a key and returns an encrypted and base64-encoded string
func (s *Crypt) EncodeText(plainText string, key []byte) string {
	return EncodeText(plainText, key)
}

// DecodeText decodes an encypted base64-encoded text with a key and returns a decrypted string
func (s *Crypt) DecodeText(encoded string, key []byte) string {
	return DecodeText(encoded, key)
}

// Encrypt encrypts a string using AES
func Encrypt(plainText []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plainText, nil), nil
}

// Decrypt decrypts a string using AES
func Decrypt(cipherText []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(cipherText) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	nonce, cipherText := cipherText[:nonceSize], cipherText[nonceSize:]
	return gcm.Open(nil, nonce, cipherText, nil)
}

// EncodeText encodes plain text with a key and returns an encrypted and base64-encoded string
func EncodeText(plainText string, key []byte) string {
	if plainText == "" {
		return plainText
	}
	enc, _ := Encrypt([]byte(plainText), key)
	return b64.RawURLEncoding.WithPadding(b64.NoPadding).EncodeToString(enc)
}

// DecodeText decodes an encypted base64-encoded text with a key and returns a decrypted string
func DecodeText(encoded string, key []byte) string {
	if encoded == "" {
		return encoded
	}
	benc, _ := b64.RawURLEncoding.WithPadding(b64.NoPadding).DecodeString(encoded)
	dec, _ := Decrypt(benc, key)
	return string(dec)
}
