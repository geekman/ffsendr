// This file is part of ffsendr.
// Copyright 2019 Darell Tan. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the README.

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/hkdf"
	"io"
)

// Derives a key using HKDF SHA-256.
func deriveKey(key, salt []byte, info string, length int) ([]byte, error) {
	derived := make([]byte, length)

	hash := sha256.New
	r := hkdf.New(hash, key, salt, []byte(info))
	_, err := io.ReadFull(r, derived[:])
	return derived[:], err
}

type Keychain struct {
	masterKey, encryptKey, metaKey, authKey []byte
}

// Creates a new keychain based on a given master key.
func NewKeychain(key []byte) (*Keychain, error) {
	if len(key) < 16 {
		return nil, fmt.Errorf("key too short")
	}

	encKey, err := deriveKey(key, nil, "encryption", 16)
	if err != nil {
		return nil, err
	}

	metaKey, err := deriveKey(key, nil, "metadata", 16)
	if err != nil {
		return nil, err
	}

	authKey, err := deriveKey(key, nil, "authentication", 64)
	if err != nil {
		return nil, err
	}

	return &Keychain{key, encKey, metaKey, authKey}, nil
}

// Creates a new keychain based on a given master key, in url-safe base64
// encoding
func NewKeychainFromB64(b64Key string) (*Keychain, error) {
	k, err := base64.RawURLEncoding.DecodeString(b64Key)
	if err != nil {
		return nil, err
	}
	return NewKeychain(k)
}

// Creates a new keychain based on a random key.
// To retrieve the generated key, call MasterKeyB64()
func NewKeychainFromRand() (*Keychain, error) {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}

	return NewKeychain(key)
}

// Dumps the keychain with all the keys.
// This function is primarily used for debugging.
func (k *Keychain) Dump() {
	fmt.Printf("master   key: %s\n", hex.EncodeToString(k.masterKey))
	fmt.Printf("encrypt  key: %s\n", hex.EncodeToString(k.encryptKey))
	fmt.Printf("metadata key: %s\n", hex.EncodeToString(k.metaKey))
	fmt.Printf("auth     key: %s\n", hex.EncodeToString(k.authKey))
}

// Retrieves the auth key as a URL-safe base64 string
func (k *Keychain) AuthKeyB64() string {
	return base64.RawURLEncoding.EncodeToString(k.authKey)
}

// Retrieves the master key as a URL-safe base64 string
func (k *Keychain) MasterKeyB64() string {
	return base64.RawURLEncoding.EncodeToString(k.masterKey)
}

func makeGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(block)
}

// Encrypts the metadata string with the derived metadata key.
// The result is then turned into URL-safe base64 without padding.
func (k *Keychain) EncryptMetadata(meta string) (string, error) {
	gcm, err := makeGCM(k.metaKey)
	if err != nil {
		return "", err
	}
	var nonce [12]byte
	dst := gcm.Seal(nil, nonce[:], []byte(meta), nil)
	return base64.RawURLEncoding.EncodeToString(dst), nil
}

func (k *Keychain) DecryptMetadata(meta string) (string, error) {
	encrypted, err := base64.RawURLEncoding.DecodeString(meta)
	if err != nil {
		return "", err
	}
	gcm, err := makeGCM(k.metaKey)
	if err != nil {
		return "", err
	}
	var nonce [12]byte
	dst, err := gcm.Open(nil, nonce[:], encrypted, nil)
	return string(dst), err
}

// Answers a challenge (nonce) with the authKey.
func authenticate(authKey []byte, nonceB64 string) (string, error) {
	mac := hmac.New(sha256.New, authKey)
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		return "", err
	}
	mac.Write(nonce)
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}
