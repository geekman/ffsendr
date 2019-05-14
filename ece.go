// This file is part of ffsendr.
// Copyright 2019 Darell Tan. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the README.

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
)

// Encrypted Content-Encoding
// https://trac.tools.ietf.org/html/rfc8188

// Aid with debugging of encryption and decryption of blocks
const debugEce = false

const ECE_RECORD_SIZE = 1024 * 64

type eceStream struct {
	RecordSize       int
	key, salt, nonce []byte

	gcm cipher.AEAD
	seq int
}

type eceHeader struct {
	Salt       [16]byte
	RecordSize uint32
	KeyIdLen   uint8
}

func (s *eceStream) readHeader(r io.Reader) error {
	var hdr eceHeader
	err := binary.Read(r, binary.BigEndian, &hdr)
	if err != nil {
		return err
	}

	// read the keyId if there is any
	// the keyId is then discarded
	idlen := int(hdr.KeyIdLen)
	var buf [256]byte
	for i := idlen; i > 0; i -= len(buf) {
		n, err := r.Read(buf[:i])
		if err != nil {
			return err
		}
		i -= n
	}

	s.salt = hdr.Salt[:]
	s.RecordSize = int(hdr.RecordSize)

	return nil
}

func (s *eceStream) GetNonce(seq uint32) []byte {
	seqNonce := append([]byte(nil), s.nonce...)
	offset := len(seqNonce) - 4
	n := binary.BigEndian.Uint32(seqNonce[offset:])
	n ^= seq
	binary.BigEndian.PutUint32(seqNonce[offset:], n)
	return seqNonce
}

func (s *eceStream) initCipher(ikm, salt []byte) error {
	encKey, err := deriveKey(ikm, salt[:], "Content-Encoding: aes128gcm\x00", 16)
	if err != nil {
		return err
	}

	nonce, err := deriveKey(ikm, salt[:], "Content-Encoding: nonce\x00", 12)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(encKey)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	s.key = encKey
	s.nonce = nonce
	s.salt = salt
	s.gcm = gcm

	return nil
}

func (s *eceStream) Dump() {
	fmt.Printf("rec size: %d\n", s.RecordSize)

	fmt.Printf("CEK:   %s\n", hex.EncodeToString(s.key))
	fmt.Printf("NONCE: %s\n", hex.EncodeToString(s.nonce))
	fmt.Printf("SALT:  %s\n", hex.EncodeToString(s.salt))
}

type EncryptStream struct {
	eceStream

	dst io.Writer
}

// Prepare for a new encrypted stream.
// The input keying material is provided as key, and salt is optional.
// If salt is nil, it will be generated internally.
func NewEncryptStream(key, salt []byte, recordSize int, stream io.Writer) (*EncryptStream, error) {
	if recordSize < 18 {
		return nil, fmt.Errorf("record size must be at least 18")
	}

	// generate salt if necessary
	if salt == nil {
		salt = make([]byte, 16)
		_, err := rand.Read(salt[:])
		if err != nil {
			return nil, err
		}
	}

	s := &eceStream{
		RecordSize: recordSize,
	}
	if err := s.initCipher(key, salt); err != nil {
		return nil, err
	}

	if debugEce {
		s.Dump()
	}

	return &EncryptStream{*s, stream}, nil
}

// Writes the ECE header into the stream.
// If keyId is not used, it should be an empty string
func (s *EncryptStream) WriteHeader(keyId string) error {
	if len(keyId) > 255 {
		return fmt.Errorf("key ID size can't be longer than a byte")
	}

	hdr := eceHeader{[16]byte{}, uint32(s.RecordSize), byte(len(keyId))}
	copy(hdr.Salt[:], s.salt)
	if err := binary.Write(s.dst, binary.BigEndian, hdr); err != nil {
		return err
	}
	s.dst.Write([]byte(keyId))

	return nil
}

func (s *EncryptStream) EncryptBlock(dst, src []byte, seq int) []byte {
	nonce := s.GetNonce(uint32(seq))
	return s.gcm.Seal(dst, nonce, src, nil)
}

func (s *EncryptStream) EncryptStream(src io.Reader) error {
	chunkSize := s.RecordSize - 17
	buf := make([]byte, chunkSize+1)

	r := NewRelaxedChunkedReader(src, chunkSize)

	var n int
	var err error
	lastBlock := false
	for !lastBlock {
		n, lastBlock, err = r.Read(buf[:chunkSize])
		if err != nil {
			return err
		}

		// add padding delimiter
		if lastBlock {
			buf[n] = 2
		} else {
			buf[n] = 1
		}
		n++

		if !lastBlock {
			for ; n < chunkSize+1; n++ {
				buf[n] = 0
			}
		}

		if debugEce {
			lastBlockStr := ""
			if lastBlock {
				lastBlockStr = " (LAST)"
			}
			fmt.Printf("block %d in (sz %d) %s\n%s", s.seq, n, lastBlockStr, hex.Dump(buf[:n]))
		}

		buf = s.EncryptBlock(buf[:0], buf[:n], s.seq)
		if debugEce {
			fmt.Printf("block %d out\n%s", s.seq, hex.Dump(buf))
		}

		s.seq++
		s.dst.Write(buf)
	}

	return nil
}

type DecryptStream struct {
	eceStream

	src io.Reader
}

// Prepares to decrypt a stream.
// Parameters such as salt and record size are read from the stream header.
func NewDecryptStream(key []byte, stream io.Reader) (*DecryptStream, error) {
	s := new(eceStream)

	if err := s.readHeader(stream); err != nil {
		return nil, err
	}

	if err := s.initCipher(key, s.salt); err != nil {
		return nil, err
	}

	if debugEce {
		s.Dump()
	}

	return &DecryptStream{*s, stream}, nil
}

func (s *DecryptStream) DecryptBlock(dst, src []byte, seq int) ([]byte, error) {
	nonce := s.eceStream.GetNonce(uint32(s.seq))
	return s.gcm.Open(dst, nonce, src, nil)
}

func (s *DecryptStream) DecryptStream(dst io.Writer) error {
	buf := make([]byte, s.RecordSize)

	r := NewChunkedReader(s.src, s.RecordSize)

	var n int
	var err error
	lastBlock := false
	for !lastBlock {
		n, lastBlock, err = r.Read(buf)
		if err != nil {
			return err
		}

		if debugEce {
			lastInd := ""
			if lastBlock {
				lastInd = "(LAST)"
			}
			fmt.Printf("block %d in %s\n%s", s.seq, lastInd, hex.Dump(buf[:n]))
		}

		// decrypt the block
		buf, err := s.DecryptBlock(buf[:0], buf[:n], s.seq)
		if err != nil {
			return fmt.Errorf("block %d: %s", s.seq, err)
		}

		if debugEce {
			fmt.Printf("block %d out\n%s", s.seq, hex.Dump(buf))
		}

		// check padding
		for n = len(buf) - 1; n > 0; n-- {
			if buf[n] != 0 {
				if lastBlock {
					if buf[n] != 2 {
						return fmt.Errorf("incorrect padding for last block")
					}
				} else if buf[n] != 1 {
					return fmt.Errorf("incorrect padding for block %d", s.seq)
				}
				break
			}
		}

		dst.Write(buf[:n])

		s.seq++
	}

	return nil
}
