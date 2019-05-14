// This file is part of ffsendr.
// Copyright 2019 Darell Tan. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the README.

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io"
	"testing"
)

func b64e(v []byte) string { return base64.RawURLEncoding.EncodeToString(v) }

func b64d(v string) []byte {
	data, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		panic(err)
	}
	return data
}

func multiBytes(bufs ...[]byte) io.Reader {
	var r []io.Reader

	for _, b := range bufs {
		r = append(r, bytes.NewReader(b))
	}

	return io.MultiReader(r...)
}

func bytesMustMatch(t *testing.T, testName string, want, got []byte) {
	if !bytes.Equal(want, got) {
		t.Logf("%s\nwant:\n%s\ngot:\n%s", testName,
			hex.Dump(want), hex.Dump(got))
		t.Fatalf("%s - output mismatched", testName)
	}
}

// ECE example 3.1
func TestEncryptStream1(t *testing.T) {
	var buf bytes.Buffer
	ikm := b64d("yqdlZ-tYemfogSmv7Ws5PQ")
	salt := b64d("I1BsxtFttlv3u_Oo94xnmw")
	stream, err := NewEncryptStream(ikm, salt, 4096, &buf)
	if err != nil {
		t.Fatal(err)
	}

	err = stream.WriteHeader("")
	if err != nil {
		t.Fatal(err)
	}

	err = stream.EncryptStream(bytes.NewReader([]byte("I am the walrus")))
	if err != nil {
		t.Fatal(err)
	}

	bytesMustMatch(t,
		"encrypt stream failed",
		b64d("I1BsxtFttlv3u_Oo94xnmwAAEAAA-NAVub2qFgBEuQKRapoZu-IxkIva3MEB1PD-ly8Thjg"),
		buf.Bytes())
}

// ECE example 3.2
func TestEncryptStream2(t *testing.T) {
	var buf bytes.Buffer
	ikm := b64d("BO3ZVPxUlnLORbVGMpbT1Q")
	salt := b64d("uNCkWiNYzKTnBN9ji3-qWA")
	stream, err := NewEncryptStream(ikm, salt, 25, &buf)
	if err != nil {
		t.Fatal(err)
	}

	err = stream.WriteHeader("a1")
	if err != nil {
		t.Fatal(err)
	}

	input := multiBytes(
		[]byte("I am th"),
		[]byte("e walrus"),
	)
	err = stream.EncryptStream(input)
	if err != nil {
		t.Fatal(err)
	}

	bytesMustMatch(t,
		"encrypt stream failed",
		b64d("uNCkWiNYzKTnBN9ji3-qWAAAABkCYTHOG8chz_gnvgOqdGYovxyjuqRyJFjEDyoF1Fvkj6hQPdPHI51OEUKEpgz3SsLWIqS_uA"),
		buf.Bytes())
}

// ECE example 3.2 decryption
func TestDecryptStream2(t *testing.T) {
	ikm := b64d("BO3ZVPxUlnLORbVGMpbT1Q")
	input := b64d("uNCkWiNYzKTnBN9ji3-qWAAAABkCYTHOG8chz_gnvgOqdGYovxyjuqRyJFjEDyoF1Fvkj6hQPdPHI51OEUKEpgz3SsLWIqS_uA")

	stream, err := NewDecryptStream(ikm, bytes.NewBuffer(input))
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	err = stream.DecryptStream(&out)
	if err != nil {
		t.Fatal(err)
	}

	bytesMustMatch(t,
		"decrypt stream failed",
		[]byte("I am the walrus"),
		out.Bytes())
}

// Make sure when passed an empty salt, one is actually generated
func TestNonEmptySalt(t *testing.T) {
	var buf bytes.Buffer
	estream, err := NewEncryptStream([]byte{}, nil, 17+1, &buf)
	if err != nil {
		t.Fatal(err)
	}

	if estream.salt == nil {
		t.Fatal("salt of EncryptStream is nil")
	}
}

func TestRoundTrip(t *testing.T) {
	ikm := b64d("yqdlZ-tYemfogSmv7Ws5PQ")
	input := []byte("I am the walrus2")

	var buf bytes.Buffer
	estream, err := NewEncryptStream(ikm, nil, 17+8, &buf)
	if err != nil {
		t.Fatal(err)
	}

	err = estream.WriteHeader("")
	if err != nil {
		t.Fatal(err)
	}

	err = estream.EncryptStream(bytes.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}

	// decrypt
	dstream, err := NewDecryptStream(ikm, &buf)
	if err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	err = dstream.DecryptStream(&output)
	if err != nil {
		t.Fatal(err)
	}

	bytesMustMatch(t,
		"round-trip enc-dec failed",
		input,
		output.Bytes())
}
