// This file is part of ffsendr.
// Copyright 2019 Darell Tan. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the README.

package main

import (
	"bufio"
	"errors"
	"io"
)

type ChunkedReader struct {
	r         *bufio.Reader
	chunkSize int
	relaxed   bool
}

var ErrBufSizeSmallerThanChunk = errors.New("buf size cannot be smaller than chunk size")

func NewChunkedReader(r io.Reader, chunkSize int) *ChunkedReader {
	br := bufio.NewReaderSize(r, chunkSize)
	return &ChunkedReader{r: br, chunkSize: chunkSize}
}

func NewRelaxedChunkedReader(r io.Reader, chunkSize int) *ChunkedReader {
	br := bufio.NewReaderSize(r, chunkSize)
	return &ChunkedReader{r: br, chunkSize: chunkSize, relaxed: true}
}

// Like a regular Read(), but indicates whether this is the last block.
func (r *ChunkedReader) Read(buf []byte) (n int, isLast bool, err error) {
	if len(buf) < r.r.Buffered() {
		err = ErrBufSizeSmallerThanChunk
		return
	}

	if r.relaxed {
		n, err = r.r.Read(buf)
	} else {
		n, err = io.ReadFull(r.r, buf)
	}
	if err == nil {
		// attempt to read the next chunk and see if it errors
		// that would indicate that *this* is the last block
		_, err2 := r.r.ReadByte()
		if err2 == nil {
			err = r.r.UnreadByte()
		} else if err2 == io.EOF {
			isLast = true
		} else {
			err = err2
		}
	} else if err == io.ErrUnexpectedEOF {
		isLast = true
		err = nil
	}

	return
}
