package main

/*
 * crypto.go
 * Encrypt/decrypt functions
 * by J. Stuart McMurray
 * created 20150115
 * last modified 20150217
 *
 * Copyright (c) 2014 J. Stuart McMurray <kd5pbo@gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

import (
	"crypto/cipher"
	"fmt"
	"github.com/codahale/chacha20"
)

/* Number of bytes in the nonce */
const (
	nonceLen = chacha20.NonceSize
	keyLen   = chacha20.KeySize
)

/* Our own idea of a Stream */
type Cryptor struct {
	cipher.Stream
}

/* Generate the two crypt.Streams given the key, the nonce sent by insert, and
the time the nonce was received (give or take a pre-applied offset). */
func NewCryptorPair(key [keyLen]byte, nonce [nonceLen]byte, when int64) (
	stoi *Cryptor, /* Shift to Insert stream */
	itos *Cryptor, /* Insert to Shift stream */
	err error) {

	/* Generate the time-adjusted nonce */
	timedNonce := make([]byte, 8)
	for i, n := range nonce {
		/* Should never happen */
		if 0 > i {
			return nil, nil,
				fmt.Errorf("unpossible negative nonce index")
		}
		timedNonce[i] = n ^ byte((when>>(8*uint(i)))&0xFF)
	}
	debug("Time-adjusted nonce: %02X", timedNonce)

	/* Make the cryptors */
	timedNonce[0] &= 0xFC
	s, err := chacha20.New(key[:], timedNonce)
	if nil != err {
		return nil, nil, err
	}
	stoi = &Cryptor{s}
	timedNonce[0] |= 0x03
	i, err := chacha20.New(key[:], timedNonce)
	if nil != err {
		return nil, nil, err
	}
	itos = &Cryptor{i}
	/* TODO: Make sure key is 32 bytes long early */
	return
}

/* Encrypt/Decrypt data */
func (c *Cryptor) Crypt(d []byte) []byte {
	o := make([]byte, len(d))
	c.XORKeyStream(o, d)
	return o
}
