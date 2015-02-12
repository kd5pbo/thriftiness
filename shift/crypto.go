package main

/*
 * crypto.go
 * Encrypt/decrypt functions
 * by J. Stuart McMurray
 * created 20150115
 * last modified 20150115
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
	"flag"
	"fmt"
	"github.com/codahale/chacha20"
	"time"
)

var (
	key = flag.String("k", "012345678901234567890123456789AB",
		"Encryption key.  Must be 32 bytes long.  May contain "+
			"non-ascii characters.")
	timeoff = flag.Int64("o", 0, "Time offset.  This number of seconds "+
		"will be added to the current time to match the target's "+
		"idea of the time.  May be negative.")

	/* Encryption and decryption streams */
	txStream cipher.Stream
	rxStream cipher.Stream
)

/* Generate the two crypt.Streams given the nonce sent by insert */
func makeCryptors(nonce [nonceLen]byte) error {
	timedNonce := make([]byte, 8)
	/* Get the time */
	var now int64 /* Just in case time.Unix()'s type changes */
	now = time.Now().Unix() + *timeoff

	/* Generate the time-adjusted nonce */
	for i, n := range nonce {
		/* Should never happen */
		if 0 > i {
			return fmt.Errorf("unpossible negative nonce index")
		}
		timedNonce[i] = n ^ byte((now>>(8*uint(i)))&0xFF)
	}
	debug("Time-adjusted nonce: %02X", timedNonce)
	/* TODO: Make sure key is 32 bytes long early */

	/* Make Streams */
	var err error
	timedNonce[0] &= 0xFC
	if txStream, err = chacha20.New([]byte(*key), timedNonce); nil != err {
		return err
	}
	timedNonce[0] |= 0x03
	if rxStream, err = chacha20.New([]byte(*key), timedNonce); nil != err {
		return err
	}

	return nil
}

/* Encrypt data in-place with txStream */
func encrypt(d []byte) {
	txStream.XORKeyStream(d, d)
}

/* Decrypt data in-place with rxStream */
func decrypt(d []byte) {
	rxStream.XORKeyStream(d, d)
}
