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
	"flag"
	//	"github.com/codahale/chacha20"
)

var (
	key = flag.String("k", "012345678901234567890123456789AB",
		"Encryption key.  Must be 32 bytes long.  May contain "+
			"non-ascii characters.")
	timeoff = flag.Int("o", 0, "Time offset.  This number of seconds "+
		"will be added to the current time to match the target's "+
		"idea of the time.  May be negative.")
)

/* Return a new crypt.Stream with the key and time-based nonce.  Stoi indicates
whether it's the shift-to-insert stream or the insert-to-shift stream */
func newCryptor(stoi bool, seqnum int) {
	/* Get the time */
	//var now int64 = time.Now().Unix()
	/* Generate the nonce */
	/* TODO: Finish this */
}
