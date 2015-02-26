package main

/*
 * rx.go
 * Goroutine to receive data from insert
 * by J. Stuart McMurray
 * created 20150122
 * last modified 20150123
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
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

/* Errors which may be returned */
var (
	ErrorBadChecksum = fmt.Errorf("checksum mismatch")
	ErrorRXTooBig    = fmt.Errorf("the received fram was langer than the tunnel allows")
)

/* Read data from insert, send it to the tunnel */
func rx(tun Tunnel, in *Insert, echan chan error) {
	for {
		/* Read a size from insert */
		sizen, err := in.RecvEnc(2)
		if nil != err {
			echan <- err
			return
		}

		/* Convert to host byte order */
		sizeh := binary.BigEndian.Uint16(sizen)

		/* Make sure it's not bigger than a frame */
		if tun.MaxFrameLen() < int(sizeh) {
			echan <- ErrorRXTooBig
			return
		}

		/* Read that many bytes */
		data, err := in.RecvEnc(uint(sizeh))
		if nil != err {
			echan <- err
			return
		}
		data = data[:sizeh]

		/* Read the checksum */
		rxhash, err := in.RecvEnc(sha256.Size224)

		if nil != err {
			echan <- err
			return
		}

		/* Compute the local checksum */
		exhashA := sha256.Sum224(append(sizen, data...))
		/* Turn into a slice */
		exhashS := make([]byte, len(exhashA))
		for i := 0; i < len(exhashA); i++ {
			exhashS[i] = exhashA[i]
		}

		/* Verify checksum in constant time */
		diff := 0
		for i := 0; i < len(rxhash); i++ {
			if exhashS[i] != rxhash[i] {
				diff |= 1
			}
		}
		if 0 != diff {
			fmt.Printf("Got %02X, expected %02X\n", rxhash, exhashS)

			echan <- ErrorBadChecksum
		}

		/* Send frame to the kernel */
		if err := tun.Write(data); nil != err {
			fmt.Printf("Error sending data to tunnel: %v\n", err)
			echan <- err
		}
	}
}
