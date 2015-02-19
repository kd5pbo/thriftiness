package main

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
)

/*
 * tun.go
 * Interface describing a tunnel
 * by J. Stuart McMurray
 * created 20150116
 * last modified 20150116
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

/* An ethernet frame is just a byte array */
type Frame []byte

/* Interface representing a platform-independent tunnel.  Each mktun_* must
provide a function of type MakeTunFunc. */
type Tunnel interface {
	Read() (Frame, error) /* Read the next frame from the tunnel */
	Write(Frame) error    /* Write a frame to the tunnel */
	Close() error         /* Close the tunnel */
	MaxFrameLen() int     /* Maximum frame size */
}

/* MakeTunFunc serves to document the type of the MakeTun function in each of
the mktun_* source files.  The returned value should be a struct that satisfies
the Tunnel interface, a string describing the tunnel, such as "tun0" or "tap2",
and the customary error-or-nil */
type MakeTunFunc func() (Tunnel, string, error)

var (
	ErrorMarshallTooLong = fmt.Errorf(
		"frame too long for protocol's max %v bytes",
		math.MaxUint16,
	)
)

/* Marshall returns a byte slyce resulting from prepending the Frame with the
frame's size, and appending the appropriate hash. */
func (f Frame) Marshall() ([]byte, error) {
	/* Get the length of the frame */
	l := len(f)
	if l > math.MaxUint16 {
		return nil, ErrorMarshallTooLong
	}

	/* Header, which is just the size of the data in two bytes */
	hdr := make([]byte, 2)
	binary.BigEndian.PutUint16(hdr, uint16(l))

	/* Payload, sans checksum */
	payload := append(hdr, f...)

	/* Append hash */
	hashA := sha256.Sum224(payload)
	fmt.Printf("TX Hash: %02X\n", hashA) /* DEBUG */
	hashS := make([]byte, len(hashA))
	for i := 0; i < len(hashA); i++ {
		hashS[i] = hashA[i]
	}
	payload = append(payload, hashS...)

	/* Return payload */
	return payload, nil
}
