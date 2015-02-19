package main

import (
	"fmt"
	"log"
	"math"
)

/*
 * tx.go
 * Goroutine to send data to insert
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

/* Reads from the tun device and sends the data to insert. fatal errors will be
reported on echan.  The goroutine will terminate when dchan is closed. */
func tx(tun Tunnel, in *Insert, echan chan error) {
	for {
		/* Read a frame from the tun device */
		fmt.Printf("Waiting on a frame.\n")
		f, err := tun.Read()
		if nil != err {
			echan <- err
			return
		}
		/* Drop frames that are bigger than the tunnel can handle */
		if tun.MaxFrameLen() < len(f) {
			log.Printf(
				"Dropping frame of length %v > %v",
				len(f),
				tun.MaxFrameLen(),
			)
			continue
		}
		/* Drop frames that are bigger than the protocol can handle */
		if math.MaxUint16 < len(f) {
			log.Printf(
				"Dropping %v-byte frame that is bigger than "+
					"the protocol's max %v bytes.",
				len(f),
				math.MaxUint16,
			)
			continue
		}
		/* Send frame to insert */
		fmt.Printf("Frame (%v): %02X\n", len(f), f) /* DEBUG */
		mf, err := f.Marshall()
		if nil != err { /* Shouldn't happen */
			log.Printf("Marshall error: %v", err)
			continue
		}
		in.SendEnc(mf)
	}
}
