package main

/*
 * tx.go
 * Goroutine to send data to insert
 * by J. Stuart McMurray
 * created 20150116
 * last modified 20150126
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
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"math/big"
	"time"
)

var (
	kaMin = 2    /* Minimum keepalive junk length */
	kaMax = 1024 /* Maximum  keepalive junk length */
)

/* Errors that might be sent on echan */
var (
	ErrorKATooBig = fmt.Errorf("Keepalive size is larger than a 16-bit uint")
)

/* Reads from the tun device and sends the data to insert. fatal errors will be
reported on echan.  The goroutine will terminate when dchan is closed. */
func tx(
	tun Tunnel,
	in *Insert,
	echan chan error,
	/* Time range to wait before sending a keepalive */
	minWait time.Duration,
	maxWait time.Duration,
) {
	/* Start reads from the tunnel into a chan */
	fchan := make(chan Frame)
	go readIntoChan(tun, fchan, echan)

	for {
		/* Bounded random wait before sending keepalive */
		wait, err := randomWait(minWait, maxWait)
		if nil != err {
			echan <- err
			return
		}
		/* Wait for either time to send a keepalive or a packet */
		select {
		case <-time.After(wait): /* Send a keepalive */
			if err := sendKeepalive(in); nil != err {
				echan <- err
				return
			}

		case f, ok := <-fchan: /* (Maybe) send a frame */
			/* Give up if the channel's closed */
			if !ok {
				return
			}
			/* Try to send the frame to insert */
			if err := sendToInsert(
				in,
				f,
				tun.MaxFrameLen(),
			); nil != err {
				echan <- err
				return
			}
		}
	}
}

/* Read from a Tunnel into a chan, which will be closed on error (which will
be sent to echan) */
func readIntoChan(t Tunnel, fchan chan Frame, echan chan error) {
	for {
		/* Read a frame from the tunnel */
		f, err := t.Read()
		/* Give up if there's an error */
		if nil != err {
			echan <- err
			close(fchan)
			return
		}
		/* Send the frame on the channel */
		fchan <- f
	}
}

/* Marshall a frame and send it to the insert if it's shorter than maxLen  */
func sendToInsert(in *Insert, f Frame, maxLen int) error {
	/* Drop frames that are bigger than the tunnel can handle */
	if maxLen < len(f) {
		log.Printf(
			"Dropping frame of length %v > %v",
			len(f),
			maxLen,
		)
		return nil
	}
	/* Drop frames that are bigger than the protocol can handle */
	if math.MaxUint16 < len(f) {
		log.Printf(
			"Dropping %v-byte frame that is bigger than "+
				"the protocol's max %v bytes.",
			len(f),
			math.MaxUint16,
		)
		return nil
	}
	/* Marshall a nice message */
	mf, err := f.Marshall()
	if nil != err { /* Shouldn't happen */
		log.Printf("Marshall error: %v", err)
		return nil
	}
	/* Send frame to insert */
	if err := in.SendEnc(mf); nil != err {
		return err
	}

	return nil
}

/* randomWait returns a time.Duration between min and max */
func randomWait(min, max time.Duration) (time.Duration, error) {
	big, err := rand.Int(rand.Reader, big.NewInt(int64(max-min)))
	if nil != err {
		return 0, err
	}
	return time.Duration(big.Int64()) + min, nil
}

/* sendKeepalive sends a keepalive to Insert */
func sendKeepalive(in *Insert) error {
	/* Get a random size */
	big, err := rand.Int(rand.Reader, big.NewInt(int64(kaMax-kaMin)))
	if nil != err {
		return err
	}
	sizeh := big.Uint64() + uint64(kaMin)

	/* Make sure it's not too large */
	if math.MaxUint16 < sizeh {
		return ErrorKATooBig
	}

	/* Get it network byte order */
	sizen := make([]byte, 2)
	binary.BigEndian.PutUint16(sizen, uint16(sizeh))

	/* Make that much junk */
	junk := make([]byte, sizeh)
	if _, err := rand.Read(junk); nil != err {
		return err
	}

	/* Put it all together and send it */
	header := append([]byte{0x00, 0x00}, sizen...)
	ka := append(header, junk...)
	debug("Sending %v-byte keepalive", sizeh)
	if err := in.SendEnc(ka); nil != err {
		return err
	}

	return nil
}
