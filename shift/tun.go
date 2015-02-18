package main

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
	MaxFrameLen() uint    /* Maximum frame size */
}

/* MakeTunFunc serves to document the type of the MakeTun function in each of
the mktun_* source files.  The returned value should be a struct that satisfies
the Tunnel interface, a string describing the tunnel, such as "tun0" or "tap2",
and the customary error-or-nil */
type MakeTunFunc func() (Tunnel, string, error)
