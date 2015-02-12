package main

/*
 * comms.go
 * Functions to communicate with insert
 * by J. Stuart McMurray
 * created 20150115
 * last modified 20150204
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
	"crypto/subtle"
	"flag"
	"fmt"
	"net"
	"strconv"
)

var (
	insertName = flag.String("name", "0001", "Name set in insert to "+
		"deter replay attacks")
	insertNameLen = flag.Uint("nlen", 1024, "Length of data to send "+
		"with -name, including size of -name.")
	junk = flag.String("junk", "GET / HTTP/1.1\r\n",
		"Junk data in handshake")
)

/* Number of bytes in the nonce */
const nonceLen = 8

/* Get a connection with the peer */
func get_peer() (net.Conn, error) {
	/* Make sure we are only supposed to listen xor connect */
	if *listen && *connect {
		return nil, fmt.Errorf("Unable to both listen and connect.")
	}
	/* Get IP versin */
	tcp := "tcp"
	switch {
	case *ipv4 && *ipv6:
		return nil, fmt.Errorf("Both -4 and -6 were given but at " +
			"most one is allowed")
	case *ipv4:
		tcp = "tcp4"
	case *ipv6:
		tcp = "tcp6"
	}
	/* He he, goto */
	if *connect {
		goto CONNECT
	}
	/* Try to listen on the port */
	if l, err := net.Listen(tcp, *addr); nil != err {
		return nil, err
	} else {
		return l.Accept()
	}
CONNECT:
	/* Try to connect to the client */
	return net.Dial(tcp, *addr)
}

/* Handshake with insert.  Returns the nonce value sent by insert. */
func handshake(c net.Conn) error {
	/* Say Hello */
	debug("Sending %v bytes of junk: %v",
		len(*junk), strconv.QuoteToASCII(*junk))
	if err := sendAll(c, []byte(*junk)); nil != err {
		return err
	}
	/* Get the nonce */
	nonce, err := recvAll(c, nonceLen)
	if nil != err {
		return err
	}
	debug("Nonce is %02X\n", nonce)

	/* Initialize crypto */
	var nonceArr [nonceLen]byte
	for i, v := range nonce {
		nonceArr[i] = v
	}
	makeCryptors(nonceArr)

	/* Null-pad our name out to insertNameLen bytes */
	txnamelong := []byte(*insertName)
	txnamelong = append(txnamelong, make([]byte,
		*insertNameLen-uint(len(txnamelong)))...)

	/* Work out how many null-padded bytes there are */
	txnameshort, txnulls := trimTrailingNulls(txnamelong)

	/* Send our idea of the name */
	debug("Sending name %v with %v trailing null bytes",
		strconv.QuoteToASCII(string(txnameshort)), txnulls)
	if err := sendEnc(c, txnamelong); nil != err {
		return fmt.Errorf("sending name: %v", err)
	}
	verbose("Sent name: %v", strconv.QuoteToASCII(string(txnameshort)))

	/* Get (hopefully) the same name back */
	debug("Waiting on insert to send name back in %v byte message",
		*insertNameLen)
	rxnamelong, err := recvEnc(c, int(*insertNameLen))
	if nil != err {
		return fmt.Errorf("receiving name: %v", err)
	}
	rxnameshort, rxnulls := trimTrailingNulls(rxnamelong)
	verbose("Got name: %v", strconv.QuoteToASCII(string(rxnameshort)))

	/* Make sure the two match */
	if 1 != subtle.ConstantTimeCompare(txnamelong, rxnamelong) {
		return fmt.Errorf("Received name (%v with %v trailing nulls) "+
			"is different than expected (%v with %v trailing "+
			"nulls)",
			strconv.QuoteToASCII(string(rxnameshort)), rxnulls,
			strconv.QuoteToASCII(string(txnameshort)), txnulls)
	}

	return nil
}

/* Send all the bytes to a conn */
func sendAll(c net.Conn, b []byte) error {
	/* Number of bytes to send */
	tosend := len(b)
	/* Number of bytes sent so far */
	sent := 0

	/* Go until we've not got any more */
	for sent < tosend {
		/* Try to send the remaining bytes */
		n, err := c.Write(b[sent:])
		if nil != err {
			return err
		}
		sent += n
	}
	return nil
}

/* Read n bytes from the conn */
func recvAll(c net.Conn, n int) ([]byte, error) {
	nRead := 0      /* Number of bytes sent */
	buf := []byte{} /* Output buffer */

	/* Keep trying until we've sent enough */
	for nRead < n {
		/* Make a read buffer with the remaining number of bytes */
		b := make([]byte, n-nRead)
		/* Try to fill it */
		r, err := c.Read(b)
		if nil != err {
			return nil, err
		}
		/* Update count and buffer */
		buf = append(buf, b...)
		nRead += r
	}
	return buf, nil
}

/* Encrypt and send b to c */
func sendEnc(c net.Conn, b []byte) error {
	/* Copy b into a local buffer */
	ebuf := make([]byte, len(b))
	copy(ebuf, b)
	/* Encrypt data */
	encrypt(ebuf)
	/* Send it */
	return sendAll(c, ebuf)
}

/* Read and decrypt n bytes from c */
func recvEnc(c net.Conn, n int) ([]byte, error) {
	/* Get n bytes */
	b, err := recvAll(c, n)
	if nil != err {
		return nil, err
	}
	/* Decrypt them */
	decrypt(b)
	return b, nil
}

/* Trim the null bytes from the end of a byte slice, return a trimmed copy and
the number of null bytes at the end */
func trimTrailingNulls(b []byte) ([]byte, int) {
	nulls := 0            /* Number of trailing nulls */
	lastind := len(b) - 1 /* Last non-null index before trailing nulls */

	/* Find the last non-null byte */
	for ; lastind >= 0; lastind-- {
		if 0 != b[lastind] {
			break
		}
		nulls++
	}
	lastind++

	/* Make a slice to hold the non-null bits */
	trimmed := make([]byte, lastind)
	/* Copy the bytes to the slice */
	for i := 0; i < lastind; i++ {
		trimmed[i] = b[i]
	}

	return trimmed, nulls
}
