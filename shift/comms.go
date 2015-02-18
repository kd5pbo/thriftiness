package main

/*
 * comms.go
 * Functions to communicate with insert
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
	"crypto/subtle"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

/* Insert represents a connection to insert */
type Insert struct {
	c   net.Conn   /* Connection to Insert */
	sic *Cryptor   /* Shift to Insert Cryptor */
	sim sync.Mutex /* Shift to Insert Send Lock */
	isc *Cryptor   /* Insert to Shift Cryptor */
	ism sync.Mutex /* Insert to Shift Receive Lock */
}

/* Connect to Insert at addr (or optionally listening on addr if listen is
true),  forcing IPv4 if force is 4, IPv6 is force is 6, or maintaining the
default is force is 0, and handshake using the given junk, key, time offset,
and name.  The returned Insert will be ready for two-way communications. */
func NewInsert(
	addr string, /* Connect/listen address */
	connect bool, /* True to connect, false to listen */
	force int, /* Fore 4 for IPv4, 6 for IPv6, 0 for no forcing */
	junk []byte, /* Initial junk to send */
	key [keyLen]byte, /* Encryption key */
	offset int64, /* Time offset in seconds */
	name string, /* Insert's install name */
	nLen uint, /* Length of chunk of data in which to put name */
) (*Insert, error) {
	/* Struct to return */
	in := &Insert{}

	/* Work out whether to force IPv4 or IPv6 */
	tnet := "tcp"
	switch force {
	case 0:
		break
	case 4:
		tnet = "tcp4"
	case 6:
		tnet = "tcp6"
	default:
		return nil, fmt.Errorf("cannot is no IPv%v as it doesn't "+
			"exist", force)
	}

	/* Make sure the address is a valid address */
	tcpAddr, err := net.ResolveTCPAddr(tnet, addr)
	if nil != err {
		return nil, fmt.Errorf("resolving %v: %v", err)
	}

	/* Try to connect to Insert */
	c, err := makeConnection(tnet, tcpAddr, connect)
	if nil != err {
		return nil, err
	}
	in.c = c

	/* Send Junk */
	debug("Sending %v bytes of junk: %v",
		len(junk), strconv.QuoteToASCII(string(junk)))
	if err := in.sendAll(junk); nil != err {
		return nil, err
	}

	/* Get the Nonce */
	nonce, err := in.recvAll(nonceLen)
	if nil != err {
		return nil, err
	}
	nonceTime := time.Now().Unix()
	debug("Got nonce %02X at time %v", nonce, nonceTime)

	/* Make the nonce an array */
	var narr [nonceLen]byte
	for i := 0; i < nonceLen; i++ {
		narr[i] = nonce[i]
	}

	/* Make the cryptors */
	in.sic, in.isc, err = NewCryptorPair(key, narr, nonceTime)
	if nil != err {
		return nil, err
	}

	/* Exchange names */
	if err := in.exchangeNames(name, nLen); nil != err {
		return nil, err
	}

	/* Return the insert struct */
	return in, nil
}

/* Make a connection with the peer */
func makeConnection(tnet string,
	addr *net.TCPAddr,
	connect bool) (net.Conn, error) {
	/* Listen or connect, as appropriate */
	if connect {
		/* Try to connect to the client */
		debug("Attempting a %v connection to %v", tnet, addr)
		return net.DialTCP(tnet, nil, addr)
	}
	/* Try to listen on the port */
	debug("Listening on %v address %v", tnet, addr)
	l, err := net.ListenTCP(tnet, addr)
	if nil != err {
		return nil, err
	}
	/* Get a connection */
	return l.Accept()
}

/* Send/Receive the name with which insert was installed.  Closes the
connection on error. */
func (in *Insert) exchangeNames(name string, nlen uint) error {

	/* Null-pad our name out to insertNameLen bytes */
	txnamelong := []byte(name)
	txnamelong = append(txnamelong, make([]byte,
		nlen-uint(len(txnamelong)))...)

	/* Work out how many null-padded bytes there are */
	txnameshort, txnulls := trimTrailingNulls(txnamelong)

	/* Send our idea of the name */
	debug("Sending name %v with %v trailing null bytes",
		strconv.QuoteToASCII(string(txnameshort)), txnulls)
	if err := in.SendEnc(txnamelong); nil != err {
		return fmt.Errorf("sending name: %v", err)
	}
	verbose("Sent name: %v", strconv.QuoteToASCII(string(txnameshort)))

	/* Get (hopefully) the same name back */
	debug("Waiting on insert to send name back in %v byte message", nlen)
	rxnamelong, err := in.RecvEnc(nlen)
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

/* Send all the bytes to insert */
func (in *Insert) sendAll(b []byte) error {
	/* Number of bytes to send */
	tosend := len(b)
	/* Number of bytes sent so far */
	sent := 0

	/* Prevent interleaved sends */
	in.sim.Lock()
	defer in.sim.Unlock()

	/* Go until we've not got any more */
	for sent < tosend {
		/* Try to send the remaining bytes */
		n, err := in.c.Write(b[sent:])
		if nil != err {
			in.c.Close()
			return err
		}
		sent += n
	}
	return nil
}

/* Read n bytes from Insert */
func (in *Insert) recvAll(n uint) ([]byte, error) {
	nRead := uint(0) /* Number of bytes sent */
	buf := []byte{}  /* Output buffer */
	fmt.Printf("Got a request for %v bytes\n", n)

	/* Prevent interleaved receives */
	in.ism.Lock()
	defer in.ism.Unlock()

	/* Keep trying until we've sent enough */
	for nRead < n {
		b := make([]byte, n-nRead)
		/* Try to fill it */
		r, err := in.c.Read(b)
		if nil != err {
			in.c.Close()
			return nil, err
		}
		/* Update count and buffer */
		buf = append(buf, b...)
		if 0 < r {
			nRead += uint(r)
		}
	}
	return buf, nil
}

/* Encrypt and send b to Insert */
func (in *Insert) SendEnc(b []byte) error {
	/* Copy b into a local buffer */
	ebuf := make([]byte, len(b))
	copy(ebuf, b)
	/* Encrypt data and Send it */
	return in.sendAll(in.encrypt(ebuf))
}

/* Read and decrypt n bytes from Insert */
func (in *Insert) RecvEnc(n uint) ([]byte, error) {
	/* Get n bytes */
	b, err := in.recvAll(n)
	if nil != err {
		return nil, err
	}
	p := in.decrypt(b)

	return p, nil
}

/* Encrypt data for sending */
func (in *Insert) encrypt(d []byte) []byte {
	return in.sic.Crypt(d)
}

/* Decrypt data for receiving */
func (in *Insert) decrypt(d []byte) []byte {
	return in.isc.Crypt(d)
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

/* Wrapper for the connection's RemoteAddr */
func (in *Insert) RemoteAddr() net.Addr {
	return in.c.RemoteAddr()
}
