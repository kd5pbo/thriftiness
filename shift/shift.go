/* Shift, when used with insert, puts the local host on the remote network */
package main

/*
 * shift.go
 * The local half of thriftiness, uses stdin/out
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
	"fmt"
	"github.com/kd5pbo/confflags"
	"github.com/kd5pbo/easylogger"
	"log"
	"os"
	"strconv"
)

var ()

/* Logger variables */
var verbose, debug = easylogger.Generate(true)

func main() { os.Exit(mymain()) }
func mymain() int {
	/* Flags */
	var (
		addr = flag.String("addr", ":31337", "Address for "+
			"listening or connecting.")
		connect = flag.Bool("c", false, "Don't listen (the default), "+
			"but rather connect to the address specified by "+
			"-addr.")
		ipv4 = flag.Bool("4", false, "Force IPv4.  May not be "+
			"specified with -6.")
		ipv6 = flag.Bool("6", false, "Force IPv6.  May not be "+
			"specified with -4.")
		insertName = flag.String("name", "0001", "Name set in "+
			"insert to deter replay attacks")
		insertNameLen = flag.Uint("nlen", 1024, "Length of data to "+
			"send with -name, including size of -name.")
		junk = flag.String("junk", "GET / HTTP/1.1\r\n", "Junk data "+
			"in handshake")
		key = flag.String("k", "012345678901234567890123456789AB",
			"Encryption key.  Must be 32 bytes long.  May "+
				"contain non-ascii characters.")
		timeoff = flag.Int64("o", 0, "Time offset.  This number of "+
			"seconds will be added to the current time to match "+
			"the target's idea of the time.  May be negative.")
	)

	/* Parse command-line flags */
	confflags.Parse(nil)

	/* Work out whether to use IPv4 or IPv6 */
	ipv := 0
	/* For IPv4 */
	if *ipv4 {
		ipv = 4
	}
	/* Force IPv6 */
	if *ipv6 {
		/* Don't use both */
		if 4 == ipv {
			log.Printf("Unable to force both IPv4 and IPv6")
			return -4
		}
		ipv = 6
	}

	/* Make sure key is the right length and make it a byte array */
	if keyLen != len(*key) {
		log.Printf("Key (%v) is %v bytes, but should be %v bytes",
			strconv.QuoteToASCII(*key),
			len(*key),
			keyLen,
		)
	}
	var keyb [keyLen]byte
	for i := 0; i < keyLen; i++ {
		keyb[i] = []byte(*key)[i]
	}

	/* Warn user if he's not root */
	/* TODO: Update for systems in which 0 isn't root */
	if u := os.Geteuid(); 0 != u {
		log.Printf("Running as non-root user (uid %v).  This may "+
			"cause problems.", u)
	}
	/* Try to open a tun device */
	tun, tunname, err := MakeTun()
	if nil != err {
		log.Printf("Unable to make tun device: %v", err)
		return -1
	}
	log.Printf("Tunnel device: %v", tunname)
	/* Destroy the tun device when we're done with it */
	defer func() { tun.Close() }()
	/* Make or accept a connection */
	in, err := NewInsert(
		*addr,
		*connect,
		ipv,
		[]byte(*junk),
		keyb,
		*timeoff,
		*insertName,
		*insertNameLen,
	)
	if nil != err {
		log.Printf("Error establishing connection to insert: %v", err)
		return -2
	}
	log.Printf("Connected to %v", in.RemoteAddr())

	/* Channel on which to receive errors from the frame-copying
	goroutines */
	echan := make(chan error)

	/* Fire off a goroutine to encrypt and send traffic */
	go tx(tun, in, echan)

	/* Fire off another to decrypt traffic and put it on the tun device */
	/* TODO: Finish this */

	/* Wait for an error */
	err = <-echan
	fmt.Printf("Fatal error: %v", err)

	return 0
}
