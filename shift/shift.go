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
	"github.com/kd5pbo/confflags"
	"github.com/kd5pbo/easylogger"
	"log"
	"os"
)

var (
	addr = flag.String("addr", ":31337", "Address for listening or "+
		"connecting.")
	listen = flag.Bool("l", false, "Listen (the default).  May not be "+
		"specifed with -c.")
	connect = flag.Bool("c", false, "Connect.  May not be specified with "+
		"-l.")
	ipv4 = flag.Bool("4", false, "Force IPv4.  May not be specified "+
		"with -6.")
	ipv6 = flag.Bool("6", false, "Force IPv6.  May not be specified "+
		"with -4.")
)

/* Logger variables */
var verbose, debug = easylogger.Generate(true)

func main() { os.Exit(mymain()) }
func mymain() int {
	var tun *os.File
	/* Parse command-line flags */
	confflags.Parse(nil)
	/* Try to open a tun device */
	tun, tunname, err := make_tun()
	if nil != err {
		log.Printf("Unable to make tun device: %v", err)
		return -1
	}
	log.Printf("Tunnel device: %v", tunname)
	/* Destroy the tun device when we're done with it */
	defer func() { tun.Close(); destroy_tun(tunname) }()
	/* Make or accept a connection */
	peer, err := get_peer()
	if nil != err {
		log.Printf("Error establishing connection to peer: %v", err)
		return -2
	}
	verbose("Connected to %v", peer.RemoteAddr())
	/* Handshake with the peer */
	if err := handshake(peer); nil != err {
		log.Printf("Error handshaking: %v", err)
		return -3
	}

	/* Fire off a goroutine to encrypt and send traffic */
	/* Fire off another to decrypt traffic and put it on the tun device */
	/* Exit when appropriate */
	return 0
}

/* Handshake with the peer */

//o, e := exec.Command("ifconfig").CombinedOutput() /* DEBUG */
//log.Printf("(%v) %v", e, string(o)) /* DEBUG */
