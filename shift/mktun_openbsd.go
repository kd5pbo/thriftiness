package main

/*
 * mktun_openbsd.go
 * OpenBSD-specific source to make the tun(4) device
 * by J. Stuart McMurray
 * created 20150116
 * last modified 20150218
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
	"log"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

/* Flags speficic to openbsd */
var (
	mac = flag.String(
		"mac",
		"",
		"MAC address to use for tun(4) device.  If none is "+
			"specified, none will be set, and OpenBSD will "+
			"assign an address.",
	)
	ip = flag.String(
		"ip",
		"",
		"IP Address to use for tun(4) device.  Should probably be "+
			"an IP address on the remote subnet.  If not set, "+
			"no address will be assigned (e.g. for DHCP).",
	)
	netmask = flag.String(
		"nm",
		"",
		"Netmask.  Will only be set if an IP address is specified.",
	)
	mtu = flag.Int(
		"mtu",
		1500,
		"MTU.  If 0 is specified, the default will be used.",
	)
	destroy = flag.Bool(
		"rmtun",
		true,
		"Attempt to remove the tunnel with ifconfig destroy on exit",
	)
)

const (
	MTUWARN = 1 << 14 /* Expected MTU limit */
)

/* Struct representing a tunnel.  Implements the Tunnel interface */
type TunOpenBSD struct {
	f       *os.File /* /dev/tun file */
	devname string   /* Device name */
	destroy bool     /* Destroy on close */
}

/* Read and return a frame from the kernel */
func (t *TunOpenBSD) Read() (Frame, error) {
	/* Read buffer.  We should never fill this */
	buf := make([]byte, 2*MTUWARN)
	/* Block until we have data */
	n, err := t.f.Read(buf)
	if nil != err {
		return nil, err
	}
	/* If we read more than MTUWARN bytes, something's buggy */
	if n > MTUWARN {
		return nil, fmt.Errorf("read a %v-byte ethernet frame from "+
			"%v.  This is way too big and likely indicates a bug.",
			n)
	}
	/* Give back the read bytes */
	return buf[:n], nil
}

/* Write a frame to the kernel */
func (t *TunOpenBSD) Write(b Frame) error {
	/* Send the frame to the kernel */
	n, err := t.f.Write(b)
	if nil != err {
		return fmt.Errorf("only wrote %v/%v bytes: %v", n, len(b), err)
	}
	return nil
}

/* Close the tunnel */
func (t *TunOpenBSD) Close() error {
	cerr := t.f.Close()
	if t.destroy {
		if output, err := exec.Command(
			"/sbin/ifconfig",
			t.devname,
			"destroy",
		).CombinedOutput(); nil != err {
			debug("Unable to destroy %v: %v (output %v)",
				t.devname, err, strings.TrimSpace(string(output)))
		}
		debug("Destroyed %v", t.devname)
	}
	return cerr
}

/* Make and open a tun(4) device. */
func MakeTun() (*TunOpenBSD, string, error) {
	var t *os.File = nil /* Tun device */
	var devname = ""     /* Name of tun device */

	/* Validate MAC and IP Addres */
	if "" != *mac && !regexp.MustCompile(`^[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:`+
		`[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:`+
		`[0-9A-Fa-f]{2}$`).MatchString(*mac) {
		return nil, "", fmt.Errorf("invalid MAC address: %v", *mac)
	}
	if "" != *ip && !regexp.MustCompile(`^[0-9A-Fa-f:]{2,39}|`+
		`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`).MatchString(*ip) {
		return nil, "", fmt.Errorf("Invalid IP address: %v", *ip)
	}

	/* Make sure MTU is > 0 */
	if 0 >= *mtu {
		return nil, "", fmt.Errorf("mtu must be greater than zero.")
	}

	/* Try successive device numbers until one works */
	for i := 0; i < 256; i++ {
		/* Work out which device to open */
		devname = fmt.Sprintf("tun%v", i)
		/* Try to open a tun device */
		var err error
		if t, err = os.OpenFile(
			fmt.Sprintf("/dev/%v", devname),
			os.O_RDWR|os.O_CREATE|os.O_SYNC,
			0600,
		); nil != err {
			debug("Unable to open %v: %v", devname, err)
			continue
		}
		debug("Opened /dev/%v", devname)
		break
	}

	/* If we still have no device, give up */
	if nil == t {
		return nil, "", fmt.Errorf("unable to open any tun device")
	}

	/* Set device to layer 2 tunneling */
	if output, err := exec.Command("/sbin/ifconfig", devname,
		"link0").CombinedOutput(); nil != err {
		return nil, "", fmt.Errorf("setting link0: %v (output: %v)",
			err, strings.TrimSpace(string(output)))
	}
	/* Set mac address if one is given */
	if "" != *mac {
		if output, err := exec.Command("/sbin/ifconfig", devname,
			"lladdr", *mac).CombinedOutput(); nil != err {
			return nil, "", fmt.Errorf("setting mac address "+
				"(%v): %v (output %v)",
				*mac, err, strings.TrimSpace(string(output)))
		}
	}

	/* Set the IP address if one is given */
	if "" != *ip {
		if output, err := exec.Command("/sbin/ifconfig", devname,
			"inet", *ip).CombinedOutput(); nil != err {
			return nil, "", fmt.Errorf("setting IP address (%v): "+
				"%v (output %v)",
				*ip, err, strings.TrimSpace(string(output)))
		}
		/* Set the netmask if it's given */
		if "" != *netmask {
			output, err := exec.Command("/sbin/ifconfig",
				devname,
				"netmask",
				*netmask).CombinedOutput()
			if nil != err {
				return nil, "", fmt.Errorf("setting netmask "+
					"(%v): %v (output %v)",
					*netmask, err,
					strings.TrimSpace(string(output)))
			}
		}
	}

	/* Set the MTU if one is given */
	if *mtu > MTUWARN {
		log.Printf("MTU (%v) is unusually high.  It probably should "+
			"be lower", *mtu)
	}
	if *mtu < 0 {
		return nil, "", fmt.Errorf("MTU (%v) less than 0", *mtu)
	}
	if 0 != *mtu {
		if output, err := exec.Command(
			"/sbin/ifconfig",
			devname,
			"mtu",
			strconv.Itoa(*mtu),
		).CombinedOutput(); nil != err {
			return nil, "", fmt.Errorf("setting mtu (%v): %v "+
				"(output %v)",
				*mtu, err, strings.TrimSpace(string(output)))
		}
	}

	/* Bring the interface up */
	if output, err := exec.Command(
		"/sbin/ifconfig",
		devname,
		"up",
	).CombinedOutput(); nil != err {
		return nil, "", fmt.Errorf("Bringing %v up: %v (output %v)",
			devname, err, output)
	}
	tun := &TunOpenBSD{f: t, devname: devname, destroy: *destroy}
	return tun, devname, nil
}

/* Report the maximum frame length */
func (t *TunOpenBSD) MaxFrameLen() int {
	return *mtu
}
