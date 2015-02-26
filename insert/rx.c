/*
 * rx.c
 * Code to receive data from insert
 * by J. Stuart McMurray
 * created 20150212
 * last modified 20150226
 *
 * Copyright (c) 2015 J. Stuart McMurray <kd5pbo@gmail.com>
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

#include <netinet/in.h>
#include <inttypes.h>
#include <pcap.h>
#include <string.h>
#include <unistd.h>

#include "comm.h"
#include "crypto.h"
#include "insert.h"
#include "retvals.h"
#include "sha2.h"

/* Handle a keepalive packet from fd (after the initial 0x00).  Returns 0 on
 * success.  */
int handle_keepalive(int fd);

/* Get data from shift (as fd) and put it on the wire. */
void shift_to_insert(int fd, pcap_t *p) {
        uint16_t sizeh;                 /* Size in host byte order */
        uint8_t buf[sizeof(sizeh) + UINT16_MAX]; /* Read buffer */
        uint8_t comphash[DIGESTLEN];    /* Message digest */
        uint8_t rxhash[DIGESTLEN];      /* Digest, as sent by shift */
        int i;                          /* Index variable */
        int ret;                        /* Return value */

        sizeh = 0;
        memset(buf, 0, sizeof(buf));
        memset(comphash, 0, sizeof(comphash));
        memset(rxhash, 0, sizeof(rxhash));
        i = 0;
        ret = 0;

        for (;;) {
                /* Pull a size off the wire */
                if (0 != (ret = recv_enc(fd, (uint8_t*)buf, sizeof(sizeh)))) {
                        break;
                }

                /* Convert to host format */
                sizeh = htons(*(uint16_t*)buf);

                /* If the size is 0, it's a keepalive */
                if (0 == sizeh) {
                        if (0 != (ret = handle_keepalive(fd))) {
                                return;
                        }
                        /* Process the next packet */
                        continue;
                }

                /* Read that many bytes of data */
                if (0 != (ret = recv_enc(fd, buf+sizeof(sizeh), sizeh))) {
                        break;
                }

                /* Read the hash, as sent by shift */
                if (0 != (ret = recv_enc(fd, rxhash, DIGESTLEN))) {
                        break;
                }

                /* Get the hash of the data */
                /* Possible pitfall size_t -> unsigned int typecast */
                sha224(buf, (unsigned int)sizeh+(unsigned int)sizeof(sizeh), comphash);
                /* TODO: Make sure sizeof(unsigned int) >= 2 bytes */

                /* Make sure the two are the same */
                if (0 != constcmp(comphash, rxhash, DIGESTLEN)) {
                        ret = RET_ERR_HASH;
                        break;
                }

                /* Send it out on the wire */
                if ((ret = pcap_inject(p, buf+sizeof(sizeh), sizeh)) !=
                                sizeh) {
                        printf("Only injected %i/%i bytes\n", ret, sizeh);
                }
        }
        /* TODO: Handle the interface going down */
        /* TODO: Break from the pcap read loop */
        
        /* If we're here, something failed (or shift disconnected) */
        set_reterr(ret);
}

/* Handle a keepalive packet from fd (after the initial 0x00).  Returns 0 on
 * success.  */
int handle_keepalive(int fd) {
        uint16_t junksizen;      /* Number of junk bytes to read in NBO */
        uint16_t junksizeh;      /* Number of junk bytes to read in HBO */
        uint8_t buf[UINT16_MAX]; /* Receive buffer */
        int ret;                 /* Return value */

        /* Read the size of the junk data */
        if (0 != (ret = recv_enc(fd, (uint8_t*)&junksizen,
                                        sizeof(uint16_t)))) {
                return ret;
        }

        /* Convert from network byte order to host byte order */
        junksizeh = ntohs(junksizen);

        /* Read (and discard) that many bytes of data */
        if (0 != (ret = recv_enc(fd, buf, junksizeh))) {
                return ret;
        }

        return 0;
}
