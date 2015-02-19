/*
 * rx.c
 * Code to receive data from insert
 * by J. Stuart McMurray
 * created 20150212
 * last modified 20150218
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
                printf("Rexpecting 0x%hX bytes\n", sizeh); /* DEBUG */

                /* Read that many bytes of data */
                if (0 != (ret = recv_enc(fd, buf+sizeof(sizeh), sizeh))) {
                        break;
                }
                printf("RX Frame: ");for(i = 0; i < sizeh;++i){printf("%02X", buf[i]);}printf("\n"); /* DEBUG */

                /* Read the hash, as sent by shift */
                if (0 != (ret = recv_enc(fd, rxhash, DIGESTLEN))) {
                        break;
                }

                printf("RX Hash: ");for(i = 0; i < DIGESTLEN;++i){printf("%02X", rxhash[i]);}printf("\n"); /* DEBUG */

                /* Get the hash of the data */
                /* Possible pitfall size_t -> unsigned int typecast */
                sha224(buf, (unsigned int)sizeh+(unsigned int)sizeof(sizeh), comphash);
                /* TODO: Make sure sizeof(unsigned int) >= 2 bytes */

                /* Make sure the two are the same */
                if (0 != constcmp(comphash, rxhash, DIGESTLEN)) {
                        ret = RET_ERR_HASH;
                        printf("Hash mismatch\n"); /* DEBUG */
                        break;
                }

                /* print the data DEBUG */
                for (i = sizeof(sizeh); i < sizeh; ++i) {
                        printf("%02" PRIX8, buf[i]);/* DEBUG */
                }printf("\n"); /* DEBUG */
        }
        
        /* If we're here, something failed (or shift disconnected) */
        set_reterr(ret);
        close(fd);
        if (NULL != p) {
                pcap_close(p);
        }
}





