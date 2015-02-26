/*
 * tx.c
 * Code for thread to send data to insert
 * by J. Stuart McMurray
 * created 20150212
 * last modified 20150222
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
#include <string.h>

#include "comm.h"
#include "insert.h"
#include "retvals.h"
#include "sha2.h"
#include "tx.h"

/* Get data from pcap, send to shift */
void *insert_to_shift(void *data) {
        struct its_data id;    /* Input data, pulled from the void* */
        struct handle_data hd; /* Data for handle_frame */
        int ret;               /* Return value */
        int hret;              /* Return value from handler */

        memset(&hd, 0, sizeof(hd));
        ret = 0;
        hret = 0;

        /* Get a copy of the input data */
        memcpy(&id, data, sizeof(id));

        /* Data for handle_frame */
        hd.p = id.p;
        hd.fd = id.fd;
        hd.ret = &hret;

        /* Capture frames until an error occurs */
        ret = pcap_loop(id.p, 0, handle_packet, (u_char*)&hd);
        switch (ret) {
                case -2: /* Explicit loop break */
                        set_reterr(hret);
                        return NULL;
                        break;
                case -1:
                        set_reterr(RET_ERR_CAP);
                        return NULL;
                        break;
                default:
                        printf("Unknown pcap_loop return: %i\n", ret);
                        set_reterr(RET_ERR_CAP);
                        return NULL;
                        break;
        }

        /* Shouldn't get here */
        return NULL;
}

/* Callback function for pcap_loop */
void handle_packet(u_char *user, const struct pcap_pkthdr *header,
        const u_char *data) {

        uint8_t databuf[UINT16_MAX+sizeof(uint16_t)];
                                   /* Buffer to hold the data */
        uint8_t txhash[DIGESTLEN]; /* Hash of the data */
        uint16_t len;              /* Size of the data */
        struct handle_data hd;     /* User data passed in */
        int ret;                   /* Return value */

        memset(txhash, 0, sizeof(txhash));
        len = 0;
        memcpy(&hd, user, sizeof(hd));

        /* Make sure we captured the entire frame */
        if (header->len != header->caplen) {
                *hd.ret = RET_ERR_CSZS;
                goto BREAK;
        }

        /* Make sure frame isn't too large */
        if (UINT16_MAX < header->len) {
                *hd.ret = RET_ERR_CSZL;  
                goto BREAK;
        }

        /* Copy the size to a buffer */
        len = htons(header->len);
        memcpy(databuf, &len, sizeof(len));

        /* Copy the data to a buffer */
        memcpy(databuf+sizeof(len), data, header->len);

        /* Calculate hash */
        sha224(databuf, header->len+sizeof(len), txhash);



        /* Send the bits.  We're boned if anything else is sending */
        if ((0 != (ret = send_enc(hd.fd, databuf, header->len+sizeof(len)))) ||
                        (0 != (ret = send_enc(hd.fd, txhash,
                                              sizeof(txhash))))) {
                *hd.ret = ret;
                goto BREAK;
        }

        /* Return success */
        *hd.ret = 0;
        return;

        /* Something bad happened, stop the capture */
BREAK:
        pcap_breakloop(hd.p);
        return;
}
