/*
 * comm.c
 * Functions related to communications
 * by J. Stuart McMurray
 * created 20150122
 * last modified 20150204
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
#include <sys/socket.h>
#include <sys/types.h>

#include <limits.h>
#include <stdint.h>
#include <stdio.h> /* TODO: Remove this */
#include <stdlib.h>
#include <unistd.h>

#include "comm.h"
#include "crypto.h"
#include "insert.h"
#include "retvals.h"

/* Handshake with insert */
int handshake(fd) {
        char junk[MAXJUNKSIZE]; /* Initial junk data to wait on */
        char *endptr;
        int junksize; /* Number of junk bytes to read */
        int nread, toread;
        uint8_t nonce[8];
        int ret;
        char installname[INSTALLNAMELEN+1]; /* Install name */
        printf("In handshake()\n"); /* DEBUG */

        /* Work out how much junk to read */
        endptr = NULL;
        if ((0 == (junksize = strtol(JUNKSIZE, &endptr, 0))) &&
                        ('\0' != *endptr)) {
                /* Unable to convert JUNKSIZE */
                return RET_INV_JUNK;
        }

        printf("reading %i bytes of junk\n", junksize); /* DEBUG */
        
        /* Read that much data */
        /* TODO: Time out after N seconds */
        toread = junksize;
        nread = 0;
        while (0 < toread) {
                if (-1 == (nread = (recv(fd, junk, toread, MSG_WAITALL)))) {
                        return RET_ERR_READ;
                }
                toread -= nread;
        }
        printf("Read junk\n");

        /* Make the nonce */
        make_nonce(nonce);

        /* Send the nonce */
        int i;printf("Sending Nonce: ");for(i = 0; i < 8; ++i){printf("%02X ",nonce[i]);}printf("\n");/* DEBUG */
        if (0 > (ret = send_all(fd, nonce, 8))) {
                return ret;
        }

        /* Wait for the install name */

        return 0;
}

/* Send ALL the len bytes starting at b to tofd. */
int send_all(int tofd, uint8_t *b, int len) {
        int nsent; /* Number of bytes sent */
        int nleft; /* Number of bytes left to send */
        int ret;   /* Return code */
        nsent = 0;
        nleft = len;
        ret = -1;
        /* Keep going until all the data's been sent */
        while (nleft) {
                /* Try to send the data */
                if (-1 == (ret = send(tofd, (void*)(b+nsent), nleft,
                                                MSG_NOSIGNAL))) {
                        return RET_ERR_SEND;
                }
                /* Update counts */
                nleft -= ret;
                nsent += ret;
        }

        return 0;
}

/* TODO: recv_all */
