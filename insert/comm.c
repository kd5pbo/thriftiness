/*
 * comm.c
 * Functions related to communications
 * by J. Stuart McMurray
 * created 20150122
 * last modified 20150211
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
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "comm.h"
#include "crypto.h"
#include "insert.h"
#include "retvals.h"

/* Handshake with insert */
int handshake(fd) {
        uint8_t junk[MAXJUNKSIZE];      /* Initial junk data to wait on */
        char *endptr;                   /* Used in strtol */
        int junksize;                   /* Number of junk bytes to read */
        uint8_t nonce[8];               /* Nonce for this connection */
        int ret;                        /* Return value */
        uint8_t rxname[INSTALLNAMELEN]; /* Received install name */


        /* Work out how much junk to read */
        endptr = NULL;
        if ((0 == (junksize = strtol(JUNKSIZE, &endptr, 0))) &&
                        ('\0' != *endptr)) {
                /* Unable to convert JUNKSIZE */
                return RET_INV_JUNK;
        }
        if (0 > junksize) {
                return RET_INV_JUNK;
        }


        /* Read that much data */
        if (0 != recv_all(fd, junk, junksize)) {
                return RET_ERR_JUNK;
        }

        /* Make the nonce */
        make_nonce(nonce);

        /* Send the nonce */
        if (0 != (ret = send_all(fd, nonce, 8))) {
                return RET_ERR_NONCE;
        }

        /* Initialize the crypto streams for this connection. */
        streams_init(nonce);

        /* Wait for the install name */
        memset(rxname, 0, sizeof(rxname));
        if (0 != recv_enc(fd, rxname, INSTALLNAMELEN)) {
                return RET_ERR_RIN;
        }

        /* Make sure it's what we expect */
        if (0 != (ret = constcmp(rxname, installname, INSTALLNAMELEN))) {
                return RET_INV_RIN;
        }

        /* Send it back */
        if (0 != send_enc(fd, rxname, INSTALLNAMELEN)) {
                return RET_ERR_SIN;
        }

        return 0;
}

/* Send ALL the len bytes starting at b to tofd. */
int send_all(int tofd, uint8_t *b, size_t len) {
        int nsent; /* Number of bytes sent */
        int nleft; /* Number of bytes left to send */
        int ret;   /* Return code */
        nsent = 0;
        nleft = len;
        ret = -1;
        /* Keep going until all the data's been sent */
        while (0 < nleft) {
                /* Try to send the data */
                if (-1 == (ret = send(tofd, (void*)(b+nsent), nleft,
                                                MSG_NOSIGNAL))) {
                        return RET_ERR_SEND;
                } else if (0 == ret) { /* DISCONNECT */
                        return RET_DISCON;
                }
                /* Update counts */
                nleft -= ret;
                nsent += ret;
        }

        return 0;
}

/* Receive len bytes from fmfd int b */
int recv_all(int fmfd, uint8_t *b, size_t len) {
        int nread; /* Number of bytes read */
        int nleft; /* Number of bytes left to read */
        int ret;
        nread = 0;
        nleft = len;
        ret = -1;
        /* Read bytes until we've got enough */
        while (0 < nleft) {
                if (-1 == (ret = recv(fmfd, (void*)(b+nread), nleft,
                                                MSG_WAITALL))) {

                        return RET_ERR_RECV;
                } else if (0 == ret) { /* DISCONNECT */
                        return RET_DISCON;
                }
                        
                nleft -= ret;
                nread += ret;
        }
        return 0;
}

/* TODO: Work out why reads are non-blocking */

/* Encrypt (with txctx) and send the n bytes at b to fd. */
int send_enc(int fd, uint8_t *b, size_t n) {
        uint8_t *ebuf; /* Buffer for encrypted data */
        int ret;       /* Return value */

        /* Allocate buffer */
        ebuf = calloc(n, sizeof(uint8_t));
        /* Make a copy of the data */
        memcpy(ebuf, b, n);
        /* Encrypt the buffer */
        txencrypt(ebuf, n);
        /* Send it */
        ret = send_all(fd, ebuf, n);
        free(ebuf);
        return ret;
}

/* Decrypt (with rxctx) n bytes from fd into b. */
int recv_enc(int fd, uint8_t *b, size_t n) {
        int ret; /* Return value */

        /* Zero the buffer */
        memset(b, 0, n);
        /* Receive data into it */
        if (0 != (ret = recv_all(fd, b, n))) {
                return ret;
        }
        /* Decrypt the data */
        rxdecrypt(b, n);
        return 0;
}
