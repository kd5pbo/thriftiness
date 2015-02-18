/*
 * crypto.c
 * Functions related to encryption/decryption
 * by J. Stuart McMurray
 * created 20150122
 * last modified 20150213
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "chacha20_simple.h"
#include "crypto.h"
#include "insert.h"
#include "retvals.h"

int random_seeded = 0; /* Nonzero after seed_random() */
int noncestream_init_done = 0; /* Nonzero after noncestream_init() */
uint64_t nonce_ctr = 0; /* Number of nonces sent */
chacha20_ctx txctx; /* Send crypto stream */
chacha20_ctx rxctx; /* Receive crypto stream */

/* Seed the random number generator.  This is probably one of those things that
 * needs to be made more secure.  */
void seed_random() {
        pid_t pid;
        int i;
        long r;
        /* Don't seed twice */
        if (random_seeded) {
                return;
        }
        /* First seed random with the time. */
        srandom(time(NULL));
        /* To avoid two inserts started at the same time having the same seed
         * reseed with the pid+1'th random number */
        pid = getpid();
        for (i = 0; i < pid; ++i) {
                r = random();
                /* This should always fail, but keep the above call from being
                 * optimized away. */
                if (NULL == &r) {
                        printf("%li", r);
                }
        }
        /* Re-seed the random number generator with a random value */
        srandom(random());
        random_seeded = 1;

        /* Surely there's a better way to do this */
}


/* Initialize the stream used to send nonces.  This should be called fairly
 * early on in main(). */
void noncestream_init() {
        uint8_t nonce_arr[8];
        int i;
        printf("In noncestream_init()\n"); /* DEBUG */


        /* Don't do this twice */
        if (noncestream_init_done) {
                return;
        }

        /* Seed the random number generator */
        seed_random();

        /* Eight bytes to use as the nonce */
        for (i = 0; i < 8; ++i) {
                /* If random() gives us more than a byte, use the upper one */
                if (1 < sizeof(random())) {
                        nonce_arr[i] = (random() >> 8) & 0xFF;
                } else { /* If not, just use the one byte */
                        nonce_arr[i] = random() & 0xFF;
                }
        }

        /* Zero the nonce context and the key bytes */
        memset((void*)&noncectx, 0, sizeof(noncectx));

        /* Set up stream */
        chacha20_setup(&noncectx, key, KEYLEN, nonce_arr);
        noncestream_init_done = 1;

        return;
}

/* Get the next nonce */
void make_nonce(uint8_t nonce[8]) {
        ++nonce_ctr;

        /* Make sure the nonce stream has been initialized */
        if (0 == noncestream_init_done) {
                noncestream_init();
        }

        /* Encrypt the number of connection attempts */
        chacha20_encrypt(&noncectx, (uint8_t*)&nonce_ctr, nonce, 8);
        return;
}

/* Initialize the two crypto streams.  I hope a lot of this gets optimized. */
void streams_init(uint8_t nonce[8]) {
        time_t now;             /* Time now */
        uint64_t now8;          /* 8 bytes of time */
        uint8_t timed_nonce[8]; /* Nonce xored with time */
        int i;

        /* Zero the contexts */
        memset(&txctx, 0, sizeof(txctx));
        memset(&rxctx, 0, sizeof(rxctx));

        /* Get the current time */
        now = time(NULL);

        /* Make it 8 bytes */
        now8 = 0x000000000000 | now;

        /* Make a copy of the nonce with the time xored in */
        printf("Timed nonce: "); /* DEBUG */
        for (i = 0; i < 8; ++i) {
                timed_nonce[i] = nonce[i] ^ ((now8 >> (8 * i)) & 0xFF);
                printf("[%02X^%02X->%02X]", nonce[i], (uint8_t)((now8 >> (8*i)) & 0xFF), timed_nonce[i]); /* DEBUG */
        }
        printf("\n"); /* DEBUG */

        /* Make the two keystreams */
        timed_nonce[0] &= 0xFC;
        printf("SIN: ");for (i = 0; i < 8; ++i){printf("%02X",timed_nonce[i]);}printf("\n");
        chacha20_setup(&rxctx, key, KEYLEN, timed_nonce);
        timed_nonce[0] |= 0x03;
        printf("ISN: ");for (i = 0; i < 8; ++i){printf("%02X",timed_nonce[i]);}printf("\n");
        printf("ISK: ");for (i = 0; i < KEYLEN; ++i){printf("%02X",key[i]);}printf("\n");
        chacha20_setup(&txctx, key, KEYLEN, timed_nonce);
}

/* Encrypt n bytes at b with txctx for sending. */
void txencrypt(uint8_t *b, size_t n) {
        chacha20_encrypt(&txctx, b, b, n);
}

/* Decrypt n (received) bytes at b with rxctx. */
void rxdecrypt(uint8_t *b, size_t n) {
        chacha20_decrypt(&rxctx, b, b, n);
}

/* Compare the n bytes at a with the n bytes at b in constant time.  Returns 0
 * if the two sets of bytes are equal. */
int constcmp(uint8_t *a, uint8_t *b, int n) {
        int ret;
        int i;
        ret = 0;
        for (i = 0; i < n; ++i) {
                ret |= a[i] ^ b[i];
        }
        return ret;
}
