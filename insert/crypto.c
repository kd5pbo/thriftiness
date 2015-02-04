/*
 * crypto.c
 * Functions related to encryption/decryption
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
        uint8_t key[KEYMAX];
        int keymax_plus_one;
        int keylen;
        int i;
        printf("In noncestream_init()\n"); /* DEBUG */

        /* Make sure key is shorter than keymax */
        keymax_plus_one = KEYMAX + 1;
        keylen = strnlen(KEY, keymax_plus_one);
        if (keylen > KEYMAX) {
                exit(EX_KEY_LONG);
        }

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
        memset((void*)key, 0, sizeof(key));

        /* Copy key bytes */
        for (i = 0; i < keylen; ++i) {
                key[i] = KEY[i];
        }

        /* Set up stream */
        chacha20_setup(&noncectx, key, keylen, nonce_arr);
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
