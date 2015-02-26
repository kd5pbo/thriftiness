/*
 * tx.h
 * Code for thread to send data to insert
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

#ifndef HAVE_TX_H
#define HAVE_TX_H

#include <pcap.h>

/* Struct to pass data to insert_to_shift */
struct its_data {
        pcap_t *p; /* Pcap handle */
        int fd;    /* File Descriptor for shift */
};

/* Data to pass to handle_packet */
struct handle_data {
        pcap_t *p; /* Pcap handle */
        int fd;    /* File descriptor for shift */
        int *ret;  /* Return value from failed packet handle */
};

/* Mutex to prevent multiple sends */
extern pthread_mutex_t txmutex;

/* Get data from pcap, send to shift */
extern void *insert_to_shift(void *data);

/* Callback function for pcap_loop */
extern void handle_packet(u_char *user, const struct pcap_pkthdr *header,
        const u_char *data);

#endif /* HAVE_TX_H */
