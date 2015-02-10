/*
 * comm.h
 * Function protoypes related to communications
 * by J. Stuart McMurray
 * created 20150122
 * last modified 20150210
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

#ifndef HAVE_COMM_H
#define HAVE_COMM_H

/* Handshake with insert */
int handshake(int fd);

/* Send ALL the len bytes starting at b to tofd. */
int send_all(int tofd, uint8_t *b, size_t len);

/* Receive len bytes from fmfd int b */
int recv_all(int fmfd, uint8_t *b, size_t len);

/* Encrypt (with txctx) and send the n bytes at b to fd. */
int send_enc(int fd, uint8_t *b, size_t n);

/* Decrypt (with rxctx) n bytes from fd into b. */
int recv_enc(int fd, uint8_t *b, size_t n);

#endif /* HAVE_COMM_H */
