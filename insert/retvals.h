/*
 * retvals.h
 * Return values for insert.c
 * by J. Stuart McMurray
 * created 20150117
 * last modified 20150126
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

#ifndef HAVE_RETVALS_H
#define HAVE_RETVALS_H

/* These values may be put in the SYS environment variable on error */
#define CANNOT_SPRINT_SYS "00" /* Can't to make a string to which to set SYS */

/* These values will be returned to the shell (i.e. $?) or put in the SYS (or
 * another defined) environment variable on fatal errors */
#define RET_UNK_ACT    -1 /* Unknown action, not c (callxx) or w (waitxx) */
#define RET_INV_SLEEP  -2 /* Unable to parse SLEEPSEC */
#define RET_UNK_IPV    -3 /* Cannot guess whether ADDR is IPv4 or IPv6 */
#define RET_ENOMEM     -4 /* Unable to allocate memory */
#define RET_ERR_GAI    -5 /* getaddressinfo(3) failed with HOST and PORT */
#define RET_ERR_LIST   -6 /* Couldn't make a listening socket */
#define RET_ERR_ACC    -7 /* Error accepting connection */
#define RET_ERR_CON    -8 /* Error connecting */
#define RET_INV_JUNK   -9 /* Invalid JUNKSIZE */
#define RET_ERR_READ  -10 /* Error during a read(2) from the network */
#define RET_INV_TIME  -11 /* Could not get time from time(3) */
#define EX_KEY_LONG   -12 /* KEY is too long */
#define RET_ERR_SEND  -13 /* Error sending ALL the data */
#define RET_ERR_STO   -14 /* Unable to set socket send/receive timeouts */


#endif /* #ifndef HAVE_RETVALS_H */
