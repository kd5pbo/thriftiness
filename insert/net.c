/*
 * net.h
 * Functions dealing with the network
 * by J. Stuart McMurray
 * created 20150118
 * last modified 20150204
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

#include <sys/socket.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "insert.h"
#include "net.h"
#include "retvals.h"

/* Wait for shift to connect */
int peer_wait(void) {
        int lfd, cfd;                  /* Listen and child file descriptors. */
        struct sockaddr_storage caddr; /* Insert's address */
        socklen_t caddr_size;
        int yes;
        /* Thanks to beej for most of this */
        struct addrinfo hints;
        struct addrinfo *servinfo;
        struct addrinfo *cur;
        memset((void*)&hints, 0, sizeof(hints));
        printf("In peer_wait()\n"); /* DEBUG */
        /* Set flags in hints to only give addresses on interfaces */
        hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICHOST | AI_NUMERICSERV |
                AI_PASSIVE | AI_NUMERICSERV;
        hints.ai_family = PF_UNSPEC; /* The address should provide this */
        hints.ai_socktype = SOCK_STREAM; /* TCP */
        hints.ai_protocol = IPPROTO_TCP; /* TCP */
        /* Get network info */
        if (0 != getaddrinfo(ADDR+1, PORT, &hints, &servinfo)) {
               return RET_ERR_GAI;
        } 
        /* We'll know we've bound if lfd is something other than -1 */
        lfd = -1;
        /* Try to bind to one of the returned results, which ideally should
         * only take one try, unless the port's in use. */
        for (cur = servinfo; NULL != cur; cur = cur->ai_next) {
                /* Make a socket of the appropriate type */
                if (-1 == (lfd = socket(cur->ai_family, cur->ai_socktype,
                                                cur->ai_protocol))) {
                        continue;
                }
                /* Allow the socket to be reused */
                yes = 1;
                if (setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &yes,
                                        sizeof(yes)) == -1) {
                        close(lfd);
                        lfd = -1;
                        continue;
                }
                /* Bind socket to address */
                if (-1 == bind(lfd, cur->ai_addr, cur->ai_addrlen)) {
                        /* If we can't bind, close the FD, try later */
                        perror("bind"); /* DEUBG */
                        close(lfd);
                        lfd = -1;
                        continue;
                }
                /* Try to listen */
                if (-1 == listen(lfd, 0)) { /* Only one client allowed */
                        printf("Listen fail\n"); /* DEBUG */
                        close(lfd);
                        lfd = -1;
                        continue;
                }
        }
        /* Free the memory allocated by getaddrinfo */
        freeaddrinfo(servinfo);

        /* If the file descriptor is still -1, try again later. */
        if (-1 == lfd) {
                return RET_ERR_LIST;
        }
        
        /* Wait for a client */
        caddr_size = (socklen_t)sizeof(caddr);
        printf("Waiting for shift\n"); /* DEBUG */
        if (-1 == (cfd = accept(lfd, (struct sockaddr*)&caddr, &caddr_size))) {
                return RET_ERR_ACC;
        }
        printf("Got shift.\n"); /* DEBUG */
        
        /* Stop listening and return the connected file descriptor */
        close(lfd);
        return cfd;
}

/* Connect to shift */
int peer_call(void) {
        int fd;
        struct addrinfo hints;
        struct addrinfo *servinfo;
        struct addrinfo *cur;
        /* Set flags in hints to only give addresses on interfaces */
        hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICHOST | AI_NUMERICSERV |
                AI_NUMERICSERV;
        hints.ai_family = PF_UNSPEC; /* The address should provide this */
        hints.ai_socktype = SOCK_STREAM; /* TCP */
        hints.ai_protocol = IPPROTO_TCP; /* TCP */
        /* Get network info */
        if (0 != getaddrinfo(ADDR+1, PORT, &hints, &servinfo)) {
               return RET_ERR_GAI;
        } 
        /* Try to connect (adapted from the OpenBSD getaddrinfo(3) man page) */
        fd = -1;
        for (cur = servinfo; NULL != cur; cur = cur->ai_next) {
                /* Attempt to make the proper sort of socket */
                if (-1 == (fd = socket(cur->ai_family, cur->ai_socktype,
                                                cur->ai_protocol))) {
                        continue;
                }
                /* Attempt to connect to shift */
                if (-1 == connect(fd,cur->ai_addr, cur->ai_addrlen)) {
                        close(fd);
                        fd = -1;
                        continue;
                }
                break;
        }
        freeaddrinfo(servinfo);
        /* If we've not connected, fd will be -1 */
        if (-1 == fd) {
                return RET_ERR_CON;
        }
        return fd;
}

/* Set send/receive timeouts on a socket */
int set_txrx_timeouts(int fd) {
        struct timeval t;
        socklen_t optlen;
        /* Timeout after two seconds */
        memset((void*)&t, 0, sizeof(t));
        t.tv_sec = TXRXTO;
        t.tv_usec = 0; /* Should be optimized out */
        optlen = sizeof(t);

        /* Set the timeouts */
        if (-1 == setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &t, optlen)) {
                return RET_ERR_STO;
        }
        if (-1 == setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &t, optlen)) {
                return RET_ERR_STO;
        }
        
        return 0;
}
