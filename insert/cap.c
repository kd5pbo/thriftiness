/*
 * cap.c
 * pcap initialization functions
 * by J. Stuart McMurray
 * created 20150220
 * last modified 20150222
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

#include <pcap.h>
#include <string.h>

#include "insert.h"
#include "retvals.h"

/* pcap_setup initializes (and starts) pcap, but doesn't start it */
int pcap_setup(pcap_t **pret) {
        struct bpf_program fp; /* BPF filter */
        pcap_t *p;

        *pret = NULL;
        p = NULL;
        memset(&fp, 0, sizeof(fp));

        /* Try to open the interface */
        if (NULL == (p = pcap_open_live(PCAPINT, SNAPLEN, 0, -1, NULL))) {
                return RET_ERR_PINIT;
        }

        /* Compile the BPF filter */
        if (0 != pcap_compile(p, &fp, PCAPFILT, 1, 0)) {
                return RET_ERR_BFC;
        }

        /* Set the BPF filter */
        if (0 != pcap_setfilter(p, &fp)) {
                return RET_ERR_BFS;
        }

        /* Free the momery allocated by pcap_compile */
        pcap_freecode(&fp);

        /* Returned value */
        *pret = p;

        return 0;
}
