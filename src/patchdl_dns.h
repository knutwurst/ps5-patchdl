/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Knutwurst
 *
 * PatchDL is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version. See the LICENSE file in the project root for details.
 */

#pragma once

#include <stddef.h>

/* Own resolver, the console's DNS usually blocks Sony to stop updates.
   Order: UDP, TCP, DoH, then the last good answer saved on disk.
   Private/loopback answers count as blocked, that's what sinkholes send. */

#define PATCHDL_DNS_MAX_IPS 8

typedef struct {
    int  n;
    char ip[PATCHDL_DNS_MAX_IPS][16];
    char source[40];     /* "udp 1.1.1.1", "doh dns.google", "saved" */
    char trail[384];     /* what each step said, last fresh lookup */
} patchdl_dns_answer_t;

/* IPv4 only. good answers cached for minutes, failures for seconds */
int  patchdl_dns_lookup(const char *host, patchdl_dns_answer_t *out);

/* after a refused/stalled connect. a fresh answer is kept anyway, so ten
   failing workers cause one new lookup, not ten */
void patchdl_dns_forget(const char *host);

/* unconditional, for diagnostics */
void patchdl_dns_refresh(const char *host);

/* once per request, spreads connections over the CDN edges */
unsigned patchdl_dns_rotation(void);

/* 255-char host, port and every address */
#define PATCHDL_DNS_ENTRY_MAX (256 + 8 + PATCHDL_DNS_MAX_IPS * 16)

/* "host:port:ip1,ip2,..." for CURLOPT_RESOLVE, starting at rotation % n.
   curl tries the next one if an address doesn't connect */
int  patchdl_dns_resolve_entry(const patchdl_dns_answer_t *a, const char *host,
                               int port, unsigned rotation, char *out, size_t sz);
