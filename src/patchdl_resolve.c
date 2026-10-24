/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Knutwurst
 *
 * PatchDL is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version. See the LICENSE file in the project root for details.
 */

#include "patchdl_resolve.h"

#include <openssl/hmac.h>
#include <stdio.h>
#include <string.h>

#define DB_PATH "/data/patchdl/db/ps5_xml.tsv"

static int
lookup_tsv(const char *title_id, char *url_out, size_t url_sz) {
    FILE *fp;
    char  line[1024];

    fp = fopen(DB_PATH, "r");
    if (!fp) return -1;

    while (fgets(line, sizeof(line), fp)) {
        char *tab = strchr(line, '\t');
        if (!tab) continue;
        *tab = '\0';
        if (strcmp(line, title_id)) continue;

        char *url = tab + 1;
        size_t len = strlen(url);
        while (len > 0 && (url[len - 1] == '\n' || url[len - 1] == '\r'))
            url[--len] = '\0';
        if (len == 0 || len >= url_sz) {
            fclose(fp);
            return -1;
        }
        /* anyone with /data access can edit the TSV. host_allowed checks
           later too, but drop non-https lines right here */
        if (strncmp(url, "https://", 8) != 0) {
            fclose(fp);
            return -1;
        }
        memcpy(url_out, url, len + 1);
        fclose(fp);
        return 0;
    }
    fclose(fp);
    return -1;
}

/* PS4 ver.xml path is HMAC-SHA256("np_" + title id). public key from the
   PS4 system software, every update checker uses it */
static const unsigned char PS4_UPDATE_KEY[32] = {
    0xAD, 0x62, 0xE3, 0x7F, 0x90, 0x5E, 0x06, 0xBC, 0x19, 0x59, 0x31, 0x42,
    0x28, 0x1C, 0x11, 0x2C, 0xEC, 0x0E, 0x7E, 0xC3, 0xE9, 0x7E, 0xFD, 0xCA,
    0xEF, 0xCD, 0xBA, 0xAF, 0xA6, 0x37, 0x8D, 0x84,
};

static int
ps4_update_url(const char *title_id, char *url_out, size_t url_sz) {
    unsigned char mac[32];
    unsigned int  mac_len = 0;
    char          msg[24], hex[65];
    int           n;

    if (strlen(title_id) != 9) return -1;
    n = snprintf(msg, sizeof msg, "np_%s", title_id);
    if (!HMAC(EVP_sha256(), PS4_UPDATE_KEY, sizeof PS4_UPDATE_KEY,
              (const unsigned char *)msg, (size_t)n, mac, &mac_len) ||
        mac_len != sizeof mac)
        return -1;
    for (unsigned i = 0; i < mac_len; i++)
        snprintf(hex + 2 * i, 3, "%02x", mac[i]);
    n = snprintf(url_out, url_sz,
                 "https://gs-sec.ww.np.dl.playstation.net/plo/np/%s/%s/%s-ver.xml",
                 title_id, hex, title_id);
    return (n > 0 && (size_t)n < url_sz) ? 0 : -1;
}

int
patchdl_resolve_url(const char *title_id, char *url_out, size_t url_sz) {
    if (!title_id) return -1;

    if (!strncmp(title_id, "CUSA", 4))
        return ps4_update_url(title_id, url_out, url_sz);

    if (strncmp(title_id, "PPSA", 4) &&
        strncmp(title_id, "PPSE", 4) &&
        strncmp(title_id, "PPSH", 4) &&
        strncmp(title_id, "PPSJ", 4) &&
        strncmp(title_id, "PPSC", 4))
        return -1;

    return lookup_tsv(title_id, url_out, url_sz);
}
