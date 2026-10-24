/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Knutwurst
 *
 * PatchDL is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version. See the LICENSE file in the project root for details.
 */

#include "patchdl_net.h"
#include "patchdl_dns.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#ifdef PATCHDL_HAVE_CURL
#include <curl/curl.h>
#include <openssl/evp.h>
#include "patchdl_ca.h"
#endif

/* manifest sanity caps. biggest real one I've seen: ~70 GB in 18 pieces */
#define PATCHDL_MAX_PIECES         4096
#define PATCHDL_MAX_PIECE_BYTES    (8ULL  * 1024 * 1024 * 1024)
#define PATCHDL_MAX_TOTAL_BYTES    (200ULL * 1024 * 1024 * 1024)

/* RAM caps for whole-body fetches. version.xml is a few KB, real
   manifests 1-2 MB */
#define PATCHDL_BUF_MAX_VERXML     (4   * 1024 * 1024)
#define PATCHDL_BUF_MAX_MANIFEST   (16  * 1024 * 1024)

#ifdef PATCHDL_HAVE_CURL
/* fopen without following symlinks, a planted link could redirect the
   download. new files get 0600 */
static FILE *
fopen_safe(const char *path, int rw_existing) {
    int flags = O_CLOEXEC | O_NOFOLLOW;
    int fd;
    flags |= rw_existing ? O_RDWR : (O_WRONLY | O_CREAT | O_TRUNC);
    FILE *fp;
    fd = open(path, flags, 0600);
    if (fd < 0) return NULL;
    if (!(fp = fdopen(fd, rw_existing ? "r+b" : "wb"))) close(fd);
    return fp;
}
#endif

#ifdef PATCHDL_HAVE_CURL

static const char *ALLOWED_HOSTS[] = {
    "sgst.prod.dl.playstation.net",
    "gst.prod.dl.playstation.net",
    "gs2.ww.prod.dl.playstation.net",
    "gs-sec.ww.np.dl.playstation.net",   /* PS4 update lists */
    NULL,
};

/* PS4 manifests only exist over plain http on gs2 (its https is CloudFront
   without Sony's cert). the installer checks the pkg signature anyway */
#define PLAIN_HTTP_HOST "gs2.ww.prod.dl.playstation.net"

static int
host_allowed(const char *host) {
    size_t hlen = strlen(host);
    /* case-insensitive, a redirect to "SGST.prod..." is still Sony */
    for (int i = 0; ALLOWED_HOSTS[i]; i++) {
        if (!strcasecmp(host, ALLOWED_HOSTS[i]))
            return 1;
        size_t alen = strlen(ALLOWED_HOSTS[i]);
        if (hlen > alen + 1 &&
            host[hlen - alen - 1] == '.' &&
            !strcasecmp(host + hlen - alen, ALLOWED_HOSTS[i]))
            return 1;
    }
    return 0;
}

static _Thread_local struct {
    char step[24];
    int  curl_rc;
    long http_code;
} g_last;

static void
set_last(const char *step, int curl_rc, long http_code) {
    snprintf(g_last.step, sizeof g_last.step, "%s", step);
    g_last.curl_rc   = curl_rc;
    g_last.http_code = http_code;
}

/* CURLOPT_RESOLVE for 443 and 80 from PatchDL's resolver, curl never asks
   the console's DNS */
static struct curl_slist *
resolve_list_for(const char *host) {
    patchdl_dns_answer_t a;
    char                 entry[PATCHDL_DNS_ENTRY_MAX];
    struct curl_slist   *rl, *both;
    unsigned             turn = patchdl_dns_rotation();

    if (patchdl_dns_lookup(host, &a) ||
        patchdl_dns_resolve_entry(&a, host, 443, turn, entry, sizeof entry) ||
        !(rl = curl_slist_append(NULL, entry)))
        return NULL;
    if (patchdl_dns_resolve_entry(&a, host, 80, turn, entry, sizeof entry) ||
        !(both = curl_slist_append(rl, entry))) {
        curl_slist_free_all(rl);
        return NULL;
    }
    return both;
}

/* dead or stalled edge: ask DNS again, a fresh answer usually names
   other edges */
static void
note_curl_result(const char *host, CURLcode res) {
    if (res == CURLE_COULDNT_CONNECT || res == CURLE_COULDNT_RESOLVE_HOST ||
        res == CURLE_OPERATION_TIMEDOUT || res == CURLE_RECV_ERROR ||
        res == CURLE_SEND_ERROR || res == CURLE_GOT_NOTHING)
        patchdl_dns_forget(host);
}

void
patchdl_http_last_error(char *step, size_t step_sz, int *curl_rc, long *http_code) {
    if (step && step_sz) snprintf(step, step_sz, "%s", g_last.step);
    if (curl_rc) *curl_rc = g_last.curl_rc;
    if (http_code) *http_code = g_last.http_code;
}

/* PS5 manifests use SHA-256, PS4 ones SHA-1 (40 hex digits) */
static const EVP_MD *
digest_for(const char *hex) {
    return (hex && strlen(hex) == 40) ? EVP_sha1() : EVP_sha256();
}

static int
url_host(const char *url, char *out, size_t out_sz) {
    const char *p = strstr(url, "://");
    const char *end;
    size_t len;

    if (!p) return -1;
    p += 3;
    end = strpbrk(p, "/:?");
    len = end ? (size_t)(end - p) : strlen(p);
    if (len == 0 || len >= out_sz) return -1;
    memcpy(out, p, len);
    out[len] = '\0';
    return 0;
}

/* the default 64 KB rcvbuf caps a connection at ~11 MB/s. asking for 4 MB
   gets the system max (512 KB) and ~45 MB/s */
#define PATCHDL_RCVBUF_BYTES (4 * 1024 * 1024)

static int
sockopt_rcvbuf_cb(void *clientp, curl_socket_t fd, curlsocktype purpose) {
    int sz = PATCHDL_RCVBUF_BYTES;
    (void)clientp;
    if (purpose == CURLSOCKTYPE_IPCXN)
        (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof sz);
    return CURL_SOCKOPT_OK;
}

static size_t
write_cb(void *ptr, size_t size, size_t nmemb, void *userdata) {
    patchdl_buf_t *b     = userdata;
    size_t         total = size * nmemb;
    char          *newp;
    /* size + total can wrap on 32-bit */
    if (total > (size_t)-1 - b->size - 1) return 0;
    /* hostile server can't eat all the RAM */
    if (b->max && b->size + total > b->max) return 0;
    newp = realloc(b->data, b->size + total + 1);
    if (!newp) return 0;
    b->data = newp;
    memcpy(b->data + b->size, ptr, total);
    b->size += total;
    b->data[b->size] = '\0';
    return total;
}

static int http_get_once(const char *url, patchdl_buf_t *out);

int
patchdl_http_get(const char *url, patchdl_buf_t *out) {
    return http_get_once(url, out);
}

/* manifests only: network errors get two more tries on other edges.
   update lists don't retry, the background check would crawl */
static int
http_get_retrying(const char *url, patchdl_buf_t *out) {
    static const unsigned pause_s[] = { 2, 5 };
    size_t                max = out->max;
    int                   rc = -1;

    for (int attempt = 0; attempt < 3; attempt++) {
        if (attempt) {
            if (strcmp(g_last.step, "connect") && strcmp(g_last.step, "timeout") &&
                strcmp(g_last.step, "network"))
                break;
            sleep(pause_s[attempt - 1]);
            memset(out, 0, sizeof *out);
            out->max = max;
        }
        if (!(rc = http_get_once(url, out))) break;
    }
    return rc;
}

static int
http_get_once(const char *url, patchdl_buf_t *out) {
    CURL             *curl;
    CURLcode          res;
    char              host[256];
    struct curl_slist *resolve_list = NULL;
    struct curl_blob  ca_blob;

    int plain = !strncmp(url, "http://", 7);
    long http_code = 0;

    set_last("", 0, 0);
    if (url_host(url, host, sizeof(host))) { set_last("bad_url", 0, 0); return -1; }
    if (!host_allowed(host)) { set_last("host_not_allowed", 0, 0); return -1; }
    if (plain && strcasecmp(host, PLAIN_HTTP_HOST)) { set_last("http_not_allowed", 0, 0); return -1; }
    if (!(resolve_list = resolve_list_for(host))) { set_last("dns", 0, 0); return -1; }

    {
        size_t caller_max = out->max;
        memset(out, 0, sizeof(*out));
        out->max = caller_max;
    }

    curl = curl_easy_init();
    if (!curl) { curl_slist_free_all(resolve_list); return -1; }

    /* trust only the embedded SCEI root */
    ca_blob.data  = (void *)PATCHDL_SCEI_DNAS_ROOT_PEM;
    ca_blob.len   = strlen(PATCHDL_SCEI_DNAS_ROOT_PEM);
    ca_blob.flags = CURL_BLOB_COPY;

    curl_easy_setopt(curl, CURLOPT_URL,             url);
    curl_easy_setopt(curl, CURLOPT_RESOLVE,         resolve_list);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,   write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,       out);
    curl_easy_setopt(curl, CURLOPT_CAINFO_BLOB,     &ca_blob);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER,  1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST,  2L);
    /* some edges still serve SHA-1 signed certs. in 2026. OpenSSL 3 refuses
       them at the default level, the chain is still checked against the root */
    curl_easy_setopt(curl, CURLOPT_SSL_CIPHER_LIST, "DEFAULT@SECLEVEL=0");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,         15L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION,  1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS,       3L);
    /* redirects stay on https, plain http only for PLAIN_HTTP_HOST */
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR,       plain ? "http" : "https");
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL,        1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT,       "patchdl/1.0");

    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    note_curl_result(host, res);
    curl_easy_cleanup(curl);
    curl_slist_free_all(resolve_list);

    if (res != CURLE_OK) {
        /* http_get_retrying retries connect, timeout and network */
        set_last(res == CURLE_COULDNT_CONNECT ? "connect" :
                 res == CURLE_PEER_FAILED_VERIFICATION ||
                 res == CURLE_SSL_CONNECT_ERROR ? "tls"
                 : res == CURLE_UNSUPPORTED_PROTOCOL ||
                   res == CURLE_TOO_MANY_REDIRECTS ? "redirect"
                 : res == CURLE_WRITE_ERROR ? "bad_manifest"   /* over the size cap */
                 : res == CURLE_OPERATION_TIMEDOUT ? "timeout" : "network",
                 (int)res, http_code);
        free(out->data);
        out->data = NULL;
        out->size = 0;
        return -1;
    }
    set_last(http_code >= 400 ? "http_status" : "", 0, http_code);
    return 0;
}

static int
http_external(const char *url, const char *method,
              const char *content_type, const char *body,
              patchdl_buf_t *out) {
#ifndef PATCHDL_HAVE_CURL
    (void)url; (void)method; (void)content_type; (void)body; (void)out;
    return -1;
#else
    CURL             *curl;
    CURLcode          res;
    char              host[256];
    struct curl_slist *resolve_list = NULL;
    struct curl_slist *headers      = NULL;

    if (url_host(url, host, sizeof(host))) return -1;
    if (!(resolve_list = resolve_list_for(host))) return -1;

    {
        size_t caller_max = out->max;
        memset(out, 0, sizeof(*out));
        out->max = caller_max;
    }

    curl = curl_easy_init();
    if (!curl) { curl_slist_free_all(resolve_list); return -1; }

    curl_easy_setopt(curl, CURLOPT_URL,             url);
    curl_easy_setopt(curl, CURLOPT_RESOLVE,         resolve_list);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,   write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,       out);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER,  0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST,  0L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT,         10L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION,  1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS,       3L);
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR,       "https");
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "https");
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL,        1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT,
                     "Mozilla/5.0 (PlayStation; PatchDL)");

    if (body) {
        if (content_type) {
            char ct[256];
            snprintf(ct, sizeof(ct), "Content-Type: %s", content_type);
            headers = curl_slist_append(headers, ct);
        }
        headers = curl_slist_append(headers, "Accept: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    }

    res = curl_easy_perform(curl);
    note_curl_result(host, res);
    curl_easy_cleanup(curl);
    curl_slist_free_all(resolve_list);
    curl_slist_free_all(headers);

    if (res != CURLE_OK) {
        free(out->data);
        out->data = NULL;
        out->size = 0;
        return -1;
    }
    return 0;
#endif
}

int
patchdl_http_get_external(const char *url, patchdl_buf_t *out) {
    return http_external(url, "GET", NULL, NULL, out);
}

int
patchdl_http_post_external(const char *url, const char *content_type,
                           const char *body, patchdl_buf_t *out) {
    return http_external(url, "POST", content_type, body, out);
}

/* file plus running hash when verifying */
typedef struct {
    FILE       *fp;
    EVP_MD_CTX *md;
} write_sink_t;

static size_t
file_write_cb(void *ptr, size_t size, size_t nmemb, void *userdata) {
    write_sink_t *s = (write_sink_t *)userdata;
    size_t written = fwrite(ptr, size, nmemb, s->fp);
    if (s->md && written)
        EVP_DigestUpdate(s->md, ptr, written * size);
    return written;
}

static void
hex_encode(const unsigned char *d, unsigned int len, char *out, size_t out_sz) {
    static const char hexd[] = "0123456789abcdef";
    unsigned int i;
    for (i = 0; i < len && (2u * i + 2u) < out_sz; i++) {
        out[2 * i]     = hexd[(d[i] >> 4) & 0xf];
        out[2 * i + 1] = hexd[d[i] & 0xf];
    }
    out[2 * i] = '\0';
}

typedef struct {
    patchdl_download_progress_cb cb;
    void *ctx;
    long long base;
    long long total;
} progress_state_t;

static int
curl_progress_cb(void *clientp, curl_off_t dltotal, curl_off_t dlnow,
                 curl_off_t ultotal, curl_off_t ulnow) {
    progress_state_t *p = (progress_state_t *)clientp;
    long long total;

    (void)ultotal;
    (void)ulnow;
    if (!p || !p->cb) return 0;

    total = p->total > 0 ? p->total : (long long)dltotal;
    /* non-zero aborts the transfer, that's how cancel works */
    return p->cb(p->ctx, p->base + (long long)dlnow, total);
}

/* -2 hash mismatch, -3 range ignored (no 206). with range_start > 0 the
   body is appended at the current position and can't be verified */
static int
http_download_to_file_progress(const char *url, FILE *fp, long long *bytes_out,
                               progress_state_t *progress,
                               const char *expected_sha256_hex,
                               long long range_start) {
    CURL             *curl;
    CURLcode          res;
    char              host[256];
    char              range_hdr[48];
    long              http_code = 0;
    struct curl_slist *rl = NULL;
    struct curl_blob  ca_blob;
    curl_off_t        dl = 0;
    write_sink_t      sink = { fp, NULL };
    int               verify = (expected_sha256_hex && expected_sha256_hex[0]);

    if (bytes_out) *bytes_out = 0;
    if (url_host(url, host, sizeof(host))) return -1;
    if (!host_allowed(host)) return -1;
    if (!(rl = resolve_list_for(host))) return -1;

    if (verify) {
        sink.md = EVP_MD_CTX_new();
        if (!sink.md) { curl_slist_free_all(rl); return -1; }   /* never skip a requested check */
        EVP_DigestInit_ex(sink.md, digest_for(expected_sha256_hex), NULL);
    }

    ca_blob.data  = (void *)PATCHDL_SCEI_DNAS_ROOT_PEM;
    ca_blob.len   = strlen(PATCHDL_SCEI_DNAS_ROOT_PEM);
    ca_blob.flags = CURL_BLOB_COPY;

    curl = curl_easy_init();
    if (!curl) {
        curl_slist_free_all(rl);
        if (sink.md) EVP_MD_CTX_free(sink.md);
        return -1;
    }

    curl_easy_setopt(curl, CURLOPT_URL,             url);
    curl_easy_setopt(curl, CURLOPT_RESOLVE,         rl);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,   file_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,       &sink);
    curl_easy_setopt(curl, CURLOPT_CAINFO_BLOB,     &ca_blob);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER,  1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST,  2L);
    curl_easy_setopt(curl, CURLOPT_SSL_CIPHER_LIST, "DEFAULT@SECLEVEL=0");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION,  1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS,       5L);
    /* no https pin on redirects here, the CDN sometimes 302s a piece to a
       signed http:// URL. NOSIGNAL keeps a RST from SIGPIPEing the worker */
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL,        1L);
    /* a 404 page makes a lousy patch */
    curl_easy_setopt(curl, CURLOPT_FAILONERROR,     1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT,  20L);
    /* no total timeout, only stalls abort */
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 1024L);
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME,  30L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT,       "patchdl/1.0");
    curl_easy_setopt(curl, CURLOPT_SOCKOPTFUNCTION, sockopt_rcvbuf_cb);
    if (range_start > 0) {
        snprintf(range_hdr, sizeof(range_hdr), "%lld-", range_start);
        curl_easy_setopt(curl, CURLOPT_RANGE, range_hdr);
    }
    if (progress && progress->cb) {
        curl_easy_setopt(curl, CURLOPT_NOPROGRESS,       0L);
        curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, curl_progress_cb);
        curl_easy_setopt(curl, CURLOPT_XFERINFODATA,     progress);
    }

    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_getinfo(curl, CURLINFO_SIZE_DOWNLOAD_T, &dl);
    note_curl_result(host, res);
    curl_easy_cleanup(curl);
    curl_slist_free_all(rl);

    if (res != CURLE_OK) {
        if (sink.md) EVP_MD_CTX_free(sink.md);
        return -1;
    }
    if (range_start > 0 && http_code != 206) {
        if (sink.md) EVP_MD_CTX_free(sink.md);
        return -3;
    }

    if (sink.md) {
        unsigned char dig[EVP_MAX_MD_SIZE];
        unsigned int  dlen = 0;
        char          hex[2 * EVP_MAX_MD_SIZE + 1];
        int           ok = EVP_DigestFinal_ex(sink.md, dig, &dlen);
        EVP_MD_CTX_free(sink.md);
        if (ok != 1 || dlen == 0) return -2;
        hex_encode(dig, dlen, hex, sizeof(hex));
        if (strcasecmp(hex, expected_sha256_hex) != 0)
            return -2;
    }

    if (bytes_out) *bytes_out = (long long)dl;
    return 0;
}

int
patchdl_http_download_progress(const char *url, const char *dest_path,
                               long long *bytes_out,
                               patchdl_download_progress_cb cb, void *ctx) {
    FILE *fp = fopen_safe(dest_path, 0);
    progress_state_t progress = { cb, ctx, 0, 0 };
    int rc;

    if (!fp) return -1;
    rc = http_download_to_file_progress(url, fp, bytes_out, &progress, NULL, 0);
    if (fclose(fp) != 0 && !rc) rc = -1;   /* last flush, disk full */

    if (rc) {
        unlink(dest_path);
        return -1;
    }
    return 0;
}

int
patchdl_http_download(const char *url, const char *dest_path,
                      long long *bytes_out) {
    return patchdl_http_download_progress(url, dest_path, bytes_out, NULL, NULL);
}

/* NULL limit: search to the end */
static const char *
strstr_bounded(const char *p, const char *needle, const char *limit) {
    const char *hit = strstr(p, needle);
    if (!hit) return NULL;
    if (limit && hit >= limit) return NULL;
    return hit;
}

/* minimal "key": "value" reader, enough for manifests. \u escapes are
   not decoded */
static int
json_string_after(const char *p, const char *key, char *out, size_t out_sz,
                  const char *limit) {
    char needle[48];
    const char *q;
    size_t n = 0;

    if (!p || !out || out_sz == 0) return -1;
    out[0] = '\0';
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    q = strstr_bounded(p, needle, limit);
    if (!q) return -1;
    q += strlen(needle);
    while ((!limit || q < limit) &&
           (*q == ' ' || *q == '\t' || *q == '\r' || *q == '\n')) q++;
    if (limit && q >= limit) return -1;
    if (*q++ != ':') return -1;
    while ((!limit || q < limit) &&
           (*q == ' ' || *q == '\t' || *q == '\r' || *q == '\n')) q++;
    if (limit && q >= limit) return -1;
    if (*q++ != '"') return -1;

    while ((!limit || q < limit) && *q && *q != '"' && n + 1 < out_sz) {
        if (*q == '\\' && q[1] && (!limit || q + 1 < limit)) {
            q++;
            switch (*q) {
            case '"':  out[n++] = '"';  break;
            case '\\': out[n++] = '\\'; break;
            case '/':  out[n++] = '/';  break;
            case 'n':  out[n++] = '\n'; break;
            case 'r':  out[n++] = '\r'; break;
            case 't':  out[n++] = '\t'; break;
            case 'b':  out[n++] = '\b'; break;
            case 'f':  out[n++] = '\f'; break;
            default:   out[n++] = *q;   break;
            }
            q++;
        } else {
            out[n++] = *q++;
        }
    }
    out[n] = '\0';
    return n ? 0 : -1;
}

static int
json_u64_after(const char *p, const char *key, unsigned long long *out,
               const char *limit) {
    char needle[48];
    const char *q;

    if (!p || !out) return -1;
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    q = strstr_bounded(p, needle, limit);
    if (!q) return -1;
    q += strlen(needle);
    while ((!limit || q < limit) &&
           (*q == ' ' || *q == '\t' || *q == '\r' || *q == '\n')) q++;
    if (limit && q >= limit) return -1;
    if (*q++ != ':') return -1;
    while ((!limit || q < limit) &&
           (*q == ' ' || *q == '\t' || *q == '\r' || *q == '\n')) q++;
    if (limit && q >= limit) return -1;
    if (*q < '0' || *q > '9') return -1;
    *out = strtoull(q, NULL, 10);
    return 0;
}

int
patchdl_http_download_manifest_progress(const char *manifest_url,
                                        const char *dest_path,
                                        long long *bytes_out,
                                        patchdl_download_progress_cb cb,
                                        void *ctx, int verify, int resume) {
    patchdl_buf_t manifest;
    const char *pieces, *pieces_end, *p;
    FILE *fp = NULL;
    long long total = 0, have = 0;
    unsigned long long manifest_total = 0;
    int count = 0, started, rc = -1;

    if (bytes_out) *bytes_out = 0;
    memset(&manifest, 0, sizeof(manifest));
    manifest.max = PATCHDL_BUF_MAX_MANIFEST;
    if (patchdl_http_get(manifest_url, &manifest))
        return -1;
    if (!manifest.data || !manifest.size) {
        free(manifest.data);
        return -1;
    }

    pieces = strstr(manifest.data, "\"pieces\"");
    if (!pieces || !(pieces = strchr(pieces, '['))) {
        free(manifest.data);
        return -1;
    }
    /* stop at the end of "pieces", a later "url" key isn't a piece */
    pieces_end = strchr(pieces, ']');
    json_u64_after(manifest.data, "originalFileSize", &manifest_total, NULL);

    /* resume: skip complete pieces, continue the half one with a range */
    if (resume) {
        fp = fopen_safe(dest_path, 1);
        if (fp) { fseek(fp, 0, SEEK_END); have = ftell(fp); if (have < 0) have = 0; }
    }
    if (!fp) { fp = fopen_safe(dest_path, 0); have = 0; }
    if (!fp) { free(manifest.data); return -1; }
    started = (have <= 0);

    p = pieces;
    while ((p = strstr(p, "\"url\"")) && (!pieces_end || p < pieces_end)) {
        char url[768];
        char hash[80] = {0};
        long long got = 0, range_start = 0;
        unsigned long long expected = 0;
        unsigned long long offset = 0;
        int have_offset, drc;
        const char *want_hash;
        const char *obj_end = strchr(p, '}');
        const char *piece_limit = (obj_end && (!pieces_end || obj_end < pieces_end))
                                  ? obj_end : pieces_end;

        if (json_string_after(p, "url", url, sizeof(url), piece_limit))
            break;
        json_u64_after(p, "fileSize", &expected, piece_limit);
        have_offset = (json_u64_after(p, "fileOffset", &offset, piece_limit) == 0);

        if (!started && have_offset && expected &&
            have >= (long long)(offset + expected)) {
            total = (long long)(offset + expected);
            count++;
            if (cb && cb(ctx, total, manifest_total ? (long long)manifest_total : total))
                goto done;
            p = obj_end ? obj_end + 1 : p + 5;
            continue;
        }

        /* first missing piece: range if part of it is on disk, else cut off
           the stray bytes. all later pieces come whole */
        if (!started) {
            if (have_offset && expected && have > (long long)offset &&
                have < (long long)(offset + expected)) {
                range_start = have - (long long)offset;
                fseek(fp, 0, SEEK_END);
                total = have;
            } else {
                long long start_at = have_offset ? (long long)offset : 0;
                fflush(fp);
                if (ftruncate(fileno(fp), (off_t)start_at) != 0)
                    goto done;             /* keep the partial */
                fseek(fp, 0, SEEK_END);
                total = start_at;
            }
            started = 1;
        }

        /* a ranged piece starts mid-piece, so only check whole ones */
        if (have_offset && range_start == 0 && offset != (unsigned long long)total)
            goto done;

        /* only the tail of a ranged piece comes in, can't hash it */
        want_hash = NULL;
        if (range_start == 0 && verify) {
            json_string_after(p, "hashValue", hash, sizeof(hash), piece_limit);
            want_hash = hash[0] ? hash : NULL;
        }

        {
            progress_state_t progress = {
                cb, ctx, total, manifest_total ? (long long)manifest_total : 0
            };
            drc = http_download_to_file_progress(url, fp, &got, &progress,
                                                 want_hash, range_start);
            if (drc == -3) {
                fflush(fp);
                if (ftruncate(fileno(fp), (off_t)offset) != 0)
                    goto done;
                fseek(fp, 0, SEEK_END);
                total = (long long)offset;
                range_start = 0;
                if (verify) {
                    json_string_after(p, "hashValue", hash, sizeof(hash),
                                      piece_limit);
                    want_hash = hash[0] ? hash : NULL;
                }
                progress.base = total;
                drc = http_download_to_file_progress(url, fp, &got, &progress,
                                                     want_hash, 0);
            }
        }
        if (drc) {
            if (drc == -2) rc = -2;
            goto done;
        }
        if (expected && (unsigned long long)(range_start + got) != expected)
            goto done;

        total += got;
        if (cb && cb(ctx, total, manifest_total ? (long long)manifest_total : total))
            goto done;
        count++;
        p = obj_end ? obj_end + 1 : p + 5;
    }

    if (count > 0) {
        rc = 0;
        if (bytes_out) *bytes_out = total;
    }

done:
    fclose(fp);
    free(manifest.data);
    /* partial stays for a resume, the caller deletes it on cancel or -2 */
    return rc;
}

int
patchdl_http_download_manifest(const char *manifest_url, const char *dest_path,
                               long long *bytes_out) {
    return patchdl_http_download_manifest_progress(manifest_url, dest_path,
                                                  bytes_out, NULL, NULL, 0, 0);
}

void patchdl_net_global_init(void)    { curl_global_init(CURL_GLOBAL_ALL); }
void patchdl_net_global_cleanup(void) { curl_global_cleanup(); }

/* curl hands over ~2 KB chunks and every write to /data costs about the
   same. writing them one by one topped out at ~8 MB/s, so batch to 2 MB */
#define PATCHDL_PIECE_WBUF   (2 * 1024 * 1024)

/* written = received so far, flushed = on disk */
typedef struct {
    int                 fd;
    long long           base;
    long long           written;
    long long           flushed;
    unsigned char      *wbuf;         /* NULL: write each chunk directly */
    size_t              wlen;
    long long           size;         /* never write past it */
    long long           resume;       /* bytes of the piece already on disk */
    long long           range_start;  /* from Content-Range, -1 if none */
    int                 checked;      /* first body bytes seen */
    int                 bad_range;    /* the server sent a different range */
    CURL               *curl;
    EVP_MD_CTX         *md;
    const EVP_MD       *md_type;
    volatile long long *bytes_slot;
} piece_sink_t;

/* -1 read error, -2 aborted (pause or cancel) */
static int
digest_fd_region(EVP_MD_CTX *md, int fd, long long offset, long long size,
                 volatile int *abort) {
    const size_t   CHUNK = 1u << 20;
    unsigned char *buf = malloc(CHUNK);
    if (!buf) return -1;
    while (size > 0) {
        size_t  want = size > (long long)CHUNK ? CHUNK : (size_t)size;
        ssize_t got;
        if (abort && *abort) { free(buf); return -2; }
        got = pread(fd, buf, want, (off_t)offset);
        if (got <= 0) { free(buf); return -1; }
        EVP_DigestUpdate(md, buf, (size_t)got);
        offset += got; size -= got;
    }
    free(buf);
    return 0;
}

static size_t
piece_header_cb(char *b, size_t size, size_t nitems, void *ud) {
    piece_sink_t *s = (piece_sink_t *)ud;
    size_t        n = size * nitems;
    long long     start;
    /* redirect headers come first, only the last response counts */
    if (n > 5 && !strncmp(b, "HTTP/", 5)) s->range_start = -1;
    if (n > 20 && !strncasecmp(b, "Content-Range:", 14) &&
        sscanf(b + 14, " bytes %lld-", &start) == 1)
        s->range_start = start;
    return n;
}

static int
piece_pwrite(piece_sink_t *s, const unsigned char *p, size_t len) {
    while (len > 0) {
        ssize_t w = pwrite(s->fd, p, len, (off_t)(s->base + s->flushed));
        if (w <= 0) return -1;
        p += w; len -= (size_t)w;
        s->flushed += w;
    }
    if (s->bytes_slot) *s->bytes_slot = s->flushed;
    return 0;
}

static int
piece_flush(piece_sink_t *s) {
    int rc = s->wlen ? piece_pwrite(s, s->wbuf, s->wlen) : 0;
    s->wlen = 0;
    return rc;
}

static size_t
piece_write_cb(void *ptr, size_t size, size_t nmemb, void *ud) {
    piece_sink_t *s = (piece_sink_t *)ud;
    size_t        n = size * nmemb;
    if (n == 0) return 0;
    if (s->resume && !s->checked) {
        long code = 0;
        s->checked = 1;
        curl_easy_getinfo(s->curl, CURLINFO_RESPONSE_CODE, &code);
        if (code != 206) {
            /* got the whole piece, start over in place */
            s->written = s->flushed = 0;
            if (s->bytes_slot) *s->bytes_slot = 0;
            if (s->md) EVP_DigestInit_ex(s->md, s->md_type, NULL);
        } else if (s->range_start != s->resume) {
            s->bad_range = 1;
            return 0;                         /* not where it left off */
        }
    }
    /* overflow would land in the next piece */
    if (s->size > 0 && s->written + (long long)n > s->size) return 0;
    if (s->md) EVP_DigestUpdate(s->md, ptr, n);
    if (!s->wbuf) {
        if (piece_pwrite(s, ptr, n)) return 0;   /* curl errors out on this */
    } else {
        const unsigned char *p = ptr;
        size_t               left = n;
        while (left > 0) {
            size_t take = PATCHDL_PIECE_WBUF - s->wlen;
            if (take > left) take = left;
            memcpy(s->wbuf + s->wlen, p, take);
            s->wlen += take; p += take; left -= take;
            if (s->wlen == PATCHDL_PIECE_WBUF && piece_flush(s)) return 0;
        }
    }
    s->written += (long long)n;
    return n;
}

static int
piece_xfer_cb(void *clientp, curl_off_t dltotal, curl_off_t dlnow,
              curl_off_t ultotal, curl_off_t ulnow) {
    volatile int *abort_flag = (volatile int *)clientp;
    (void)dltotal; (void)dlnow; (void)ultotal; (void)ulnow;
    return (abort_flag && *abort_flag) ? 1 : 0;
}

int
patchdl_http_download_piece(const char *url, int fd,
                            long long file_offset, long long file_size,
                            long long resume_from,
                            const char *expected_sha256_or_null,
                            patchdl_piece_ctx_t *ctx,
                            int *curl_rc_out, long *http_code_out) {
    CURL             *curl;
    CURLcode          res;
    long              http_code = 0;
    char              host[256];
    struct curl_slist *rl = NULL;
    struct curl_blob  ca_blob;
    piece_sink_t      sink;
    int               verify = (expected_sha256_or_null && expected_sha256_or_null[0]);

    if (curl_rc_out)   *curl_rc_out   = 0;
    if (http_code_out) *http_code_out = 0;

    if (url_host(url, host, sizeof(host))) return -1;
    if (!host_allowed(host)) return -1;
    if (!(rl = resolve_list_for(host))) return -1;

    if (resume_from < 0 || file_size <= 0 || resume_from >= file_size) resume_from = 0;
    memset(&sink, 0, sizeof(sink));
    sink.fd          = fd;
    sink.base        = file_offset;
    sink.size        = file_size;
    sink.resume      = resume_from;
    sink.written     = resume_from;
    sink.flushed     = resume_from;
    sink.range_start = -1;
    sink.bytes_slot  = ctx ? ctx->bytes_slot : NULL;
    if (sink.bytes_slot) *sink.bytes_slot = resume_from;
    if (verify) {
        sink.md_type = digest_for(expected_sha256_or_null);
        sink.md = EVP_MD_CTX_new();
        if (!sink.md) { curl_slist_free_all(rl); return -1; }   /* never skip a requested check */
        EVP_DigestInit_ex(sink.md, sink.md_type, NULL);
        if (sink.md && resume_from) {
            int drc = digest_fd_region(sink.md, fd, file_offset, resume_from,
                                       ctx ? ctx->abort : NULL);
            if (drc == -2) {                /* paused or cancelled meanwhile */
                EVP_MD_CTX_free(sink.md);
                curl_slist_free_all(rl);
                return -1;
            }
            if (drc) {                      /* unreadable: fetch it all again */
                EVP_DigestInit_ex(sink.md, sink.md_type, NULL);
                sink.resume = sink.written = sink.flushed = 0;
                if (sink.bytes_slot) *sink.bytes_slot = 0;
            }
        }
    }

    ca_blob.data  = (void *)PATCHDL_SCEI_DNAS_ROOT_PEM;
    ca_blob.len   = strlen(PATCHDL_SCEI_DNAS_ROOT_PEM);
    ca_blob.flags = CURL_BLOB_COPY;

    curl = curl_easy_init();
    if (!curl) {
        curl_slist_free_all(rl);
        if (sink.md) EVP_MD_CTX_free(sink.md);
        return -1;
    }

    curl_easy_setopt(curl, CURLOPT_URL,             url);
    curl_easy_setopt(curl, CURLOPT_RESOLVE,         rl);
    sink.curl = curl;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,   piece_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA,       &sink);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION,  piece_header_cb);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA,      &sink);
    if (sink.resume) {
        char range[48];
        snprintf(range, sizeof range, "%lld-%lld", sink.resume, file_size - 1);
        curl_easy_setopt(curl, CURLOPT_RANGE, range);
    }
    curl_easy_setopt(curl, CURLOPT_CAINFO_BLOB,     &ca_blob);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER,  1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST,  2L);
    curl_easy_setopt(curl, CURLOPT_SSL_CIPHER_LIST, "DEFAULT@SECLEVEL=0");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION,  1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS,       5L);
    /* no https pin on redirects, see http_download_to_file_progress */
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL,        1L);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR,     1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT,  20L);
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 1024L);
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME,  30L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT,       "patchdl/1.0");
    curl_easy_setopt(curl, CURLOPT_SOCKOPTFUNCTION, sockopt_rcvbuf_cb);
    if (ctx && ctx->abort) {
        curl_easy_setopt(curl, CURLOPT_NOPROGRESS,       0L);
        curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, piece_xfer_cb);
        curl_easy_setopt(curl, CURLOPT_XFERINFODATA,     (void *)ctx->abort);
    }

    sink.wbuf = malloc(PATCHDL_PIECE_WBUF);   /* NULL is fine, just slower */
    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    note_curl_result(host, res);
    curl_easy_cleanup(curl);
    curl_slist_free_all(rl);
    /* also on failure or pause, keeps what arrived for a resume */
    if (piece_flush(&sink) && res == CURLE_OK) res = CURLE_WRITE_ERROR;
    free(sink.wbuf);

    if (curl_rc_out)   *curl_rc_out   = (int)res;
    if (http_code_out) *http_code_out = http_code;

    if (res != CURLE_OK) {
        if (sink.md) EVP_MD_CTX_free(sink.md);
        return sink.resume && (sink.bad_range || http_code == 416) ? -3 : -1;
    }
    if (file_size > 0 && sink.written != file_size) {
        if (sink.md) EVP_MD_CTX_free(sink.md);
        return -1;                          /* short or too long */
    }
    if (sink.md) {
        unsigned char dig[EVP_MAX_MD_SIZE];
        unsigned int  dl = 0;
        char          hex[2 * EVP_MAX_MD_SIZE + 1];
        int           ok = EVP_DigestFinal_ex(sink.md, dig, &dl);
        EVP_MD_CTX_free(sink.md);
        if (ok != 1 || dl == 0) return -2;
        hex_encode(dig, dl, hex, sizeof(hex));
        if (strcasecmp(hex, expected_sha256_or_null) != 0)
            return -2;
    }
    /* must be on disk before the caller sets the done bit */
    if (fdatasync(fd) != 0) return -1;
    return 0;
}

/* pread, leaves the fd offset alone */
int
patchdl_hash_fd_region(int fd, long long offset, long long size,
                       const char *like_hex, char *out_hex) {
    EVP_MD_CTX   *md;
    unsigned char *buf;
    long long      pos = offset, remaining = size;
    const size_t   CHUNK = 1u << 20;

    out_hex[0] = '\0';
    if (fd < 0 || size < 0) return -1;
    md = EVP_MD_CTX_new();
    if (!md) return -1;
    buf = malloc(CHUNK);
    if (!buf) { EVP_MD_CTX_free(md); return -1; }
    EVP_DigestInit_ex(md, digest_for(like_hex), NULL);
    while (remaining > 0) {
        size_t  want = remaining > (long long)CHUNK ? CHUNK : (size_t)remaining;
        ssize_t got  = pread(fd, buf, want, (off_t)pos);
        if (got <= 0) { free(buf); EVP_MD_CTX_free(md); return -1; }
        EVP_DigestUpdate(md, buf, (size_t)got);
        pos += got; remaining -= got;
    }
    {
        unsigned char dig[EVP_MAX_MD_SIZE];
        unsigned int  dl = 0, i;
        int           ok = EVP_DigestFinal_ex(md, dig, &dl);
        if (ok != 1 || dl == 0) { free(buf); EVP_MD_CTX_free(md); return -1; }
        for (i = 0; i < dl; i++) snprintf(out_hex + 2 * i, 3, "%02x", dig[i]);
        out_hex[2 * dl] = '\0';
    }
    free(buf);
    EVP_MD_CTX_free(md);
    return 0;
}

void
patchdl_manifest_free(patchdl_manifest_t *m) {
    if (!m || !m->pieces) return;
    for (int i = 0; i < m->count; i++) free(m->pieces[i].url);
    free(m->pieces);
    m->pieces = NULL;
    m->count = 0;
}

int
patchdl_fetch_manifest(const char *manifest_url, patchdl_manifest_t *out) {
    patchdl_buf_t buf;
    const char *pieces, *pieces_end, *p;
    int       cap = 0, n = 0;
    long long running = 0;

    memset(out, 0, sizeof(*out));
    memset(&buf, 0, sizeof(buf));
    buf.max = PATCHDL_BUF_MAX_MANIFEST;
    if (http_get_retrying(manifest_url, &buf)) return -1;
    if (!buf.data || !buf.size) {
        free(buf.data);
        if (!g_last.step[0]) set_last("empty_reply", 0, g_last.http_code);
        return -1;
    }

    pieces = strstr(buf.data, "\"pieces\"");
    if (!pieces || !(pieces = strchr(pieces, '['))) {
        free(buf.data);
        if (!g_last.step[0]) set_last("bad_manifest", 0, g_last.http_code);
        return -1;
    }
    pieces_end = strchr(pieces, ']');

    for (p = pieces; (p = strstr(p, "\"url\"")) && (!pieces_end || p < pieces_end); p += 5)
        cap++;
    if (cap <= 0) { free(buf.data); set_last("bad_manifest", 0, g_last.http_code); return -1; }
    if (cap > PATCHDL_MAX_PIECES) { free(buf.data); set_last("bad_manifest", 0, g_last.http_code); return -1; }
    out->pieces = calloc((size_t)cap, sizeof(patchdl_piece_t));
    if (!out->pieces) { free(buf.data); return -1; }

    p = pieces;
    while ((p = strstr(p, "\"url\"")) && (!pieces_end || p < pieces_end) && n < cap) {
        char               url[768] = {0};
        unsigned long long sz = 0, off = 0;
        const char        *obj_end = strchr(p, '}');
        const char        *piece_limit = (obj_end && (!pieces_end || obj_end < pieces_end))
                                         ? obj_end : pieces_end;

        if (json_string_after(p, "url", url, sizeof(url), piece_limit))
            break;
        json_u64_after(p, "fileSize", &sz, piece_limit);
        if (json_u64_after(p, "fileOffset", &off, piece_limit) != 0)
            off = (unsigned long long)running;   /* no offset: assume contiguous */

        /* in order, no gaps, no empty pieces, under the caps */
        if ((long long)off != running || sz == 0 || sz > PATCHDL_MAX_PIECE_BYTES ||
            (unsigned long long)running + sz > PATCHDL_MAX_TOTAL_BYTES) {
            patchdl_manifest_free(out);
            free(buf.data);
            set_last("bad_manifest", 0, g_last.http_code);
            return -1;
        }
        out->pieces[n].url    = strdup(url);
        out->pieces[n].offset = (long long)off;
        out->pieces[n].size   = (long long)sz;
        json_string_after(p, "hashValue", out->pieces[n].hash,
                          sizeof(out->pieces[n].hash), piece_limit);
        if (!out->pieces[n].url) {
            patchdl_manifest_free(out);
            free(buf.data);
            return -1;
        }
        running += (long long)sz;
        n++;
        out->count = n;          /* so manifest_free frees exactly n */
        p = obj_end ? obj_end + 1 : p + 5;
    }
    json_string_after(buf.data, "playgoChunkCrcUrl", out->crc_url,
                      sizeof(out->crc_url), NULL);
    free(buf.data);
    if (n == 0) { patchdl_manifest_free(out); set_last("bad_manifest", 0, g_last.http_code); return -1; }
    out->total = running;
    return 0;
}

void
patchdl_net_diag(const char *url, char *out_json, size_t sz) {
    char                 host[256] = {0};
    int                  hostrc, allowrc, dnsrc = -1;
    long                 http_code = 0;
    CURLcode             res = CURLE_OK;
    int                  did_curl = 0;
    patchdl_dns_answer_t a;

    memset(&a, 0, sizeof a);
    hostrc  = url_host(url, host, sizeof(host));
    allowrc = (hostrc == 0) ? host_allowed(host) : 0;
    if (hostrc == 0) {
        patchdl_dns_refresh(host);
        dnsrc = patchdl_dns_lookup(host, &a);
    }

    if (hostrc == 0 && allowrc && dnsrc == 0) {
        patchdl_buf_t buf;
        memset(&buf, 0, sizeof(buf));
        CURL *curl = curl_easy_init();
        if (curl) {
            char rs[PATCHDL_DNS_ENTRY_MAX];
            struct curl_slist *rl;
            struct curl_blob ca_blob;
            rl = patchdl_dns_resolve_entry(&a, host, 443, 0, rs, sizeof rs)
                 ? NULL : curl_slist_append(NULL, rs);
            ca_blob.data = (void *)PATCHDL_SCEI_DNAS_ROOT_PEM;
            ca_blob.len = strlen(PATCHDL_SCEI_DNAS_ROOT_PEM);
            ca_blob.flags = CURL_BLOB_COPY;
            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_RESOLVE, rl);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
            curl_easy_setopt(curl, CURLOPT_CAINFO_BLOB, &ca_blob);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
            curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
            curl_easy_setopt(curl, CURLOPT_SSL_CIPHER_LIST, "DEFAULT@SECLEVEL=0");
            curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR,       "https");
            curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "https");
            curl_easy_setopt(curl, CURLOPT_NOSIGNAL,        1L);
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
            res = curl_easy_perform(curl);
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
            curl_easy_cleanup(curl);
            curl_slist_free_all(rl);
            free(buf.data);
            did_curl = 1;
        }
    }

    /* not escaped. source and trail are ours, host is from Sony's URL */
    snprintf(out_json, sz,
             "{\"host\":\"%s\",\"host_ok\":%d,\"allowed\":%d,"
             "\"dns_rc\":%d,\"ip\":\"%s\",\"dns_source\":\"%s\",\"dns_trail\":\"%s\","
             "\"curl_ran\":%d,\"curl_rc\":%d,\"curl_err\":\"%s\",\"http_code\":%ld}",
             host, hostrc == 0, allowrc, dnsrc, a.n ? a.ip[0] : "", a.source, a.trail,
             did_curl, (int)res,
             did_curl ? curl_easy_strerror(res) : "n/a", http_code);
}

#else /* !PATCHDL_HAVE_CURL */

int
patchdl_http_get(const char *url, patchdl_buf_t *out) {
    (void)url;
    (void)out;
    return -1; /* built without curl, set CURL_DIR= */
}

void
patchdl_http_last_error(char *step, size_t step_sz, int *curl_rc, long *http_code) {
    if (step && step_sz) snprintf(step, step_sz, "no_curl");
    if (curl_rc) *curl_rc = 0;
    if (http_code) *http_code = 0;
}

int
patchdl_http_download(const char *url, const char *dest_path,
                      long long *bytes_out) {
    (void)url; (void)dest_path;
    if (bytes_out) *bytes_out = 0;
    return -1;
}

int
patchdl_http_download_progress(const char *url, const char *dest_path,
                               long long *bytes_out,
                               patchdl_download_progress_cb cb, void *ctx) {
    (void)cb; (void)ctx;
    return patchdl_http_download(url, dest_path, bytes_out);
}

int
patchdl_http_download_manifest(const char *manifest_url, const char *dest_path,
                               long long *bytes_out) {
    (void)manifest_url; (void)dest_path;
    if (bytes_out) *bytes_out = 0;
    return -1;
}

int
patchdl_http_download_manifest_progress(const char *manifest_url,
                                        const char *dest_path,
                                        long long *bytes_out,
                                        patchdl_download_progress_cb cb,
                                        void *ctx, int verify, int resume) {
    (void)cb; (void)ctx; (void)verify; (void)resume;
    return patchdl_http_download_manifest(manifest_url, dest_path, bytes_out);
}

void
patchdl_net_diag(const char *url, char *out_json, size_t sz) {
    (void)url;
    snprintf(out_json, sz, "{\"error\":\"curl not built\"}");
}

#endif /* PATCHDL_HAVE_CURL */

patchdl_buf_t *
patchdl_buf_new(void) {
    return calloc(1, sizeof(patchdl_buf_t));
}

void
patchdl_buf_free(patchdl_buf_t *b) {
    if (!b) return;
    free(b->data);
    free(b);
}
