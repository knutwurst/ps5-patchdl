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

typedef struct {
    char  *data;
    size_t size;
    size_t cap;
    size_t max;     /* 0 = no cap, else write_cb fails past it */
} patchdl_buf_t;

patchdl_buf_t *patchdl_buf_new(void);
void           patchdl_buf_free(patchdl_buf_t *b);

/* single-threaded only, before the workers start / after they joined.
   curl's lazy global init races otherwise */
void patchdl_net_global_init(void);
void patchdl_net_global_cleanup(void);

int patchdl_http_get(const char *url, patchdl_buf_t *out);

/* non-Sony hosts: no allowlist, no cert check at all (no CA store on the
   PS5). public metadata only, never anything sensitive */
int patchdl_http_get_external(const char *url, patchdl_buf_t *out);
int patchdl_http_post_external(const char *url, const char *content_type,
                               const char *body, patchdl_buf_t *out);

/* url is heap-allocated */
typedef struct {
    char     *url;
    long long offset;     /* in the assembled file */
    long long size;
    char      hash[80];   /* hex, SHA-256 (SHA-1 on PS4) or "" */
} patchdl_piece_t;

typedef struct {
    patchdl_piece_t *pieces;
    int              count;
    long long        total;   /* sum of piece sizes */
    char             crc_url[768]; /* playgoChunkCrcUrl, or "" */
    char             crc_hash[80]; /* playgoChunkCrcHashValue, or "" */
    char             digest[80];   /* packageDigest, or "" */
} patchdl_manifest_t;

/* pieces are checked to tile the file without gaps.
   free with patchdl_manifest_free */
int  patchdl_fetch_manifest(const char *manifest_url, patchdl_manifest_t *out);

/* per thread: why the last get/fetch_manifest failed. step "" on success,
   else "dns", "connect", "tls", "timeout", "bad_manifest" and friends */
void patchdl_http_last_error(char *step, size_t step_sz, int *curl_rc, long *http_code);

void patchdl_manifest_free(patchdl_manifest_t *m);


/* owned by the worker. bytes_slot has a single writer, abort is set from
   outside */
typedef struct {
    volatile long long *bytes_slot;  /* bytes of this piece on disk */
    volatile int       *abort;
} patchdl_piece_ctx_t;

/* pwrite-based, so parallel pieces on one fd are fine. 0 ok (fdatasynced),
   -1 network/io/abort (partial kept), -2 hash mismatch, -3 server can't
   resume there, start the piece over */
int patchdl_http_download_piece(const char *url, int fd,
                                long long file_offset, long long file_size,
                                long long resume_from,
                                const char *expected_sha256_or_null,
                                patchdl_piece_ctx_t *ctx,
                                int *curl_rc_out, long *http_code_out);

/* out_hex needs 65 bytes. SHA-1 if like_hex is 40 digits (PS4), else
   SHA-256 */
int patchdl_hash_fd_region(int fd, long long offset, long long size,
                           const char *like_hex, char *out_hex);

/* non-zero return cancels the download */
typedef int (*patchdl_download_progress_cb)(void *ctx,
                                            long long downloaded,
                                            long long total);

int patchdl_http_download(const char *url, const char *dest_path,
                          long long *bytes_out);
int patchdl_http_download_progress(const char *url, const char *dest_path,
                                   long long *bytes_out,
                                   patchdl_download_progress_cb cb, void *ctx);

/* glues all pieces into one pkg. verify: -2 on a hash mismatch. resume:
   keep the partial at dest_path and only fetch what's missing. the partial
   stays on failure */
int patchdl_http_download_manifest(const char *manifest_url, const char *dest_path,
                                   long long *bytes_out);
int patchdl_http_download_manifest_progress(const char *manifest_url,
                                            const char *dest_path,
                                            long long *bytes_out,
                                            patchdl_download_progress_cb cb,
                                            void *ctx, int verify, int resume);

/* JSON report of dns + one GET, for /api/netcheck */
void patchdl_net_diag(const char *url, char *out_json, size_t sz);
