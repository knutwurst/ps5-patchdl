/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Knutwurst
 *
 * PatchDL is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version. See the LICENSE file in the project root for details.
 */

#include "patchdl_websrv.h"
#include "patchdl_assets.h"
#include "patchdl_fw.h"
#include "patchdl_scan.h"
#include "patchdl_install.h"
#include "patchdl_net.h"
#include "patchdl_dns.h"
#include "patchdl_resolve.h"
#include "patchdl_tile.h"
#include "patchdl_verxml.h"
#include "patchdl_prospero.h"
#include "patchdl_version.h"

#include <arpa/inet.h>
#include <microhttpd.h>
#include <netinet/in.h>
#include <pthread.h>
#include <dirent.h>
#include <strings.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <poll.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/mount.h>
#include <unistd.h>

static struct MHD_Daemon *web_daemon;
static unsigned          g_web_restarts; /* times the watch restarted it */

static patchdl_fw_t     g_fw;
static patchdl_title_t *g_titles;
static size_t           g_title_count;
static pthread_mutex_t  g_mutex = PTHREAD_MUTEX_INITIALIZER;
static char            *g_debug_json; /* built once at startup */
/* version.xml thread, joinable so shutdown can wait for it
   before g_titles gets freed */
static pthread_t        g_verxml_tid;
static int              g_verxml_started;
static volatile int     g_verxml_stop;
/* auto rescan, see scan_watch_thread */
static pthread_t        g_scan_tid;
static int              g_scan_started;
static volatile int     g_scan_stop;
static volatile int     g_scan_now;       /* set by /api/rescan */
/* bumped under g_mutex on any title list change, UI reloads /api/titles */
static unsigned long    g_titles_gen;
/* rescan ms: scan, verxml wait, total */
static long             g_rescan_ms[3];
static const char *volatile g_rescan_step = "idle";
static volatile long    g_rescan_since;

static long
mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
static unsigned long    g_pkg_hits;
static char             g_pkg_diag_json[768] = "{\"hits\":0}";
/* ring of the last /api/pkg requests */
#define PKG_LOG_LINES 32
static char             g_pkg_log[PKG_LOG_LINES][200];
static unsigned         g_pkg_log_next;
/* last package fetch by the console. hands off the pkg while it reads */
static char             g_pkg_last_tid[16];
static time_t           g_pkg_last_time;
#define INSTALL_QUIET_SECS 60
/* install progress counted on PatchDL's side, Sony's own status query just
   says 0x80A30003 here. one entry per title. g_mutex */
typedef struct {
    char      title_id[16];
    long long read;        /* distinct bytes served, Sony re-reads */
    int       nspans;      /* served byte ranges, sorted, merged */
    struct { long long a, b; } span[48];
    long long total;
    int       crc;         /* the .crc was fetched: reading is over */
    time_t    started, last;
    char      version[16];
    char      file[160];   /* package file in the title folder */
    int       checked;
    int       verified;    /* 1: installed and from this package, -1: not shown */
    int       deleted;     /* package removed after the check (setting on) */
    int       claiming;    /* an install request is starting it right now */
} install_stream_t;

#define MAX_STREAMS 8
static install_stream_t g_streams[MAX_STREAMS];

/* add [a,b) and recount. full table drops the range, so the count errs
   low, never high. g_mutex held */
static void
stream_cover(install_stream_t *st, long long a, long long b) {
    int i, j;
    if (b <= a) return;
    for (i = 0; i < st->nspans && st->span[i].b < a; i++) ;
    for (j = i; j < st->nspans && st->span[j].a <= b; j++) {
        if (st->span[j].a < a) a = st->span[j].a;
        if (st->span[j].b > b) b = st->span[j].b;
    }
    if (j == i && st->nspans >= (int)(sizeof st->span / sizeof st->span[0]))
        return;
    memmove(&st->span[i + 1], &st->span[j], (size_t)(st->nspans - j) * sizeof st->span[0]);
    st->nspans += 1 - (j - i);
    st->span[i].a = a;
    st->span[i].b = b;
    st->read = 0;
    for (i = 0; i < st->nspans; i++) st->read += st->span[i].b - st->span[i].a;
}

/* g_mutex held */
static install_stream_t *
stream_find(const char *title_id) {
    for (int i = 0; i < MAX_STREAMS; i++)
        if (g_streams[i].title_id[0] &&
            !strncmp(g_streams[i].title_id, title_id, 9))
            return &g_streams[i];
    return NULL;
}

/* all bytes out, or .crc fetched plus a quiet minute. the .crc alone proves
   nothing, I've seen it fetched at 88%. g_mutex held */
static int
stream_read_all(const install_stream_t *st) {
    int quiet = time(NULL) - st->last >= INSTALL_QUIET_SECS;
    return (st->total > 0 && st->read >= st->total) ||
           (st->crc && quiet) ||
           /* PS4 patches come without a .crc */
           (!strncmp(st->title_id, "CUSA", 4) && st->read > 0 && quiet);
}

#define INSTALL_STALL_SECS 300

static const char *
stream_phase(const install_stream_t *st, time_t now) {
    int read_all = stream_read_all(st);
    if (!read_all && now - st->last >= INSTALL_STALL_SECS) return "stalled";
    if (!read_all) return st->read ? "reading" : "waiting";
    if (now - st->last < INSTALL_QUIET_SECS || !st->checked) return "finishing";
    return "done";
}

/* settings in PATCHDL_CFG_PATH, per-title enable is in the title structs */
#define POOL_MAX_CONN 16
#define POOL_MAX_JOBS 16
#define SIDECAR_MAX_HAVE 64   /* started pieces remembered in the sidecar */

static struct {
    char default_policy[8];        /* "deny" | "allow" */
    int  install_after_download;
    int  delete_pkg_after_install;
    int  verify_downloads;         /* SHA-256 every piece, default off */
    int  home_shortcut;            /* home-screen tile */
    int  max_connections;          /* 1..POOL_MAX_CONN */
    char download_drive[32];       /* /data, /mnt/extN or /mnt/usbN */
} g_cfg = { "deny", 0, 1, 0, 1, 4, "/data" };

/* workers share one job, extra titles queue. the sidecar bitmap survives
   reboots. lock: g_pool.mtx, not g_mutex */

typedef enum { PC_PENDING = 0, PC_INFLIGHT, PC_DONE, PC_FAILED } pc_state_t;

typedef struct {
    pc_state_t state;
    int        attempts;
    int        slot;       /* worker slot while INFLIGHT, else -1 */
    long       retry_at;   /* mono_ms() before which a failed piece waits */
    long long  have;       /* synced bytes of a failed piece, to resume */
} dl_pstate_t;

/* network errors retry with backoff, hash mismatches fail at once */
#define PIECE_MAX_ATTEMPTS 8
static long
piece_backoff_ms(int attempts) {
    static const long steps[] = { 5000, 10000, 20000, 40000, 60000 };
    int i = attempts - 1;
    if (i < 0) i = 0;
    if (i > 4) i = 4;
    return steps[i];
}

typedef enum {
    JOB_QUEUED = 0, JOB_ADMITTING, JOB_ACTIVE, JOB_PAUSING, JOB_CANCELLING,
    JOB_PAUSED, JOB_DONE, JOB_FAILED
} job_state_t;

typedef struct dl_job {
    char               title_id[32];
    char               name[128];
    char               version[16];
    char               manifest_url[768];
    char               dir[288];
    char               dest[320];
    int                is_manifest;
    int                verify;
    job_state_t        state;
    unsigned int       seq;            /* bumped on cancel, stale results dropped */
    volatile int       abort;          /* read by the piece transfer callback */
    long long          total;          /* assembled size (preallocated) */
    long long          done_bytes;     /* sum of DONE pieces */
    long long          speed_bps;
    long long          sample_bytes;
    double             sample_ts;
    patchdl_manifest_t mf;
    dl_pstate_t       *ps;
    unsigned char     *bitmap;         /* bit set = DONE and on disk */
    int                pieces_done;
    int                pieces_failed;
    int                inflight;
    int                fd;             /* -1 until admit */
    int                rc;             /* 0 ok, -1 net/io, -2 verify, -3 no space */
    long long          need_bytes;     /* rc -3: bytes the package still needed */
    int                verifying;      /* admit is hashing a pkg found on disk */
    int                in_admit;       /* admit_next has it, lock dropped */
    long long          verify_bytes;
    long long          free_bytes;     /* rc -3: free bytes on that drive */
    int                space_install;  /* rc -3: the install needs room too */
    int                last_curl_rc;   /* CURLcode of the last piece */
    char               fail_step[24];  /* why the manifest fetch failed, or "" */
    long               last_http_code; /* HTTP status of the last piece */
    struct dl_job     *next;
} dl_job_t;

static struct {
    pthread_mutex_t mtx;
    pthread_cond_t  cv;                /* workers wait; broadcast on any change */
    dl_job_t       *jobs;
    dl_job_t       *active;            /* the one admitted job, or NULL */
    int             admitting;         /* admit in progress */
    int             stopping;
    int             n_workers;
    int             active_conns;      /* workers with slot >= this idle */
    pthread_t       workers[POOL_MAX_CONN];
    volatile long long inflight_bytes[POOL_MAX_CONN];
} g_pool = { .mtx = PTHREAD_MUTEX_INITIALIZER, .cv = PTHREAD_COND_INITIALIZER };

#define PATCHDL_DATA_DIR  "/data/patchdl"      /* config and caches, always internal */
#define PATCHDL_CFG_PATH  "/data/patchdl/config.json"

/* <drive>/patchdl/<title>/, a title stays where its download started */

#define MAX_DRIVES 12

/* guards g_cfg.download_drive. leaf lock, taken after g_mutex or
   g_pool.mtx, nothing under it */
static pthread_mutex_t g_drive_mtx = PTHREAD_MUTEX_INITIALIZER;

static int
drive_name_ok(const char *m) {
    if (!strcmp(m, "/data")) return 1;
    return (!strncmp(m, "/mnt/ext", 8) || !strncmp(m, "/mnt/usb", 8)) &&
           isdigit((unsigned char)m[8]) && (!m[9] || (isdigit((unsigned char)m[9]) && !m[10]));
}

static int
drive_mounted(const char *drive) {
    struct statfs sf;
    if (!strcmp(drive, "/data")) return 1;
    return statfs(drive, &sf) == 0 && !strcmp(sf.f_mntonname, drive);
}

/* /data first, then every mounted extN/usbN */
static int
list_drives(char out[][32], int max) {
    struct statfs *mnt;
    int            n = 0, k;
    snprintf(out[n++], 32, "/data");
    /* own buffer, getmntinfo's static one isn't thread-safe */
    k = getfsstat(NULL, 0, MNT_NOWAIT);
    if (k <= 0 || !(mnt = calloc((size_t)k + 4, sizeof *mnt))) return n;
    k = getfsstat(mnt, (long)(((size_t)k + 4) * sizeof *mnt), MNT_NOWAIT);
    for (int i = 0; i < k && n < max; i++) {
        int dup = 0;
        if (!drive_name_ok(mnt[i].f_mntonname) || !strcmp(mnt[i].f_mntonname, "/data")) continue;
        for (int j = 0; j < n; j++) if (!strcmp(out[j], mnt[i].f_mntonname)) dup = 1;
        if (!dup) snprintf(out[n++], 32, "%s", mnt[i].f_mntonname);
    }
    free(mnt);
    return n;
}

/* chosen drive, or /data while that one isn't mounted */
static void
current_root(char *out, size_t sz) {
    char drive[32];
    pthread_mutex_lock(&g_drive_mtx);
    snprintf(drive, sizeof drive, "%s", g_cfg.download_drive);
    pthread_mutex_unlock(&g_drive_mtx);
    if (!drive_name_ok(drive) || !drive_mounted(drive)) snprintf(drive, sizeof drive, "/data");
    snprintf(out, sz, "%s/patchdl", drive);
}

/* existing folder on any drive, else the current one. title_id must be safe */
static void
title_dir(const char *title_id, char *out, size_t sz) {
    char        drives[MAX_DRIVES][32], root[64];
    int         n = list_drives(drives, MAX_DRIVES);
    struct stat st;
    for (int i = 0; i < n; i++) {
        snprintf(out, sz, "%s/patchdl/%s", drives[i], title_id);
        if (stat(out, &st) == 0 && S_ISDIR(st.st_mode)) return;
    }
    current_root(root, sizeof root);
    snprintf(out, sz, "%s/%s", root, title_id);
}

static void
make_title_dir(const char *dir) {
    char parent[288];
    const char *slash = strrchr(dir, '/');
    if (slash && (size_t)(slash - dir) < sizeof parent) {
        memcpy(parent, dir, (size_t)(slash - dir));
        parent[slash - dir] = '\0';
        mkdir(parent, 0777);
    }
    mkdir(dir, 0777);
}

/* source policy and CDN allowlist are fixed (safety model), not settings */
static const char config_tail_json[] =
  "\"source_policy\":{"
  "\"official\":{\"allow_check\":true,\"allow_download\":true,\"allow_install\":true},"
  "\"external\":{\"allow_check\":true,\"allow_download\":true,\"allow_install\":true},"
  "\"shadowmount\":{\"allow_check\":true,\"allow_download\":false,\"allow_install\":false},"
  "\"unknown\":{\"allow_check\":true,\"allow_download\":false,\"allow_install\":false},"
  "\"fake\":{\"allow_check\":true,\"allow_download\":false,\"allow_install\":false}"
  "},"
  "\"cdn_allowlist\":["
  "\"sgst.prod.dl.playstation.net\","
  "\"gst.prod.dl.playstation.net\","
  "\"gs2.ww.prod.dl.playstation.net\","
  "\"gs-sec.ww.np.dl.playstation.net\""
  "]}";
/* tiny JSON lookups, flat objects only */

static int
json_get_bool(const char *s, const char *key, int dflt) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(s, pat);
    if (!p) return dflt;
    p = strchr(p + strlen(pat), ':');
    if (!p) return dflt;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (!strncmp(p, "true", 4))  return 1;
    if (!strncmp(p, "false", 5)) return 0;
    return dflt;
}

static int
json_get_int(const char *s, const char *key, int dflt) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(s, pat);
    if (!p) return dflt;
    p = strchr(p + strlen(pat), ':');
    if (!p) return dflt;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p < '0' || *p > '9') return dflt;
    return (int)strtol(p, NULL, 10);
}

/* \uXXXX becomes '?', no field needs multi-byte */
static void
json_get_str(const char *s, const char *key, char *out, size_t sz) {
    out[0] = '\0';
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(s, pat);
    if (!p) return;
    p = strchr(p + strlen(pat), ':');
    if (!p) return;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    if (*p != '"') return;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < sz) {
        if (*p == '\\' && p[1]) {
            p++;
            switch (*p) {
            case '"':  out[i++] = '"';  break;
            case '\\': out[i++] = '\\'; break;
            case '/':  out[i++] = '/';  break;
            case 'n':  out[i++] = '\n'; break;
            case 'r':  out[i++] = '\r'; break;
            case 't':  out[i++] = '\t'; break;
            case 'b':  out[i++] = '\b'; break;
            case 'f':  out[i++] = '\f'; break;
            case 'u':
                if (p[1] && p[2] && p[3] && p[4]) p += 4;
                out[i++] = '?';
                break;
            default:   out[i++] = *p;   break;
            }
            p++;
        } else {
            out[i++] = *p++;
        }
    }
    out[i] = '\0';
}


typedef struct {
    char  *buf;
    size_t len;
    size_t cap;
} jbuf_t;

/* 0 if extra bytes plus the NUL fit */
static int
jbuf_ensure(jbuf_t *j, size_t extra) {
    if (!j->buf || j->len + extra + 1 > j->cap) {
        size_t newcap = (j->cap + extra + 1) * 2;
        if (newcap < 1024) newcap = 1024;
        char *p = realloc(j->buf, newcap);
        if (!p) return -1;      /* old buffer stays, just too small */
        j->buf = p;
        j->cap = newcap;
    }
    return 0;
}

static void
jbuf_append(jbuf_t *j, const char *s) {
    size_t slen = strlen(s);
    if (jbuf_ensure(j, slen) || !j->buf) return;
    memcpy(j->buf + j->len, s, slen + 1);
    j->len += slen;
}

static void
jbuf_appendf(jbuf_t *j, const char *fmt, ...) {
    char tmp[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    jbuf_append(j, tmp);
}

static void
jbuf_append_str(jbuf_t *j, const char *s) {
    jbuf_append(j, "\"");
    for (const char *p = s; *p; p++) {
        if      (*p == '"')  jbuf_append(j, "\\\"");
        else if (*p == '\\') jbuf_append(j, "\\\\");
        else if (*p == '\n') jbuf_append(j, "\\n");
        else if (*p == '\r') jbuf_append(j, "\\r");
        else if (*p == '\t') jbuf_append(j, "\\t");
        else if ((unsigned char)*p < 0x20) jbuf_appendf(j, "\\u%04x", (unsigned char)*p);
        else { char c[2] = {*p, '\0'}; jbuf_append(j, c); }
    }
    jbuf_append(j, "\"");
}

static void
jbuf_append_ver_or_null(jbuf_t *j, const char *ver) {
    if (ver[0])
        jbuf_append_str(j, ver);
    else
        jbuf_append(j, "null");
}


static enum MHD_Result
queue_buffer(struct MHD_Connection *conn, unsigned int status,
             const char *mime, const void *data, size_t size,
             enum MHD_ResponseMemoryMode mm) {
    struct MHD_Response *resp;
    enum MHD_Result      ret;

    resp = MHD_create_response_from_buffer(size, (void *)data, mm);
    if (!resp) {
        /* MUST_FREE is only MHD's on success, free it here or it leaks */
        if (mm == MHD_RESPMEM_MUST_FREE) free((void *)data);
        return MHD_NO;
    }

    MHD_add_response_header(resp, MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN, "*");
    MHD_add_response_header(resp, MHD_HTTP_HEADER_CACHE_CONTROL, "no-store");
    if (mime)
        MHD_add_response_header(resp, MHD_HTTP_HEADER_CONTENT_TYPE, mime);

    ret = MHD_queue_response(conn, status, resp);
    MHD_destroy_response(resp);
    return ret;
}

static enum MHD_Result
queue_text(struct MHD_Connection *conn, unsigned int status, const char *text) {
    return queue_buffer(conn, status, "text/plain; charset=utf-8",
                        text, strlen(text), MHD_RESPMEM_PERSISTENT);
}

static enum MHD_Result
queue_json(struct MHD_Connection *conn, unsigned int status, const char *json) {
    return queue_buffer(conn, status, "application/json",
                        json, strlen(json), MHD_RESPMEM_PERSISTENT);
}

/* takes ownership, MHD frees it */
static enum MHD_Result
queue_json_owned(struct MHD_Connection *conn, unsigned int status, char *json) {
    if (!json) return queue_text(conn, MHD_HTTP_INTERNAL_SERVER_ERROR, "oom");
    return queue_buffer(conn, status, "application/json",
                        json, strlen(json), MHD_RESPMEM_MUST_FREE);
}

/* icons never change and cards re-render every poll, let the browser cache */
static enum MHD_Result
queue_icon(struct MHD_Connection *conn, const char *title_id) {
    struct MHD_Response *resp;
    enum MHD_Result      ret;
    struct stat          st;
    unsigned char       *buf;
    int                  fd = -1;

    /* dup under the lock, a rescan closes the old icon fds */
    pthread_mutex_lock(&g_mutex);
    for (size_t i = 0; i < g_title_count; i++)
        if (!strcmp(g_titles[i].title_id, title_id)) {
            if (g_titles[i].icon_fd >= 0) fd = dup(g_titles[i].icon_fd);
            break;
        }
    pthread_mutex_unlock(&g_mutex);

    if (fd < 0) return queue_text(conn, MHD_HTTP_NOT_FOUND, "no icon");
    if (fstat(fd, &st) || st.st_size <= 0) {
        close(fd);
        return queue_text(conn, MHD_HTTP_NOT_FOUND, "no icon");
    }
    buf = malloc((size_t)st.st_size);
    if (!buf) { close(fd); return queue_text(conn, MHD_HTTP_INTERNAL_SERVER_ERROR, "oom"); }
    if (pread(fd, buf, (size_t)st.st_size, 0) != st.st_size) {
        close(fd);
        free(buf);
        return queue_text(conn, MHD_HTTP_NOT_FOUND, "no icon");
    }
    close(fd);

    resp = MHD_create_response_from_buffer((size_t)st.st_size, buf,
                                           MHD_RESPMEM_MUST_FREE);
    if (!resp) { free(buf); return MHD_NO; }
    MHD_add_response_header(resp, MHD_HTTP_HEADER_CONTENT_TYPE, "image/png");
    MHD_add_response_header(resp, MHD_HTTP_HEADER_CACHE_CONTROL, "max-age=86400");
    ret = MHD_queue_response(conn, MHD_HTTP_OK, resp);
    MHD_destroy_response(resp);
    return ret;
}

static enum MHD_Result
queue_asset(struct MHD_Connection *conn, const char *url) {
    const patchdl_asset_t *asset = patchdl_asset_find(url);
    if (!asset) return queue_text(conn, MHD_HTTP_NOT_FOUND, "not found");
    return queue_buffer(conn, MHD_HTTP_OK, asset->mime,
                        asset->data, asset->size, MHD_RESPMEM_PERSISTENT);
}

static int
path_segment_safe(const char *s) {
    if (!s || !s[0] || strstr(s, "..")) return 0;
    for (const char *p = s; *p; p++) {
        int ok = (*p >= 'A' && *p <= 'Z') ||
                 (*p >= 'a' && *p <= 'z') ||
                 (*p >= '0' && *p <= '9') ||
                 *p == '_' || *p == '-' || *p == '.';
        if (!ok) return 0;
    }
    return 1;
}

/* only <drive>/patchdl/<safe-title-id>/<safe-file> */
static int
local_install_path_safe(const char *path) {
    char        drives[MAX_DRIVES][32], prefix[64];
    int         nd = list_drives(drives, MAX_DRIVES), hit = -1;
    size_t      plen = 0;
    const char *tail, *slash;
    char        seg[64];
    size_t      len;

    if (!path) return 0;
    for (int i = 0; i < nd && hit < 0; i++) {
        snprintf(prefix, sizeof prefix, "%s/patchdl/", drives[i]);
        plen = strlen(prefix);
        if (!strncmp(path, prefix, plen)) hit = i;
    }
    if (hit < 0) return 0;
    tail  = path + plen;
    slash = strchr(tail, '/');
    if (!slash || slash == tail) return 0;
    len = (size_t)(slash - tail);
    if (len >= sizeof(seg)) return 0;
    memcpy(seg, tail, len);
    seg[len] = '\0';
    if (!path_segment_safe(seg)) return 0;

    tail = slash + 1;
    if (!tail[0] || strchr(tail, '/')) return 0;
    if (strlen(tail) >= sizeof(seg)) return 0;
    return path_segment_safe(tail);
}

/* subset of ALLOWED_HOSTS in patchdl_net.c, kept in sync by hand */
static const char *INSTALL_URI_HOSTS[] = {
    "sgst.prod.dl.playstation.net",
    "gst.prod.dl.playstation.net",
    "gs2.ww.prod.dl.playstation.net",
    NULL,
};

/* host in INSTALL_URI_HOSTS or a subdomain, redirects go via host_allowed */
static int
cdn_host_ok(const char *host_start) {
    const char *end;
    size_t      hlen;
    char        host[128];

    end        = strpbrk(host_start, "/:?");
    hlen       = end ? (size_t)(end - host_start) : strlen(host_start);
    if (hlen == 0 || hlen >= sizeof(host)) return 0;
    memcpy(host, host_start, hlen);
    host[hlen] = '\0';

    for (int i = 0; INSTALL_URI_HOSTS[i]; i++) {
        size_t alen = strlen(INSTALL_URI_HOSTS[i]);
        if (hlen == alen && !strcasecmp(host, INSTALL_URI_HOSTS[i])) return 1;
        if (hlen > alen + 1 &&
            host[hlen - alen - 1] == '.' &&
            !strcasecmp(host + hlen - alen, INSTALL_URI_HOSTS[i])) return 1;
    }
    return 0;
}

static int
install_uri_safe(const char *uri) {
    return uri && !strncmp(uri, "https://", 8) && cdn_host_ok(uri + 8);
}

typedef struct {
    int      fd;
    uint64_t start;
    uint64_t size;
    char     title_id[16];
    int      is_pkg;       /* the package itself (not the .crc) */
    time_t   noted;        /* last time progress was published */
    uint64_t counted;      /* bytes of this response already counted as read */
} pkg_reader_t;

static void note_pkg_served(pkg_reader_t *r, uint64_t sent);

static ssize_t
pkg_reader_cb(void *cls, uint64_t pos, char *buf, size_t max) {
    pkg_reader_t *r = (pkg_reader_t *)cls;
    uint64_t rem;
    ssize_t n;

    if (!r || pos >= r->size)
        return MHD_CONTENT_READER_END_WITH_ERROR;

    rem = r->size - pos;
    if ((uint64_t)max > rem)
        max = (size_t)rem;

    n = pread(r->fd, buf, max, (off_t)(r->start + pos));
    if (n <= 0)
        return MHD_CONTENT_READER_END_WITH_ERROR;
    /* max once a second plus at the end, so long requests don't look idle */
    if (time(NULL) != r->noted || pos + (uint64_t)n >= r->size) {
        r->noted = time(NULL);
        note_pkg_served(r, pos + (uint64_t)n);
    }
    return n;
}

static void
pkg_reader_free(void *cls) {
    pkg_reader_t *r = (pkg_reader_t *)cls;
    if (!r) return;
    close(r->fd);
    free(r);
}

static void
record_pkg_diag(const char *url, const char *range, unsigned int status,
                uint64_t start, uint64_t end, uint64_t total) {
    pthread_mutex_lock(&g_mutex);
    g_pkg_hits++;
    snprintf(g_pkg_diag_json, sizeof(g_pkg_diag_json),
             "{\"hits\":%lu,\"url\":\"%.220s\",\"range\":\"%.160s\","
             "\"status\":%u,\"start\":%llu,\"end\":%llu,\"total\":%llu}",
             g_pkg_hits, url ? url : "", range ? range : "", status,
             (unsigned long long)start,
             (unsigned long long)end,
             (unsigned long long)total);
    snprintf(g_pkg_log[g_pkg_log_next++ % PKG_LOG_LINES], sizeof(g_pkg_log[0]),
             "%u %.120s %.40s", status, url ? url : "", range ? range : "");
    if (url && !strncmp(url, "/api/pkg/", 9)) {
        size_t ul = strlen(url);
        snprintf(g_pkg_last_tid, sizeof g_pkg_last_tid, "%.9s", url + 9);
        g_pkg_last_time = time(NULL);
        install_stream_t *st = stream_find(url + 9);
        if (st) {
            st->last = g_pkg_last_time;
            if (ul > 4 && !strcmp(url + ul - 4, ".crc") && status < 300)
                st->crc = 1;
        }
    }
    pthread_mutex_unlock(&g_mutex);
}

/* console is still reading, for a tracked install this is its progress */
static void
note_pkg_served(pkg_reader_t *r, uint64_t sent) {
    pthread_mutex_lock(&g_mutex);
    snprintf(g_pkg_last_tid, sizeof g_pkg_last_tid, "%s", r->title_id);
    g_pkg_last_time = r->noted;
    if (r->is_pkg) {
        install_stream_t *st = stream_find(r->title_id);
        if (st) {
            st->last = r->noted;
            stream_cover(st, (long long)(r->start + r->counted),
                         (long long)(r->start + sent));
        }
    }
    r->counted = sent;
    pthread_mutex_unlock(&g_mutex);
}

/* fetched in the last minute. per title, the last-request check covers
   installs from before a restart */
static int
install_reading(const char *title_id) {
    const install_stream_t *st;
    time_t now = time(NULL);
    int    busy;
    pthread_mutex_lock(&g_mutex);
    st   = stream_find(title_id);
    /* own installs stay protected until checked or stalled */
    busy = (st && (st->claiming ||
                   (!st->checked && strcmp(stream_phase(st, now), "stalled")))) ||
           (g_pkg_last_tid[0] && !strncmp(g_pkg_last_tid, title_id, 9) &&
            now - g_pkg_last_time < INSTALL_QUIET_SECS);
    pthread_mutex_unlock(&g_mutex);
    return busy;
}

/* serve a downloaded pkg back to Sony's installer over localhost */
static enum MHD_Result
queue_pkg_file(struct MHD_Connection *conn, const char *url) {
    const char *prefix = "/api/pkg/";
    const char *p, *slash;
    char title_id[32], file[160], path[360];
    size_t len;
    struct stat st;
    int fd;
    const char *range;
    uint64_t total, start = 0, end = 0, send_size = 0;
    unsigned int status = MHD_HTTP_OK;
    char content_range[96];
    struct MHD_Response *resp;
    pkg_reader_t *reader;
    enum MHD_Result ret;

    if (strncmp(url, prefix, strlen(prefix)))
        return queue_text(conn, MHD_HTTP_NOT_FOUND, "not found");
    p = url + strlen(prefix);
    slash = strchr(p, '/');
    if (!slash || slash == p || !slash[1])
        return queue_text(conn, MHD_HTTP_NOT_FOUND, "not found");

    len = (size_t)(slash - p);
    if (len >= sizeof(title_id))
        return queue_text(conn, MHD_HTTP_NOT_FOUND, "not found");
    memcpy(title_id, p, len);
    title_id[len] = '\0';

    len = strlen(slash + 1);
    if (len >= sizeof(file))
        return queue_text(conn, MHD_HTTP_NOT_FOUND, "not found");
    memcpy(file, slash + 1, len + 1);

    if (!path_segment_safe(title_id) || !path_segment_safe(file))
        return queue_text(conn, MHD_HTTP_FORBIDDEN, "forbidden");

    {
        char dir[160];
        title_dir(title_id, dir, sizeof dir);
        snprintf(path, sizeof(path), "%s/%s", dir, file);
    }
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        record_pkg_diag(url, NULL, MHD_HTTP_NOT_FOUND, 0, 0, 0);
        return queue_text(conn, MHD_HTTP_NOT_FOUND, "not found");
    }
    if (fstat(fd, &st) || st.st_size <= 0) {
        close(fd);
        return queue_text(conn, MHD_HTTP_NOT_FOUND, "not found");
    }

    total = (uint64_t)st.st_size;
    end = total - 1;
    send_size = total;

    range = MHD_lookup_connection_value(conn, MHD_HEADER_KIND,
                                        MHD_HTTP_HEADER_RANGE);
    if (range && !strncmp(range, "bytes=", 6)) {
        const char *spec = range + 6;
        char *dash = strchr(spec, '-');
        if (!dash || strchr(dash + 1, ',')) {
            close(fd);
            return queue_text(conn, MHD_HTTP_RANGE_NOT_SATISFIABLE, "invalid range");
        }

        if (dash == spec) {
            uint64_t suffix = strtoull(dash + 1, NULL, 10);
            if (!suffix) {
                close(fd);
                return queue_text(conn, MHD_HTTP_RANGE_NOT_SATISFIABLE, "invalid range");
            }
            start = suffix >= total ? 0 : total - suffix;
        } else {
            start = strtoull(spec, NULL, 10);
            if (dash[1])
                end = strtoull(dash + 1, NULL, 10);
        }

        if (start >= total || end < start) {
            close(fd);
            return queue_text(conn, MHD_HTTP_RANGE_NOT_SATISFIABLE, "range not satisfiable");
        }
        if (end >= total) end = total - 1;
        send_size = end - start + 1;
        status = 206;
    }
    record_pkg_diag(url, range, status, start, end, total);

    reader = calloc(1, sizeof(*reader));
    if (!reader) {
        close(fd);
        return queue_text(conn, MHD_HTTP_INTERNAL_SERVER_ERROR, "oom");
    }
    reader->fd    = fd;
    reader->start = start;
    reader->size  = send_size;
    snprintf(reader->title_id, sizeof reader->title_id, "%.9s", title_id);
    {
        size_t fl = strlen(file);
        reader->is_pkg = fl > 4 && !strcmp(file + fl - 4, ".pkg");
    }

    resp = MHD_create_response_from_callback(send_size, 65536,
                                             pkg_reader_cb, reader,
                                             pkg_reader_free);
    if (!resp) {
        close(fd);
        free(reader);
        return MHD_NO;
    }
    MHD_add_response_header(resp, MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN, "*");
    MHD_add_response_header(resp, MHD_HTTP_HEADER_CACHE_CONTROL, "no-store");
    MHD_add_response_header(resp, MHD_HTTP_HEADER_CONTENT_TYPE, "application/octet-stream");
    MHD_add_response_header(resp, MHD_HTTP_HEADER_ACCEPT_RANGES, "bytes");
    if (status == 206) {
        snprintf(content_range, sizeof(content_range), "bytes %llu-%llu/%llu",
                 (unsigned long long)start,
                 (unsigned long long)end,
                 (unsigned long long)total);
        MHD_add_response_header(resp, MHD_HTTP_HEADER_CONTENT_RANGE, content_range);
    }
    ret = MHD_queue_response(conn, status, resp);
    MHD_destroy_response(resp); /* pkg_reader_free closes fd */
    return ret;
}


/* a folder that doesn't exist yet counts as its closest existing parent */
static int
statvfs_up(const char *path, struct statvfs *vfs) {
    char p[288], *slash;
    snprintf(p, sizeof p, "%s", path);
    for (;;) {
        if (statvfs(p, vfs) == 0) return 0;
        if (!(slash = strrchr(p, '/')) || slash == p) return -1;
        *slash = '\0';
    }
}

static long long
drive_free_mb(const char *path) {
    struct statvfs vfs;
    if (statvfs_up(path, &vfs)) return 0;
    return (long long)(((unsigned long long)vfs.f_bavail *
                        (unsigned long long)vfs.f_frsize) / (1024ULL * 1024ULL));
}

/* -1 if unknown. game paths only resolve through the scanner's system root */
static long long
game_free_bytes(const char *game_dir) {
    struct statvfs vfs;
    if (!game_dir[0] || patchdl_scan_sys_statvfs(game_dir, &vfs)) return -1;
    return (long long)((unsigned long long)vfs.f_bavail * (unsigned long long)vfs.f_frsize);
}

/* the two paths live in different fs views, so compare fsid, else size */
static int
same_drive(const char *dl_dir, const char *game_dir) {
    struct statvfs a, b;
    if (!game_dir[0] || statvfs_up(dl_dir, &a) || patchdl_scan_sys_statvfs(game_dir, &b))
        return 0;
    if (a.f_fsid && a.f_fsid == b.f_fsid) return 1;
    return a.f_blocks == b.f_blocks && a.f_frsize == b.f_frsize;
}

static long long
data_free_mb(void) {
    char root[64], *slash;
    current_root(root, sizeof root);
    if ((slash = strrchr(root, '/'))) *slash = '\0';
    return drive_free_mb(root);
}

/* headroom, a download never fills the drive to the last byte */
#define PATCHDL_SPACE_MARGIN (2LL * 1024 * 1024 * 1024)

/* extra room for the install on the game's drive. a guess */
#define INSTALL_SPACE_MARGIN (1LL * 1024 * 1024 * 1024)

/* a partial from an earlier run already takes part of it */
static long long
space_needed(const char *path, long long total) {
    struct stat st;
    long long   have = 0;
    if (stat(path, &st) == 0) have = (long long)st.st_blocks * 512;
    return total > have ? total - have : 0;
}

static int
space_ok(const char *dir, long long need, long long *free_out) {
    long long free_b = drive_free_mb(dir) * 1024LL * 1024LL;
    if (free_out) *free_out = free_b;
    return need + PATCHDL_SPACE_MARGIN <= free_b;
}

/* the install needs the pkg size again on the game's drive, shared if same */
static int
download_and_install_fit(const char *dl_dir, const char *game_dir,
                         long long remaining, long long total,
                         long long *need_out, long long *free_out, int *for_install) {
    long long inst = total + INSTALL_SPACE_MARGIN, free_b = 0;
    int       same = same_drive(dl_dir, game_dir);

    *for_install = 0;
    if (!space_ok(dl_dir, remaining + (same ? inst : 0), &free_b)) {
        *need_out    = remaining + (same ? inst : 0);
        *free_out    = free_b;
        *for_install = same;
        return 0;
    }
    if (game_dir[0] && !same) {
        long long gfree = game_free_bytes(game_dir);
        if (gfree >= 0 && gfree < inst) {
            *need_out    = inst;
            *free_out    = gfree;
            *for_install = 1;
            return 0;
        }
    }
    *need_out = remaining;
    *free_out = free_b;
    return 1;
}

/* LAN IP for the phone link. connecting a UDP socket sends nothing, it
   just picks the interface */
static void
lan_ipv4(char *out, size_t sz) {
    struct sockaddr_in a;
    socklen_t          len = sizeof a;
    int                s = socket(AF_INET, SOCK_DGRAM, 0);

    out[0] = '\0';
    if (s < 0) return;
    memset(&a, 0, sizeof a);
    a.sin_family      = AF_INET;
    a.sin_port        = htons(53);
    a.sin_addr.s_addr = htonl(0x01010101);
    if (connect(s, (struct sockaddr *)&a, sizeof a) == 0 &&
        getsockname(s, (struct sockaddr *)&a, &len) == 0 &&
        !inet_ntop(AF_INET, &a.sin_addr, out, (socklen_t)sz))
        out[0] = '\0';
    close(s);
}

/* title id folders only, <drive>/patchdl also holds the "db" folder */
static int
is_title_dir_name(const char *n) {
    if (strlen(n) != 9) return 0;
    for (int i = 0; i < 4; i++) if (n[i] < 'A' || n[i] > 'Z') return 0;
    for (int i = 4; i < 9; i++) if (n[i] < '0' || n[i] > '9') return 0;
    return 1;
}

/* all drives, for the storage tile */
static long long
downloads_bytes(void) {
    DIR           *d, *sd;
    struct dirent *de, *fe;
    struct stat    st;
    char           dir[288], path[560];
    long long      sum = 0;

    char           drives[MAX_DRIVES][32], root[64];
    int            nd = list_drives(drives, MAX_DRIVES);

    for (int k = 0; k < nd; k++) {
        snprintf(root, sizeof root, "%s/patchdl", drives[k]);
        if (!(d = opendir(root))) continue;
        while ((de = readdir(d))) {
            if (!is_title_dir_name(de->d_name)) continue;
            snprintf(dir, sizeof dir, "%s/%s", root, de->d_name);
            if (!(sd = opendir(dir))) continue;
            while ((fe = readdir(sd))) {
                if (fe->d_name[0] == '.') continue;
                snprintf(path, sizeof path, "%s/%s", dir, fe->d_name);
                if (!stat(path, &st) && S_ISREG(st.st_mode)) sum += (long long)st.st_size;
            }
            closedir(sd);
        }
        closedir(d);
    }
    return sum;
}

static unsigned long
titles_gen(void) {
    unsigned long g;
    pthread_mutex_lock(&g_mutex);
    g = g_titles_gen;
    pthread_mutex_unlock(&g_mutex);
    return g;
}

static char *
build_status_json(void) {
    char  ip[INET_ADDRSTRLEN], root[64];
    char *out = malloc(896);
    if (!out) return NULL;
    lan_ipv4(ip, sizeof ip);
    current_root(root, sizeof root);
    snprintf(out, 896,
             "{\"firmware\":\"%s\","
             "\"firmware_build\":\"0x%08x\","
             "\"dns_guard\":\"Active\","
             "\"resolver\":\"Internal allowlist\","
             "\"free_space_mb\":%lld,"
             "\"download_dir\":\"%s\","
             "\"lan_ip\":\"%s\","
             "\"http_port\":%d,"
             "\"version\":\"%s\","
             "\"titles_gen\":%lu,"
             "\"downloads_bytes\":%lld,"
             "\"rescan_ms\":[%ld,%ld,%ld],"
             "\"rescan_step\":\"%s / %s\",\"rescan_running_ms\":%ld,"
             "\"web_restarts\":%u}",
             g_fw.str, g_fw.bin, data_free_mb(), root, ip, PATCHDL_HTTP_PORT,
             PATCHDL_VERSION, titles_gen(), downloads_bytes(),
             g_rescan_ms[0], g_rescan_ms[1], g_rescan_ms[2],
             g_rescan_step, patchdl_scan_step(),
             strcmp(g_rescan_step, "idle") ? mono_ms() - g_rescan_since : 0L,
             g_web_restarts);
    return out;
}


/* policy + allowlist come from config_tail_json */
static char *
build_config_json(void) {
    char head[384], root[64];

    current_root(root, sizeof root);
    pthread_mutex_lock(&g_mutex);
    snprintf(head, sizeof(head),
             "{\"default_policy\":\"%s\","
             "\"install_after_download\":%s,"
             "\"delete_pkg_after_install\":%s,"
             "\"verify_downloads\":%s,"
             "\"home_shortcut\":%s,"
             "\"max_connections\":%d,"
             "\"download_drive\":\"%s\",\"download_dir\":\"%s\",",
             g_cfg.default_policy[0] ? g_cfg.default_policy : "deny",
             g_cfg.install_after_download ? "true" : "false",
             g_cfg.delete_pkg_after_install ? "true" : "false",
             g_cfg.verify_downloads ? "true" : "false",
             g_cfg.home_shortcut ? "true" : "false",
             g_cfg.max_connections, g_cfg.download_drive, root);
    pthread_mutex_unlock(&g_mutex);

    char *out = malloc(strlen(head) + sizeof(config_tail_json));
    if (!out) return NULL;
    strcpy(out, head);
    strcat(out, config_tail_json);
    return out;
}

/* takes g_mutex itself, don't call with it held */
static void
save_config(void) {
    FILE *f;

    mkdir(PATCHDL_DATA_DIR, 0777);
    f = fopen(PATCHDL_CFG_PATH, "w");
    if (!f) return;

    pthread_mutex_lock(&g_mutex);
    fprintf(f,
            "{\n\"default_policy\":\"%s\",\n"
            "\"install_after_download\":%s,\n"
            "\"delete_pkg_after_install\":%s,\n"
            "\"verify_downloads\":%s,\n"
            "\"home_shortcut\":%s,\n"
            "\"max_connections\":%d,\n\"download_drive\":\"%s\",\n\"titles\":{",
            g_cfg.default_policy[0] ? g_cfg.default_policy : "deny",
            g_cfg.install_after_download ? "true" : "false",
            g_cfg.delete_pkg_after_install ? "true" : "false",
            g_cfg.verify_downloads ? "true" : "false",
            g_cfg.home_shortcut ? "true" : "false",
            g_cfg.max_connections, g_cfg.download_drive);
    for (size_t i = 0; i < g_title_count; i++)
        fprintf(f, "%s\"%s\":%s", i ? "," : "",
                g_titles[i].title_id, g_titles[i].enabled ? "true" : "false");
    /* kept separate so a switch saved before sideloads defaulted to off
       can't turn one on */
    fprintf(f, "},\n\"sideload_updates\":{");
    for (size_t i = 0, n = 0; i < g_title_count; i++)
        if (g_titles[i].sideloaded && g_titles[i].enabled)
            fprintf(f, "%s\"%s\":true", n++ ? "," : "", g_titles[i].title_id);
    fprintf(f, "}\n}\n");
    pthread_mutex_unlock(&g_mutex);

    fclose(f);
}

/* one switch per title, so no fixed buffer */
static char *
read_config_file(void) {
    FILE  *f = fopen(PATCHDL_CFG_PATH, "r");
    long   len;
    char  *buf;
    size_t n;

    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) || (len = ftell(f)) < 0 || len > 1024 * 1024 ||
        fseek(f, 0, SEEK_SET) || !(buf = malloc((size_t)len + 1))) {
        fclose(f);
        return NULL;
    }
    n = fread(buf, 1, (size_t)len, f);
    fclose(f);
    buf[n] = '\0';
    return buf;
}

/* "titles" for normal ones, "sideload_updates" for sideloads */
static void
overlay_title_policy(const char *cfg, patchdl_title_t *arr, size_t cnt) {
    const char *titles = strstr(cfg, "\"titles\"");
    const char *side   = strstr(cfg, "\"sideload_updates\"");
    for (size_t i = 0; i < cnt; i++) {
        if (arr[i].sideloaded)   /* off unless switched on as sideloaded */
            arr[i].enabled = side ? json_get_bool(side, arr[i].title_id, 0) : 0;
        else if (titles)
            arr[i].enabled = json_get_bool(titles, arr[i].title_id, arr[i].enabled);
    }
}

/* startup only, after the scan, still single-threaded */
static void
load_config(void) {
    char  *buf = read_config_file();
    char   pol[8];

    if (!buf) return;

    json_get_str(buf, "default_policy", pol, sizeof(pol));
    if (pol[0]) {
        strncpy(g_cfg.default_policy, pol, sizeof(g_cfg.default_policy) - 1);
        g_cfg.default_policy[sizeof(g_cfg.default_policy) - 1] = '\0';
    }
    g_cfg.install_after_download =
        json_get_bool(buf, "install_after_download", g_cfg.install_after_download);
    g_cfg.delete_pkg_after_install =
        json_get_bool(buf, "delete_pkg_after_install", g_cfg.delete_pkg_after_install);
    g_cfg.verify_downloads =
        json_get_bool(buf, "verify_downloads", g_cfg.verify_downloads);
    g_cfg.home_shortcut =
        json_get_bool(buf, "home_shortcut", g_cfg.home_shortcut);
    g_cfg.max_connections =
        json_get_int(buf, "max_connections", g_cfg.max_connections);
    if (g_cfg.max_connections < 1) g_cfg.max_connections = 1;
    if (g_cfg.max_connections > POOL_MAX_CONN) g_cfg.max_connections = POOL_MAX_CONN;
    {
        char drive[32] = "";
        json_get_str(buf, "download_drive", drive, sizeof drive);
        if (drive_name_ok(drive)) {
            pthread_mutex_lock(&g_drive_mtx);
            snprintf(g_cfg.download_drive, sizeof g_cfg.download_drive, "%s", drive);
            pthread_mutex_unlock(&g_drive_mtx);
        }
    }

    overlay_title_policy(buf, g_titles, g_title_count);
    free(buf);
}

/* unknown sources start off, a saved choice wins, fakes stay off */
static void
apply_title_policy(patchdl_title_t *arr, size_t cnt) {
    char *buf = read_config_file();

    for (size_t i = 0; i < cnt; i++)
        arr[i].enabled = (arr[i].source_type != PATCHDL_SOURCE_UNKNOWN) &&
                         !arr[i].sideloaded;
    overlay_title_policy(buf ? buf : "", arr, cnt);
    free(buf);
    for (size_t i = 0; i < cnt; i++)
        if (arr[i].source_type == PATCHDL_SOURCE_FAKE)
            arr[i].enabled = 0;
}


/* a pasted link counts while it's newer than installed, stays until Cancel */
static int
manual_pending(const patchdl_title_t *t) {
    return t->manual_url[0] &&
           strcmp(t->manual_version, t->installed_version) > 0;
}

static const char *
title_status_str(const patchdl_title_t *t) {
    if (!t->verxml_done)                          return "checking";
    /* a mounted image can't take a patch, same as fake */
    if (t->source_type == PATCHDL_SOURCE_UNKNOWN ||
        t->source_type == PATCHDL_SOURCE_FAKE ||
        t->source_type == PATCHDL_SOURCE_SHADOWMOUNT) return "blocked";
    if (t->compatible_version[0]) {
        /* versions are zero-padded (01.000.011), strcmp orders them */
        if (t->installed_version[0] &&
            strcmp(t->compatible_version, t->installed_version) <= 0) {
            /* a newer patch exists but needs newer firmware */
            if (t->latest_version[0] &&
                strcmp(t->latest_version, t->installed_version) > 0)
                return "incompatible_fw";
            return "up_to_date";
        }
        return "available";
    }
    if (t->latest_version[0]) {
        if (t->installed_version[0] &&
            strcmp(t->latest_version, t->installed_version) <= 0)
            return "up_to_date";
        return "incompatible_fw";
    }
    return "no_update";
}

static const char *
title_mode_str(patchdl_source_t src) {
    switch (src) {
    case PATCHDL_SOURCE_SHADOWMOUNT: return "disabled";
    case PATCHDL_SOURCE_UNKNOWN:     return "disabled";
    case PATCHDL_SOURCE_FAKE:        return "disabled";
    default:                          return "latest_compatible";
    }
}

static char *
build_titles_json(void) {
    jbuf_t j = {0};

    pthread_mutex_lock(&g_mutex);

    jbuf_append(&j, "[");
    for (size_t i = 0; i < g_title_count; i++) {
        const patchdl_title_t *t = &g_titles[i];
        if (i > 0) jbuf_append(&j, ",");
        jbuf_append(&j, "{");
        jbuf_append(&j, "\"title_id\":");      jbuf_append_str(&j, t->title_id);
        jbuf_append(&j, ",\"name\":");          jbuf_append_str(&j, t->name);
        jbuf_append(&j, ",\"content_id\":");   jbuf_append_str(&j, t->content_id);
        jbuf_append(&j, ",\"installed_version\":");
            jbuf_append_ver_or_null(&j, t->installed_version);
        jbuf_append(&j, ",\"compatible_version\":");
            jbuf_append_ver_or_null(&j, t->compatible_version);
        jbuf_append(&j, ",\"latest_version\":");
            jbuf_append_ver_or_null(&j, t->latest_version);
        jbuf_append(&j, ",\"latest_required_fw\":");
            jbuf_append_ver_or_null(&j, t->latest_required_fw);
        jbuf_append(&j, ",\"source_type\":");
            jbuf_append_str(&j, patchdl_source_str(t->source_type));
        jbuf_append(&j, t->icon_fd >= 0 ? ",\"has_icon\":true" : ",\"has_icon\":false");
        jbuf_append(&j, ",\"pkg_sign\":");
            jbuf_append_str(&j, t->pkg_sign == PATCHDL_PKG_RETAIL ? "retail"
                              : t->pkg_sign == PATCHDL_PKG_FAKE   ? "fake"
                              : t->pkg_sign == PATCHDL_PKG_UNREAD ? "unreadable"
                                                                  : "none");
        jbuf_append(&j, ",\"source_path\":");  jbuf_append_str(&j, t->source_path);
        jbuf_append(&j, ",\"mount_from\":");   jbuf_append_str(&j, t->mount_from);
        jbuf_append(&j, ",\"version_file_uri\":");
            jbuf_append_ver_or_null(&j, t->version_file_uri);
        jbuf_append(&j, ",\"patch_title_id\":");
            jbuf_append_ver_or_null(&j, t->patch_title_id);
        jbuf_append(&j, ",\"patch_storage_title_id\":");
            jbuf_append_ver_or_null(&j, t->patch_storage_title_id);
        jbuf_appendf(&j, ",\"patch_storage_match\":%s",
                     (!t->patch_storage_title_id[0] ||
                      !strncmp(t->patch_storage_title_id, t->title_id, 9)) ? "true" : "false");
        /* patch_title_id is from version.xml. the CDN storage id may differ by
           region and must not block the match */
        jbuf_appendf(&j, ",\"patch_title_match\":%s",
                     (!t->patch_title_id[0] ||
                      !strncmp(t->patch_title_id, t->title_id, 9)) ? "true" : "false");
        jbuf_append(&j, ",\"prospero_version\":");
            jbuf_append_ver_or_null(&j, t->prospero_version);
        jbuf_append(&j, ",\"prospero_required_fw\":");
            jbuf_append_ver_or_null(&j, t->prospero_required_fw);
        jbuf_append(&j, ",\"prospero_size\":");
            jbuf_append_ver_or_null(&j, t->prospero_size);
        jbuf_appendf(&j, ",\"prospero_done\":%s",
                     t->prospero_done ? "true" : "false");
        jbuf_append(&j, ",\"manual_version\":");
            jbuf_append_ver_or_null(&j, manual_pending(t) ? t->manual_version : "");
        jbuf_appendf(&j, ",\"enabled\":%s", t->enabled ? "true" : "false");
        jbuf_appendf(&j, ",\"resumable\":%s", t->resumable ? "true" : "false");
        jbuf_appendf(&j, ",\"partial_bytes\":%lld", t->partial_bytes);
        jbuf_appendf(&j, ",\"downloaded\":%s", t->downloaded ? "true" : "false");
        jbuf_appendf(&j, ",\"sideloaded\":%s", t->sideloaded ? "true" : "false");
        jbuf_append(&j, ",\"mode\":");
            jbuf_append_str(&j, title_mode_str(t->source_type));
        jbuf_append(&j, ",\"queued\":false");
        jbuf_append(&j, ",\"status\":");
            jbuf_append_str(&j, title_status_str(t));
        jbuf_append(&j, "}");
    }
    jbuf_append(&j, "]");

    pthread_mutex_unlock(&g_mutex);
    return j.buf;
}

static const char *
job_state_str(job_state_t s) {
    switch (s) {
    case JOB_QUEUED:     return "queued";
    case JOB_ADMITTING:  return "active";
    case JOB_ACTIVE:     return "active";
    case JOB_PAUSING:    return "active";
    case JOB_CANCELLING: return "active";
    case JOB_PAUSED:     return "paused";
    case JOB_DONE:       return "done";
    default:             return "error";
    }
}

/* live bytes = committed + in flight */
static char *
build_downloads_json(void) {
    jbuf_t j = {0};

    pthread_mutex_lock(&g_pool.mtx);
    jbuf_append(&j, "[");
    int first = 1;
    for (dl_job_t *job = g_pool.jobs; job; job = job->next) {
        long long bytes = job->done_bytes, total = job->total;
        int progress;
        if (job == g_pool.active)
            for (int s = 0; s < g_pool.n_workers; s++)
                bytes += g_pool.inflight_bytes[s];
        /* started pieces, paused jobs too */
        if (job->ps)
            for (int i = 0; i < job->mf.count; i++)
                if (job->ps[i].state == PC_PENDING) bytes += job->ps[i].have;
        if (job->verifying) bytes = job->verify_bytes;
        if (total > 0) {
            progress = (int)((bytes * 100) / total);
            if (progress < 0) progress = 0;
            if (progress > 100) progress = 100;
        } else {
            progress = (job->state == JOB_DONE) ? 100 : 0;
        }
        if (!first) jbuf_append(&j, ",");
        first = 0;
        jbuf_append(&j, "{");
        jbuf_append(&j, "\"title_id\":");  jbuf_append_str(&j, job->title_id);
        jbuf_append(&j, ",\"name\":");      jbuf_append_str(&j, job->name);
        jbuf_append(&j, ",\"version\":");   jbuf_append_str(&j, job->version);
        jbuf_append(&j, ",\"state\":");     jbuf_append_str(&j, job_state_str(job->state));
        jbuf_appendf(&j, ",\"progress\":%d", progress);
        if (job->verifying) jbuf_append(&j, ",\"verifying\":true");
        if (job->state == JOB_ACTIVE && job->ps) {
            long now = mono_ms();
            int  waiting = 0;
            for (int i = 0; i < job->mf.count; i++)
                if (job->ps[i].state == PC_PENDING && job->ps[i].retry_at > now) waiting++;
            if (waiting) jbuf_appendf(&j, ",\"waiting\":%d", waiting);
        }
        jbuf_appendf(&j, ",\"bytes\":%lld,\"total_bytes\":%lld", bytes, total);
        jbuf_appendf(&j, ",\"rc\":%d,\"last_curl_rc\":%d,\"last_http_code\":%ld",
                     job->rc, job->last_curl_rc, job->last_http_code);
        if (job->rc == -3)
            jbuf_appendf(&j, ",\"need_bytes\":%lld,\"free_bytes\":%lld%s",
                         job->need_bytes, job->free_bytes,
                         job->space_install ? ",\"space_install\":true" : "");
        if (job->fail_step[0]) {
            jbuf_append(&j, ",\"fail_step\":");
            jbuf_append_str(&j, job->fail_step);
        }
        jbuf_append(&j, "}");
    }
    jbuf_append(&j, "]");
    pthread_mutex_unlock(&g_pool.mtx);
    return j.buf;
}


static void *
verxml_fetch_thread(void *arg) {
    (void)arg;

    for (size_t i = 0; i < g_title_count; i++) {
        patchdl_title_t  *t = &g_titles[i];
        char              url[512] = {0};
        patchdl_verinfo_t info;

        if (g_verxml_stop) break;   /* stop before the next blocking query */
        /* done before a rescan, maybe only the Prospero lookup is left */
        if (t->verxml_done &&
            (t->prospero_done || strcmp(title_status_str(t), "incompatible_fw")))
            continue;
        memset(&info, 0, sizeof(info));


        /* version.xml URL from app.db (with UUID), resolver as fallback */
        if (t->version_file_uri[0])
            patchdl_verxml_query(t->version_file_uri, g_fw.bin, &info);
        else if (!patchdl_resolve_url(t->title_id, url, sizeof(url)))
            patchdl_verxml_query(url, g_fw.bin, &info);

        pthread_mutex_lock(&g_mutex);
        strncpy(t->compatible_version, info.compatible_version,
                sizeof(t->compatible_version) - 1);
        strncpy(t->latest_version,     info.latest_version,
                sizeof(t->latest_version) - 1);
        strncpy(t->latest_required_fw, info.latest_required_fw,
                sizeof(t->latest_required_fw) - 1);
        strncpy(t->patch_url,          info.compatible_url,
                sizeof(t->patch_url) - 1);
        strncpy(t->delta_url,          info.delta_url,
                sizeof(t->delta_url) - 1);
        strncpy(t->patch_title_id,     info.compatible_title,
                sizeof(t->patch_title_id) - 1);
        strncpy(t->patch_storage_title_id, info.compatible_storage_title,
                sizeof(t->patch_storage_title_id) - 1);
        t->verxml_done = 1;
        g_titles_gen++;
        pthread_mutex_unlock(&g_mutex);

        /* no auto cleanup: app.db may show the new version while the patch
           never got applied */

        /* latest needs newer fw: ask Prospero Patches for the whole history */
        if (g_verxml_stop) break;
        if (!strcmp(title_status_str(t), "incompatible_fw") &&
            t->source_type != PATCHDL_SOURCE_FAKE &&
            t->source_type != PATCHDL_SOURCE_UNKNOWN) {
            patchdl_prospero_result_t pp;
            if (!patchdl_prospero_query(t->title_id, g_fw.bin, &pp) &&
                pp.found && strcmp(pp.version, t->installed_version) > 0) {
                pthread_mutex_lock(&g_mutex);
                strncpy(t->prospero_version, pp.version,
                        sizeof(t->prospero_version) - 1);
                strncpy(t->prospero_required_fw, pp.required_fw,
                        sizeof(t->prospero_required_fw) - 1);
                strncpy(t->prospero_size, pp.size, sizeof(t->prospero_size) - 1);
                pthread_mutex_unlock(&g_mutex);
            }
            pthread_mutex_lock(&g_mutex);
            t->prospero_done = 1;
            g_titles_gen++;
            pthread_mutex_unlock(&g_mutex);
        }
    }
    return NULL;
}


/* snapshot under the lock, 1 if found */
static int
get_title_action_info(const char *title_id, patchdl_source_t *src,
                      char *patch_url, size_t url_sz,
                      char *delta_url, size_t durl_sz,
                      char *patch_title_id, size_t pt_sz,
                      char *patch_storage_title_id, size_t pst_sz,
                      char *content_id, size_t ci_sz,
                      char *name, size_t name_sz,
                      char *version, size_t ver_sz,
                      int *enabled) {
    int found = 0;

    pthread_mutex_lock(&g_mutex);
    for (size_t i = 0; i < g_title_count; i++) {
        if (!strcmp(g_titles[i].title_id, title_id)) {
            *src = g_titles[i].source_type;
            strncpy(patch_url, g_titles[i].patch_url, url_sz - 1);
            patch_url[url_sz - 1] = '\0';
            strncpy(delta_url, g_titles[i].delta_url, durl_sz - 1);
            delta_url[durl_sz - 1] = '\0';
            strncpy(patch_title_id, g_titles[i].patch_title_id, pt_sz - 1);
            patch_title_id[pt_sz - 1] = '\0';
            strncpy(patch_storage_title_id, g_titles[i].patch_storage_title_id, pst_sz - 1);
            patch_storage_title_id[pst_sz - 1] = '\0';
            strncpy(content_id, g_titles[i].content_id, ci_sz - 1);
            content_id[ci_sz - 1] = '\0';
            strncpy(name, g_titles[i].name, name_sz - 1);
            name[name_sz - 1] = '\0';
            strncpy(version, g_titles[i].compatible_version, ver_sz - 1);
            version[ver_sz - 1] = '\0';
            if (manual_pending(&g_titles[i])) {
                /* pasted link wins, it's the title's own pkg (checked on submit) */
                snprintf(patch_url, url_sz, "%s", g_titles[i].manual_url);
                delta_url[0] = '\0';
                snprintf(patch_title_id, pt_sz, "%.9s", title_id);
                snprintf(patch_storage_title_id, pst_sz, "%.9s", title_id);
                snprintf(version, ver_sz, "%s", g_titles[i].manual_version);
            }
            *enabled = g_titles[i].enabled;
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_mutex);
    return found;
}

static enum MHD_Result
set_title_enabled(struct MHD_Connection *conn, const char *title_id, int en) {
    int found = 0;
    char r[64];

    pthread_mutex_lock(&g_mutex);
    for (size_t i = 0; i < g_title_count; i++) {
        if (!strcmp(g_titles[i].title_id, title_id)) {
            /* fakes stay off */
            if (g_titles[i].source_type == PATCHDL_SOURCE_FAKE) en = 0;
            g_titles[i].enabled = en;
            found = 1;
            break;
        }
    }
    pthread_mutex_unlock(&g_mutex);

    if (!found) return queue_text(conn, MHD_HTTP_NOT_FOUND, "unknown title");

    save_config();
    snprintf(r, sizeof(r), "{\"ok\":true,\"enabled\":%s}", en ? "true" : "false");
    return queue_json_owned(conn, MHD_HTTP_OK, strdup(r));
}

/* the name comes from the CDN, validate it or a bad version.xml walks
   out of the folder */
static void
title_pkg_path(const char *title_id, const char *patch_url,
               char *out, size_t out_sz) {
    const char *base = strrchr(patch_url, '/');
    char name[192];
    size_t n;

    base = base ? base + 1 : "";
    snprintf(name, sizeof(name), "%s", base);
    n = strlen(name);
    if (n > 5 && !strcmp(name + n - 5, ".json"))
        snprintf(name + n - 5, sizeof(name) - (n - 5), ".pkg");
    if (!name[0] || !path_segment_safe(name)) {
        snprintf(name, sizeof(name), "%s.pkg",
                 path_segment_safe(title_id) ? title_id : "patch");
    }
    {
        char dir[160];
        title_dir(title_id, dir, sizeof dir);
        snprintf(out, out_sz, "%s/%s", dir, name);
    }
}

static int
url_is_manifest(const char *url) {
    size_t n = url ? strlen(url) : 0;
    return n > 5 && !strcmp(url + n - 5, ".json");
}



static void
title_state_path(const char *title_id, char *out, size_t sz) {
    char dir[160];
    title_dir(title_id, dir, sizeof dir);
    snprintf(out, sz, "%s/state.json", dir);
}

static void
remove_dl_state(const char *title_id) {
    char path[320];
    title_state_path(title_id, path, sizeof(path));
    unlink(path);
}

/* only ever touches <drive>/patchdl/<title> */
static void remove_dir_files(const char *dir);

static void
remove_title_dir(const char *title_id) {
    char dir[288];
    if (!path_segment_safe(title_id)) return;
    title_dir(title_id, dir, sizeof dir);
    remove_dir_files(dir);
}

static void
remove_dir_files(const char *dir) {
    char           path[560];
    DIR           *d;
    struct dirent *e;
    if ((d = opendir(dir))) {
        while ((e = readdir(d))) {
            if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
                continue;
            snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
            unlink(path);
        }
        closedir(d);
    }
    rmdir(dir);
}


static void
manual_source_path(const char *title_id, char *out, size_t sz) {
    char dir[160];
    title_dir(title_id, dir, sizeof dir);
    snprintf(out, sz, "%s/manual.json", dir);
}

/* next to the download so it survives a restart, Cancel deletes it */
static void
save_manual_source(const char *title_id, const char *url, const char *version) {
    char  dir[288], path[320];
    FILE *f;
    title_dir(title_id, dir, sizeof dir);
    make_title_dir(dir);
    manual_source_path(title_id, path, sizeof path);
    if ((f = fopen(path, "w"))) {
        fprintf(f, "{\"url\":\"%s\",\"version\":\"%s\"}\n", url, version);
        fclose(f);
    }
}

static void
set_manual_source(const char *title_id, const char *url, const char *version) {
    pthread_mutex_lock(&g_mutex);
    for (size_t i = 0; i < g_title_count; i++)
        if (!strcmp(g_titles[i].title_id, title_id)) {
            snprintf(g_titles[i].manual_url, sizeof g_titles[i].manual_url, "%s", url);
            snprintf(g_titles[i].manual_version, sizeof g_titles[i].manual_version,
                     "%s", version);
            break;
        }
    pthread_mutex_unlock(&g_mutex);
}

static void
clear_manual_source(const char *title_id) {
    char path[320], dir[288];
    set_manual_source(title_id, "", "");
    manual_source_path(title_id, path, sizeof path);
    unlink(path);
    title_dir(title_id, dir, sizeof dir);
    rmdir(dir);   /* fails while the pkg is still there, cancel removes it */
}

/* list isn't published yet (startup, or a rescan before the swap) */
static void
load_manual_sources(patchdl_title_t *arr, size_t cnt) {
    for (size_t i = 0; i < cnt; i++) {
        patchdl_title_t *t = &arr[i];
        char             path[320], buf[1024];
        FILE            *f;
        size_t           n;

        if (!path_segment_safe(t->title_id)) continue;
        manual_source_path(t->title_id, path, sizeof path);
        if (!(f = fopen(path, "r"))) continue;
        n = fread(buf, 1, sizeof buf - 1, f);
        fclose(f);
        buf[n] = '\0';
        json_get_str(buf, "url", t->manual_url, sizeof t->manual_url);
        json_get_str(buf, "version", t->manual_version, sizeof t->manual_version);
        /* keep it even if app.db shows this version, the install may not have
           applied the patch */
        if (!url_is_manifest(t->manual_url) || !t->manual_version[0])
            t->manual_url[0] = t->manual_version[0] = '\0';
    }
}

/* takes g_mutex, so not with the pool lock held (g_mutex first) */
static void
set_title_resumable(const char *title_id, int resumable, long long bytes) {
    pthread_mutex_lock(&g_mutex);
    for (size_t i = 0; i < g_title_count; i++)
        if (!strcmp(g_titles[i].title_id, title_id)) {
            g_titles[i].resumable = resumable;
            g_titles[i].partial_bytes = bytes;
            break;
        }
    pthread_mutex_unlock(&g_mutex);
}

static void
set_title_downloaded(const char *title_id, int downloaded) {
    pthread_mutex_lock(&g_mutex);
    for (size_t i = 0; i < g_title_count; i++)
        if (!strcmp(g_titles[i].title_id, title_id)) {
            g_titles[i].downloaded = downloaded;
            g_titles_gen++;
            break;
        }
    pthread_mutex_unlock(&g_mutex);
}

static int
version_installed(const char *title_id, const char *version) {
    int done = 0;
    if (!version || !version[0]) return 0;
    pthread_mutex_lock(&g_mutex);
    for (size_t i = 0; i < g_title_count; i++)
        if (!strcmp(g_titles[i].title_id, title_id)) {
            done = g_titles[i].installed_version[0] &&
                   strcmp(g_titles[i].installed_version, version) >= 0;
            break;
        }
    pthread_mutex_unlock(&g_mutex);
    return done;
}

static long long
json_get_ll(const char *s, const char *key, long long dflt) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char *p = strstr(s, pat);
    if (!p) return dflt;
    p = strchr(p + strlen(pat), ':');
    if (!p) return dflt;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p < '0' || *p > '9') return dflt;
    return strtoll(p, NULL, 10);
}

static void
bitmap_to_hex(const unsigned char *bm, int nbytes, char *out, size_t sz) {
    static const char hx[] = "0123456789abcdef";
    int i = 0;
    for (; i < nbytes && (size_t)(2 * i + 2) < sz; i++) {
        out[2 * i]     = hx[(bm[i] >> 4) & 0xf];
        out[2 * i + 1] = hx[bm[i] & 0xf];
    }
    out[2 * i] = '\0';
}

static void
hex_to_bitmap(const char *hex, unsigned char *bm, int nbytes) {
    for (int i = 0; i < nbytes; i++) {
        char a = hex[2 * i], b = a ? hex[2 * i + 1] : 0;
        int  hi, lo;
        if (!a || !b) break;
        hi = (a <= '9') ? a - '0' : (a | 32) - 'a' + 10;
        lo = (b <= '9') ? b - '0' : (b | 32) - 'a' + 10;
        bm[i] = (unsigned char)((hi << 4) | lo);
    }
}

/* set bits were fdatasync'd already. pool lock held, the write is tiny */
static void
write_job_state(const dl_job_t *job) {
    char  path[320], tmp[340], *hex;
    int   nbytes = (job->mf.count + 7) / 8;
    FILE *f;
    if (!job->bitmap) return;
    title_state_path(job->title_id, path, sizeof(path));
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    hex = malloc((size_t)nbytes * 2 + 1);
    if (!hex) return;
    bitmap_to_hex(job->bitmap, nbytes, hex, (size_t)nbytes * 2 + 1);
    f = fopen(tmp, "w");
    if (f) {
        int listed = 0;
        fprintf(f,
                "{\"manifest_url\":\"%s\",\"version\":\"%s\",\"total\":%lld,"
                "\"piece_count\":%d,\"done_bytes\":%lld,\"done\":\"%s\",\"have\":\"",
                job->manifest_url, job->version, job->total, job->mf.count,
                job->done_bytes, hex);
        /* piece:bytes of started pieces, synced bytes only */
        for (int i = 0; job->ps && i < job->mf.count && listed < SIDECAR_MAX_HAVE; i++)
            if (job->ps[i].state != PC_DONE && job->ps[i].have > 0)
                fprintf(f, "%s%d:%lld", listed++ ? "," : "", i, job->ps[i].have);
        fprintf(f, "\"}\n");
        if (fclose(f) == 0) rename(tmp, path);
        else unlink(tmp);
    }
    free(hex);
}

/* finished pieces plus the synced part of started ones. pool lock held */
static long long
partial_bytes_locked(const dl_job_t *job) {
    long long b = job->done_bytes;
    for (int i = 0; job->ps && i < job->mf.count; i++)
        if (job->ps[i].state != PC_DONE) b += job->ps[i].have;
    return b;
}

/* only if it's for this manifest (url, size, piece count). pool lock held */
static void
seed_from_sidecar(dl_job_t *job) {
    /* 8 KB fits 4096 pieces of bitmap hex, the have list and manifest_url.
       bigger hurts the worker's stack */
    char       path[320], buf[8192], murl[768];
    FILE      *f;
    size_t     n;
    int        nbytes = (job->mf.count + 7) / 8;

    title_state_path(job->title_id, path, sizeof(path));
    f = fopen(path, "r");
    if (!f) return;
    n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';

    json_get_str(buf, "manifest_url", murl, sizeof(murl));
    if (strcmp(murl, job->manifest_url) ||
        json_get_ll(buf, "total", -1) != job->total ||
        json_get_int(buf, "piece_count", -1) != job->mf.count)
        return;   /* different patch, start fresh */

    {
        size_t hexsz = (size_t)nbytes * 2 + 1;
        char  *hex   = malloc(hexsz);
        if (!hex) return;
        json_get_str(buf, "done", hex, hexsz);
        hex_to_bitmap(hex, job->bitmap, nbytes);
        free(hex);
    }
    for (int i = 0; i < job->mf.count; i++)
        if (job->bitmap[i / 8] & (1 << (i % 8))) {
            job->ps[i].state = PC_DONE;
            job->done_bytes += job->mf.pieces[i].size;
        }
    {
        char        have[SIDECAR_MAX_HAVE * 24];
        const char *p = have;
        json_get_str(buf, "have", have, sizeof have);
        while (*p) {
            char     *end;
            long      idx = strtol(p, &end, 10);
            long long b;
            if (*end != ':') break;
            b = strtoll(end + 1, &end, 10);
            if (idx >= 0 && idx < job->mf.count && job->ps[idx].state != PC_DONE &&
                b > 0 && b < job->mf.pieces[idx].size)
                job->ps[idx].have = b;
            if (*end != ',') break;
            p = end + 1;
        }
    }
}


static int
pick_pending_piece(const dl_job_t *job, long now) {
    /* first PENDING is the lowest offset, skip retry pauses */
    for (int i = 0; i < job->mf.count; i++)
        if (job->ps[i].state == PC_PENDING && job->ps[i].retry_at <= now) return i;
    return -1;
}

/* -1 if none pending. same now as pick_pending_piece, or an expiring
   pause looks like nothing left */
static long
next_retry_in_ms(const dl_job_t *job, long now) {
    long best = -1;
    for (int i = 0; i < job->mf.count; i++)
        if (job->ps[i].state == PC_PENDING) {
            long in = job->ps[i].retry_at > now ? job->ps[i].retry_at - now : 0;
            if (best < 0 || in < best) best = in;
        }
    return best;
}

/* timed wait runs on the wall clock, and time sync can set that back.
   max a second per call, the caller rechecks the monotonic deadlines */
static void
pool_wait_locked(long ms) {
    struct timespec ts;
    if (ms < 0) { pthread_cond_wait(&g_pool.cv, &g_pool.mtx); return; }
    if (ms > 1000) ms = 1000;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec  += ms / 1000;
    ts.tv_nsec += (ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
    pthread_cond_timedwait(&g_pool.cv, &g_pool.mtx, &ts);
}

/* pool lock held */
static void
free_job_locked(dl_job_t *job) {
    dl_job_t **pp = &g_pool.jobs;
    while (*pp && *pp != job) pp = &(*pp)->next;
    if (*pp) *pp = job->next;
    if (job->fd >= 0) close(job->fd);
    patchdl_manifest_free(&job->mf);
    free(job->ps);
    free(job->bitmap);
    free(job);
}

/* pool lock held, dropped briefly for the g_mutex calls */
static void
finalize_cancel_locked(dl_job_t *job) {
    char title_id[32], dir[288], dest[320];
    snprintf(title_id, sizeof title_id, "%s", job->title_id);
    snprintf(dir, sizeof dir, "%s", job->dir);
    snprintf(dest, sizeof dest, "%s", job->dest);
    if (g_pool.active == job) g_pool.active = NULL;
    free_job_locked(job);
    remove_title_dir(title_id);           /* pkg, sidecar, .crc, link */
    pthread_mutex_unlock(&g_pool.mtx);
    set_title_resumable(title_id, 0, 0);
    set_title_downloaded(title_id, 0);
    pthread_mutex_lock(&g_pool.mtx);
}

/* job stays as PAUSED, partial kept. pool lock held */
static void
finalize_pause_locked(dl_job_t *job) {
    char      title_id[32];
    long long done;
    snprintf(title_id, sizeof title_id, "%s", job->title_id);
    job->abort = 0;
    write_job_state(job);
    if (job->fd >= 0) { close(job->fd); job->fd = -1; }
    job->state = JOB_PAUSED;
    if (g_pool.active == job) g_pool.active = NULL;
    done = partial_bytes_locked(job);
    pthread_mutex_unlock(&g_pool.mtx);
    set_title_resumable(title_id, done > 0, done);
    pthread_mutex_lock(&g_pool.mtx);
}

/* all pieces done or some failed. pool lock held */
static void
settle_active_locked(dl_job_t *job) {
    char title_id[32], dir[288], dest[320];
    snprintf(title_id, sizeof title_id, "%s", job->title_id);
    snprintf(dir, sizeof dir, "%s", job->dir);
    snprintf(dest, sizeof dest, "%s", job->dest);
    if (g_pool.active == job) g_pool.active = NULL;
    if (job->fd >= 0) { close(job->fd); job->fd = -1; }

    if (job->pieces_failed == 0 && job->pieces_done == job->mf.count) {
        /* keep a full sidecar so the pkg still counts as whole after a restart */
        job->state = JOB_DONE;
        write_job_state(job);
        pthread_mutex_unlock(&g_pool.mtx);
        set_title_resumable(title_id, 0, 0);
        set_title_downloaded(title_id, 1);
        pthread_mutex_lock(&g_pool.mtx);
    } else if (job->rc == -2) {
        /* failed SHA-256, delete, not resumable */
        job->state = JOB_FAILED;
        write_job_state(job);   /* removed right below anyway */
        unlink(dest);
        remove_dl_state(title_id);
        rmdir(dir);
        pthread_mutex_unlock(&g_pool.mtx);
        set_title_resumable(title_id, 0, 0);
        pthread_mutex_lock(&g_pool.mtx);
    } else {
        /* network failure after retries, keep the partial */
        long long done = partial_bytes_locked(job);
        job->state = JOB_FAILED;
        write_job_state(job);
        pthread_mutex_unlock(&g_pool.mtx);
        set_title_resumable(title_id, done > 0, done);
        pthread_mutex_lock(&g_pool.mtx);
    }
}

/* a pkg copied in by hand may have another name: one .pkg of the right
   size gets taken */
static int
adopt_by_size(const char *dir, const char *dest, long long total) {
    DIR           *d;
    struct dirent *de;
    struct stat    st;
    char           path[600], found[600] = "";
    int            hits = 0;

    if (stat(dest, &st) == 0 || !(d = opendir(dir))) return 0;
    while ((de = readdir(d))) {
        size_t n = strlen(de->d_name);
        if (n < 5 || strcmp(de->d_name + n - 4, ".pkg")) continue;
        snprintf(path, sizeof path, "%s/%s", dir, de->d_name);
        if (stat(path, &st) == 0 && S_ISREG(st.st_mode) &&
            (long long)st.st_size == total) {
            snprintf(found, sizeof found, "%s", path);
            hits++;
        }
    }
    closedir(d);
    return hits == 1 && rename(found, dest) == 0;
}

/* same check as seed_from_sidecar */
static int
sidecar_matches(const char *title_id, const char *murl, long long total, int count) {
    char   path[320], buf[8192], url[768];
    FILE  *f;
    size_t n;

    title_state_path(title_id, path, sizeof path);
    if (!(f = fopen(path, "r"))) return 0;
    n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[n] = '\0';
    json_get_str(buf, "manifest_url", url, sizeof url);
    return !strcmp(url, murl) && json_get_ll(buf, "total", -1) == total &&
           json_get_int(buf, "piece_count", -1) == count;
}

/* pool lock dropped. q stays valid (admit is its only finalizer),
   cancel/pause end it early */
static void
verify_existing(dl_job_t *q, int fd, const patchdl_manifest_t *mf,
                unsigned char *done) {
    long long hashed = 0;

    pthread_mutex_lock(&g_pool.mtx);
    q->verifying = 1;
    q->verify_bytes = 0;
    q->total = mf->total;            /* for the progress bar, admit sets it again */
    pthread_mutex_unlock(&g_pool.mtx);
    for (int i = 0; i < mf->count; i++) {
        char hex[80];
        int  stop;
        pthread_mutex_lock(&g_pool.mtx);
        stop = (q->state == JOB_CANCELLING || q->state == JOB_PAUSING);
        pthread_mutex_unlock(&g_pool.mtx);
        if (stop) break;
        if (mf->pieces[i].hash[0] &&
            patchdl_hash_fd_region(fd, mf->pieces[i].offset, mf->pieces[i].size,
                                   mf->pieces[i].hash, hex) == 0 &&
            !strcasecmp(hex, mf->pieces[i].hash))
            done[i / 8] |= (unsigned char)(1 << (i % 8));
        hashed += mf->pieces[i].size;
        pthread_mutex_lock(&g_pool.mtx);
        q->verify_bytes = hashed;
        pthread_mutex_unlock(&g_pool.mtx);
    }
}

/* QUEUED head to ACTIVE. network and disk run without the pool lock */
static void
admit_next(void) {
    dl_job_t          *q = NULL;
    patchdl_manifest_t mf;
    char               murl[768], dest[320], dir[288];
    int                is_manifest, fd = -1, ok = 0, no_space = 0, space_inst = 0;
    char               q_title[32];
    unsigned char     *pre_done = NULL;   /* pieces proven good by hash */
    char               fstep[24] = "";
    int                fcurl = 0;
    long               fhttp = 0;
    int                adopted = 0;
    long long          total = 0, old_size = 0, need = 0, free_b = 0;
    dl_pstate_t       *ps = NULL;
    unsigned char     *bitmap = NULL;

    for (dl_job_t *j = g_pool.jobs; j; j = j->next)
        if (j->state == JOB_QUEUED) { q = j; break; }
    if (!q) return;

    g_pool.admitting = 1;
    q->in_admit = 1;
    q->state = JOB_ADMITTING;       /* cancel/pause only flag it,
                                       admit_next finalizes */
    is_manifest = q->is_manifest;
    snprintf(murl, sizeof murl, "%s", q->manifest_url);
    snprintf(dest, sizeof dest, "%s", q->dest);
    snprintf(dir, sizeof dir, "%s", q->dir);
    snprintf(q_title, sizeof q_title, "%s", q->title_id);
    pthread_mutex_unlock(&g_pool.mtx);

    /* network + disk, no pool lock */
    memset(&mf, 0, sizeof mf);
    make_title_dir(dir);
    if (is_manifest) {
        if (patchdl_fetch_manifest(murl, &mf) != 0 || mf.count <= 0) {
            patchdl_http_last_error(fstep, sizeof fstep, &fcurl, &fhttp);
            if (!fstep[0]) snprintf(fstep, sizeof fstep, "manifest");
        } else {
            total = mf.total;
            adopted = adopt_by_size(dir, dest, total);
            need  = space_needed(dest, total);
            /* the install needs the pkg size again on the game's drive */
            {
                char gdir[256] = "";
                pthread_mutex_lock(&g_mutex);
                for (size_t i = 0; i < g_title_count; i++)
                    if (!strcmp(g_titles[i].title_id, q_title)) {
                        snprintf(gdir, sizeof gdir, "%s", g_titles[i].source_path);
                        break;
                    }
                pthread_mutex_unlock(&g_mutex);
                if (!download_and_install_fit(dir, gdir, need, total,
                                              &need, &free_b, &space_inst))
                    no_space = 1;
            }
            if (!no_space) fd = open(dest, O_RDWR | O_CREAT, 0666);
            if (fd >= 0) {
                struct stat st;
                if (fstat(fd, &st) == 0) old_size = (long long)st.st_size;
                if (ftruncate(fd, (off_t)total) == 0) ok = 1;
                else { close(fd); fd = -1; }
            }
            /* the console asks for <name>.crc at the end of an install */
            if (ok && mf.crc_url[0]) {
                char crc[320];
                struct stat cst;
                size_t n = strlen(dest);
                if (n > 4 && !strcmp(dest + n - 4, ".pkg") && n < sizeof crc) {
                    snprintf(crc, sizeof crc, "%.*s.crc", (int)(n - 4), dest);
                    /* best effort, the next run retries */
                    if (stat(crc, &cst) != 0 || cst.st_size == 0)
                        (void)patchdl_http_download(mf.crc_url, crc, NULL);
                }
            }
            /* a sidecar only fits its own file. shorter or missing pkg: drop it,
               adopted or sidecar-less pkg: hash it instead of fetching again */
            if (ok && old_size < total)
                remove_dl_state(q->title_id);
            else if (ok && (adopted ||
                            !sidecar_matches(q->title_id, murl, total, mf.count))) {
                remove_dl_state(q->title_id);
                pre_done = calloc((size_t)((mf.count + 7) / 8), 1);
                if (pre_done) verify_existing(q, fd, &mf, pre_done);
            }
        }
    } else {
        mf.pieces = calloc(1, sizeof(patchdl_piece_t));
        if (mf.pieces) {
            mf.pieces[0].url = strdup(murl);
            mf.pieces[0].offset = 0;
            mf.pieces[0].size = 0;         /* unknown, no size check */
            mf.count = 1; mf.total = 0; total = 0;
            fd = open(dest, O_RDWR | O_CREAT | O_TRUNC, 0666);
            if (fd >= 0 && mf.pieces[0].url) ok = 1;
            else if (fd >= 0) { close(fd); fd = -1; }
        }
    }
    if (ok) {
        ps     = calloc((size_t)mf.count, sizeof(dl_pstate_t));
        bitmap = calloc((size_t)((mf.count + 7) / 8), 1);
        if (!ps || !bitmap) ok = 0;
    }

    pthread_mutex_lock(&g_pool.mtx);
    g_pool.admitting = 0;
    q->in_admit = 0;
    /* cancel/pause may have flagged q meanwhile. never published, so no
       worker touched it */
    q->verifying = 0;
    if (!ok || q->state == JOB_CANCELLING) {
        if (fd >= 0) close(fd);
        patchdl_manifest_free(&mf);
        free(ps);
        free(bitmap);
        free(pre_done);
        if (q->state == JOB_CANCELLING) finalize_cancel_locked(q);
        else {
            q->state = JOB_FAILED;
            q->rc = no_space ? -3 : -1;
            q->need_bytes = need;
            q->free_bytes = free_b;
            q->space_install = space_inst;
            /* tells a blocked host from TLS or HTTP trouble */
            snprintf(q->fail_step, sizeof q->fail_step, "%s", fstep);
            q->last_curl_rc   = fcurl;
            q->last_http_code = fhttp;
        }
        pthread_cond_broadcast(&g_pool.cv);
        return;
    }
    /* a resumed job still has the old mf/ps/bitmap. drop them, the sidecar
       is the only truth */
    patchdl_manifest_free(&q->mf);
    free(q->ps);     q->ps     = NULL;
    free(q->bitmap); q->bitmap = NULL;
    q->done_bytes = 0; q->pieces_failed = 0; q->rc = 0;
    q->last_curl_rc = 0; q->last_http_code = 0;
    q->fail_step[0] = '\0';

    q->mf = mf; q->ps = ps; q->bitmap = bitmap; q->fd = fd; q->total = total;
    for (int i = 0; i < mf.count; i++) q->ps[i].slot = -1;
    /* a single pkg was just truncated, the old sidecar is moot */
    if (is_manifest) seed_from_sidecar(q);
    q->pieces_done = 0;
    for (int i = 0; i < mf.count; i++)
        if (q->ps[i].state == PC_DONE) q->pieces_done++;
    /* a shorter file without sidecar isn't trusted as a prefix (holes) */
    (void)old_size;
    /* whole pkg on disk: take the pieces that matched their hash */
    if (q->pieces_done == 0 && pre_done) {
        for (int i = 0; i < mf.count; i++)
            if (pre_done[i / 8] & (1 << (i % 8))) {
                q->ps[i].state = PC_DONE;
                q->bitmap[i / 8] |= (unsigned char)(1 << (i % 8));
                q->done_bytes += mf.pieces[i].size;
                q->pieces_done++;
            }
        if (q->pieces_done > 0) write_job_state(q);
    }
    free(pre_done);
    /* paused during admit: save the bitmap and park instead of starting */
    if (q->state == JOB_PAUSING) {
        finalize_pause_locked(q);
        pthread_cond_broadcast(&g_pool.cv);
        return;
    }
    q->state = JOB_ACTIVE;
    g_pool.active = q;
    pthread_cond_broadcast(&g_pool.cv);
}

static void *
dl_worker(void *arg) {
    int slot = (int)(intptr_t)arg;

    for (;;) {
        dl_job_t *job;
        int       pidx = -1;
        char      url[768], hash[80];
        long long off = 0, sz = 0, have = 0, written = 0;
        int       synced = 0;
        unsigned int my_seq = 0;
        int       fd = -1, verify = 0, rc;
        volatile int *abort_ptr = NULL;

        pthread_mutex_lock(&g_pool.mtx);
        for (;;) {
            if (g_pool.stopping) break;
            /* live connection limit, workers above it idle here */
            if (slot >= g_pool.active_conns) {
                pthread_cond_wait(&g_pool.cv, &g_pool.mtx);
                continue;
            }
            job = g_pool.active;
            if (!job) {
                if (!g_pool.admitting) {
                    int queued = 0;
                    for (dl_job_t *j = g_pool.jobs; j; j = j->next)
                        if (j->state == JOB_QUEUED) { queued = 1; break; }
                    if (queued) { admit_next(); continue; }
                }
                pthread_cond_wait(&g_pool.cv, &g_pool.mtx);
                continue;
            }
            if (job->state == JOB_ACTIVE) {
                long now = mono_ms(), wait;
                pidx = pick_pending_piece(job, now);
                if (pidx >= 0) break;                 /* claim below */
                wait = next_retry_in_ms(job, now);
                if (job->inflight == 0 && wait < 0) { settle_active_locked(job); pthread_cond_broadcast(&g_pool.cv); continue; }
                pool_wait_locked(wait);               /* a retry pause ending wakes it too */
                continue;
            }
            if (job->state == JOB_PAUSING || job->state == JOB_CANCELLING) {
                if (job->inflight == 0) {
                    if (job->state == JOB_PAUSING) finalize_pause_locked(job);
                    else                            finalize_cancel_locked(job);
                    pthread_cond_broadcast(&g_pool.cv);
                    continue;
                }
                pthread_cond_wait(&g_pool.cv, &g_pool.mtx);
                continue;
            }
            pthread_cond_wait(&g_pool.cv, &g_pool.mtx);
        }
        if (g_pool.stopping) { pthread_mutex_unlock(&g_pool.mtx); break; }

        job->ps[pidx].state = PC_INFLIGHT;
        job->ps[pidx].slot  = slot;
        job->inflight++;
        my_seq    = job->seq;
        fd        = job->fd;
        verify    = job->verify;
        off       = job->mf.pieces[pidx].offset;
        sz        = job->mf.pieces[pidx].size;
        abort_ptr = &job->abort;
        snprintf(url, sizeof url, "%s", job->mf.pieces[pidx].url);
        snprintf(hash, sizeof hash, "%s", job->mf.pieces[pidx].hash);
        have      = job->ps[pidx].have;
        g_pool.inflight_bytes[slot] = have;
        pthread_mutex_unlock(&g_pool.mtx);

        /* download the piece, no lock */
        int  last_curl_rc   = 0;
        long last_http_code = 0;
        {
            patchdl_piece_ctx_t ctx = { &g_pool.inflight_bytes[slot], abort_ptr };
            rc = patchdl_http_download_piece(url, fd, off, sz, have,
                                             verify && hash[0] ? hash : NULL, &ctx,
                                             &last_curl_rc, &last_http_code);
        }
        /* keep a partial only once it's on disk, have may go into the sidecar */
        synced = rc == -1 && g_pool.inflight_bytes[slot] > have && fdatasync(fd) == 0;

        pthread_mutex_lock(&g_pool.mtx);
        written = g_pool.inflight_bytes[slot];
        g_pool.inflight_bytes[slot] = 0;
        job->inflight--;
        if (rc != 0) {
            job->last_curl_rc   = last_curl_rc;
            job->last_http_code = last_http_code;
        }
        job->ps[pidx].slot = -1;
        if (my_seq != job->seq) {
            /* cancelled meanwhile: drop it, finalizer runs at inflight 0 */
        } else if (rc == 0) {
            job->ps[pidx].state = PC_DONE;
            job->pieces_done++;
            job->done_bytes += sz;
            job->bitmap[pidx / 8] |= (unsigned char)(1 << (pidx % 8));
            /* save after every piece, a kill then loses only what's in flight */
            write_job_state(job);
        } else if (job->abort &&
                   (job->state == JOB_PAUSING || job->state == JOB_CANCELLING)) {
            job->ps[pidx].state = PC_PENDING;   /* paused, continue on resume */
            if (synced && written < sz) job->ps[pidx].have = written;
        } else if (rc == -2 && have > 0) {
            /* the kept part may be the bad one, refetch the whole piece once */
            job->ps[pidx].have     = 0;
            job->ps[pidx].state    = PC_PENDING;
            job->ps[pidx].retry_at = 0;
        } else if (rc == -2) {
            job->ps[pidx].state = PC_FAILED; job->pieces_failed++; job->rc = -2;
        } else if (rc == -3) {
            /* server can't resume mid-piece: start over now, no attempt used */
            job->ps[pidx].have     = 0;
            job->ps[pidx].state    = PC_PENDING;
            job->ps[pidx].retry_at = 0;
        } else {
            /* keep what arrived and was synced, the next try continues there */
            if (synced && written < sz) job->ps[pidx].have = written;
            job->ps[pidx].attempts++;
            if (job->ps[pidx].attempts < PIECE_MAX_ATTEMPTS) {
                job->ps[pidx].state    = PC_PENDING;
                job->ps[pidx].retry_at = mono_ms() + piece_backoff_ms(job->ps[pidx].attempts);
            } else {
                job->ps[pidx].state = PC_FAILED; job->pieces_failed++; job->rc = -1;
            }
        }
        pthread_cond_broadcast(&g_pool.cv);
        pthread_mutex_unlock(&g_pool.mtx);
    }
    return NULL;
}


/* 202 right away, the pool does the rest. a paused job resumes */
static enum MHD_Result
do_download(struct MHD_Connection *conn, const char *title_id,
            patchdl_source_t src, const char *patch_url, const char *delta_url,
            const char *name, const char *version, int enabled) {
    dl_job_t *job, *existing = NULL;
    int       count = 0, verify;

    if (!enabled)
        return queue_json(conn, MHD_HTTP_FORBIDDEN,
                          "{\"ok\":false,\"reason\":\"title_disabled\"}");
    if (src == PATCHDL_SOURCE_UNKNOWN)
        return queue_json(conn, MHD_HTTP_FORBIDDEN,
                          "{\"ok\":false,\"reason\":\"source_unknown\"}");
    if (src == PATCHDL_SOURCE_FAKE)
        return queue_json(conn, MHD_HTTP_FORBIDDEN,
                          "{\"ok\":false,\"reason\":\"source_fake\"}");
    if (src == PATCHDL_SOURCE_SHADOWMOUNT)
        return queue_json(conn, MHD_HTTP_FORBIDDEN,
                          "{\"ok\":false,\"reason\":\"source_shadowmount\"}");
    if (!patch_url[0])
        return queue_json(conn, MHD_HTTP_CONFLICT,
                          "{\"ok\":false,\"reason\":\"no_compatible_patch\"}");
    /* the pkg gets rewritten in place, not while an install reads it */
    if (install_reading(title_id))
        return queue_json(conn, MHD_HTTP_CONFLICT,
                          "{\"ok\":false,\"reason\":\"install_running\"}");
    if (version_installed(title_id, version))
        return queue_json(conn, MHD_HTTP_CONFLICT,
                          "{\"ok\":false,\"reason\":\"already_installed\"}");

    /* lock order is g_mutex before g_pool, so read the flag first */
    pthread_mutex_lock(&g_mutex);
    verify = g_cfg.verify_downloads;
    pthread_mutex_unlock(&g_mutex);

    pthread_mutex_lock(&g_pool.mtx);
    /* done/failed jobs take no slot, or "Update all" hits queue_full */
    for (job = g_pool.jobs; job; job = job->next) {
        if (job->state != JOB_DONE && job->state != JOB_FAILED) count++;
        if (!strcmp(job->title_id, title_id)) existing = job;
    }
    if (existing) {
        job_state_t st = existing->state;
        if (st == JOB_PAUSING && existing->in_admit) {
            /* paused while the manifest was loading: take the pause back */
            existing->state = JOB_ADMITTING;
            existing->abort = 0;
            pthread_mutex_unlock(&g_pool.mtx);
            return queue_json(conn, MHD_HTTP_OK,
                              "{\"ok\":true,\"queued\":true,\"resumed\":true}");
        }
        if (st == JOB_QUEUED || st == JOB_ADMITTING ||
            st == JOB_ACTIVE || st == JOB_PAUSING) {
            pthread_mutex_unlock(&g_pool.mtx);
            return queue_json(conn, MHD_HTTP_OK,
                              "{\"ok\":true,\"queued\":true,\"already\":true}");
        }
        if (st == JOB_CANCELLING) {        /* mid-cancel, hands off */
            pthread_mutex_unlock(&g_pool.mtx);
            return queue_json(conn, MHD_HTTP_CONFLICT,
                              "{\"ok\":false,\"reason\":\"cancelling\"}");
        }
        if (st == JOB_PAUSED) {
            existing->state = JOB_QUEUED;
            pthread_cond_broadcast(&g_pool.cv);
            pthread_mutex_unlock(&g_pool.mtx);
            return queue_json(conn, MHD_HTTP_OK,
                              "{\"ok\":true,\"queued\":true,\"resumed\":true}");
        }
        if (st == JOB_DONE) {
            pthread_mutex_unlock(&g_pool.mtx);
            return queue_json(conn, MHD_HTTP_OK,
                              "{\"ok\":true,\"downloaded\":true,\"already\":true}");
        }
        /* FAILED: drop it, re-enqueue below (it took no slot) */
        free_job_locked(existing);
    }
    if (count >= POOL_MAX_JOBS) {
        pthread_mutex_unlock(&g_pool.mtx);
        return queue_json(conn, MHD_HTTP_SERVICE_UNAVAILABLE,
                          "{\"ok\":false,\"reason\":\"queue_full\"}");
    }

    job = calloc(1, sizeof(*job));
    if (!job) {
        pthread_mutex_unlock(&g_pool.mtx);
        return queue_text(conn, MHD_HTTP_INTERNAL_SERVER_ERROR, "oom");
    }
    snprintf(job->title_id, sizeof job->title_id, "%s", title_id);
    snprintf(job->name, sizeof job->name, "%s", name && name[0] ? name : title_id);
    snprintf(job->version, sizeof job->version, "%s", version ? version : "");

    {
        snprintf(job->manifest_url, sizeof job->manifest_url, "%s", patch_url);
        title_dir(title_id, job->dir, sizeof job->dir);
        /* create it now so later lookups find it even if the drive changes */
        make_title_dir(job->dir);
        title_pkg_path(title_id, patch_url, job->dest, sizeof job->dest);
        job->is_manifest = url_is_manifest(patch_url);
    }
    job->verify = verify;
    job->state = JOB_QUEUED;
    job->fd = -1;
    {
        dl_job_t **pp = &g_pool.jobs;
        while (*pp) pp = &(*pp)->next;
        *pp = job;
    }
    pthread_cond_broadcast(&g_pool.cv);
    pthread_mutex_unlock(&g_pool.mtx);

    return queue_json(conn, MHD_HTTP_ACCEPTED, "{\"ok\":true,\"queued\":true}");
}

/* keep the partial. the active job aborts, a queued one just parks */
static enum MHD_Result
do_pause(struct MHD_Connection *conn, const char *title_id) {
    dl_job_t *job;
    int       acted = 0;

    pthread_mutex_lock(&g_pool.mtx);
    for (job = g_pool.jobs; job; job = job->next) {
        if (strcmp(job->title_id, title_id)) continue;
        if (job->state == JOB_ACTIVE || job->state == JOB_ADMITTING) {
            /* admit_next sees PAUSING on relock and parks it, nothing starts */
            job->state = JOB_PAUSING;
            job->abort = 1;
            pthread_cond_broadcast(&g_pool.cv);
            acted = 1;
        } else if (job->state == JOB_QUEUED) {
            job->state = JOB_PAUSED;
            acted = 1;
        }
        break;
    }
    pthread_mutex_unlock(&g_pool.mtx);
    if (!acted)
        return queue_json(conn, MHD_HTTP_CONFLICT,
                          "{\"ok\":false,\"reason\":\"not_downloading\"}");
    return queue_json(conn, MHD_HTTP_OK, "{\"ok\":true,\"paused\":true}");
}

/* stop and delete. the last worker finalizes once in-flight pieces drain */
static void cancel_title(const char *title_id);

static enum MHD_Result
do_cancel(struct MHD_Connection *conn, const char *title_id) {
    if (install_reading(title_id))
        return queue_json(conn, MHD_HTTP_CONFLICT,
                          "{\"ok\":false,\"reason\":\"install_running\"}");
    cancel_title(title_id);
    return queue_json(conn, MHD_HTTP_OK, "{\"ok\":true,\"cancelled\":true}");
}

/* stop the job and delete the whole folder, no install may be reading it */
static void
cancel_title(const char *title_id) {
    dl_job_t *job;
    int       had_job = 0;

    pthread_mutex_lock(&g_pool.mtx);
    for (job = g_pool.jobs; job; job = job->next) {
        if (strcmp(job->title_id, title_id)) continue;
        had_job = 1;
        if (job->state == JOB_CANCELLING) {
            /* already on its way out */
        } else if (job->in_admit) {
            /* lock dropped for manifest I/O, admit_next holds a raw pointer and
               finalizes on relock. freeing here would be a use-after-free */
            job->state = JOB_CANCELLING;
            job->seq++;
            job->abort = 1;
            pthread_cond_broadcast(&g_pool.cv);
        } else if (job->state == JOB_ACTIVE || job->state == JOB_PAUSING) {
            job->state = JOB_CANCELLING;
            job->seq++;            /* discard late piece completions */
            job->abort = 1;
            pthread_cond_broadcast(&g_pool.cv);
            if (job->inflight == 0) finalize_cancel_locked(job);
        } else {
            /* no in-flight pieces */
            finalize_cancel_locked(job);
        }
        break;
    }
    pthread_mutex_unlock(&g_pool.mtx);

    if (!had_job) {
        /* leftover partial from a previous boot, no live job */
        remove_title_dir(title_id);
        set_title_resumable(title_id, 0, 0);
        set_title_downloaded(title_id, 0);
    }
    clear_manual_source(title_id);
}

/* whole = no unfinished job and a full sidecar. no sidecar = unproven */
static int
download_complete(const char *title_id) {
    char      path[320], buf[8192];
    FILE     *f;
    size_t    n;
    int       ok = 1, done_job = 0;
    dl_job_t *job;

    pthread_mutex_lock(&g_pool.mtx);
    for (job = g_pool.jobs; job; job = job->next)
        if (!strcmp(job->title_id, title_id)) {
            ok = done_job = (job->state == JOB_DONE);
            break;
        }
    pthread_mutex_unlock(&g_pool.mtx);
    if (!ok) return 0;

    title_state_path(title_id, path, sizeof path);
    if (!(f = fopen(path, "r"))) return done_job;
    n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[n] = '\0';
    /* single-URL download has no size (total 0), only its DONE job vouches */
    if (json_get_ll(buf, "total", 0) <= 0) return done_job;
    return json_get_ll(buf, "done_bytes", 0) >= json_get_ll(buf, "total", 0);
}

/* every title folder on every drive, gone games included */
static char *
build_storage_json(void) {
    jbuf_t         j = {0};
    DIR           *d;
    struct dirent *de;
    long long      sum = 0;
    int            first = 1;

    char           drives[MAX_DRIVES][32], root[64];
    int            nd = list_drives(drives, MAX_DRIVES);

    jbuf_append(&j, "{\"items\":[");
    for (int k = 0; k < nd; k++) {
        snprintf(root, sizeof root, "%s/patchdl", drives[k]);
        if (!(d = opendir(root))) continue;
        while ((de = readdir(d))) {
            char           dir[288], path[560], name[128] = "", inst[16] = "";
            char           ver[16] = "", buf[2048], pkgname[160] = "";
            FILE          *vf;
            const char    *state = "complete";
            long long      bytes = 0;
            int            files = 0, known = 0;
            struct stat    st;
            DIR           *sd;
            struct dirent *fe;
            dl_job_t      *job;

            if (!is_title_dir_name(de->d_name)) continue;
            snprintf(dir, sizeof dir, "%s/%s", root, de->d_name);
            if (stat(dir, &st) || !S_ISDIR(st.st_mode)) continue;
            if ((sd = opendir(dir))) {
                while ((fe = readdir(sd))) {
                    if (fe->d_name[0] == '.') continue;
                    snprintf(path, sizeof path, "%s/%s", dir, fe->d_name);
                    if (!stat(path, &st) && S_ISREG(st.st_mode)) {
                        size_t fl = strlen(fe->d_name);
                        bytes += (long long)st.st_size;
                        files++;
                        if (fl > 4 && !strcmp(fe->d_name + fl - 4, ".pkg"))
                            snprintf(pkgname, sizeof pkgname, "%s", fe->d_name);
                    }
                }
                closedir(sd);
            }
            sum += bytes;

            /* version from the sidecar, or from the pasted link for Prospero */
            title_state_path(de->d_name, path, sizeof path);
            if ((vf = fopen(path, "r"))) {
                size_t n = fread(buf, 1, sizeof buf - 1, vf);
                fclose(vf);
                buf[n] = '\0';
                json_get_str(buf, "version", ver, sizeof ver);
            }
            if (!ver[0]) {
                manual_source_path(de->d_name, path, sizeof path);
                if ((vf = fopen(path, "r"))) {
                    size_t n = fread(buf, 1, sizeof buf - 1, vf);
                    fclose(vf);
                    buf[n] = '\0';
                    json_get_str(buf, "version", ver, sizeof ver);
                }
            }

            pthread_mutex_lock(&g_mutex);
            for (size_t i = 0; i < g_title_count; i++)
                if (!strcmp(g_titles[i].title_id, de->d_name)) {
                    snprintf(name, sizeof name, "%s", g_titles[i].name);
                    snprintf(inst, sizeof inst, "%s", g_titles[i].installed_version);
                    /* older download without version: a name matching Sony's
                       current patch gives it */
                    if (!ver[0] && pkgname[0] && g_titles[i].patch_url[0]) {
                        char expect[320];
                        title_pkg_path(de->d_name, g_titles[i].patch_url,
                                       expect, sizeof expect);
                        if (!strcmp(strrchr(expect, '/') + 1, pkgname))
                            snprintf(ver, sizeof ver, "%s",
                                     g_titles[i].compatible_version);
                    }
                    if (g_titles[i].resumable) state = "paused";
                    known = 1;
                    break;
                }
            pthread_mutex_unlock(&g_mutex);
            pthread_mutex_lock(&g_pool.mtx);
            for (job = g_pool.jobs; job; job = job->next)
                if (!strcmp(job->title_id, de->d_name)) {
                    if (job->state == JOB_PAUSED) state = "paused";
                    else if (job->state == JOB_FAILED) state = "failed";
                    else if (job->state != JOB_DONE) state = "downloading";
                    break;
                }
            pthread_mutex_unlock(&g_pool.mtx);
            if (install_reading(de->d_name)) state = "installing";

            jbuf_append(&j, first ? "{" : ",{");
            first = 0;
            jbuf_append(&j, "\"title_id\":");  jbuf_append_str(&j, de->d_name);
            jbuf_append(&j, ",\"name\":");      jbuf_append_str(&j, name);
            jbuf_appendf(&j, ",\"installed\":%s,\"bytes\":%lld,\"files\":%d,",
                         known ? "true" : "false", bytes, files);
            jbuf_append(&j, "\"state\":");     jbuf_append_str(&j, state);
            jbuf_append(&j, ",\"version\":");  jbuf_append_ver_or_null(&j, ver);
            jbuf_append(&j, ",\"installed_version\":");
            jbuf_append_ver_or_null(&j, inst);
            jbuf_append(&j, ",\"drive\":");  jbuf_append_str(&j, drives[k]);
            jbuf_append(&j, "}");
        }
        closedir(d);
    }
    jbuf_appendf(&j, "],\"total_bytes\":%lld}", sum);
    return j.buf;
}

/* GET /api/drives: free/total per drive and the one in use */
static char *
build_drives_json(void) {
    char  drives[MAX_DRIVES][32], root[64];
    int   nd = list_drives(drives, MAX_DRIVES);
    jbuf_t j = {0};

    current_root(root, sizeof root);
    jbuf_append(&j, "{\"current\":");
    jbuf_append_str(&j, root);
    jbuf_append(&j, ",\"drives\":[");
    for (int i = 0; i < nd; i++) {
        struct statvfs vfs;
        unsigned long long fr = 0, tot = 0;
        if (statvfs(drives[i], &vfs) == 0) {
            fr  = (unsigned long long)vfs.f_bavail * vfs.f_frsize / (1024ULL * 1024ULL);
            tot = (unsigned long long)vfs.f_blocks * vfs.f_frsize / (1024ULL * 1024ULL);
        }
        jbuf_append(&j, i ? ",{\"path\":" : "{\"path\":");
        jbuf_append_str(&j, drives[i]);
        jbuf_appendf(&j, ",\"free_mb\":%llu,\"total_mb\":%llu}", fr, tot);
    }
    jbuf_append(&j, "]}");
    return j.buf;
}

static void
url_host_of(const char *url, char *out, size_t sz) {
    const char *p = strstr(url, "://");
    size_t      n;
    out[0] = '\0';
    if (!p) return;
    p += 3;
    n = strcspn(p, "/:?");
    if (n < sz) { memcpy(out, p, n); out[n] = '\0'; }
}

/* GET /api/versions?title=<id> via Prospero/Orbis Patches, no downgrades */
static enum MHD_Result
queue_versions(struct MHD_Connection *conn, const char *tid) {
    patchdl_patch_version_t *list;
    char                     inst[16] = "", tid9[16];
    int                      n = 0, ps4;
    jbuf_t                   j = {0};

    if (!path_segment_safe(tid) || strlen(tid) < 9 || strlen(tid) >= 32)
        return queue_text(conn, MHD_HTTP_FORBIDDEN, "forbidden");
    snprintf(tid9, sizeof tid9, "%.9s", tid);
    ps4 = !strncmp(tid9, "CUSA", 4);
    pthread_mutex_lock(&g_mutex);
    for (size_t i = 0; i < g_title_count; i++)
        if (!strcmp(g_titles[i].title_id, tid)) {
            snprintf(inst, sizeof inst, "%s", g_titles[i].installed_version);
            break;
        }
    pthread_mutex_unlock(&g_mutex);

    if (!(list = calloc(PATCHSITE_MAX_VERSIONS, sizeof *list)))
        return queue_text(conn, MHD_HTTP_INTERNAL_SERVER_ERROR, "oom");
    if (patchdl_patchsite_versions(tid9, list, PATCHSITE_MAX_VERSIONS, &n)) {
        free(list);
        return queue_json(conn, MHD_HTTP_BAD_GATEWAY,
                          "{\"ok\":false,\"reason\":\"versions_unavailable\"}");
    }
    jbuf_append(&j, "{\"ok\":true,\"site\":");
    jbuf_append_str(&j, ps4 ? "Orbis Patches" : "Prospero Patches");
    jbuf_appendf(&j, ",\"page\":\"%s/%s\",\"ps4\":%s,\"installed\":",
                 patchdl_patchsite_base(tid9), tid9, ps4 ? "true" : "false");
    jbuf_append_str(&j, inst);
    jbuf_append(&j, ",\"versions\":[");
    for (int i = 0; i < n; i++) {
        const char *state =
            inst[0] && !strcmp(list[i].version, inst)  ? "installed"
          : inst[0] && strcmp(list[i].version, inst) < 0 ? "older"
          : !ps4 && list[i].fw_bin > g_fw.bin          ? "needs_fw"
                                                       : "ok";
        jbuf_append(&j, i ? ",{\"version\":" : "{\"version\":");
        jbuf_append_str(&j, list[i].version);
        jbuf_append(&j, ",\"fw\":");    jbuf_append_str(&j, list[i].required_fw);
        jbuf_append(&j, ",\"size\":");  jbuf_append_str(&j, list[i].size);
        jbuf_append(&j, ",\"state\":"); jbuf_append_str(&j, state);
        jbuf_append(&j, "}");
    }
    jbuf_append(&j, "]}");
    free(list);
    return queue_json_owned(conn, MHD_HTTP_OK, j.buf);
}

/* fresh DNS answer with source and trail, blocked DNS vs blocked connect */
static void
append_dns(jbuf_t *j, const char *host) {
    patchdl_dns_answer_t a;
    char                 ips[PATCHDL_DNS_MAX_IPS * 16 + 8] = "";

    memset(&a, 0, sizeof a);
    if (host[0]) {
        patchdl_dns_refresh(host);
        patchdl_dns_lookup(host, &a);
    }
    for (int i = 0; i < a.n; i++) {
        size_t len = strlen(ips);
        snprintf(ips + len, sizeof ips - len, "%s%s", i ? "," : "", a.ip[i]);
    }
    jbuf_append(j, ",\"ip\":");        jbuf_append_str(j, a.n ? a.ip[0] : "");
    jbuf_append(j, ",\"ips\":");       jbuf_append_str(j, ips);
    jbuf_append(j, ",\"dns\":");       jbuf_append_str(j, a.source);
    jbuf_append(j, ",\"dns_trail\":"); jbuf_append_str(j, a.trail);
}

/* GET /api/netcheck?title=<id>: walk update list and manifest like a
   download, to see where it breaks */
static enum MHD_Result
queue_netcheck_title(struct MHD_Connection *conn, const char *tid) {
    char              vurl[512] = "", host[128], step[24], tid9[16];
    char              murl[768] = "", durl[512], ptid[16], pstid[16], cid[64];
    char              nm[128], ver[16];
    patchdl_source_t  src;
    int               en;
    char             *out;
    int               curl_rc = 0, vrc, mrc = -1, pieces = 0;
    long              http = 0;
    patchdl_verinfo_t info;
    patchdl_manifest_t mf;
    jbuf_t            j = {0};

    /* Sony's URLs use the 9-char id */
    if (!path_segment_safe(tid) || strlen(tid) < 9 || strlen(tid) >= 32)
        return queue_text(conn, MHD_HTTP_FORBIDDEN, "forbidden");
    snprintf(tid9, sizeof tid9, "%.9s", tid);
    pthread_mutex_lock(&g_mutex);
    for (size_t i = 0; i < g_title_count; i++)
        if (!strncmp(g_titles[i].title_id, tid, 9)) {
            snprintf(vurl, sizeof vurl, "%s", g_titles[i].version_file_uri);
            break;
        }
    pthread_mutex_unlock(&g_mutex);
    if (!vurl[0]) patchdl_resolve_url(tid9, vurl, sizeof vurl);

    jbuf_append(&j, "{\"title_id\":");  jbuf_append_str(&j, tid);
    jbuf_append(&j, ",\"update_list\":{\"url\":"); jbuf_append_str(&j, vurl);
    url_host_of(vurl, host, sizeof host);
    append_dns(&j, host);
    memset(&info, 0, sizeof info);
    vrc = vurl[0] ? patchdl_verxml_query(vurl, g_fw.bin, &info) : -1;
    patchdl_http_last_error(step, sizeof step, &curl_rc, &http);
    jbuf_appendf(&j, ",\"ok\":%s,\"curl\":%d,\"http\":%ld,\"step\":",
                 vrc == 0 ? "true" : "false", curl_rc, http);
    jbuf_append_str(&j, step);
    jbuf_append(&j, ",\"latest\":"); jbuf_append_str(&j, info.latest_version);
    /* pasted Prospero link wins over Sony's list, same as the download */
    if (!get_title_action_info(tid, &src, murl, sizeof murl, durl, sizeof durl,
                               ptid, sizeof ptid, pstid, sizeof pstid,
                               cid, sizeof cid, nm, sizeof nm, ver, sizeof ver, &en) ||
        !murl[0])
        snprintf(murl, sizeof murl, "%s", info.compatible_url);
    jbuf_append(&j, "},\"manifest\":{\"url\":"); jbuf_append_str(&j, murl);
    url_host_of(murl, host, sizeof host);
    append_dns(&j, host);
    memset(&mf, 0, sizeof mf);
    step[0] = '\0'; curl_rc = 0; http = 0;
    if (url_is_manifest(murl)) {
        mrc = patchdl_fetch_manifest(murl, &mf);
        patchdl_http_last_error(step, sizeof step, &curl_rc, &http);
        pieces = mf.count;
        patchdl_manifest_free(&mf);
    } else if (murl[0]) {
        /* single pkg without a piece list, nothing to fetch */
        mrc = 0;
        pieces = 1;
        snprintf(step, sizeof step, "direct");
    }
    jbuf_appendf(&j, ",\"ok\":%s,\"pieces\":%d,\"curl\":%d,\"http\":%ld,\"step\":",
                 mrc == 0 ? "true" : "false", pieces, curl_rc, http);
    jbuf_append_str(&j, step);
    jbuf_append(&j, "}}");
    out = j.buf;
    return queue_json_owned(conn, MHD_HTTP_OK, out);
}

static enum MHD_Result
do_install(struct MHD_Connection *conn, const char *title_id,
           patchdl_source_t src, const char *patch_url, const char *delta_url,
           const char *patch_title_id, const char *patch_storage_title_id,
           const char *content_id, const char *version, int enabled, int force) {
    char              dest[320], msg[256], resp[720];
    int               rc;
    install_stream_t *st = NULL;

    if (!enabled)
        return queue_json(conn, MHD_HTTP_FORBIDDEN,
                          "{\"ok\":false,\"reason\":\"title_disabled\"}");

    /* only real installs get patched, shadowmounts are download-only */
    if (src != PATCHDL_SOURCE_OFFICIAL && src != PATCHDL_SOURCE_EXTERNAL)
        return queue_json(conn, MHD_HTTP_FORBIDDEN,
                          "{\"ok\":false,\"reason\":\"install_not_allowed_for_source\"}");


    if (!patch_url[0] && !delta_url[0])
        return queue_json(conn, MHD_HTTP_CONFLICT,
                          "{\"ok\":false,\"reason\":\"no_compatible_patch\"}");
    if (install_reading(title_id))
        return queue_json(conn, MHD_HTTP_CONFLICT,
                          "{\"ok\":false,\"reason\":\"install_running\"}");
    if (version_installed(title_id, version))
        return queue_json(conn, MHD_HTTP_CONFLICT,
                          "{\"ok\":false,\"reason\":\"already_installed\"}");
    if (!download_complete(title_id)) {
        struct stat pst;
        title_pkg_path(title_id, patch_url, dest, sizeof(dest));
        return queue_json(conn, MHD_HTTP_CONFLICT, stat(dest, &pst) == 0
                          ? "{\"ok\":false,\"reason\":\"download_unverified\"}"
                          : "{\"ok\":false,\"reason\":\"download_incomplete\"}");
    }

    /* the update lands next to the game and needs about the pkg size free
       there, or the installer reads the header and quietly gives up. no error,
       of course. force = user said go anyway */
    if (!force) {
        char        gdir[256] = "";
        struct stat pst;
        pthread_mutex_lock(&g_mutex);
        for (size_t i = 0; i < g_title_count; i++)
            if (!strcmp(g_titles[i].title_id, title_id)) {
                snprintf(gdir, sizeof gdir, "%s", g_titles[i].source_path);
                break;
            }
        pthread_mutex_unlock(&g_mutex);
        title_pkg_path(title_id, patch_url, dest, sizeof(dest));
        if (gdir[0] && stat(dest, &pst) == 0) {
            long long need   = (long long)pst.st_size + INSTALL_SPACE_MARGIN;
            long long free_b = game_free_bytes(gdir);
            if (free_b >= 0 && free_b < need) {
                snprintf(resp, sizeof(resp),
                         "{\"ok\":false,\"reason\":\"install_space\","
                         "\"need_bytes\":%lld,\"free_bytes\":%lld}", need, free_b);
                return queue_json_owned(conn, MHD_HTTP_CONFLICT, strdup(resp));
            }
        }
    }

    /* version.xml target title id must match the game */
    if (patch_title_id[0] && strncmp(patch_title_id, title_id, 9) != 0) {
        snprintf(resp, sizeof(resp),
                 "{\"ok\":false,\"reason\":\"patch_title_mismatch\","
                 "\"patch_title_id\":\"%.15s\",\"title_id\":\"%.15s\"}",
                 patch_title_id, title_id);
        return queue_json_owned(conn, MHD_HTTP_CONFLICT, strdup(resp));
    }

    /* shared-master pkgs carry the game's content id, nothing special.
       AppInstallPkg only writes metadata, so InstallByPackage via /api/pkg */
    title_pkg_path(title_id, patch_url, dest, sizeof(dest));

    /* check and claim in one go, so a second tab or a double click can't
       start it twice */
    {
        struct stat pst;
        const char *base = strrchr(dest, '/');
        const char *reason = NULL;
        time_t      now = time(NULL);

        pthread_mutex_lock(&g_mutex);
        st = stream_find(title_id);
        if (st) {
            int given_up = !strcmp(stream_phase(st, now), "stalled");
            if (st->claiming || (!st->checked && !given_up))
                reason = "install_running";
            else if (st->verified > 0 && !strcmp(st->version, version))
                reason = "already_installed";
        } else {
            /* a free entry, else the oldest finished one */
            for (int i = 0; i < MAX_STREAMS && !st; i++)
                if (!g_streams[i].title_id[0]) st = &g_streams[i];
            for (int i = 0; i < MAX_STREAMS; i++) {
                install_stream_t *c = &g_streams[i];
                int over = c->checked || !strcmp(stream_phase(c, now), "stalled");
                if (st && !st->title_id[0]) break;
                if (!c->claiming && over && (!st || c->started < st->started))
                    st = c;
            }
            if (!st) reason = "too_many_installs";   /* never drop a live one */
        }
        if (!reason) {
            memset(st, 0, sizeof *st);
            snprintf(st->title_id, sizeof st->title_id, "%.9s", title_id);
            st->total    = stat(dest, &pst) == 0 ? (long long)pst.st_size : 0;
            st->started  = st->last = now;
            st->claiming = 1;
            snprintf(st->version, sizeof st->version, "%s", version);
            snprintf(st->file, sizeof st->file, "%s", base ? base + 1 : dest);
        }
        pthread_mutex_unlock(&g_mutex);
        if (reason) {
            snprintf(resp, sizeof(resp), "{\"ok\":false,\"reason\":\"%s\"}", reason);
            return queue_json_owned(conn, MHD_HTTP_CONFLICT, strdup(resp));
        }
    }

    rc = patchdl_install_local_pkg(dest, title_id, NULL, content_id, msg, sizeof(msg));
    pthread_mutex_lock(&g_mutex);
    if (rc == 0) {
        st->claiming = 0;
        st->started  = st->last = time(NULL);
    } else {
        memset(st, 0, sizeof *st);   /* nothing started, release */
    }
    pthread_mutex_unlock(&g_mutex);
    snprintf(resp, sizeof(resp),
             "{\"ok\":%s,\"rc\":%d,\"message\":\"%s\",\"path\":\"%s\"}",
             rc == 0 ? "true" : "false", rc, msg, dest);
    return queue_json_owned(conn, rc == 0 ? MHD_HTTP_OK : MHD_HTTP_BAD_GATEWAY,
                            strdup(resp));
}

/* Prospero link to Sony's manifest (<name>.json next to <name>_sc.pkg
   and .crc). NULL on success, else a reason for the UI */
static const char *
manifest_from_link(const char *tid, const char *in, char *canon, size_t sz) {
    static const char *const ends[] = { "_sc.pkg", ".crc", ".json", NULL };
    char        tag[16];
    const char *p, *rest, *base, *stem_end = NULL;
    size_t      n = strlen(in);
    int         ps4_piece = 0;

    /* the URL lands unescaped in JSON, and dot segments could walk into
       another title's folder */
    for (p = in; *p; p++)
        if (!isalnum((unsigned char)*p) && !strchr("-._~:/", *p))
            return "url_invalid";
    if (strstr(in, ".."))           return "url_invalid";
    if (!strncmp(in, "https://", 8))     rest = in + 8;
    else if (!strncmp(in, "http://", 7)) rest = in + 7;
    else                            return "url_not_allowed";
    if (!cdn_host_ok(rest))         return "url_not_allowed";

    for (int i = 0; ends[i]; i++) {
        size_t el = strlen(ends[i]);
        if (n > el && !strcmp(in + n - el, ends[i])) { stem_end = in + n - el; break; }
    }
    /* PS4: Orbis lists the pieces (<name>_0.pkg ... or <name>.pkg), same
       gs2 folder as <name>.json */
    if (!stem_end && !strncmp(rest, "gs2.ww.prod.dl.playstation.net/", 31) &&
        n > 5 && !strcmp(in + n - 4, ".pkg")) {
        const char *d = in + n - 4;
        while (d > in && isdigit((unsigned char)d[-1])) d--;
        stem_end = (d < in + n - 4 && d > in && d[-1] == '_') ? d - 1 : in + n - 4;
        ps4_piece = 1;
    }
    if (!stem_end)                  return "not_an_sc_link";
    base = strrchr(in, '/') + 1;    /* the scheme guarantees a '/' */
    if (stem_end <= base)           return "not_an_sc_link";

    /* Sony's paths look like .../<TID>_00/<publisher>-<TID>_00-<label>,
       both parts must name this title */
    snprintf(tag, sizeof tag, "/%.9s_", tid);
    if (!strstr(in, tag))           return "url_title_mismatch";
    tag[0] = '-';
    if (!strstr(base, tag))         return "url_title_mismatch";

    /* PS5 manifests over https with the pinned Sony root, PS4 ones only
       exist over plain http on gs2 (PLAIN_HTTP_HOST) */
    if (sizeof("https://") - 1 + (size_t)(stem_end - rest) + sizeof(".json") > sz)
        return "url_too_long";
    snprintf(canon, sz, "%s%.*s.json", ps4_piece ? "http://" : "https://",
             (int)(stem_end - rest), rest);
    return NULL;
}

/* Prospero shows GiB, about 0.1 above the piece sum. 1 if found is
   clearly off, likely another version's link */
static int
size_mismatch(const char *tid, const char *ver, const char *given_size,
              long long found, char *label, size_t lsz) {
    char   lbl[16] = {0}, pver[16] = {0}, unit[8] = {0};
    double v, unit_bytes, expect, diff, tol;

    if (given_size && given_size[0]) {
        /* size the version list showed for the picked version */
        snprintf(lbl, sizeof lbl, "%s", given_size);
        snprintf(pver, sizeof pver, "%s", ver);
    } else {
        pthread_mutex_lock(&g_mutex);
        for (size_t i = 0; i < g_title_count; i++)
            if (!strcmp(g_titles[i].title_id, tid)) {
                memcpy(lbl, g_titles[i].prospero_size, sizeof lbl - 1);
                memcpy(pver, g_titles[i].prospero_version, sizeof pver - 1);
                break;
            }
        pthread_mutex_unlock(&g_mutex);
    }
    for (char *c = lbl; *c; c++)          /* external text, echoed into JSON */
        if (!isalnum((unsigned char)*c) && *c != '.' && *c != ' ') *c = '?';
    snprintf(label, lsz, "%s", lbl);

    /* "8.7GB" (Orbis) and "71.7 GB" (Prospero) */
    if (strcmp(pver, ver) || sscanf(lbl, "%lf %7s", &v, unit) != 2) return 0;
    if (!strcmp(unit, "TB"))      unit_bytes = 1099511627776.0;
    else if (!strcmp(unit, "GB")) unit_bytes = 1073741824.0;
    else if (!strcmp(unit, "MB")) unit_bytes = 1048576.0;
    else return 0;
    expect = v * unit_bytes;
    diff   = (double)found - expect;
    if (diff < 0) diff = -diff;
    tol = expect * 0.02;
    if (tol < 0.15 * unit_bytes) tol = 0.15 * unit_bytes;
    return diff > tol;
}

/* the link must be in this title's own CDN folder */
static enum MHD_Result
handle_download_url(struct MHD_Connection *conn, const char *body) {
    char             tid[32], in[768], ver[16], canon[512], state[320], resp[192];
    char             expect[16], given[16] = "";
    patchdl_manifest_t mf;
    char             purl[512], durl[512], ptid[16], pstid[16];
    char             cid[64], tname[128], tv[16];
    const char      *p, *why;
    struct stat      st;
    int              en = 0, busy = 0, pieces;
    long long        found;
    patchdl_source_t src = PATCHDL_SOURCE_UNKNOWN;

    json_get_str(body, "title_id", tid, sizeof tid);
    json_get_str(body, "url", in, sizeof in);
    json_get_str(body, "version", ver, sizeof ver);

    if (!tid[0] || !in[0] || !ver[0])
        return queue_json(conn, MHD_HTTP_BAD_REQUEST,
            "{\"ok\":false,\"reason\":\"title_id, url and version required\"}");
    if (!path_segment_safe(tid) || strlen(tid) < 9)
        return queue_json(conn, MHD_HTTP_FORBIDDEN,
            "{\"ok\":false,\"reason\":\"title_id_unsafe\"}");
    for (p = ver; *p; p++)
        if (!isdigit((unsigned char)*p) && *p != '.')
            return queue_json(conn, MHD_HTTP_BAD_REQUEST,
                "{\"ok\":false,\"reason\":\"version_invalid\"}");
    if ((why = manifest_from_link(tid, in, canon, sizeof canon))) {
        snprintf(resp, sizeof resp, "{\"ok\":false,\"reason\":\"%s\"}", why);
        return queue_json_owned(conn, MHD_HTTP_BAD_REQUEST, strdup(resp));
    }

    if (!get_title_action_info(tid, &src, purl, sizeof purl, durl, sizeof durl,
                               ptid, sizeof ptid, pstid, sizeof pstid,
                               cid, sizeof cid, tname, sizeof tname,
                               tv, sizeof tv, &en))
        return queue_text(conn, MHD_HTTP_NOT_FOUND, "unknown title");
    if (!en)
        return queue_json(conn, MHD_HTTP_FORBIDDEN,
            "{\"ok\":false,\"reason\":\"title_disabled\"}");
    if (src == PATCHDL_SOURCE_UNKNOWN || src == PATCHDL_SOURCE_FAKE ||
        src == PATCHDL_SOURCE_SHADOWMOUNT)
        return queue_json(conn, MHD_HTTP_FORBIDDEN,
            "{\"ok\":false,\"reason\":\"source_not_supported\"}");

    /* versions share the file name, so cancel the old download first */
    pthread_mutex_lock(&g_pool.mtx);
    for (dl_job_t *j = g_pool.jobs; j; j = j->next)
        if (!strcmp(j->title_id, tid)) busy = 1;
    pthread_mutex_unlock(&g_pool.mtx);
    title_state_path(tid, state, sizeof state);
    if (busy || stat(state, &st) == 0)
        return queue_json(conn, MHD_HTTP_CONFLICT,
            "{\"ok\":false,\"reason\":\"download_exists\","
            "\"hint\":\"cancel the current download first\"}");

    /* fetch the manifest now so a dead link fails right away */
    if (patchdl_fetch_manifest(canon, &mf) != 0)
        return queue_json(conn, MHD_HTTP_BAD_GATEWAY,
            "{\"ok\":false,\"reason\":\"manifest_unavailable\"}");
    found  = mf.total;
    pieces = mf.count;
    patchdl_manifest_free(&mf);
    {
        long long free_b;
        char      dir[160];
        title_dir(tid, dir, sizeof dir);
        if (!space_ok(dir, found, &free_b)) {
            snprintf(resp, sizeof resp,
                     "{\"ok\":false,\"reason\":\"no_space\","
                     "\"need_bytes\":%lld,\"free_bytes\":%lld}", found, free_b);
            return queue_json_owned(conn, 507, strdup(resp));
        }
    }
    json_get_str(body, "size", given, sizeof given);
    if (size_mismatch(tid, ver, given, found, expect, sizeof expect) &&
        !json_get_bool(body, "force", 0)) {
        snprintf(resp, sizeof resp,
                 "{\"ok\":false,\"reason\":\"size_mismatch\","
                 "\"found_bytes\":%lld,\"pieces\":%d,\"expected\":\"%s\"}",
                 found, pieces, expect);
        return queue_json_owned(conn, MHD_HTTP_CONFLICT, strdup(resp));
    }

    save_manual_source(tid, canon, ver);
    set_manual_source(tid, canon, ver);
    return do_download(conn, tid, src, canon, "", tname, ver, en);
}


static int
parse_title_action(const char *url, char *title_id, size_t tid_sz,
                   char *action, size_t act_sz) {
    const char *prefix = "/api/titles/";
    const char *start, *slash;
    size_t len;

    if (strncmp(url, prefix, strlen(prefix))) return -1;
    start = url + strlen(prefix);
    slash = strchr(start, '/');
    if (!slash || slash == start || !slash[1]) return -1;

    len = (size_t)(slash - start);
    if (len >= tid_sz) return -1;
    memcpy(title_id, start, len);
    title_id[len] = '\0';

    len = strlen(slash + 1);
    if (len >= act_sz) return -1;
    memcpy(action, slash + 1, len + 1);
    return 0;
}

static enum MHD_Result
handle_title_action(struct MHD_Connection *conn, const char *url) {
    char             title_id[32];
    char             action[24];
    char             patch_url[512] = {0};
    char             delta_url[512] = {0};
    char             patch_title_id[16] = {0};
    char             patch_storage_title_id[16] = {0};
    char             content_id[64] = {0};
    char             name[128] = {0};
    char             version[16] = {0};
    int              enabled = 0;
    patchdl_source_t src = PATCHDL_SOURCE_UNKNOWN;

    if (parse_title_action(url, title_id, sizeof(title_id),
                           action, sizeof(action)))
        return queue_text(conn, MHD_HTTP_NOT_FOUND, "not found");

    /* title_id ends up in paths that get created and recursively deleted.
       ".." would point the dir at /data, so reject before any mkdir/unlink */
    if (!path_segment_safe(title_id))
        return queue_text(conn, MHD_HTTP_FORBIDDEN, "forbidden");

    if (!get_title_action_info(title_id, &src,
                               patch_url, sizeof(patch_url),
                               delta_url, sizeof(delta_url),
                               patch_title_id, sizeof(patch_title_id),
                               patch_storage_title_id,
                               sizeof(patch_storage_title_id),
                               content_id, sizeof(content_id),
                               name, sizeof(name),
                               version, sizeof(version),
                               &enabled))
        return queue_text(conn, MHD_HTTP_NOT_FOUND, "unknown title");

    if (!strcmp(action, "enable"))
        return set_title_enabled(conn, title_id, 1);

    if (!strcmp(action, "disable"))
        return set_title_enabled(conn, title_id, 0);

    if (!strcmp(action, "download"))
        return do_download(conn, title_id, src, patch_url, delta_url,
                           name, version, enabled);

    if (!strcmp(action, "cancel"))
        return do_cancel(conn, title_id);

    if (!strcmp(action, "pause"))
        return do_pause(conn, title_id);

    if (!strcmp(action, "check"))
        return queue_json(conn, MHD_HTTP_ACCEPTED,
                          "{\"ok\":true,\"queued\":true,\"action\":\"check\"}");

    if (!strcmp(action, "install")) {
        const char *f = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "force");
        return do_install(conn, title_id, src, patch_url, delta_url,
                          patch_title_id, patch_storage_title_id,
                          content_id, version, enabled, f && !strcmp(f, "1"));
    }

    return queue_text(conn, MHD_HTTP_NOT_FOUND, "not found");
}


/* the body comes in chunks, collected in con_cls. real ones are a few
   hundred bytes */
#define PATCHDL_POST_MAX_BYTES (64 * 1024)
typedef struct {
    char  *data;
    size_t len;
    int    oversized;
} post_body_t;

static void
request_completed(void *cls, struct MHD_Connection *conn, void **con_cls,
                  enum MHD_RequestTerminationCode toe) {
    (void)cls; (void)conn; (void)toe;
    post_body_t *pb = *con_cls;
    if (pb) {
        free(pb->data);
        free(pb);
        *con_cls = NULL;
    }
}

static enum MHD_Result
handle_config_post(struct MHD_Connection *conn, const char *body) {
    char pol[8];
    int  mc;
    int  tile_just_enabled = 0;

    json_get_str(body, "default_policy", pol, sizeof(pol));
    /* only the two real values, anything else is dropped */
    if (pol[0] && strcmp(pol, "allow") != 0 && strcmp(pol, "deny") != 0)
        pol[0] = '\0';

    pthread_mutex_lock(&g_mutex);
    if (pol[0]) {
        strncpy(g_cfg.default_policy, pol, sizeof(g_cfg.default_policy) - 1);
        g_cfg.default_policy[sizeof(g_cfg.default_policy) - 1] = '\0';
    }
    g_cfg.install_after_download =
        json_get_bool(body, "install_after_download", g_cfg.install_after_download);
    g_cfg.delete_pkg_after_install =
        json_get_bool(body, "delete_pkg_after_install", g_cfg.delete_pkg_after_install);
    g_cfg.verify_downloads =
        json_get_bool(body, "verify_downloads", g_cfg.verify_downloads);
    {
        int prev_tile = g_cfg.home_shortcut;
        g_cfg.home_shortcut =
            json_get_bool(body, "home_shortcut", g_cfg.home_shortcut);
        tile_just_enabled = (!prev_tile && g_cfg.home_shortcut);
    }
    g_cfg.max_connections =
        json_get_int(body, "max_connections", g_cfg.max_connections);
    if (g_cfg.max_connections < 1) g_cfg.max_connections = 1;
    if (g_cfg.max_connections > POOL_MAX_CONN) g_cfg.max_connections = POOL_MAX_CONN;
    {
        /* only a drive that is mounted right now can be picked */
        char drive[32] = "";
        json_get_str(body, "download_drive", drive, sizeof drive);
        if (drive_name_ok(drive) && drive_mounted(drive)) {
            pthread_mutex_lock(&g_drive_mtx);
            snprintf(g_cfg.download_drive, sizeof g_cfg.download_drive, "%s", drive);
            pthread_mutex_unlock(&g_drive_mtx);
        }
    }
    mc = g_cfg.max_connections;
    pthread_mutex_unlock(&g_mutex);

    /* apply to the live pool, g_mutex already released (lock order) */
    pthread_mutex_lock(&g_pool.mtx);
    g_pool.active_conns = mc;
    if (g_pool.active_conns < 1) g_pool.active_conns = 1;
    if (g_pool.active_conns > g_pool.n_workers) g_pool.active_conns = g_pool.n_workers;
    pthread_cond_broadcast(&g_pool.cv);
    pthread_mutex_unlock(&g_pool.mtx);

    save_config();

    /* best effort, the config is saved already. stat-guarded, repeats are free */
    if (tile_just_enabled) {
        char tile_msg[256];
        (void)patchdl_tile_install_if_needed(tile_msg, sizeof(tile_msg));
    }

    return queue_json_owned(conn, MHD_HTTP_OK, build_config_json());
}

static enum MHD_Result
on_request(void *cls, struct MHD_Connection *conn, const char *url,
           const char *method, const char *version, const char *upload_data,
           size_t *upload_data_size, void **con_cls) {
    (void)cls; (void)version;

    if (!strcmp(method, MHD_HTTP_METHOD_OPTIONS))
        return queue_text(conn, MHD_HTTP_NO_CONTENT, "");

    if (!strcmp(method, MHD_HTTP_METHOD_POST)) {
        post_body_t *pb = *con_cls;

        if (!pb) {                          /* first call: set up the buffer */
            pb = calloc(1, sizeof(*pb));
            if (!pb) return MHD_NO;
            *con_cls = pb;
            return MHD_YES;
        }

        if (*upload_data_size) {
            if (!pb->oversized &&
                pb->len + *upload_data_size <= PATCHDL_POST_MAX_BYTES) {
                char *n = realloc(pb->data, pb->len + *upload_data_size + 1);
                if (n) {
                    memcpy(n + pb->len, upload_data, *upload_data_size);
                    pb->len += *upload_data_size;
                    n[pb->len] = '\0';
                    pb->data = n;
                } else {
                    pb->oversized = 1;
                }
            } else {
                pb->oversized = 1;     /* drop further chunks to bound RAM */
            }
            *upload_data_size = 0;
            return MHD_YES;
        }

        if (pb->oversized)
            return queue_json(conn, MHD_HTTP_CONTENT_TOO_LARGE,
                              "{\"ok\":false,\"reason\":\"body_too_large\"}");
        const char *body = pb->data ? pb->data : "";
        if (!strcmp(url, "/api/config"))
            return handle_config_post(conn, body);
        if (!strcmp(url, "/api/rescan")) {
            g_scan_now = 1;
            return queue_json(conn, MHD_HTTP_ACCEPTED, "{\"ok\":true}");
        }
        if (!strncmp(url, "/api/titles/", 12))
            return handle_title_action(conn, url);
        /* also for games no longer installed */
        if (!strncmp(url, "/api/storage/", 13)) {
            char        tid[32];
            const char *slash = strchr(url + 13, '/');
            size_t      tl    = slash ? (size_t)(slash - (url + 13)) : 0;
            if (!slash || strcmp(slash, "/delete") || !tl || tl >= sizeof tid)
                return queue_text(conn, MHD_HTTP_NOT_FOUND, "not found");
            memcpy(tid, url + 13, tl);
            tid[tl] = '\0';
            if (!is_title_dir_name(tid))
                return queue_text(conn, MHD_HTTP_FORBIDDEN, "forbidden");
            {
                /* a title can sit on two drives, delete the one the list showed */
                char drive[32] = "", dir[160], cur[160];
                json_get_str(body, "drive", drive, sizeof drive);
                if (drive[0] && drive_name_ok(drive)) {
                    snprintf(dir, sizeof dir, "%s/patchdl/%s", drive, tid);
                    title_dir(tid, cur, sizeof cur);
                    if (strcmp(dir, cur)) {   /* not the folder downloads use */
                        remove_dir_files(dir);
                        return queue_json(conn, MHD_HTTP_OK, "{\"ok\":true,\"cancelled\":true}");
                    }
                }
            }
            return do_cancel(conn, tid);
        }
        if (!strcmp(url, "/api/install_uri")) {
            char uri[768] = {0}, cid[64] = {0}, tid[32] = {0};
            char msg[256], resp[1100];
            int rc;
            json_get_str(body, "uri", uri, sizeof(uri));
            json_get_str(body, "content_id", cid, sizeof(cid));
            json_get_str(body, "title_id", tid, sizeof(tid));
            if (!uri[0])
                return queue_json(conn, MHD_HTTP_BAD_REQUEST,
                                  "{\"ok\":false,\"reason\":\"uri required\"}");
            if (!install_uri_safe(uri))
                return queue_json(conn, MHD_HTTP_FORBIDDEN,
                                  "{\"ok\":false,\"reason\":\"uri_not_allowed\","
                                  "\"hint\":\"https:// only, host must be Sony CDN\"}");
            if (tid[0] && !path_segment_safe(tid))
                return queue_json(conn, MHD_HTTP_BAD_REQUEST,
                                  "{\"ok\":false,\"reason\":\"title_id_unsafe\"}");
            if (cid[0] && !path_segment_safe(cid))
                return queue_json(conn, MHD_HTTP_BAD_REQUEST,
                                  "{\"ok\":false,\"reason\":\"content_id_unsafe\"}");
            rc = patchdl_install_by_uri(uri, tid[0] ? tid : NULL,
                                        cid[0] ? cid : NULL, msg, sizeof(msg));
            snprintf(resp, sizeof(resp),
                     "{\"ok\":%s,\"rc\":%d,\"rc_hex\":\"0x%08x\",\"message\":\"%s\","
                     "\"uri\":\"%.511s\",\"content_id\":\"%.63s\",\"title_id\":\"%.31s\"}",
                     rc == 0 ? "true" : "false", rc, (unsigned)rc, msg,
                     uri, cid, tid);
            return queue_json_owned(conn, rc == 0 ? MHD_HTTP_OK : MHD_HTTP_BAD_GATEWAY,
                                    strdup(resp));
        }
        if (!strcmp(url, "/api/install_aip")) {
            char path[768] = {0}, cid[64] = {0}, tid[32] = {0};
            char msg[256], resp[1100];
            int rc;
            json_get_str(body, "path", path, sizeof(path));
            json_get_str(body, "content_id", cid, sizeof(cid));
            json_get_str(body, "title_id", tid, sizeof(tid));
            if (!path[0])
                return queue_json(conn, MHD_HTTP_BAD_REQUEST,
                                  "{\"ok\":false,\"reason\":\"path required\"}");
            if (!local_install_path_safe(path))
                return queue_json(conn, MHD_HTTP_FORBIDDEN,
                                  "{\"ok\":false,\"reason\":\"path_not_allowed\","
                                  "\"hint\":\"must be <drive>/patchdl"
                                  "/<title_id>/<filename>\"}");
            if (tid[0] && !path_segment_safe(tid))
                return queue_json(conn, MHD_HTTP_BAD_REQUEST,
                                  "{\"ok\":false,\"reason\":\"title_id_unsafe\"}");
            if (cid[0] && !path_segment_safe(cid))
                return queue_json(conn, MHD_HTTP_BAD_REQUEST,
                                  "{\"ok\":false,\"reason\":\"content_id_unsafe\"}");
            rc = patchdl_install_app_pkg(path, tid[0] ? tid : NULL,
                                         cid[0] ? cid : NULL, msg, sizeof(msg));
            snprintf(resp, sizeof(resp),
                     "{\"ok\":%s,\"rc\":%d,\"rc_hex\":\"0x%08x\",\"message\":\"%s\","
                     "\"path\":\"%.511s\",\"content_id\":\"%.63s\",\"title_id\":\"%.31s\"}",
                     rc == 0 ? "true" : "false", rc, (unsigned)rc, msg,
                     path, cid, tid);
            return queue_json_owned(conn, rc == 0 ? MHD_HTTP_OK : MHD_HTTP_BAD_GATEWAY,
                                    strdup(resp));
        }
        if (!strcmp(url, "/api/download_url"))
            return handle_download_url(conn, body);
        if (!strcmp(url, "/api/install_tile")) {
            char msg[256], resp[320];
            int  rc = patchdl_tile_install_if_needed(msg, sizeof(msg));
            snprintf(resp, sizeof(resp),
                     "{\"ok\":%s,\"rc\":%d,\"message\":\"%s\"}",
                     rc == 0 ? "true" : "false", rc, msg);
            return queue_json_owned(conn, rc == 0 ? MHD_HTTP_OK : MHD_HTTP_BAD_GATEWAY,
                                    strdup(resp));
        }
        return queue_text(conn, MHD_HTTP_NOT_FOUND, "not found");
    }

    if (strcmp(method, MHD_HTTP_METHOD_GET) &&
        strcmp(method, MHD_HTTP_METHOD_HEAD))
        return queue_text(conn, MHD_HTTP_METHOD_NOT_ALLOWED, "method not allowed");

    if (!strcmp(url, "/api/status"))
        return queue_json_owned(conn, MHD_HTTP_OK, build_status_json());

    if (!strcmp(url, "/api/config"))
        return queue_json_owned(conn, MHD_HTTP_OK, build_config_json());

    if (!strcmp(url, "/api/titles"))
        return queue_json_owned(conn, MHD_HTTP_OK, build_titles_json());

    if (!strncmp(url, "/api/icon/", 10)) {
        if (!path_segment_safe(url + 10))
            return queue_text(conn, MHD_HTTP_FORBIDDEN, "forbidden");
        return queue_icon(conn, url + 10);
    }

    if (!strcmp(url, "/api/downloads"))
        return queue_json_owned(conn, MHD_HTTP_OK, build_downloads_json());

    if (!strcmp(url, "/api/storage"))
        return queue_json_owned(conn, MHD_HTTP_OK, build_storage_json());

    if (!strcmp(url, "/api/debug"))
        return queue_json(conn, MHD_HTTP_OK,
                          g_debug_json ? g_debug_json : "{}");

    if (!strcmp(url, "/api/installcheck")) {
        char m[256], r[320];
        int rc = patchdl_install_backend_check(m, sizeof(m));
        snprintf(r, sizeof(r), "{\"ready\":%s,\"message\":\"%s\"}",
                 rc == 0 ? "true" : "false", m);
        return queue_json_owned(conn, MHD_HTTP_OK, strdup(r));
    }

    if (!strcmp(url, "/api/apiprobe")) {
        char p[2048];
        patchdl_install_api_probe(p, sizeof(p));
        return queue_json_owned(conn, MHD_HTTP_OK, strdup(p));
    }

    if (!strcmp(url, "/api/installstatus")) {
        char   p[1024], streams[MAX_STREAMS * 260 + 32];
        size_t pl, sl = 0;
        time_t now = time(NULL);
        patchdl_install_status_json(p, sizeof(p));
        sl = (size_t)snprintf(streams, sizeof streams, ",\"streams\":[");
        pthread_mutex_lock(&g_mutex);
        for (int i = 0, n = 0; i < MAX_STREAMS; i++) {
            const install_stream_t *st = &g_streams[i];
            if (!st->title_id[0]) continue;
            sl += (size_t)snprintf(streams + sl, sizeof streams - sl,
                     "%s{\"title_id\":\"%s\",\"read\":%lld,\"total\":%lld,"
                     "\"crc\":%s,\"idle_secs\":%lld,\"phase\":\"%s\","
                     "\"verified\":%s,\"deleted\":%s}",
                     n++ ? "," : "", st->title_id, st->read, st->total,
                     st->crc ? "true" : "false", (long long)(now - st->last),
                     stream_phase(st, now),
                     !st->checked ? "null" : st->verified > 0 ? "true" : "false",
                     st->deleted ? "true" : "false");
            if (sl >= sizeof streams) sl = sizeof streams - 1;
        }
        pthread_mutex_unlock(&g_mutex);
        snprintf(streams + sl, sizeof streams - sl, "]");
        pl = strlen(p);
        {
            size_t tot = pl + strlen(streams) + 2;
            char  *out = malloc(tot);
            if (!out) return queue_text(conn, MHD_HTTP_INTERNAL_SERVER_ERROR, "oom");
            if (pl > 0 && p[pl - 1] == '}') {
                p[pl - 1] = '\0';
                snprintf(out, tot, "%s%s}", p, streams);
            } else {
                snprintf(out, tot, "%s", p);
            }
            return queue_json_owned(conn, MHD_HTTP_OK, out);
        }
    }

    if (!strcmp(url, "/api/debug_install")) {
        char p[512];
        patchdl_install_debug_state(p, sizeof(p));
        return queue_json_owned(conn, MHD_HTTP_OK, strdup(p));
    }

    if (!strcmp(url, "/api/pkgdiag")) {
        /* copy under the lock, record_pkg_diag may be mid-write */
        char   snap[sizeof(g_pkg_diag_json)];
        jbuf_t j = {0};
        pthread_mutex_lock(&g_mutex);
        memcpy(snap, g_pkg_diag_json, sizeof(snap));
        snap[sizeof(snap) - 1] = '\0';
        jbuf_append(&j, "{\"last\":");
        jbuf_append(&j, snap);
        jbuf_append(&j, ",\"log\":[");
        for (unsigned i = 0, n = 0; i < PKG_LOG_LINES; i++) {
            const char *line = g_pkg_log[(g_pkg_log_next + i) % PKG_LOG_LINES];
            if (!line[0]) continue;
            if (n++) jbuf_append(&j, ",");
            jbuf_append_str(&j, line);
        }
        jbuf_append(&j, "]}");
        pthread_mutex_unlock(&g_mutex);
        return queue_json_owned(conn, MHD_HTTP_OK, j.buf ? j.buf : strdup("{}"));
    }

    /* read-only: manifest pieces with offset/size/SHA-256 */
    if (!strncmp(url, "/api/manifest/", 14)) {
        const char      *tid = url + 14;
        char             purl[768] = {0}, durl_[512] = {0};
        char             pti[32], psti[32], cid[64], nm[128], ver[16];
        patchdl_source_t src;
        int              en;
        patchdl_manifest_t mf;
        jbuf_t           j = {0};

        if (!path_segment_safe(tid))
            return queue_text(conn, MHD_HTTP_FORBIDDEN, "forbidden");
        if (!get_title_action_info(tid, &src, purl, sizeof purl,
                                   durl_, sizeof durl_,
                                   pti, sizeof pti,
                                   psti, sizeof psti, cid, sizeof cid,
                                   nm, sizeof nm, ver, sizeof ver, &en) || !purl[0])
            return queue_json(conn, MHD_HTTP_NOT_FOUND,
                              "{\"error\":\"no patch_url for title\"}");
        memset(&mf, 0, sizeof mf);
        if (patchdl_fetch_manifest(purl, &mf) != 0)
            return queue_json(conn, MHD_HTTP_BAD_GATEWAY,
                              "{\"error\":\"manifest fetch failed\"}");
        jbuf_appendf(&j, "{\"count\":%d,\"total\":%lld,\"pieces\":[",
                     mf.count, mf.total);
        for (int i = 0; i < mf.count; i++) {
            if (i) jbuf_append(&j, ",");
            jbuf_appendf(&j, "{\"o\":%lld,\"s\":%lld,\"h\":\"%s\"}",
                         mf.pieces[i].offset, mf.pieces[i].size, mf.pieces[i].hash);
        }
        jbuf_append(&j, "]}");
        patchdl_manifest_free(&mf);
        return queue_json_owned(conn, MHD_HTTP_OK,
                                j.buf ? j.buf : strdup("{}"));
    }

    /* read-only: hash every piece of the pkg on disk against the manifest */
    if (!strncmp(url, "/api/pkgverify/", 15)) {
        const char        *tid = url + 15;
        char               purl[768] = {0}, durl_[512] = {0};
        char               pti[32], psti[32], cid[64], nm[128], ver[16];
        char               dest[320];
        patchdl_source_t   src;
        int                en, fd, okc = 0, badc = 0, first_bad = -1;
        patchdl_manifest_t mf;
        jbuf_t             j = {0};

        if (!path_segment_safe(tid))
            return queue_text(conn, MHD_HTTP_FORBIDDEN, "forbidden");
        if (!get_title_action_info(tid, &src, purl, sizeof purl,
                                   durl_, sizeof durl_,
                                   pti, sizeof pti,
                                   psti, sizeof psti, cid, sizeof cid,
                                   nm, sizeof nm, ver, sizeof ver, &en) || !purl[0])
            return queue_json(conn, MHD_HTTP_NOT_FOUND,
                              "{\"error\":\"no patch_url for title\"}");
        title_pkg_path(tid, purl, dest, sizeof dest);
        fd = open(dest, O_RDONLY);
        if (fd < 0)
            return queue_json(conn, MHD_HTTP_NOT_FOUND,
                              "{\"error\":\"pkg not on disk\"}");
        memset(&mf, 0, sizeof mf);
        if (patchdl_fetch_manifest(purl, &mf) != 0) {
            close(fd);
            return queue_json(conn, MHD_HTTP_BAD_GATEWAY,
                              "{\"error\":\"manifest fetch failed\"}");
        }
        jbuf_appendf(&j, "{\"count\":%d,\"pieces\":[", mf.count);
        for (int i = 0; i < mf.count; i++) {
            char got[80] = {0};
            int  ok = 0;
            if (mf.pieces[i].hash[0] &&
                patchdl_hash_fd_region(fd, mf.pieces[i].offset,
                                       mf.pieces[i].size, mf.pieces[i].hash, got) == 0)
                ok = (strcasecmp(got, mf.pieces[i].hash) == 0);
            if (ok) okc++; else { badc++; if (first_bad < 0) first_bad = i; }
            if (i) jbuf_append(&j, ",");
            jbuf_appendf(&j, "{\"i\":%d,\"o\":%lld,\"s\":%lld,\"ok\":%s}",
                         i, mf.pieces[i].offset, mf.pieces[i].size,
                         ok ? "true" : "false");
        }
        jbuf_appendf(&j, "],\"ok\":%d,\"bad\":%d,\"first_bad\":%d,\"all_ok\":%s}",
                     okc, badc, first_bad, (badc == 0 ? "true" : "false"));
        patchdl_manifest_free(&mf);
        close(fd);
        return queue_json_owned(conn, MHD_HTTP_OK, j.buf ? j.buf : strdup("{}"));
    }

    /* read-only: pkg's own content/title id vs the installed app's */
    if (!strncmp(url, "/api/pkgmeta/", 13)) {
        const char      *tid = url + 13;
        char             purl[768] = {0}, durl_[512] = {0};
        char             pti[32], psti[32], cid[64], nm[128], ver[16];
        char             dest[320], ecid[64] = {0}, etid[48] = {0}, msg[128], resp[900];
        patchdl_source_t src;
        int              en, is_app = 0, rc;

        if (!path_segment_safe(tid))
            return queue_text(conn, MHD_HTTP_FORBIDDEN, "forbidden");
        if (!get_title_action_info(tid, &src, purl, sizeof purl,
                                   durl_, sizeof durl_,
                                   pti, sizeof pti,
                                   psti, sizeof psti, cid, sizeof cid,
                                   nm, sizeof nm, ver, sizeof ver, &en) || !purl[0])
            return queue_json(conn, MHD_HTTP_NOT_FOUND, "{\"error\":\"unknown title\"}");
        title_pkg_path(tid, purl, dest, sizeof dest);
        rc = patchdl_install_pkg_meta(dest, ecid, sizeof ecid, etid, sizeof etid,
                                      &is_app, msg, sizeof msg);
        snprintf(resp, sizeof resp,
                 "{\"ok\":%s,\"pkg_content_id\":\"%s\",\"pkg_title_id\":\"%s\","
                 "\"is_app\":%s,\"target_content_id\":\"%s\",\"target_title_id\":\"%s\","
                 "\"storage_title_id\":\"%s\",\"installable\":%s,"
                 "\"install_plan\":\"installbypackage\",\"msg\":\"%s\"}",
                 rc == 0 ? "true" : "false", ecid, etid, is_app ? "true" : "false",
                 cid, tid, psti,
                 /* Sony's title-id query comes back empty for some
                    pkgs, because why not. the content id has it too */
                 (rc == 0 && (!strncmp(etid, tid, 9) ||
                              (ecid[0] && !strcmp(ecid, cid)))) ? "true" : "false",
                 msg);
        return queue_json_owned(conn, MHD_HTTP_OK, strdup(resp));
    }

    if (!strcmp(url, "/api/drives"))
        return queue_json_owned(conn, MHD_HTTP_OK, build_drives_json());
    if (!strcmp(url, "/api/versions")) {
        const char *want = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "title");
        return queue_versions(conn, want ? want : "");
    }
    if (!strcmp(url, "/api/netcheck")) {
        const char *want = MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "title");
        if (want && want[0])
            return queue_netcheck_title(conn, want);
    }
    if (!strcmp(url, "/api/netcheck")) {
        char diag[1024] = "{\"error\":\"no title with version_file_uri\"}";
        char uri[256] = "";
        /* copy under the lock, probe without it (blocks on the network) */
        pthread_mutex_lock(&g_mutex);
        for (size_t i = 0; i < g_title_count; i++)
            if (g_titles[i].version_file_uri[0]) {
                snprintf(uri, sizeof uri, "%s", g_titles[i].version_file_uri);
                break;
            }
        pthread_mutex_unlock(&g_mutex);
        if (uri[0]) patchdl_net_diag(uri, diag, sizeof(diag));
        /* diag is on the stack and MHD sends later, hence MUST_COPY */
        return queue_buffer(conn, MHD_HTTP_OK, "application/json",
                            diag, strlen(diag), MHD_RESPMEM_MUST_COPY);
    }

    if (!strncmp(url, "/api/pkg/", 9))
        return queue_pkg_file(conn, url);

    return queue_asset(conn, url);
}

/* progress from the sidecar, the pkg is preallocated */
static void
detect_resumable_partials(patchdl_title_t *arr, size_t cnt) {
    char   state[320], buf[16384];
    FILE  *f;
    size_t n;

    for (size_t i = 0; i < cnt; i++) {
        patchdl_title_t *t = &arr[i];
        long long total, done;
        title_state_path(t->title_id, state, sizeof(state));
        f = fopen(state, "r");
        if (!f) continue;
        n = fread(buf, 1, sizeof(buf) - 1, f);
        fclose(f);
        buf[n] = '\0';
        total = json_get_ll(buf, "total", 0);
        done  = json_get_ll(buf, "done_bytes", 0);
        {
            /* plus synced parts of started pieces */
            char        have[SIDECAR_MAX_HAVE * 24];
            const char *p = have;
            json_get_str(buf, "have", have, sizeof have);
            while (*p) {
                char *end;
                (void)strtol(p, &end, 10);
                if (*end != ':') break;
                done += strtoll(end + 1, &end, 10);
                if (*end != ',') break;
                p = end + 1;
            }
        }
        if (done > 0 && (total <= 0 || done < total)) {
            t->resumable = 1;
            t->partial_bytes = done;
        } else if (total > 0 && done >= total) {
            t->downloaded = 1;
        }
    }
}


static void
start_verxml(void) {
    pthread_attr_t attr;
    g_verxml_stop = 0;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 512 * 1024);   /* curl, OpenSSL, resolver */
    if (pthread_create(&g_verxml_tid, &attr, verxml_fetch_thread, NULL) == 0)
        g_verxml_started = 1;
    pthread_attr_destroy(&attr);
}

static void
stop_verxml(void) {
    if (!g_verxml_started) return;
    g_verxml_stop = 1;
    pthread_join(g_verxml_tid, NULL);
    g_verxml_started = 0;
}

/* update info only carries over with same version/content id, no refresh */
static void
carry_title_state(patchdl_title_t *dst, const patchdl_title_t *src, int recheck) {
    /* turned sideloaded (or back): keep the new default, so no update
       without the user's ok */
    if (dst->sideloaded == src->sideloaded)
        dst->enabled = src->enabled;
    dst->resumable     = src->resumable;
    dst->partial_bytes = src->partial_bytes;
    dst->downloaded    = src->downloaded;
    memcpy(dst->manual_url, src->manual_url, sizeof dst->manual_url);
    memcpy(dst->manual_version, src->manual_version, sizeof dst->manual_version);
    /* an explicit refresh asks Sony again for new patches */
    if (recheck || strcmp(dst->installed_version, src->installed_version) ||
        strcmp(dst->content_id, src->content_id))
        return;
    memcpy(dst->compatible_version, src->compatible_version, sizeof dst->compatible_version);
    memcpy(dst->latest_version, src->latest_version, sizeof dst->latest_version);
    memcpy(dst->latest_required_fw, src->latest_required_fw, sizeof dst->latest_required_fw);
    memcpy(dst->patch_url, src->patch_url, sizeof dst->patch_url);
    memcpy(dst->delta_url, src->delta_url, sizeof dst->delta_url);
    memcpy(dst->patch_title_id, src->patch_title_id, sizeof dst->patch_title_id);
    memcpy(dst->patch_storage_title_id, src->patch_storage_title_id,
           sizeof dst->patch_storage_title_id);
    dst->verxml_done = src->verxml_done;
    memcpy(dst->prospero_version, src->prospero_version, sizeof dst->prospero_version);
    memcpy(dst->prospero_required_fw, src->prospero_required_fw,
           sizeof dst->prospero_required_fw);
    memcpy(dst->prospero_size, src->prospero_size, sizeof dst->prospero_size);
    dst->prospero_done = src->prospero_done;
}

/* only the scan thread calls this */
static int
rescan_titles(int recheck) {
    patchdl_title_t *arr, *old;
    size_t           cnt, old_cnt;
    long             t0 = mono_ms(), t1, t2;

    g_rescan_since = t0;
    g_rescan_step  = "scan";
    if (patchdl_scan(&arr, &cnt)) { g_rescan_step = "scan failed"; return -1; }
    t1 = mono_ms();
    g_rescan_step = "policy";
    apply_title_policy(arr, cnt);
    load_manual_sources(arr, cnt);
    detect_resumable_partials(arr, cnt);

    /* the version.xml thread holds pointers into g_titles */
    g_rescan_step = "stop verxml";
    stop_verxml();
    t2 = mono_ms();
    g_rescan_step = "swap";
    pthread_mutex_lock(&g_mutex);
    for (size_t i = 0; i < cnt; i++)
        for (size_t k = 0; k < g_title_count; k++)
            if (!strcmp(arr[i].title_id, g_titles[k].title_id)) {
                carry_title_state(&arr[i], &g_titles[k], recheck);
                break;
            }
    old = g_titles;  old_cnt = g_title_count;
    g_titles = arr;  g_title_count = cnt;
    g_titles_gen++;
    g_rescan_ms[0] = t1 - t0;
    g_rescan_ms[1] = t2 - t1;
    g_rescan_ms[2] = mono_ms() - t0;
    pthread_mutex_unlock(&g_mutex);
    patchdl_scan_free(old, old_cnt);
    start_verxml();
    g_rescan_step = "idle";
    return 0;
}

#define POST_INSTALL_GIVE_UP (15 * 60)

/* did the install really take this pkg? version and app.json (the file
   and size) must both say so */
static void
check_one_install(int idx) {
    char              tid[16], ver[16], file[160], size_key[48];
    char             *aj;
    long long         total, idle;
    time_t            last;
    int               del, ok, deleted = 0;
    install_stream_t *st;

    pthread_mutex_lock(&g_mutex);
    st = &g_streams[idx];
    if (!st->title_id[0] || st->checked || st->claiming || !stream_read_all(st) ||
        time(NULL) - st->last < INSTALL_QUIET_SECS) {
        pthread_mutex_unlock(&g_mutex);
        return;
    }
    snprintf(tid, sizeof tid, "%s", st->title_id);
    snprintf(ver, sizeof ver, "%s", st->version);
    snprintf(file, sizeof file, "%s", st->file);
    total = st->total;
    last  = st->last;
    del   = g_cfg.delete_pkg_after_install;
    pthread_mutex_unlock(&g_mutex);

    /* app.json lists every piece URL, give it room */
    idle = (long long)(time(NULL) - last);
    snprintf(size_key, sizeof size_key, "\"originalFileSize\":%lld", total);
    aj = malloc(256 * 1024);
    /* a PS5 update replaces app.pkg (app.json), a PS4 patch lands in
       /user/patch/<id>/ (patch.json) */
    ok = aj && version_installed(tid, ver) && file[0] &&
         (strncmp(tid, "CUSA", 4)
              ? patchdl_scan_read_app_file(tid, "app.json", aj, 256 * 1024)
              : patchdl_scan_read_patch_file(tid, "patch.json", aj, 256 * 1024)) == 0 &&
         strstr(aj, file) && strstr(aj, size_key);
    free(aj);
    /* install_reading() would say busy, but this is the install being
       checked and it's done */
    if (ok && del) {
        cancel_title(tid);
        deleted = 1;
    }

    /* the console may register the version a while after the last
       request, so keep trying for 15 minutes */
    if (!ok && idle < POST_INSTALL_GIVE_UP)
        return;
    pthread_mutex_lock(&g_mutex);
    if ((st = stream_find(tid))) {     /* the entry may have been reused */
        st->checked  = 1;
        st->verified = ok ? 1 : -1;
        st->deleted  = deleted;
    }
    pthread_mutex_unlock(&g_mutex);
}

static void
post_install_check(void) {
    for (int i = 0; i < MAX_STREAMS; i++)
        check_one_install(i);
}

/* rescan when the title dirs or app.db held still for a poll (disc copies
   take minutes), or a minute after the last pkg fetch */
static void *
scan_watch_thread(void *arg) {
    unsigned long long scanned = patchdl_scan_signature(), seen = scanned;
    time_t             fetched_seen = 0, next_check = 0;
    (void)arg;

    while (!g_scan_stop) {
        unsigned long long now;
        time_t             fetched;
        int                install_done;
        for (int s = 0; s < 5 && !g_scan_stop && !g_scan_now; s++)
            sleep(1);
        if (g_scan_stop) break;
        now = patchdl_scan_signature();
        pthread_mutex_lock(&g_mutex);
        fetched = g_pkg_last_time;
        pthread_mutex_unlock(&g_mutex);
        install_done = fetched != fetched_seen &&
                       time(NULL) - fetched >= INSTALL_QUIET_SECS;
        if (g_scan_now || install_done ||
            (now && now != scanned && now == seen)) {
            int recheck = g_scan_now;   /* the Refresh button */
            g_scan_now = 0;
            if (install_done) fetched_seen = fetched;
            /* a failed scan (app.db caught mid-write, happens more than you'd
               think) keeps the old signature, so the next poll retries */
            if (rescan_titles(recheck) == 0) scanned = now;
            if (install_done) {
                post_install_check();
                next_check = time(NULL) + INSTALL_QUIET_SECS;
            }
        } else if (next_check && time(NULL) >= next_check) {
            /* not checked yet: rescan and retry each minute until it gives up */
            int pending;
            pthread_mutex_lock(&g_mutex);
            pending = 0;
            for (int i = 0; i < MAX_STREAMS; i++)
                if (g_streams[i].title_id[0] && !g_streams[i].checked &&
                    strcmp(stream_phase(&g_streams[i], time(NULL)), "stalled"))
                    pending = 1;
            pthread_mutex_unlock(&g_mutex);
            if (pending) {
                rescan_titles(0);
                post_install_check();
                next_check = time(NULL) + INSTALL_QUIET_SECS;
            } else {
                next_check = 0;
            }
        }
        seen = now;
    }
    return NULL;
}


static unsigned short web_port;

static struct MHD_Daemon *
start_web_daemon(unsigned short port) {
    return MHD_start_daemon(
        MHD_USE_INTERNAL_POLLING_THREAD | MHD_USE_THREAD_PER_CONNECTION,
        port, NULL, NULL, &on_request, NULL,
        MHD_OPTION_NOTIFY_COMPLETED, request_completed, NULL,
        /* RAM caps, the process budget is a few hundred MB. single-user UI */
        MHD_OPTION_CONNECTION_LIMIT,        (unsigned int)8,
        MHD_OPTION_PER_IP_CONNECTION_LIMIT, (unsigned int)8,
        MHD_OPTION_CONNECTION_TIMEOUT,      (unsigned int)30,
        MHD_OPTION_THREAD_STACK_SIZE,       (size_t)(512 * 1024),
        MHD_OPTION_END);
}

int
patchdl_websrv_start(unsigned short port) {
    if (web_daemon) return 0;

    /* fw and titles synchronously, the UI only comes up after this */
    patchdl_fw_get(&g_fw);

    if (patchdl_scan(&g_titles, &g_title_count))
        g_title_count = 0;

    /* default: unknown sources off, then the saved config on top */
    for (size_t i = 0; i < g_title_count; i++)
        g_titles[i].enabled = (g_titles[i].source_type != PATCHDL_SOURCE_UNKNOWN) &&
                              !g_titles[i].sideloaded;
    load_config();
    /* a saved config can't switch a fake back on */
    for (size_t i = 0; i < g_title_count; i++)
        if (g_titles[i].source_type == PATCHDL_SOURCE_FAKE)
            g_titles[i].enabled = 0;

    /* home tile, stat-guarded. a failure never blocks startup */
    if (g_cfg.home_shortcut) {
        char tile_msg[256];
        (void)patchdl_tile_install_if_needed(tile_msg, sizeof(tile_msg));
    }

    /* partials on disk get Resume after a reboot */
    load_manual_sources(g_titles, g_title_count);
    detect_resumable_partials(g_titles, g_title_count);

    /* single-threaded only, the root vnode swap inside is unsafe once
       MHD threads run */
    g_debug_json = patchdl_scan_debug_json();

    /* curl/OpenSSL global init once, before the workers race their first
       curl_easy_init */
    patchdl_net_global_init();

    /* spawn all up front and cap with active_conns, so the count can go up
       live. limits set before the first pthread_create */
    g_pool.n_workers   = POOL_MAX_CONN;
    g_pool.active_conns = g_cfg.max_connections;
    if (g_pool.active_conns < 1) g_pool.active_conns = 1;
    if (g_pool.active_conns > POOL_MAX_CONN) g_pool.active_conns = POOL_MAX_CONN;
    g_pool.stopping = 0;
    {
        /* explicit stack, the default was too small once */
        pthread_attr_t wattr;
        int spawned = 0;
        pthread_attr_init(&wattr);
        pthread_attr_setstacksize(&wattr, 256 * 1024);
        for (int s = 0; s < POOL_MAX_CONN; s++) {
            if (pthread_create(&g_pool.workers[s], &wattr, dl_worker,
                               (void *)(intptr_t)s))
                break;             /* only the threads that started exist */
            spawned++;
        }
        pthread_attr_destroy(&wattr);
        if (spawned < g_pool.n_workers) {
            pthread_mutex_lock(&g_pool.mtx);
            g_pool.n_workers = spawned;
            if (g_pool.active_conns > g_pool.n_workers)
                g_pool.active_conns = g_pool.n_workers;
            pthread_mutex_unlock(&g_pool.mtx);
        }
    }

    web_port   = port;
    web_daemon = start_web_daemon(port);

    if (!web_daemon) {
        pthread_mutex_lock(&g_pool.mtx);
        g_pool.stopping = 1;
        pthread_cond_broadcast(&g_pool.cv);
        pthread_mutex_unlock(&g_pool.mtx);
        for (int s = 0; s < g_pool.n_workers; s++)
            pthread_join(g_pool.workers[s], NULL);
        patchdl_net_global_cleanup();
        patchdl_scan_free(g_titles, g_title_count);
        g_titles = NULL;
        g_title_count = 0;
        return -1;
    }

    /* no more root vnode swaps from here, they're process-wide and would race
       the MHD threads. later scans go through the kept root fd */
    patchdl_scan_lock();

    start_verxml();

    /* load the install backend early so the first Install click finds it ready */
    {
        char m[128];
        (void)patchdl_install_backend_check(m, sizeof m);
    }

    /* the scan keeps a few 8 KB buffers on its stack and the default stack
       disagrees (EFAULT on a read, that was a fun one) */
    g_scan_stop = 0;
    {
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setstacksize(&attr, 1024 * 1024);
        if (pthread_create(&g_scan_tid, &attr, scan_watch_thread, NULL) == 0)
            g_scan_started = 1;
        pthread_attr_destroy(&attr);
    }

    return 0;
}

/* only a refused loopback connect means the listener is gone, a timeout
   says nothing */
static int
listener_refused(unsigned short port) {
    struct sockaddr_in sa;
    struct pollfd      pfd;
    int                fd, err = 0, refused = 0;
    socklen_t          len = sizeof err;

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) return 0;
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    memset(&sa, 0, sizeof sa);
    sa.sin_family      = AF_INET;
    sa.sin_port        = htons(port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (!connect(fd, (struct sockaddr *)&sa, sizeof sa)) {
        close(fd);
        return 0;
    }
    if (errno == ECONNREFUSED) {
        refused = 1;
    } else if (errno == EINPROGRESS) {
        pfd.fd     = fd;
        pfd.events = POLLOUT;
        if (poll(&pfd, 1, 2000) == 1 &&
            !getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len))
            refused = err == ECONNREFUSED;
    }
    close(fd);
    return refused;
}

/* the console drops listening sockets on network changes and the process
   lives on happily with nobody able to connect. restart it */
int
patchdl_websrv_watch(void) {
    struct MHD_Daemon *d = NULL;

    if (!web_daemon || !listener_refused(web_port)) return 0;
    printf("PatchDL web server stopped accepting, restarting it\n");
    MHD_stop_daemon(web_daemon);
    web_daemon = NULL;
    for (int i = 0; i < 5 && !(d = start_web_daemon(web_port)); i++)
        sleep(1);
    web_daemon = d;
    if (d) g_web_restarts++;
    printf("PatchDL web server restart %s\n", d ? "done" : "failed");
    return d ? 1 : -1;
}

void
patchdl_websrv_stop(void) {
    if (web_daemon) {
        MHD_stop_daemon(web_daemon);
        web_daemon = NULL;
    }
    /* rescan thread first (it restarts version.xml), then version.xml before
       g_titles goes */
    if (g_scan_started) {
        g_scan_stop = 1;
        pthread_join(g_scan_tid, NULL);
        g_scan_started = 0;
    }
    stop_verxml();
    /* workers finish their current piece write, then exit */
    pthread_mutex_lock(&g_pool.mtx);
    g_pool.stopping = 1;
    pthread_cond_broadcast(&g_pool.cv);
    pthread_mutex_unlock(&g_pool.mtx);
    for (int s = 0; s < g_pool.n_workers; s++)
        pthread_join(g_pool.workers[s], NULL);
    g_pool.n_workers = 0;
    /* workers are joined, nobody else touches the list */
    pthread_mutex_lock(&g_pool.mtx);
    while (g_pool.jobs) free_job_locked(g_pool.jobs);
    pthread_mutex_unlock(&g_pool.mtx);
    patchdl_net_global_cleanup();

    pthread_mutex_lock(&g_mutex);
    patchdl_scan_free(g_titles, g_title_count);
    g_titles      = NULL;
    g_title_count = 0;
    free(g_debug_json);
    g_debug_json  = NULL;
    pthread_mutex_unlock(&g_mutex);
}
