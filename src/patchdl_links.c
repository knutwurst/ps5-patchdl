/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Knutwurst
 *
 * PatchDL is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version. See the LICENSE file in the project root for details.
 */

#include "patchdl_links.h"

#include <ctype.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    char tid[16];
    char ver[16];
    char url[512];
} link_t;

static pthread_mutex_t g_mtx = PTHREAD_MUTEX_INITIALIZER;
static link_t          g_links[PATCHDL_LINKS_MAX];
static int             g_count;
static char            g_path[256];

/* the file is ours, but /data is writable by anyone: trust nothing in it */
static int
tid_ok(const char *s) {
    size_t n = strlen(s);
    if (n < 9 || n > 15) return 0;
    for (; *s; s++)
        if (!isupper((unsigned char)*s) && !isdigit((unsigned char)*s) && *s != '_')
            return 0;
    return 1;
}

static int
ver_ok(const char *s) {
    if (!*s || strlen(s) > 15) return 0;
    for (; *s; s++)
        if (!isdigit((unsigned char)*s) && *s != '.') return 0;
    return 1;
}

static int
url_ok(const char *s) {
    if (strncmp(s, "https://", 8) && strncmp(s, "http://", 7)) return 0;
    if (strlen(s) >= sizeof g_links[0].url) return 0;
    for (; *s; s++)
        if ((unsigned char)*s <= ' ' || *s == '"' || *s == '\\' || *s == 0x7f) return 0;
    return 1;
}

static int
find_locked(const char *tid, const char *ver) {
    for (int i = 0; i < g_count; i++)
        if (!strcmp(g_links[i].tid, tid) && !strcmp(g_links[i].ver, ver))
            return i;
    return -1;
}

/* tmp + rename, a crash mid-write keeps the old file */
static void
save_locked(void) {
    char  tmp[272];
    FILE *f;
    int   bad = 0, fd;

    if (!g_path[0]) return;
    snprintf(tmp, sizeof tmp, "%s.tmp", g_path);
    /* /data is writable by anyone, a planted symlink must not get truncated */
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return;
    if (!(f = fdopen(fd, "w"))) { close(fd); return; }
    for (int i = 0; i < g_count; i++)
        if (fprintf(f, "%s\t%s\t%s\n", g_links[i].tid, g_links[i].ver, g_links[i].url) < 0)
            bad = 1;
    if (fclose(f) || bad || rename(tmp, g_path)) unlink(tmp);
}

int
patchdl_links_load(const char *path) {
    FILE *f;
    char  line[640];

    pthread_mutex_lock(&g_mtx);
    snprintf(g_path, sizeof g_path, "%s", path);
    g_count = 0;
    if (!(f = fopen(path, "r"))) {
        pthread_mutex_unlock(&g_mtx);
        return 0;
    }
    while (fgets(line, sizeof line, f) && g_count < PATCHDL_LINKS_MAX) {
        char *tid = line, *ver, *url, *nl;
        if (!(ver = strchr(tid, '\t'))) continue;
        *ver++ = '\0';
        if (!(url = strchr(ver, '\t'))) continue;
        *url++ = '\0';
        if ((nl = strpbrk(url, "\r\n"))) *nl = '\0';
        if (!tid_ok(tid) || !ver_ok(ver) || !url_ok(url) || find_locked(tid, ver) >= 0)
            continue;
        snprintf(g_links[g_count].tid, sizeof g_links[0].tid, "%s", tid);
        snprintf(g_links[g_count].ver, sizeof g_links[0].ver, "%s", ver);
        snprintf(g_links[g_count].url, sizeof g_links[0].url, "%s", url);
        g_count++;
    }
    fclose(f);
    pthread_mutex_unlock(&g_mtx);
    return 0;
}

int
patchdl_links_get(const char *tid, const char *ver, char *url, size_t url_sz) {
    int i, rc = -1;
    if (!tid || !ver || !url || !url_sz) return -1;
    pthread_mutex_lock(&g_mtx);
    if ((i = find_locked(tid, ver)) >= 0) {
        snprintf(url, url_sz, "%s", g_links[i].url);
        rc = 0;
    }
    pthread_mutex_unlock(&g_mtx);
    return rc;
}

void
patchdl_links_put(const char *tid, const char *ver, const char *url) {
    int i;
    if (!tid || !ver || !url || !tid_ok(tid) || !ver_ok(ver) || !url_ok(url)) return;
    pthread_mutex_lock(&g_mtx);
    if ((i = find_locked(tid, ver)) < 0) {
        if (g_count == PATCHDL_LINKS_MAX) {
            memmove(&g_links[0], &g_links[1], sizeof g_links[0] * (PATCHDL_LINKS_MAX - 1));
            g_count--;
        }
        i = g_count++;
        snprintf(g_links[i].tid, sizeof g_links[0].tid, "%s", tid);
        snprintf(g_links[i].ver, sizeof g_links[0].ver, "%s", ver);
    } else if (!strcmp(g_links[i].url, url)) {
        pthread_mutex_unlock(&g_mtx);
        return;                             /* nothing new, no write */
    }
    snprintf(g_links[i].url, sizeof g_links[0].url, "%s", url);
    save_locked();
    pthread_mutex_unlock(&g_mtx);
}

void
patchdl_links_drop(const char *tid, const char *ver) {
    int i;
    if (!tid || !ver) return;
    pthread_mutex_lock(&g_mtx);
    if ((i = find_locked(tid, ver)) >= 0) {
        memmove(&g_links[i], &g_links[i + 1], sizeof g_links[0] * (size_t)(g_count - i - 1));
        g_count--;
        save_locked();
    }
    pthread_mutex_unlock(&g_mtx);
}

int
patchdl_links_versions(const char *tid, char (*out)[16], int max) {
    int n = 0;
    if (!tid || !out || max <= 0) return 0;
    pthread_mutex_lock(&g_mtx);
    for (int i = 0; i < g_count && n < max; i++)
        if (!strcmp(g_links[i].tid, tid))
            snprintf(out[n++], 16, "%s", g_links[i].ver);
    pthread_mutex_unlock(&g_mtx);
    return n;
}
