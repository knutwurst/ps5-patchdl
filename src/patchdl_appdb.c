/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Knutwurst
 *
 * PatchDL is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version. See the LICENSE file in the project root for details.
 */

#include "patchdl_appdb.h"

#include <errno.h>
#include <fcntl.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define APP_DB_URI \
    "file:/system_data/priv/mms/app.db?immutable=1"
/* sqlite getcwd()s a relative path back into the payload's own root, so a
   rescan copies app.db out via the cwd (system root, see patchdl_scan) */
#define APP_DB_REL      "system_data/priv/mms/app.db"
#define APP_DB_SNAPSHOT "/data/patchdl/.appdb.snapshot"
#define APP_DB_URI_SNAPSHOT "file:" APP_DB_SNAPSHOT "?immutable=1"

static char g_appdb_err[64];

const char *
patchdl_appdb_error(void) {
    return g_appdb_err;
}

static int
snapshot_appdb(void) {
    char   *buf;
    ssize_t n;
    int     in, out, rc = 0;

    if ((in = open(APP_DB_REL, O_RDONLY | O_CLOEXEC)) < 0) {
        snprintf(g_appdb_err, sizeof g_appdb_err, "open app.db errno %d", errno);
        return -1;
    }
    out = open(APP_DB_SNAPSHOT, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (out < 0) {
        snprintf(g_appdb_err, sizeof g_appdb_err, "open snapshot errno %d", errno);
        close(in);
        return -1;
    }
    if (!(buf = malloc(65536))) {
        close(in);
        close(out);
        return -1;
    }
    while ((n = read(in, buf, 65536)) > 0)
        if (write(out, buf, (size_t)n) != n) {
            snprintf(g_appdb_err, sizeof g_appdb_err, "write snapshot errno %d", errno);
            rc = -1;
            break;
        }
    if (n < 0) {
        snprintf(g_appdb_err, sizeof g_appdb_err, "read app.db errno %d", errno);
        rc = -1;
    }
    free(buf);
    close(in);
    close(out);
    if (rc) unlink(APP_DB_SNAPSHOT);
    return rc;
}

#define APPDB_MAX 1024

/* flat AppInfoJson only. Sony pads VERSION_FILE_URI with spaces */
static void
json_str(const char *json, const char *key, char *out, size_t out_sz) {
    char        needle[48];
    const char *p;
    size_t      len;

    out[0] = '\0';
    if ((size_t)snprintf(needle, sizeof(needle), "\"%s\"", key) >= sizeof(needle))
        return;

    p = strstr(json, needle);
    if (!p) return;
    p += strlen(needle);
    while (*p == ' ' || *p == '\t' || *p == ':' || *p == '\n' || *p == '\r')
        p++;
    if (*p != '"') return;
    p++;
    /* URLs come as https:\/\/..., so a bit of unescaping */
    len = 0;
    while (*p && *p != '"' && len < out_sz - 1) {
        if (*p == '\\' && p[1]) {
            p++;
            switch (*p) {
            case 'n': out[len++] = '\n'; break;
            case 't': out[len++] = '\t'; break;
            case 'r': out[len++] = '\r'; break;
            default:  out[len++] = *p;   break;
            }
            p++;
            continue;
        }
        out[len++] = *p++;
    }
    out[len] = '\0';
    while (len > 0 && (out[len - 1] == ' ' || out[len - 1] == '\t'))
        out[--len] = '\0';
}

static int
load_db(const char *uri, patchdl_appinfo_t **out, size_t *count) {
    int           step = SQLITE_DONE;
    sqlite3      *db = NULL;
    sqlite3_stmt *stmt = NULL;
    patchdl_appinfo_t *arr;
    size_t        n = 0;

    *out = NULL;
    *count = 0;

    if (sqlite3_open_v2(uri, &db,
                        SQLITE_OPEN_READONLY | SQLITE_OPEN_URI |
                        SQLITE_OPEN_FULLMUTEX, NULL) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return -1;
    }

    if (sqlite3_prepare_v2(db,
            "SELECT titleId, titleName, contentId, AppInfoJson "
            "FROM tbl_contentinfo;", -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }

    arr = calloc(APPDB_MAX, sizeof(*arr));
    if (!arr) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return -1;
    }

    while ((step = sqlite3_step(stmt)) == SQLITE_ROW && n < APPDB_MAX) {
        patchdl_appinfo_t *e = &arr[n];
        const char *tid  = (const char *)sqlite3_column_text(stmt, 0);
        const char *name = (const char *)sqlite3_column_text(stmt, 1);
        const char *cid  = (const char *)sqlite3_column_text(stmt, 2);
        const char *json = (const char *)sqlite3_column_text(stmt, 3);

        if (!tid) continue;
        strncpy(e->title_id, tid, sizeof(e->title_id) - 1);
        if (name) strncpy(e->title_name, name, sizeof(e->title_name) - 1);
        if (cid)  strncpy(e->content_id, cid, sizeof(e->content_id) - 1);
        if (json) {
            json_str(json, "CONTENT_VERSION", e->content_version,
                     sizeof(e->content_version));
            /* PS4: no CONTENT_VERSION, APP_VER includes the patch */
            if (!e->content_version[0])
                json_str(json, "APP_VER", e->content_version,
                         sizeof(e->content_version));
            json_str(json, "VERSION_FILE_URI", e->version_file_uri,
                     sizeof(e->version_file_uri));
        }
        n++;
    }
    sqlite3_finalize(stmt);
    /* read broke off (copy taken mid-write?): fail, don't drop titles */
    if (step != SQLITE_DONE && step != SQLITE_ROW) {
        free(arr);
        sqlite3_close(db);
        return -1;
    }

    /* own query, so a fw without icon0Info only loses the icons */
    if (sqlite3_prepare_v2(db,
            "SELECT titleId, icon0Info FROM tbl_contentinfo "
            "WHERE icon0Info IS NOT NULL AND icon0Info != '';",
            -1, &stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *tid  = (const char *)sqlite3_column_text(stmt, 0);
            const char *icon = (const char *)sqlite3_column_text(stmt, 1);
            patchdl_appinfo_t *e;
            if (!tid || !icon) continue;
            e = (patchdl_appinfo_t *)patchdl_appdb_find(arr, n, tid);
            if (!e || e->icon_path[0]) continue;
            strncpy(e->icon_path, icon, sizeof(e->icon_path) - 1);
            e->icon_path[strcspn(e->icon_path, "?")] = '\0';
        }
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);

    *out = arr;
    *count = n;
    return 0;
}

int
patchdl_appdb_load(patchdl_appinfo_t **out, size_t *count, int relative) {
    int rc;
    *out = NULL;
    *count = 0;
    if (!relative) return load_db(APP_DB_URI, out, count);
    if (snapshot_appdb()) return -2;
    rc = load_db(APP_DB_URI_SNAPSHOT, out, count);
    unlink(APP_DB_SNAPSHOT);
    return rc;
}

void
patchdl_appdb_free(patchdl_appinfo_t *arr) {
    free(arr);
}

const patchdl_appinfo_t *
patchdl_appdb_find(const patchdl_appinfo_t *arr, size_t count,
                   const char *title_id) {
    for (size_t i = 0; i < count; i++)
        if (!strcmp(arr[i].title_id, title_id))
            return &arr[i];
    return NULL;
}
