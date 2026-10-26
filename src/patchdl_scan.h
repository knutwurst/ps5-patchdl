/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Knutwurst
 *
 * PatchDL is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version. See the LICENSE file in the project root for details.
 */

#pragma once

#include <sys/types.h>

#include <stddef.h>
#include <stdint.h>

typedef enum {
    PATCHDL_SOURCE_OFFICIAL    = 0,
    PATCHDL_SOURCE_EXTERNAL    = 1,
    PATCHDL_SOURCE_SHADOWMOUNT = 2,
    PATCHDL_SOURCE_UNKNOWN     = 3,
    PATCHDL_SOURCE_FAKE        = 4, /* debug/fake-signed, not supported */
} patchdl_source_t;

/* from the installed app.pkg header */
typedef enum {
    PATCHDL_PKG_NONE    = 0, /* no app.pkg */
    PATCHDL_PKG_RETAIL  = 1,
    PATCHDL_PKG_FAKE    = 2,
    PATCHDL_PKG_UNREAD  = 3, /* app.pkg present but header unreadable/unknown */
} patchdl_pkg_sign_t;

typedef struct {
    char             title_id[32];
    char             content_id[64];
    char             name[128];
    char             installed_version[16];
    char             source_path[256];
    char             mount_from[256];
    char             version_file_uri[256]; /* from app.db, for version.xml */
    patchdl_source_t source_type;
    patchdl_pkg_sign_t pkg_sign;      /* for diagnostics */
    int              sideloaded;       /* Sony-signed, other installer */
    int              icon_fd;          /* open icon0.png, or -1 */
    /* filled by the verxml fetch, under the websrv mutex */
    char             compatible_version[16];
    char             latest_version[16];
    char             latest_required_fw[16];
    char             patch_url[512];   /* manifest_url, else pkg URL */
    char             delta_url[512];   /* DP.pkg bootstrap URL */
    char             patch_title_id[16]; /* target title id from version.xml */
    char             patch_storage_title_id[16]; /* from delta_url */
    int              verxml_done;
    /* Prospero Patches: best compatible patch from the history */
    char             prospero_version[16];
    char             prospero_required_fw[16];
    char             prospero_size[16];
    int              prospero_done;
    /* from a pasted Prospero link, replaces patch_url when set */
    char             manual_url[512];
    char             manual_version[16];
    int              enabled;          /* user setting, config.json */
    int              resumable;        /* a partial download is on disk */
    int              downloaded;       /* a finished download is on disk */
    long long        partial_bytes;    /* size of that partial, for the UI */
} patchdl_title_t;

int         patchdl_scan(patchdl_title_t **titles_out, size_t *count_out);
void        patchdl_scan_free(patchdl_title_t *titles, size_t count);
const char *patchdl_source_str(patchdl_source_t src);

/* mount table + scan dirs as malloc'd JSON, caller frees */
char       *patchdl_scan_debug_json(void);

/* cheap hash over the title dirs and app.db for the auto rescan. 0 without
   the system root fd, never rescan on that */
unsigned long long patchdl_scan_signature(void);

/* current scan step, "idle" when none */
const char *patchdl_scan_step(void);

/* statvfs via the kept system root, the process root doesn't see /user/app */
struct statvfs;
int patchdl_scan_sys_statvfs(const char *path, struct statvfs *out);

/* <title dir>/<name> via the kept system root, thread-safe, cwd untouched */
int patchdl_scan_read_app_file(const char *title_id, const char *name,
                               char *buf, size_t sz);
/* same for PS4 patches in /user/patch/<id> */
int patchdl_scan_read_patch_file(const char *title_id, const char *name,
                                 char *buf, size_t sz);

/* len bytes at offset of an installed app's file, e.g. a slice of app.pkg.
   bytes read, -1 if the file isn't there */
ssize_t patchdl_scan_read_app_range(const char *title_id, const char *name,
                                    long long offset, void *buf, size_t len);

/* once, after MHD_start_daemon: the root vnode swap is process-wide and
   would race the workers. after that scans go via the kept root fd (cwd
   only, one caller at a time) and the debug dump returns NULL */
void        patchdl_scan_lock(void);
