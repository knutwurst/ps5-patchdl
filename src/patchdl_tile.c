/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Knutwurst
 *
 * PatchDL is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version. See the LICENSE file in the project root for details.
 */

#include "patchdl_tile.h"
#include "patchdl_install.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <ps5/kernel.h>

/* .incbin straight into .rodata, no codegen step */
#define INCASSET(name, file)                                                  \
    __asm__(".section .rodata\n"                                              \
            ".global " #name "\n"                                             \
            ".global " #name "_end\n"                                         \
            ".global " #name "_size\n"                                        \
            ".align 16\n" #name ":\n"                                         \
            ".incbin \"" file "\"\n" #name "_end:\n" #name "_size:\n"         \
            ".quad " #name "_end - " #name "\n"                               \
            ".previous\n");                                                   \
    extern const uint8_t name[];                                              \
    extern const size_t  name##_size;

INCASSET(tile_param_json, "assets/param.json");
INCASSET(tile_icon0_png,  "assets/icon0.png");

#define TILE_TITLE_ID "PTDL00001"

/* resolved at runtime, linking the sce libs breaks the elfldr */
typedef int (*ai_init_fn)(void);
typedef int (*ai_install_dir_fn)(const char *title_id, const char *parent_dir,
                                  void *opts);
typedef int (*ai_install_all_fn)(void *opts);
typedef int (*ai_uninstall_fn)(const char *title_id);

static intptr_t
dynsym_by_name(const char *sym) {
    uint32_t h = 0;
    if (kernel_dynlib_handle(-1, "libSceAppInstUtil.sprx", &h) < 0) return 0;
    return kernel_dynlib_dlsym(-1, h, sym);
}

static intptr_t
dynsym_by_nid(const char *nid) {
    uint32_t h = 0;
    if (kernel_dynlib_handle(-1, "libSceAppInstUtil.sprx", &h) < 0) return 0;
    return kernel_dynlib_resolve(-1, h, nid);
}

static int
write_all(const char *path, const uint8_t *data, size_t size) {
    int     fd;
    ssize_t w;
    size_t  off = 0;

    /* no symlink games, no 0666 (same as fopen_safe) */
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    while (off < size) {
        w = write(fd, data + off, size - off);
        if (w < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        off += (size_t)w;
    }
    close(fd);
    return 0;
}

static int
file_matches(const char *path, const uint8_t *expected, size_t expected_size) {
    struct stat st;
    uint8_t    *buf;
    int         fd;
    ssize_t     n;
    int         match = 0;

    if (stat(path, &st) != 0) return 0;
    if ((size_t)st.st_size != expected_size) return 0;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;

    buf = malloc(expected_size);
    if (!buf) { close(fd); return 0; }

    n = read(fd, buf, expected_size);
    close(fd);
    if (n == (ssize_t)expected_size && memcmp(buf, expected, expected_size) == 0)
        match = 1;

    free(buf);
    return match;
}

int
patchdl_tile_install_if_needed(char *msg, size_t msg_sz) {
    char base_dir[128];
    char sce_sys_dir[160];
    char param_path[192];
    char icon_path[192];
    char receipt_path[192];

    ai_init_fn        ai_initialize    = NULL;
    ai_install_dir_fn ai_install_title = NULL;
    ai_install_all_fn ai_install_all   = NULL;
    int               rc, was_registered;

    snprintf(base_dir,    sizeof base_dir,    "/user/app/%s",                  TILE_TITLE_ID);
    snprintf(sce_sys_dir, sizeof sce_sys_dir, "/user/app/%s/sce_sys",          TILE_TITLE_ID);
    snprintf(param_path,  sizeof param_path,  "/user/app/%s/sce_sys/param.json", TILE_TITLE_ID);
    snprintf(icon_path,   sizeof icon_path,   "/user/app/%s/sce_sys/icon0.png",  TILE_TITLE_ID);
    /* written once the installer took the tile, or leftovers from a failed
       register would pass the stat-guard forever */
    snprintf(receipt_path, sizeof receipt_path, "/user/app/%s/.patchdl_registered", TILE_TITLE_ID);

    /* stat-guard: don't bother the installer on every start */
    {
        struct stat st;
        if (stat(receipt_path, &st) == 0 &&
            file_matches(param_path, tile_param_json, tile_param_json_size) &&
            file_matches(icon_path,  tile_icon0_png,  tile_icon0_png_size)) {
            snprintf(msg, msg_sz, "tile already installed and up to date");
            return 0;
        }
    }

    /* the backend thread maps libSceAppInstUtil.sprx lazily. wait max 15 s,
       a stuck init must not hang an MHD worker */
    {
        char    ready_msg[128];
        int     ready = -1;
        for (int i = 0; i < 60 && ready != 0; i++) {
            ready = patchdl_install_backend_check(ready_msg, sizeof ready_msg);
            if (ready != 0) usleep(250 * 1000);
        }
        if (ready != 0) {
            snprintf(msg, msg_sz,
                     "install backend not ready: %s", ready_msg);
            return -1;
        }
    }

    /* Sony-private export: NID first, name as fallback */
    ai_install_title = (ai_install_dir_fn)dynsym_by_nid("Wudg3Xe3heE");
    if (!ai_install_title)
        ai_install_title = (ai_install_dir_fn)dynsym_by_name(
            "sceAppInstUtilAppInstallTitleDir");
    /* gone on fw 13.xx. AppInstallAll rescans /user/app, same result */
    if (!ai_install_title)
        ai_install_all = (ai_install_all_fn)dynsym_by_name(
            "sceAppInstUtilAppInstallAll");
    if (!ai_install_title && !ai_install_all) {
        snprintf(msg, msg_sz,
                 "neither AppInstallTitleDir nor AppInstallAll resolved");
        return -1;
    }

    ai_initialize = (ai_init_fn)dynsym_by_name("sceAppInstUtilInitialize");
    if (ai_initialize) {
        rc = ai_initialize();
        if (rc != 0 && rc != 0x80B21161 /* ALREADY_INITIALIZED */) {
            snprintf(msg, msg_sz,
                     "sceAppInstUtilInitialize failed 0x%08x", (unsigned)rc);
            return -1;
        }
    }

    if (mkdir(base_dir, 0755) && errno != EEXIST) {
        snprintf(msg, msg_sz, "mkdir %s failed errno=%d", base_dir, errno);
        return -1;
    }
    if (mkdir(sce_sys_dir, 0755) && errno != EEXIST) {
        snprintf(msg, msg_sz, "mkdir %s failed errno=%d", sce_sys_dir, errno);
        return -1;
    }

    /* a tile stays in the section (Games/Media) it was first registered in.
       old ones sit in Games, so uninstall first. only ever PatchDL's own id */
    {
        struct stat st;
        /* old param.json, receipt or not (pre-0.0.7 tiles have none) */
        was_registered = stat(param_path, &st) == 0 &&
                         !file_matches(param_path, tile_param_json, tile_param_json_size);
    }
    if (was_registered) {
        ai_uninstall_fn ai_uninstall = (ai_uninstall_fn)dynsym_by_name(
            "sceAppInstUtilAppUnInstall");
        if (ai_uninstall) (void)ai_uninstall(TILE_TITLE_ID);
        if (mkdir(base_dir, 0755) && errno != EEXIST) {
            snprintf(msg, msg_sz, "mkdir %s failed errno=%d", base_dir, errno);
            return -1;
        }
        if (mkdir(sce_sys_dir, 0755) && errno != EEXIST) {
            snprintf(msg, msg_sz, "mkdir %s failed errno=%d", sce_sys_dir, errno);
            return -1;
        }
    }

    unlink(receipt_path);
    if (write_all(param_path, tile_param_json, tile_param_json_size)) {
        snprintf(msg, msg_sz, "write param.json failed errno=%d", errno);
        return -1;
    }
    if (write_all(icon_path, tile_icon0_png, tile_icon0_png_size)) {
        snprintf(msg, msg_sz, "write icon0.png failed errno=%d", errno);
        return -1;
    }

    rc = ai_install_title ? ai_install_title(TILE_TITLE_ID, "/user/app/", NULL)
                          : ai_install_all(NULL);
    if (rc != 0) {
        snprintf(msg, msg_sz, "%s(%s) returned 0x%08x",
                 ai_install_title ? "AppInstallTitleDir" : "AppInstallAll",
                 TILE_TITLE_ID, (unsigned)rc);
        return -1;
    }

    (void)write_all(receipt_path, (const uint8_t *)"1", 1);
    snprintf(msg, msg_sz, "tile installed (%s via %s)", TILE_TITLE_ID,
             ai_install_title ? "AppInstallTitleDir" : "AppInstallAll");
    return 0;
}
