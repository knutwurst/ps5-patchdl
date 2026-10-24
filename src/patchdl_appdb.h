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
    char title_id[16];
    char title_name[128];
    char content_id[64];
    char content_version[16];
    char version_file_uri[256]; /* version.xml URL */
    char icon_path[256];        /* icon0Info without its "?ts=" suffix, or "" */
} patchdl_appinfo_t;

/* tbl_contentinfo from app.db. needs elevated authid plus the root vnode
   swap, or with relative set, the cwd at the system root */
int  patchdl_appdb_load(patchdl_appinfo_t **out, size_t *count, int relative);
/* why the last app.db copy failed, or "" */
const char *patchdl_appdb_error(void);
void patchdl_appdb_free(patchdl_appinfo_t *arr);

const patchdl_appinfo_t *patchdl_appdb_find(const patchdl_appinfo_t *arr,
                                            size_t count, const char *title_id);
