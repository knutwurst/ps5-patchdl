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

/* manifest links people pasted from Prospero/Orbis, kept per title and
   version so the next time needs no browser. thread-safe, leaf lock */

#define PATCHDL_LINKS_MAX 1024

/* 0 if the file was read (missing file counts as empty) */
int  patchdl_links_load(const char *path);

/* 0 and url filled if there's one for title_id + version */
int  patchdl_links_get(const char *title_id, const char *version,
                       char *url, size_t url_sz);

/* add or replace, written to disk right away. full list drops the oldest */
void patchdl_links_put(const char *title_id, const char *version, const char *url);

void patchdl_links_drop(const char *title_id, const char *version);

/* versions with a saved link for title_id, up to max. returns the count */
int  patchdl_links_versions(const char *title_id, char (*out)[16], int max);
