/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Knutwurst
 *
 * PatchDL is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version. See the LICENSE file in the project root for details.
 */

#pragma once

#include <stdint.h>

typedef struct {
    char compatible_version[16]; /* newest with system_ver <= fw_bin */
    char latest_version[16];
    char latest_required_fw[16]; /* "11.60" */
    char compatible_url[512];    /* manifest_url, else delta_url */
    char delta_url[512];         /* DP.pkg, always a PKG, never JSON */
    char compatible_title[16];
    char compatible_storage_title[16]; /* from the delta_url path */
} patchdl_verinfo_t;

int patchdl_verxml_query(const char *url, uint32_t fw_bin, patchdl_verinfo_t *out);
