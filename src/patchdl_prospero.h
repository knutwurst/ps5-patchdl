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
    char version[16];      /* "01.003.000" */
    char required_fw[16];  /* "7.01" */
    char size[16];         /* site label, "71.7 GB" (GiB, rounded up) */
    int  found;
} patchdl_prospero_result_t;

/* newest patch that runs on fw_bin. 0 with found==0 means none fits,
   -1 means the site didn't answer. best effort only */
int patchdl_prospero_query(const char *title_id, uint32_t fw_bin,
                           patchdl_prospero_result_t *out);

typedef struct {
    char     version[16];      /* "01.003.000" (PS5) or "01.07" (PS4) */
    char     required_fw[16];  /* for PS4 a PS4 firmware */
    char     size[16];         /* site label, "8.7GB" */
    uint32_t fw_bin;           /* PS5 firmware it needs, 0 for PS4 */
} patchdl_patch_version_t;

/* more than any game ever had, the response is capped at 512 KB anyway */
#define PATCHSITE_MAX_VERSIONS 512

const char *patchdl_patchsite_base(const char *title_id);

/* in site order, newest first */
int patchdl_patchsite_versions(const char *title_id, patchdl_patch_version_t *out,
                               int max, int *count);
