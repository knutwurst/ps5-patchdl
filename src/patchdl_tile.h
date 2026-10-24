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

/* param.json + icon0.png into /user/app/<id>/sce_sys, the installer registers
   the dir (no pkg, no signing). opens http://127.0.0.1:12880/, so only useful
   while the ELF runs. no-op when the files on disk already match */
int patchdl_tile_install_if_needed(char *msg, size_t msg_sz);
