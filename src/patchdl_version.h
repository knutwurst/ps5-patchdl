/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Knutwurst
 *
 * PatchDL is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version. See the LICENSE file in the project root for details.
 * Additional terms under section 7 of the GPL apply, see the NOTICE file.
 */

#pragma once

#define PATCHDL_VERSION "0.3.13"

/* set by the Makefile from GitHub Actions, empty for a local build */
#ifndef PATCHDL_BUILD_REPO
#define PATCHDL_BUILD_REPO ""
#endif
#ifndef PATCHDL_BUILD_COMMIT
#define PATCHDL_BUILD_COMMIT ""
#endif
