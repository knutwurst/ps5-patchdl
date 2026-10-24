/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Knutwurst
 *
 * PatchDL is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version. See the LICENSE file in the project root for details.
 */

#pragma once

/* sets the main thread name, that's what the PS5 process list shows */
void patchdl_proc_set_name(const char *name);

/* SIGKILLs other processes with this name, returns how many */
int patchdl_proc_kill_others(const char *name);
