/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Knutwurst
 *
 * PatchDL is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version. See the LICENSE file in the project root for details.
 */

#pragma once

int patchdl_websrv_start(unsigned short port);
void patchdl_websrv_stop(void);
/* restarts the server if the port went dead (network change).
   1 restarted, 0 fine, -1 restart failed */
int patchdl_websrv_watch(void);
