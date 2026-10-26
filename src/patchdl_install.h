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

/* async: 0 = the installer queue took it, else the SCE error. changes the
   installed game, official titles on user request only. target_content_id
   (app.db) is required when the pkg's title id differs, MetaInfo gets "".
   name is what Downloads shows, NULL or "" means "PatchDL" */
int patchdl_install_local_pkg(const char *local_path,
                              const char *expected_title_id,
                              const char *storage_title_id,
                              const char *target_content_id,
                              const char *name,
                              char *msg, size_t msg_sz);

/* load + init AppInstUtil, no install. 0 when ready */
int patchdl_install_backend_check(char *msg, size_t msg_sz);

/* which AppInstUtil/Bgft symbols this fw has, as JSON. dlsym only */
int patchdl_install_api_probe(char *out, size_t out_sz);

/* content id, title id and app-vs-patch of a .pkg. 0 if anything was read */
int patchdl_install_pkg_meta(const char *local_path, char *content_id, size_t cid_sz,
                             char *title_id, size_t tid_sz, int *is_app,
                             char *msg, size_t msg_sz);

/* status of the last install PatchDL started, as JSON */
int patchdl_install_status_json(char *out, size_t out_sz);

void patchdl_install_debug_state(char *out, size_t out_sz);

/* install straight from an http:// or file:// URI. target_content_id goes
   into MetaInfo.content_id to pick the title (shared-master deltas) */
int patchdl_install_by_uri(const char *uri,
                            const char *target_title_id,
                            const char *target_content_id,
                            char *msg, size_t msg_sz);

/* raw AppInstallPkg, no MetaInfo. careful: it only writes the app metadata,
   no content (see patchdl_install_local_pkg) */
int patchdl_install_app_pkg(const char *local_path,
                             const char *expected_title_id,
                             const char *target_content_id,
                             char *msg, size_t msg_sz);
