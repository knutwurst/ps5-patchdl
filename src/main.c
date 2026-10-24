/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Knutwurst
 *
 * PatchDL is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version. See the LICENSE file in the project root for details.
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "patchdl_notify.h"
#include "patchdl_proc.h"
#include "patchdl_version.h"
#include "patchdl_websrv.h"

#ifndef PATCHDL_HTTP_PORT
#define PATCHDL_HTTP_PORT 12880
#endif

#define PATCHDL_PROC_NAME "patchdl.elf"

int
main(int argc, char** argv) {
  unsigned short port = PATCHDL_HTTP_PORT;

  if(argc > 1) {
    int requested_port = atoi(argv[1]);
    if(requested_port > 0 && requested_port <= 65535) {
      port = (unsigned short)requested_port;
    }
  }

  signal(SIGPIPE, SIG_IGN);

  /* kill the old instance from the last deploy, it still holds the port */
  patchdl_proc_set_name(PATCHDL_PROC_NAME);
  patchdl_proc_kill_others(PATCHDL_PROC_NAME);

  printf("PatchDL v%s starting web UI on port %u\n", PATCHDL_VERSION, port);

  if(patchdl_websrv_start(port)) {
    puts("PatchDL web server failed to start");
    return 1;
  }

  patchdl_notify_startup(port);

  while(1) {
    sleep(5);
    patchdl_websrv_watch();
  }

  return 0;
}
