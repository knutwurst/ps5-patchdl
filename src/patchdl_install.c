/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright (C) 2026 Knutwurst
 *
 * PatchDL is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version. See the LICENSE file in the project root for details.
 */

#include "patchdl_install.h"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <ps5/kernel.h>

#include <pthread.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>

/* AppInstUtil layouts from CheatRunner and ps5-payload-dev/websrv */
#define AI_CONTENTID_SIZE        0x30
#define AI_PLAYGOSCENARIOID_SIZE 3
#define AI_LANGUAGE_SIZE         8
#define AI_NUM_LANGUAGES         30
#define AI_NUM_IDS               64

typedef struct {
    char content_id[AI_CONTENTID_SIZE];
    int  content_type;
    int  content_platform;
} ai_pkg_info_t;

typedef struct {
    const char *uri;
    const char *ex_uri;
    const char *playgo_scenario_id;
    const char *content_id;
    const char *content_name;
    const char *icon_url;
    /* Sony reads past icon_url: unknown_30 is the install mode, 0 = plain.
       stack garbage here gave random 0x80B2116F (ps5upload, FW 13.60) */
    uint64_t    unknown_30;
    uint64_t    reserved[7];
} ai_meta_info_t;

typedef struct {
    char languages[AI_NUM_LANGUAGES][AI_LANGUAGE_SIZE];
    char playgo_scenario_ids[AI_NUM_IDS][AI_PLAYGOSCENARIOID_SIZE];
    char content_ids[AI_NUM_IDS][AI_CONTENTID_SIZE];
    long unknown[810];
} ai_playgo_info_t;

typedef struct {
    int32_t error_code;
    int32_t version;
    char    description[512];
    char    type[9];
} ai_install_error_t;

typedef struct {
    char               status[16];
    char               src_type[8];
    uint32_t           remain_time;
    uint64_t           downloaded_size;
    uint64_t           initial_chunk_size;
    uint64_t           total_size;
    uint32_t           promote_progress;
    ai_install_error_t error_info;
    int32_t            local_copy_percent;
    bool               is_copy_only;
    char               _pad[2048]; /* Sony's real struct may be bigger */
} ai_install_status_t;

/* out buffers for Sony calls without a length arg. ids fit in 0x30 / 16, but
   who knows how much it pads. copy_bounded() into the real target after */
#define AI_CONTENTID_OUT_SIZE    256
#define AI_TITLEID_OUT_SIZE      128

#define STATIC_ASSERT(c, n) typedef char static_assert_##n[(c) ? 1 : -1]
STATIC_ASSERT(sizeof(ai_pkg_info_t) == 0x38, pkg_info_size);
STATIC_ASSERT(sizeof(ai_meta_info_t) == 0x70, meta_info_size);
STATIC_ASSERT(sizeof(ai_playgo_info_t) == 0x2700, playgo_info_size);
STATIC_ASSERT(offsetof(ai_meta_info_t, uri) == 0, meta_uri_offset);
STATIC_ASSERT(offsetof(ai_meta_info_t, icon_url) == (5 * sizeof(void *)),
              meta_icon_offset);

/* from ps5-payload-dev/sdk crt/rtld_sprx.c */
#define SYSMOD_IPMI           0x8000001d
#define SYSMOD_USERSERVICE    0x80000011
#define SYSMOD_SYSTEMSERVICE  0x80000010
#define SYSMOD_APPINSTUTIL    0x80000014

typedef int (*sysmod_load_fn)(unsigned int id);
typedef int (*ai_init_fn)(void);
typedef int (*ai_install_pkg_fn)(const char *path, ai_pkg_info_t *info);
typedef int (*ai_install_by_pkg_fn)(ai_meta_info_t *meta, ai_pkg_info_t *info,
                                    ai_playgo_info_t *playgo);
typedef int (*ai_title_from_pkg_fn)(const char *path, char *title_id, int *is_app);
typedef int (*ai_content_from_pkg_fn)(const char *path, char *content_id, int *is_app);
typedef int (*ai_get_status_fn)(char *content_id_out, ai_install_status_t *status);
/* the two out-params take NULL (ps5upload calls it this way) */
typedef int (*ai_uninstall_fn)(const char *title_id, int *out1, int *out2);
typedef int (*ai_uninstall_pat_fn)(const char *title_id);

static ai_init_fn             ai_initialize;
static ai_install_pkg_fn      ai_install_pkg;
static ai_install_by_pkg_fn   ai_install_by_package;
static ai_title_from_pkg_fn   ai_title_from_pkg;
static ai_content_from_pkg_fn ai_content_from_pkg;
static ai_get_status_fn       ai_get_status;
static ai_uninstall_fn        ai_uninstall;
static ai_uninstall_pat_fn    ai_uninstall_patch;

/* no sce lib linking (elfldr refuses the ELF), no raw sceKernelLoadStartModule
   (wedged the process, ask me how I know). sysmodule loader + dlsym instead.
   g_stage 1-4 = step, 5 = ready, <0 = failed. atomic: 5 means fn ptrs set */
static _Atomic int     g_stage;
static _Atomic int     g_err;
static pthread_mutex_t g_mtx = PTHREAD_MUTEX_INITIALIZER;
static char            g_probe_json[2048]; /* filled by the backend thread */
static char            g_last_content_id[AI_CONTENTID_SIZE];
static char            g_last_target_title_id[32];
static char            g_last_method[32];
static int             g_last_start_rc;

static intptr_t
dynsym(const char *module, const char *sym) {
    uint32_t h = 0;
    if (kernel_dynlib_handle(-1, module, &h) < 0)
        return 0;
    return kernel_dynlib_dlsym(-1, h, sym);
}

static void
local_ip(char *out, size_t n) {
    struct ifaddrs *ifa = NULL, *p;

    out[0] = '\0';
    if (getifaddrs(&ifa))
        return;

    for (p = ifa; p; p = p->ifa_next) {
        char ip[INET_ADDRSTRLEN];
        struct sockaddr_in *s;

        if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET)
            continue;
        s = (struct sockaddr_in *)p->ifa_addr;
        if (!inet_ntop(AF_INET, &s->sin_addr, ip, sizeof(ip)))
            continue;
        if (strcmp(ip, "127.0.0.1") && strncmp(ip, "0.", 2)) {
            strncpy(out, ip, n - 1);
            out[n - 1] = '\0';
            break;
        }
    }
    freeifaddrs(ifa);
}

static void
copy_bounded(char *dst, size_t dst_sz, const char *src, size_t src_sz) {
    size_t n;
    if (!dst || !dst_sz) return;
    dst[0] = '\0';
    if (!src || !src_sz) return;
    for (n = 0; n + 1 < dst_sz && n < src_sz && src[n]; n++)
        dst[n] = src[n];
    dst[n] = '\0';
}

/* these end up in the HTTP request line of Sony's installer: no CRLF, no '/' */
static int
install_id_safe(const char *s) {
    if (!s || !s[0]) return 0;
    for (const char *p = s; *p; p++) {
        if (!((*p >= 'A' && *p <= 'Z') ||
              (*p >= 'a' && *p <= 'z') ||
              (*p >= '0' && *p <= '9') ||
              *p == '_' || *p == '-' || *p == '.'))
            return 0;
    }
    return 1;
}

/* exactly 9 chars, so PPSA12345EVIL doesn't pass for PPSA12345 */
static int
title_id_eq9(const char *a, const char *b) {
    if (!a || !b) return 0;
    if (strnlen(a, 16) != 9 || strnlen(b, 16) != 9) return 0;
    return strncmp(a, b, 9) == 0;
}

static void
remember_install(const char *target_title_id, const char *method,
                 const ai_pkg_info_t *pkg, const char *fallback_content_id,
                 int rc) {
    char cid[AI_CONTENTID_SIZE] = {0};

    if (pkg)
        copy_bounded(cid, sizeof(cid), pkg->content_id, sizeof(pkg->content_id));
    if (!cid[0] && fallback_content_id)
        copy_bounded(cid, sizeof(cid), fallback_content_id, strlen(fallback_content_id));

    pthread_mutex_lock(&g_mtx);
    snprintf(g_last_content_id, sizeof(g_last_content_id), "%s", cid);
    snprintf(g_last_target_title_id, sizeof(g_last_target_title_id), "%s",
             target_title_id ? target_title_id : "");
    snprintf(g_last_method, sizeof(g_last_method), "%s", method ? method : "");
    g_last_start_rc = rc;
    pthread_mutex_unlock(&g_mtx);
}

/* dlsym only, nothing gets called. backend thread, module already loaded */
static void
fill_probe(void) {
    static const char *ai_syms[] = {
        "sceAppInstUtilInitialize",
        "sceAppInstUtilAppInstallPkg",
        "sceAppInstUtilAppInstallTitleDir",
        "sceAppInstUtilAppInstallAll",          /* tile fallback on 13.xx */
        "sceAppInstUtilInstallByPackage",
        "sceAppInstUtilInstallByPackageEx",
        "sceAppInstUtilGetTitleIdFromPkg",
        "sceAppInstUtilGetContentIdFromPkg",
        "sceAppInstUtilGetInstallStatus",
        "sceAppInstUtilAppExist",
        "sceAppInstUtilAppGetInstallStatus",
        "sceAppInstUtilAppInstallStatus",
        "sceAppInstUtilAppUnInstall",
        "sceAppInstUtilGetMetaInfoFromPkg",
        "sceAppInstUtilUpdateTitleByTitleId",
        "sceAppInstUtilInstallByChunk",
        NULL
    };
    static const char *bgft_syms[] = {
        "sceBgftInitialize",
        "sceBgftServiceIntInit",
        "sceBgftServiceDownloadRegisterTask",
        "sceBgftServiceDownloadRegisterTaskByStorage",
        "sceBgftServiceDownloadRegisterTaskByStorageEx",
        "sceBgftServiceIntDownloadRegisterTaskByStorageEx",
        "sceBgftServiceDownloadStartTask",
        "sceBgftServiceDownloadGetProgress",
        "sceBgftServiceInstallPackage",
        NULL
    };
    uint32_t h = 0;
    int ai_loaded   = (kernel_dynlib_handle(-1, "libSceAppInstUtil.sprx", &h) >= 0);
    int bgft_loaded = (kernel_dynlib_handle(-1, "libSceBgft.sprx", &h) >= 0);
    char   tmp[sizeof(g_probe_json)];
    size_t n = 0, sz = sizeof(tmp);
    char  *out = tmp;
    int    first = 1;

    n += snprintf(out + n, sz - n,
                  "{\"appinstutil_loaded\":%s,\"bgft_loaded\":%s,\"symbols\":{",
                  ai_loaded ? "true" : "false", bgft_loaded ? "true" : "false");
    for (int i = 0; ai_syms[i] && n < sz - 80; i++) {
        intptr_t a = dynsym("libSceAppInstUtil.sprx", ai_syms[i]);
        n += snprintf(out + n, sz - n, "%s\"%s\":%s",
                      first ? "" : ",", ai_syms[i], a ? "true" : "false");
        first = 0;
    }
    for (int i = 0; bgft_syms[i] && n < sz - 80; i++) {
        intptr_t a = bgft_loaded ? dynsym("libSceBgft.sprx", bgft_syms[i]) : 0;
        n += snprintf(out + n, sz - n, "%s\"%s\":%s",
                      first ? "" : ",", bgft_syms[i], a ? "true" : "false");
        first = 0;
    }
    snprintf(out + n, sz - n, "}}");

    /* MHD getter reads under the lock, never sees half a buffer */
    pthread_mutex_lock(&g_mtx);
    memcpy(g_probe_json, tmp, sizeof(g_probe_json));
    pthread_mutex_unlock(&g_mtx);
}

static void *
backend_init_thread(void *arg) {
    (void)arg;
    sysmod_load_fn sysmod_load;

    g_stage = 1;
    sysmod_load = (sysmod_load_fn)dynsym("libSceSysmodule.sprx",
                                         "sceSysmoduleLoadModuleInternal");
    if (!sysmod_load) { g_stage = -1; return NULL; }

    g_stage = 2;
    /* deps first */
    sysmod_load(SYSMOD_IPMI);
    sysmod_load(SYSMOD_USERSERVICE);
    sysmod_load(SYSMOD_SYSTEMSERVICE);
    g_err = sysmod_load(SYSMOD_APPINSTUTIL);
    if (g_err) { g_stage = -2; return NULL; }

    g_stage = 3;
    ai_initialize         = (ai_init_fn)dynsym("libSceAppInstUtil.sprx",
                                               "sceAppInstUtilInitialize");
    ai_install_pkg        = (ai_install_pkg_fn)dynsym("libSceAppInstUtil.sprx",
                                                      "sceAppInstUtilAppInstallPkg");
    ai_install_by_package = (ai_install_by_pkg_fn)dynsym("libSceAppInstUtil.sprx",
                                                         "sceAppInstUtilInstallByPackage");
    ai_title_from_pkg     = (ai_title_from_pkg_fn)dynsym("libSceAppInstUtil.sprx",
                                                         "sceAppInstUtilGetTitleIdFromPkg");
    ai_content_from_pkg   = (ai_content_from_pkg_fn)dynsym("libSceAppInstUtil.sprx",
                                                          "sceAppInstUtilGetContentIdFromPkg");
    ai_get_status         = (ai_get_status_fn)dynsym("libSceAppInstUtil.sprx",
                                                     "sceAppInstUtilGetInstallStatus");
    ai_uninstall          = (ai_uninstall_fn)dynsym("libSceAppInstUtil.sprx",
                                                    "sceAppInstUtilAppUnInstall");
    ai_uninstall_patch    = (ai_uninstall_pat_fn)dynsym("libSceAppInstUtil.sprx",
                                                    "sceAppInstUtilAppUnInstallPat");

    fill_probe();

    if (!ai_initialize || !ai_install_pkg || !ai_install_by_package) {
        g_stage = -3;
        return NULL;
    }

    g_stage = 4;
    g_err = ai_initialize();
    if (g_err) { g_stage = -4; return NULL; }

    g_stage = 5;
    return NULL;
}

static void
backend_start(void) {
    pthread_mutex_lock(&g_mtx);
    if (g_stage == 0) {
        pthread_t      tid;
        pthread_attr_t attr;
        g_stage = 1;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        pthread_create(&tid, &attr, backend_init_thread, NULL);
        pthread_attr_destroy(&attr);
    }
    pthread_mutex_unlock(&g_mtx);
}

/* up to 15 s, so an install right after startup doesn't fail for being early */
static void
backend_wait(void) {
    backend_start();
    for (int i = 0; i < 150 && g_stage > 0 && g_stage != 5; i++)
        usleep(100 * 1000);
}

static const char *
stage_str(int s) {
    switch (s) {
    case 0:  return "idle";
    case 1:  return "resolving sysmodule loader";
    case 2:  return "loading AppInstUtil module";
    case 3:  return "resolving AppInstUtil symbols";
    case 4:  return "initializing service";
    case 5:  return "ready";
    case -1: return "sysmodule loader unavailable";
    case -2: return "AppInstUtil module load failed";
    case -3: return "AppInstUtil symbol resolution failed";
    case -4: return "AppInstUtil init failed";
    default: return "unknown";
    }
}

int
patchdl_install_backend_check(char *msg, size_t msg_sz) {
    int s;
    backend_start();
    s = g_stage;
    snprintf(msg, msg_sz, "%s (rc=0x%08x)", stage_str(s), (unsigned)g_err);
    return (s == 5) ? 0 : -1;
}

/* MHD worker: only hands out the cached probe, the backend thread fills it */
int
patchdl_install_api_probe(char *out, size_t out_sz) {
    int ready;

    backend_start();
    pthread_mutex_lock(&g_mtx);
    ready = (g_probe_json[0] != '\0');
    if (ready)
        snprintf(out, out_sz, "%s", g_probe_json);
    pthread_mutex_unlock(&g_mtx);
    if (ready)
        return 0;

    snprintf(out, out_sz,
             "{\"pending\":true,\"stage\":\"%s\"}", stage_str(g_stage));
    return -1;
}

int
patchdl_install_pkg_meta(const char *local_path, char *content_id, size_t cid_sz,
                         char *title_id, size_t tid_sz, int *is_app,
                         char *msg, size_t msg_sz) {
    char        sdk_path[1024];
    /* Get*IdFromPkg take no length */
    char        cid[AI_CONTENTID_OUT_SIZE] = {0};
    char        tid[AI_TITLEID_OUT_SIZE]   = {0};
    int         app_c = 0, app_t = 0, ok = 0;
    struct stat st;

    if (content_id && cid_sz) content_id[0] = '\0';
    if (title_id && tid_sz)   title_id[0]   = '\0';
    if (is_app) *is_app = 0;

    if (!local_path || !local_path[0] || stat(local_path, &st) != 0) {
        snprintf(msg, msg_sz, "package not on disk");
        return -1;
    }
    backend_wait();
    if (g_stage != 5) {
        snprintf(msg, msg_sz, "install backend not ready: %s", stage_str(g_stage));
        return -1;
    }
    if (!strncmp(local_path, "/data/", 6))
        snprintf(sdk_path, sizeof sdk_path, "/user%s", local_path);
    else
        snprintf(sdk_path, sizeof sdk_path, "%s", local_path);

    if (ai_content_from_pkg &&
        ai_content_from_pkg(sdk_path, cid, &app_c) == 0 && cid[0]) {
        copy_bounded(content_id, cid_sz, cid, sizeof(cid));
        if (is_app) *is_app = app_c;
        ok = 1;
    }
    if (ai_title_from_pkg &&
        ai_title_from_pkg(sdk_path, tid, &app_t) == 0 && tid[0]) {
        copy_bounded(title_id, tid_sz, tid, sizeof(tid));
        ok = 1;
    }
    snprintf(msg, msg_sz, ok ? "ok" : "could not read pkg metadata");
    return ok ? 0 : -1;
}

void
patchdl_install_debug_state(char *out, size_t out_sz) {
    char cid[AI_CONTENTID_SIZE];
    char tid[32], method[32];
    int  start_rc;
    int  stage;

    pthread_mutex_lock(&g_mtx);
    memcpy(cid, g_last_content_id, sizeof(cid));
    snprintf(tid,    sizeof(tid),    "%s", g_last_target_title_id);
    snprintf(method, sizeof(method), "%s", g_last_method);
    start_rc = g_last_start_rc;
    stage    = g_stage;
    pthread_mutex_unlock(&g_mtx);

    snprintf(out, out_sz,
             "{\"stage\":%d,\"cid_len\":%d,\"cid_hex\":\"%02x%02x%02x%02x\","
             "\"content_id\":\"%s\",\"target_title_id\":\"%s\","
             "\"method\":\"%s\",\"start_rc\":%d}",
             stage,
             (int)strnlen(cid, sizeof(cid)),
             (unsigned char)cid[0], (unsigned char)cid[1],
             (unsigned char)cid[2], (unsigned char)cid[3],
             cid, tid, method, start_rc);
}

int
patchdl_install_status_json(char *out, size_t out_sz) {
    char cid[AI_CONTENTID_SIZE];
    char tid[32];
    char method[32];
    int  start_rc;
    /* heap: 2 KB pad, polled a lot, keep it off the MHD worker stacks */
    ai_install_status_t *st = NULL;
    char status[17], src_type[9];
    int  rc;
    int  progress = 0;
    int  terminal = 0;

    if (!out || !out_sz)
        return -1;

    backend_start();

    pthread_mutex_lock(&g_mtx);
    snprintf(cid, sizeof(cid), "%s", g_last_content_id);
    snprintf(tid, sizeof(tid), "%s", g_last_target_title_id);
    snprintf(method, sizeof(method), "%s", g_last_method);
    start_rc = g_last_start_rc;
    pthread_mutex_unlock(&g_mtx);

    if (!cid[0]) {
        snprintf(out, out_sz, "{\"active\":false}");
        return -1;
    }
    if (g_stage != 5) {
        snprintf(out, out_sz,
                 "{\"active\":true,\"content_id\":\"%s\",\"target_title_id\":\"%s\","
                 "\"method\":\"%s\",\"start_rc\":%d,\"status\":\"backend_not_ready\","
                 "\"stage\":\"%s\"}",
                 cid, tid, method, start_rc, stage_str(g_stage));
        return -1;
    }
    if (!ai_get_status) {
        snprintf(out, out_sz,
                 "{\"active\":true,\"content_id\":\"%s\",\"target_title_id\":\"%s\","
                 "\"method\":\"%s\",\"start_rc\":%d,\"status\":\"unavailable\","
                 "\"message\":\"sceAppInstUtilGetInstallStatus not exported\"}",
                 cid, tid, method, start_rc);
        return -1;
    }

    st = calloc(1, sizeof(*st));
    if (!st) {
        snprintf(out, out_sz, "{\"error\":\"oom\"}");
        return -1;
    }

    /* first arg is an out buffer (running install's content_id). passing cid
       would clobber it */
    {
        char ai_cid_out[AI_CONTENTID_OUT_SIZE] = {0};
        rc = ai_get_status(ai_cid_out, st);
        (void)ai_cid_out;
    }
    copy_bounded(status, sizeof(status), st->status, sizeof(st->status));
    copy_bounded(src_type, sizeof(src_type), st->src_type, sizeof(st->src_type));
    if (st->total_size > 0)
        progress = (int)((st->downloaded_size * 100) / st->total_size);
    if (progress < 0) progress = 0;
    if (progress > 100) progress = 100;
    terminal = (!strcmp(status, "playable") ||
                !strcmp(status, "error") ||
                !strcmp(status, "none"));

    snprintf(out, out_sz,
             "{\"active\":true,\"terminal\":%s,\"content_id\":\"%s\","
             "\"target_title_id\":\"%s\",\"method\":\"%s\",\"start_rc\":%d,"
             "\"rc\":%d,\"status\":\"%s\",\"src_type\":\"%s\","
             "\"progress\":%d,\"downloaded_size\":%llu,\"total_size\":%llu,"
             "\"promote_progress\":%u,\"error_code\":%d}",
             terminal ? "true" : "false", cid, tid, method, start_rc, rc,
             status, src_type, progress,
             (unsigned long long)st->downloaded_size,
             (unsigned long long)st->total_size,
             (unsigned)st->promote_progress,
             (int)st->error_info.error_code);
    free(st);
    return rc;
}

int
patchdl_install_local_pkg(const char *local_path, const char *expected_title_id,
                          const char *storage_title_id,
                          const char *target_content_id,
                          const char *name,
                          char *msg, size_t msg_sz) {
    char        sdk_path[1024];
    char        pkg_tid[48] = {0};
    struct stat st;
    int         rc = -1;
    int         pkg_tid_mismatch = 0;

    if (!local_path || !local_path[0]) {
        snprintf(msg, msg_sz, "no package path");
        return -1;
    }
    if (stat(local_path, &st) != 0) {
        snprintf(msg, msg_sz, "package not downloaded");
        return -1;
    }

    backend_wait();
    if (g_stage != 5) {
        snprintf(msg, msg_sz, "install backend not ready: %s", stage_str(g_stage));
        return -1;
    }

    /* the installer allowlists /user/data/ and /mnt/usb. plain /data/ gets
       0x80B2116F (ps5upload found that one) */
    if (!strncmp(local_path, "/data/", 6))
        snprintf(sdk_path, sizeof(sdk_path), "/user%s", local_path);
    else
        snprintf(sdk_path, sizeof(sdk_path), "%s", local_path);

    /* Sony sometimes keeps a regional patch under a master title id. only ok
       with a target content id, refused otherwise */
    if (storage_title_id && storage_title_id[0] &&
        expected_title_id && expected_title_id[0] &&
        !title_id_eq9(storage_title_id, expected_title_id)) {
        pkg_tid_mismatch = 1;
        strncpy(pkg_tid, storage_title_id, sizeof(pkg_tid) - 1);
        pkg_tid[sizeof(pkg_tid) - 1] = '\0';
    }
    if (ai_title_from_pkg && expected_title_id && expected_title_id[0]) {
        char tid_out[AI_TITLEID_OUT_SIZE] = {0};
        int  is_app = 0;
        if (ai_title_from_pkg(sdk_path, tid_out, &is_app) == 0 && tid_out[0]) {
            if (!title_id_eq9(tid_out, expected_title_id))
                pkg_tid_mismatch = 1;
            copy_bounded(pkg_tid, sizeof(pkg_tid), tid_out, sizeof(tid_out));
        }
    }
    if (pkg_tid_mismatch && (!target_content_id || !target_content_id[0])) {
        snprintf(msg, msg_sz,
                 "refused: package metadata is %.12s, target is %.12s",
                 pkg_tid, expected_title_id);
        return -1;
    }
    {
        char              file_uri[1100];
        char              http_loop_uri[1200] = {0};
        char              http_lan_uri[1200] = {0};
        char              json_loop_uri[1200] = {0};
        char              icon[1040];
        const char       *uris[5];
        ai_meta_info_t    meta    = {0};
        ai_pkg_info_t     pkg     = {0};
        /* 0x2700 bytes, too much for the MHD worker stack */
        ai_playgo_info_t *playgo  = calloc(1, sizeof(*playgo));
        int               rc2     = -1;
        const char       *title_dir;
        const char       *file_base;

        if (!playgo) {
            snprintf(msg, msg_sz, "out of memory");
            return -1;
        }

        snprintf(file_uri, sizeof(file_uri), "file://%s", sdk_path);
        /* <drive>/patchdl/<title>/<file>, on any download drive */
        title_dir = strstr(local_path, "/patchdl/");
        file_base = strrchr(local_path, '/');
        if (title_dir && file_base && file_base > title_dir + strlen("/patchdl/")) {
            char title_id[32] = {0};
            const char *t = title_dir + strlen("/patchdl/");
            size_t tlen = (size_t)(file_base - t);
            if (tlen > 0 && tlen < sizeof(title_id)) {
                char ip[INET_ADDRSTRLEN] = {0};
                memcpy(title_id, t, tlen);
                if (install_id_safe(title_id) && install_id_safe(file_base + 1)) {
                    snprintf(http_loop_uri, sizeof(http_loop_uri),
                             "http://127.0.0.1:%d/api/pkg/%s/%s",
                             PATCHDL_HTTP_PORT, title_id, file_base + 1);
                    /* the local manifest from the downloader, if there is one */
                    {
                        char   jpath[1024];
                        size_t ln = strlen(local_path), fl = strlen(file_base + 1);
                        if (ln > 4 && fl > 4 && !strcmp(local_path + ln - 4, ".pkg") &&
                            snprintf(jpath, sizeof jpath, "%.*s.json",
                                     (int)(ln - 4), local_path) < (int)sizeof jpath &&
                            stat(jpath, &st) == 0)
                            snprintf(json_loop_uri, sizeof(json_loop_uri),
                                     "http://127.0.0.1:%d/api/pkg/%s/%.*s.json",
                                     PATCHDL_HTTP_PORT, title_id,
                                     (int)(fl - 4), file_base + 1);
                    }
                    local_ip(ip, sizeof(ip));
                    if (ip[0])
                        snprintf(http_lan_uri, sizeof(http_lan_uri),
                                 "http://%s:%d/api/pkg/%s/%s",
                                 ip, PATCHDL_HTTP_PORT, title_id, file_base + 1);
                }
            }
        }
        /* HTTP first: the installer pulls ranges from /api/pkg, and that's
           the route that really writes content. bare paths last */
        uris[0]                 = json_loop_uri[0] ? json_loop_uri : NULL;
        uris[1]                 = http_loop_uri[0] ? http_loop_uri : NULL;
        uris[2]                 = http_lan_uri[0] ? http_lan_uri : NULL;
        uris[3]                 = sdk_path;      /* /user/data/... */
        uris[4]                 = file_uri;       /* file:///user/data/... */
        meta.ex_uri             = "";
        meta.playgo_scenario_id = "";
        /* empty like etaHEN's DPI, the installer takes the pkg's own id */
        meta.content_id         = "";
        /* name and picture of the notification. Downloads finds the cover
           by itself, the notification only shows what we pass here */
        meta.content_name       = name && name[0] ? name : "PatchDL";
        snprintf(icon, sizeof icon, "/user/appmeta/%.9s/icon0.png",
                 expected_title_id ? expected_title_id : "");
        if (stat(icon, &st) != 0) {
            /* game got uninstalled for a fresh install and its appmeta
               went with it. the cover from the pkg sits next to it */
            const char *sl = strrchr(sdk_path, '/');
            snprintf(icon, sizeof icon, "%.*s/icon0.png",
                     sl ? (int)(sl - sdk_path) : 0, sdk_path);
        }
        meta.icon_url           = stat(icon, &st) == 0 ? icon : "";

        {
            char        tries[260] = {0};
            const char *labels[5]  = { "manifest", "loop", "lan", "userdata", "file" };
            for (int i = 0; i < 5; i++) {
                if (!uris[i]) continue;
                memset(&pkg, 0, sizeof(pkg));
                memset(playgo, 0, sizeof(*playgo));
                meta.uri = uris[i];
                rc2 = ai_install_by_package(&meta, &pkg, playgo);
                {
                    size_t l = strlen(tries);
                    snprintf(tries + l, sizeof(tries) - l, "%s%s=0x%08x",
                             l ? "," : "", labels[i], (unsigned)rc2);
                }
                if (rc2 == 0) {
                    remember_install(expected_title_id, "InstallByPackage",
                                     &pkg, target_content_id, rc2);
                    snprintf(msg, msg_sz, "install started (InstallByPackage, content %.47s)",
                             pkg.content_id[0] ? pkg.content_id :
                             (target_content_id ? target_content_id : ""));
                    free(playgo);
                    return 0;
                }
            }
            rc = rc2;
        }
        free(playgo);
    }

    /* no AppInstallPkg fallback: returns 0, writes only metadata (version,
       tile) and no content. looks updated, isn't */
    snprintf(msg, msg_sz, "install rejected (InstallByPackage=0x%08x)", (unsigned)rc);
    return rc ? rc : -1;
}

int
patchdl_install_by_uri(const char *uri, const char *target_title_id,
                       const char *target_content_id,
                       char *msg, size_t msg_sz) {
    ai_meta_info_t    meta   = {0};
    ai_pkg_info_t     pkg    = {0};
    ai_playgo_info_t *playgo;
    int rc;

    if (!uri || !uri[0]) {
        snprintf(msg, msg_sz, "no uri");
        return -1;
    }
    backend_wait();
    if (g_stage != 5) {
        snprintf(msg, msg_sz, "install backend not ready: %s", stage_str(g_stage));
        return -1;
    }
    playgo = calloc(1, sizeof(*playgo));
    if (!playgo) { snprintf(msg, msg_sz, "out of memory"); return -1; }

    meta.uri                = uri;
    meta.ex_uri             = "";
    meta.playgo_scenario_id = "";
    meta.content_id         = target_content_id ? target_content_id : "";
    meta.content_name       = "PatchDL";
    meta.icon_url           = "";

    rc = ai_install_by_package(&meta, &pkg, playgo);
    remember_install(target_title_id, "InstallByURI", &pkg, target_content_id, rc);
    free(playgo);

    if (rc == 0) {
        snprintf(msg, msg_sz, "install started (InstallByPackage/uri, content %.47s)",
                 pkg.content_id[0] ? pkg.content_id :
                 (target_content_id ? target_content_id : ""));
    } else {
        snprintf(msg, msg_sz, "install rejected rc=0x%08x", (unsigned)rc);
    }
    return rc;
}

int
patchdl_install_app_pkg(const char *local_path,
                        const char *expected_title_id,
                        const char *target_content_id,
                        char *msg, size_t msg_sz) {
    char          sdk_path[1024];
    ai_pkg_info_t pkg = {0};
    struct stat   st;
    int           rc;

    if (!local_path || !local_path[0]) { snprintf(msg, msg_sz, "no path"); return -1; }
    if (stat(local_path, &st) != 0)    { snprintf(msg, msg_sz, "package not downloaded"); return -1; }

    backend_wait();
    if (g_stage != 5) {
        snprintf(msg, msg_sz, "install backend not ready: %s", stage_str(g_stage));
        return -1;
    }

    if (!strncmp(local_path, "/data/", 6))
        snprintf(sdk_path, sizeof sdk_path, "/user%s", local_path);
    else
        snprintf(sdk_path, sizeof sdk_path, "%s", local_path);

    rc = ai_install_pkg(sdk_path, &pkg);
    remember_install(expected_title_id, "AppInstallPkg/direct", &pkg, target_content_id, rc);

    if (rc == 0)
        snprintf(msg, msg_sz, "install started (AppInstallPkg, content %.47s)",
                 pkg.content_id[0] ? pkg.content_id :
                 (target_content_id ? target_content_id : ""));
    else
        snprintf(msg, msg_sz, "install rejected rc=0x%08x", (unsigned)rc);
    return rc;
}

/* ShellCore's authid. ps5upload swaps to it for every uninstall, without
   it the console refuses from 9.60 on there. only for the one call, kept
   for longer ps5upload saw the console restart mid-install */
#define SHELLCORE_AUTHID 0x3800000000000010ULL

static pthread_mutex_t g_uninst_mtx = PTHREAD_MUTEX_INITIALIZER;

/* the authid is per process, so one call at a time and back right after */
static int
uninstall_call(const char *title_id, int patch, int shellcore) {
    pid_t    pid = getpid();
    uint64_t saved = 0;
    int      rc;

    pthread_mutex_lock(&g_uninst_mtx);
    if (shellcore && (saved = kernel_get_ucred_authid(pid)) &&
        kernel_set_ucred_authid(pid, SHELLCORE_AUTHID) != 0)
        saved = 0;
    rc = patch ? ai_uninstall_patch(title_id) : ai_uninstall(title_id, NULL, NULL);
    for (int i = 0; saved && i < 3; i++) {
        kernel_set_ucred_authid(pid, saved);
        if (kernel_get_ucred_authid(pid) == saved) break;
    }
    pthread_mutex_unlock(&g_uninst_mtx);
    return rc;
}

static int
uninstall_common(const char *title_id, int patch, int shellcore,
                 char *msg, size_t msg_sz) {
    const char *what = patch ? "patch removal" : "uninstall";
    int         rc;
    if (!title_id || !title_id[0]) {
        snprintf(msg, msg_sz, "no title");
        return -1;
    }
    backend_wait();
    if (g_stage != 5 || !(patch ? (void *)ai_uninstall_patch : (void *)ai_uninstall)) {
        snprintf(msg, msg_sz, "%s not available: %s", what, stage_str(g_stage));
        return -1;
    }
    rc = uninstall_call(title_id, patch, shellcore);
    snprintf(msg, msg_sz, "%s%s rc=0x%08x", what, shellcore ? " as shellcore" : "",
             (unsigned)rc);
    return rc;
}

int
patchdl_install_uninstall(const char *title_id, int shellcore, char *msg, size_t msg_sz) {
    return uninstall_common(title_id, 0, shellcore, msg, msg_sz);
}

int
patchdl_install_uninstall_patch(const char *title_id, int shellcore,
                                char *msg, size_t msg_sz) {
    return uninstall_common(title_id, 1, shellcore, msg, msg_sz);
}
