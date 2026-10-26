const API = {
  status: "/api/status",
  titles: "/api/titles",
  config: "/api/config",
  downloads: "/api/downloads",
  installStatus: "/api/installstatus",
  rescan: "/api/rescan",
  storage: "/api/storage",
  storageDelete: (titleId) => `/api/storage/${encodeURIComponent(titleId)}/delete`,
  action: (titleId, action) => `/api/titles/${encodeURIComponent(titleId)}/${action}`,
};

const iconCache = new Map();

const SOURCE_TYPES = {
  official:    { className: "ok",       installAllowed: true  },
  external:    { className: "external", installAllowed: true  },
  shadowmount: { className: "shadow",   installAllowed: false },
  unknown:     { className: "blocked",  installAllowed: false },
  fake:        { className: "blocked",  installAllowed: false },
};
function sourceLabel(type) { return t(`source.${type}`); }
function sourceDescription(type) { return t(`source.${type}.desc`); }

function tCode(prefix, code, fallbackText) {
  return code && tHas(prefix + code) ? t(prefix + code) : fallbackText;
}

const fallback = {
  status: {
    firmware: "11.60",
    firmware_build: "0x11600000",
    dns_guard: "Active",
    resolver: "Internal allowlist",
    free_space_mb: 771916,
    download_dir: "/data/patchdl (internal)",
    lan_ip: "192.168.178.90",
    http_port: 12880,
  },
  config: {
    default_policy: "deny",
    download_dir: "/data/patchdl (internal)",
    install_after_download: false,
    delete_pkg_after_install: true,
    verify_downloads: false,
    home_shortcut: true,
    max_connections: 4,
    source_policy: {
      official: { allow_check: true, allow_download: true, allow_install: true },
      external: { allow_check: true, allow_download: true, allow_install: true },
      shadowmount: { allow_check: true, allow_download: false, allow_install: false },
      unknown: { allow_check: true, allow_download: false, allow_install: false },
      fake: { allow_check: true, allow_download: false, allow_install: false },
    },
    cdn_allowlist: [
      "sgst.prod.dl.playstation.net",
      "gst.prod.dl.playstation.net",
      "gs2.ww.prod.dl.playstation.net",
      "gs-sec.ww.np.dl.playstation.net",
    ],
  },
  titles: [
    {
      title_id: "PPSA01628_00", name: "Call of Duty Black Ops Cold War",
      content_id: "UP0002-PPSA01628_00-CODCWTHEGAME0001",
      installed_version: "01.032.000", compatible_version: "01.041.000",
      latest_version: "01.041.000", latest_required_fw: "11.60",
      source_type: "official", source_path: "/system_ex/app/PPSA01628_00",
      patch_storage_match: true,
      mount_from: "/dev/ssd0.system_ex", enabled: true, status: "available",
    },
    {
      title_id: "PPSA01284_00", name: "Demon's Souls",
      content_id: "UP9000-PPSA01284_00-DEMONSSOULS00001",
      installed_version: "01.004.000", compatible_version: "01.004.000",
      latest_version: "01.004.000", latest_required_fw: "10.01",
      source_type: "external", source_path: "/system_data/priv/appmeta/external/PPSA01284_00",
      patch_storage_match: true,
      mount_from: "/mnt/ext0/user/app/PPSA01284_00", enabled: true, status: "up_to_date",
    },
    {
      title_id: "PPSA90001_00", name: "Shadowmounted Test Title",
      content_id: "UP0000-PPSA90001_00-SHADOWMOUNT0001",
      installed_version: "01.000.000", compatible_version: "01.006.000",
      latest_version: "01.009.000", latest_required_fw: "12.00",
      source_type: "shadowmount", source_path: "/system_ex/app/PPSA90001_00",
      patch_storage_match: true,
      mount_from: "/mnt/usb0/itemzflow/Shadowmounted Test Title", enabled: true, status: "blocked",
    },
    {
      title_id: "PPSA03396", name: "The Last of Us Part I",
      content_id: "UP9000-PPSA03396_00-THELASTOFUSPART1",
      installed_version: "01.000.000", compatible_version: null,
      latest_version: "02.002.000", latest_required_fw: "10.20",
      prospero_version: "01.003.000", prospero_required_fw: "7.01", prospero_size: "71.7 GB", prospero_done: true,
      source_type: "official", source_path: "/system_ex/app/PPSA03396",
      patch_storage_match: true,
      mount_from: "/dev/ssd0.system_ex", enabled: true, status: "incompatible_fw",
    },
  ],
  downloads: [],
  logs: [],
};

let state = {
  status: fallback.status,
  config: fallback.config,
  titles: fallback.titles,
  downloads: fallback.downloads,
  logs: fallback.logs,
  view: "games",
  filter: "updates",
  query: "",
  usingFallback: false,
};

let downloadPollTimer = null;
let installPollTimer = null;
const freshInstalling = new Map();   // title id -> name of games being replaced
let emptyPolls = 0;
const dlMeta = {}; // title_id: { bytes, t, speed }

const els = {};

document.addEventListener("DOMContentLoaded", () => {
  applyI18n();
  bindElements();
  fillLanguageSelect();
  bindEvents();
  loadInitialData().then(() => { openGuideFromHash(); openDiagFromHash(); });
  window.addEventListener("hashchange", openGuideFromHash);
  setInterval(watchTitles, 5000);
  watchCoverErrors();
  document.querySelectorAll("[data-donate]").forEach((b) => b.addEventListener("click", openDonate));
  // cards get rebuilt all the time, so delegate
  document.addEventListener("click", (e) => {
    const b = e.target.closest("[data-diag]");
    if (b) openDiag(b.dataset.diag);
    const v = e.target.closest("[data-versions]");
    if (v) openVersions(v.dataset.versions);
  });
  window.addEventListener("hashchange", openDiagFromHash);
});

/* dialogs */

function icon(name) { return `<svg aria-hidden="true"><use href="#icon-${name}"></use></svg>`; }

function closeButtonHtml() {
  return `<button class="icon-button guide-close" type="button" aria-label="${escapeHtml(t("common.close"))}">${icon("close")}</button>`;
}

function openSheet(html, labelledBy, extraClass = "") {
  const back = document.activeElement;
  const wrap = document.createElement("div");
  wrap.className = "guide-backdrop";
  wrap.innerHTML = `<section class="guide ${extraClass}" role="dialog" aria-modal="true" aria-labelledby="${labelledBy}">${html}</section>`;
  const close = () => {
    document.removeEventListener("keydown", onKey);
    wrap.remove();
    if (back && document.contains(back)) back.focus();
  };
  const onKey = (e) => { if (e.key === "Escape") close(); };
  wrap.querySelector(".guide-close").addEventListener("click", close);
  wrap.addEventListener("click", (e) => { if (e.target === wrap) close(); });
  document.addEventListener("keydown", onKey);
  document.body.appendChild(wrap);
  wrap.querySelector(".guide-close").focus();
  return { wrap, close };
}

function coverHtml(game, cls) {
  const src = game && game.has_icon ? `/api/icon/${encodeURIComponent(game.title_id)}` : "";
  const ini = escapeHtml(initials(game ? game.name : ""));
  return `<div class="cover ${cls}" aria-hidden="true" data-initials="${ini}">${src
    ? `<img src="${src}" alt="">` : ini}</div>`;
}

// img errors don't bubble, so catch them on the way down
function watchCoverErrors() {
  document.addEventListener("error", (e) => {
    const img = e.target;
    if (img.tagName !== "IMG" || !img.parentElement) return;
    const cover = img.parentElement;
    if (cover.dataset.initials !== undefined) cover.textContent = cover.dataset.initials;
  }, true);
}

/* other versions */

async function openVersions(titleId) {
  const game = state.titles.find((g) => g.title_id === titleId);
  if (!game) return;
  const { wrap, close } = openSheet(`
      <header class="guide-head">
        <div class="sheet-title">
          ${coverHtml(game, "cover-sm")}
          <div>
            <p class="eyebrow">${t("versions.title")}</p>
            <h2 id="verTitle">${escapeHtml(game.name)}</h2>
            <p class="guide-game">${escapeHtml(t("card.installed", { version: game.installed_version || "?" }))}</p>
          </div>
        </div>
        ${closeButtonHtml()}
      </header>
      <div class="sheet-body"><div class="vskeleton" aria-busy="true"><i></i><i></i><i></i></div>
        <p class="visually-hidden" role="status">${t("versions.loading")}</p></div>`, "verTitle", "is-sheet");

  const data = await fetchJson(`/api/versions?title=${encodeURIComponent(titleId)}`);
  if (!document.contains(wrap)) return;
  const body = wrap.querySelector(".sheet-body");
  if (!data || !data.ok) {
    body.innerHTML = `<div class="callout is-warn">${icon("alert")}<span>${t("versions.loadFailed")}</span></div>`;
    return;
  }
  const rows = (data.versions || []).slice().sort((a, b) => (a.version < b.version ? 1 : -1));
  const group = (st) => rows.filter((r) => r.state === st);
  const ok = group("ok"), locked = group("needs_fw"), installed = group("installed"), older = group("older");
  // locked rows already show the fw in their badge
  const meta = (r) => [r.size, !data.ps4 && r.fw && r.state !== "needs_fw" ? `FW ${r.fw}` : ""]
    .filter(Boolean).map(escapeHtml).join(" · ");
  const row = (r, extra) => `
      <li class="vrow is-${r.state}">
        <div class="vrow-main"><strong>${escapeHtml(r.version)}</strong>${meta(r) ? `<span>${meta(r)}</span>` : ""}</div>
        ${extra}
      </li>`;
  const section = (title, list, render, cls = "") => list.length ? `
      <section class="vgroup ${cls}">
        <h3>${title} <span>${list.length}</span></h3>
        <ul class="vlist">${list.map(render).join("")}</ul>
      </section>` : "";

  body.innerHTML = `
    ${ok.length
      ? `<p class="guide-why">${t("versions.pickHint")}</p>`
      : `<div class="callout">${icon("check")}<span>${rows.length ? t("versions.noneNewer") : t("versions.none")}</span></div>`}
    ${section(t("versions.available"), ok, (r) => row(r,
      `<button type="button" class="row-button is-update" data-pick="${escapeHtml(r.version)}" data-size="${escapeHtml(r.size || "")}">${icon("download")}${t("versions.get")}</button>`))}
    ${section(t("versions.needsFwGroup"), locked, (r) => row(r,
      `<span class="vbadge is-warn">${icon("lock")}${t("card.needsFw", { fw: escapeHtml(r.fw || "?") })}</span>`))}
    ${installed.length ? `<ul class="vlist vcurrent">${installed.map((r) => row(r,
      `<span class="vbadge is-ok">${icon("check")}${t("versions.installedGroup")}</span>`)).join("")}</ul>` : ""}
    ${older.length ? `
      <details class="vgroup volder">
        <summary>${icon("chevron")}${t("versions.olderGroup", { count: older.length })}</summary>
        <ul class="vlist">${older.map((r) => row(r, "")).join("")}</ul>
      </details>` : ""}
    <p class="sheet-source">${t("versions.source", { site: `<a href="${escapeHtml(data.page)}" target="_blank" rel="noopener">${escapeHtml(data.site)}${icon("external")}</a>` })}</p>`;
  body.querySelectorAll("[data-pick]").forEach((btn) => btn.addEventListener("click", () => {
    close();
    if (hasSavedLink(game, btn.dataset.pick)) savedDownload(game, btn.dataset.pick, btn.dataset.size);
    else openGuide(game, false, pickFor(game, btn.dataset.pick, btn.dataset.size));
  }));
  const first = body.querySelector("[data-pick]");
  if (first) first.focus();
}

/* download diagnosis */

function diagLink(titleId) {
  const h = location.hostname;
  let base = location.origin;
  if (!h || h === "localhost" || h === "127.0.0.1" || h === "[::1]") {
    if (!state.status.lan_ip) return null;
    base = `http://${state.status.lan_ip}:${state.status.http_port || location.port || 12880}`;
  }
  return `${base}/#diag/${encodeURIComponent(titleId)}`;
}

function openDiagFromHash() {
  const m = location.hash.match(/^#(diag|versions)\/([A-Za-z0-9_.-]+)$/);
  if (!m) return;
  history.replaceState(null, "", location.pathname + location.search);
  if (m[1] === "diag") openDiag(m[2]);
  else openVersions(m[2]);
}

async function fetchJson(url) {
  try {
    const r = await fetch(url, { cache: "no-store" });
    return r.ok ? await r.json() : null;
  } catch (_) { return null; }
}

function diagRow(ok, label, detail) {
  return `<li class="diag-row ${ok ? "is-ok" : "is-bad"}"><b>${ok ? "✓" : "✗"}</b>
    <span><strong>${escapeHtml(label)}</strong>${detail ? `<br><em>${escapeHtml(detail)}</em>` : ""}</span></li>`;
}

// no clipboard on the PS5, so a QR opens the same dialog on a phone
async function openDiag(titleId) {
  const game = state.titles.find((g) => g.title_id === titleId);
  const name = game ? game.name : titleId;
  const { wrap } = openSheet(`
      <header class="guide-head">
        <div class="sheet-title">
          ${coverHtml(game, "cover-sm")}
          <div>
            <p class="eyebrow">${t("diag.eyebrow")}</p>
            <h2 id="diagTitle">${escapeHtml(name)}</h2>
            <p class="guide-game">${escapeHtml(titleId)}</p>
          </div>
        </div>
        ${closeButtonHtml()}
      </header>
      <div class="diag-body"><p class="guide-why">${t("diag.checking")}</p></div>`, "diagTitle");

  const [check, status, downloads, pkg, inst] = await Promise.all([
    fetchJson(`/api/netcheck?title=${encodeURIComponent(titleId)}`),
    fetchJson(API.status),
    fetchJson(API.downloads),
    fetchJson("/api/pkgdiag"),
    fetchJson(API.installStatus),
  ]);
  if (!document.contains(wrap)) return;
  const job = (downloads || []).find((d) => d.title_id === titleId) || null;
  const ul = check && check.update_list, mf = check && check.manifest;
  const mfDetail = !mf ? "" : mf.ok && mf.step === "direct" ? t("diag.singlePackage") :
    mf.ok ? t("diag.pieces", { count: mf.pieces }) :
    mf.url ? failStepText({ fail_step: mf.step || "manifest", last_http_code: mf.http }) :
    t("diag.noPackage");
  const rows = [
    diagRow(Boolean(ul && ul.ok), t("diag.updateList"),
      !ul ? t("diag.noAnswer")
        : ul.ok ? t("diag.newest", { version: ul.latest || "?" })
        : !ul.url ? t("diag.noUpdateUrl")
        : failStepText({ fail_step: ul.step || "network", last_http_code: ul.http })),
    diagRow(Boolean(mf && mf.ok), t("diag.manifest"), mfDetail),
  ];
  if (job) rows.push(diagRow(job.state !== "error", t("diag.lastDownload"),
    job.state === "error" ? (Number(job.rc) === -3 ? noSpaceText(job.need_bytes, job.free_bytes, job.space_install)
      : job.fail_step ? failStepText(job) : t("diag.failedPieces"))
      : tCode("diag.jobState.", job.state, job.state)));

  const report = [
    "PatchDL diagnostic report",
    `PatchDL ${status ? status.version : "?"} · FW ${status ? status.firmware : "?"}`,
    `Game: ${name} (${titleId})${game ? ` · installed ${game.installed_version || "?"} · ${game.source_type}${game.sideloaded ? ", sideloaded" : ""}` : ""}`,
    `Download: ${job ? JSON.stringify(job) : "none"}`,
    `Network check: ${check ? JSON.stringify(check) : "unavailable"}`,
    `Install: ${inst ? JSON.stringify(inst.streams || inst) : "unavailable"}`,
    `Console requests: ${pkg && pkg.log ? pkg.log.slice(-8).join(" | ") : "none"}`,
    ...(state.logs.length ? ["Log:", ...state.logs.slice(-15).map((e) => logLine(e, tEn))] : []),
  ].join("\n");

  const onConsole = isConsoleBrowser();
  const link = onConsole ? diagLink(titleId) : null;
  const matrix = link ? qrEncode(link) : null;
  wrap.querySelector(".diag-body").innerHTML = `
    <ul class="diag-list">${rows.join("")}</ul>
    ${onConsole
      ? (matrix ? `<div class="guide-qr">${qrSvg(matrix)}<div>
          <span>${t("diag.reportPhone")}</span></div></div>` : "")
      : `<p class="guide-why">${t("diag.reportHint")}</p>`}
    <textarea class="diag-report" readonly rows="8" aria-label="${t("diag.reportAria")}">${escapeHtml(report)}</textarea>
    ${onConsole ? "" : `<button type="button" class="row-button is-update diag-copy">${t("diag.copy")}</button>`}`;
  const copy = wrap.querySelector(".diag-copy");
  if (copy) copy.addEventListener("click", async () => {
    const ta = wrap.querySelector(".diag-report");
    try { await navigator.clipboard.writeText(report); }
    catch (_) { ta.select(); document.execCommand("copy"); }
    showToast(t("diag.copied"));
  });
}

const DONATE_URL = "https://paypal.me/oliverkoester";

// a link is useless on the TV, hence the QR (hidden on phones)
function openDonate() {
  const matrix = qrEncode(DONATE_URL);
  openSheet(`
      <header class="guide-head">
        <div>
          <p class="eyebrow">${t("donate.eyebrow")}</p>
          <h2 id="donateTitle">${t("donate.title")}</h2>
        </div>
        ${closeButtonHtml()}
      </header>
      <p class="guide-why">${t("donate.why")}</p>
      ${matrix ? `<div class="guide-qr">${qrSvg(matrix)}<div>
        <span>${t("donate.scan")}</span>
        <code>${escapeHtml(DONATE_URL)}</code></div></div>` : ""}
      <a class="row-button is-update donate-open" href="${DONATE_URL}" target="_blank" rel="noopener">${t("donate.open")}</a>
      <p class="guide-why"><small>${escapeHtml(t("donate.small"))}</small></p>`, "donateTitle");
}

// server bumps titles_gen when the game list or an update check changes
let watchBusy = false;
async function watchTitles() {
  if (watchBusy) return;
  watchBusy = true;
  try {
    const response = await fetch(API.status, { cache: "no-store" });
    if (!response.ok) return;
    const status = await response.json();
    const changed = state.status && status.titles_gen !== state.status.titles_gen;
    if (changed) await loadInitialData({ quiet: true });
    else { state.status = status; renderStatus(); }
  } catch (_) { /* offline for a sec, next tick retries */ }
  finally { watchBusy = false; }
}

async function rescanNow() {
  try { await postJson(API.rescan, {}); } catch (_) { /* older server, plain reload then */ }
  await new Promise((resolve) => setTimeout(resolve, 1500));
  await loadInitialData();
}

function bindElements() {
  Object.assign(els, {
    firmwareValue: document.getElementById("firmwareValue"),
    firmwareBuild: document.getElementById("firmwareBuild"),
    dnsValue: document.getElementById("dnsValue"),
    resolverValue: document.getElementById("resolverValue"),
    spaceValue: document.getElementById("spaceValue"),
    downloadDirValue: document.getElementById("downloadDirValue"),
    railFw: document.getElementById("railFw"),
    railSpace: document.getElementById("railSpace"),
    gameGrid: document.getElementById("gameGrid"),
    logOutput: document.getElementById("logOutput"),
    allowlistHosts: document.getElementById("allowlistHosts"),
    sourcePolicyList: document.getElementById("sourcePolicyList"),
    storageList: document.getElementById("storageList"),
    storageTotal: document.getElementById("storageTotal"),
    searchInput: document.getElementById("searchInput"),
    defaultPolicy: document.getElementById("defaultPolicy"),
    downloadDrive: document.getElementById("downloadDrive"),
    installAfterDownload: document.getElementById("installAfterDownload"),
    deleteAfterInstall: document.getElementById("deleteAfterInstall"),
    verifyDownloads: document.getElementById("verifyDownloads"),
    homeShortcut: document.getElementById("homeShortcut"),
    connValue: document.getElementById("connValue"),
    connMinus: document.getElementById("connMinus"),
    connPlus: document.getElementById("connPlus"),
    refreshBtn: document.getElementById("refreshBtn"),
    updateAllBtn: document.getElementById("updateAllBtn"),
    brandVersion: document.getElementById("brandVersion"),
    globalDl:         document.getElementById("globalDl"),
    globalDlState:    document.getElementById("globalDlState"),
    globalDlName:     document.getElementById("globalDlName"),
    globalDlPosition: document.getElementById("globalDlPosition"),
    globalDlPct:      document.getElementById("globalDlPct"),
    globalDlSpeed:    document.getElementById("globalDlSpeed"),
    globalDlEta:      document.getElementById("globalDlEta"),
    globalDlBar:      document.getElementById("globalDlBar"),
    saveBtn: document.getElementById("saveBtn"),
    language: document.getElementById("language"),
    clearLogBtn: document.getElementById("clearLogBtn"),
    toast: document.getElementById("toast"),
  });
}

function bindEvents() {
  document.querySelectorAll(".nav-link").forEach((b) =>
    b.addEventListener("click", () => setView(b.dataset.view)));

  els.searchInput.addEventListener("input", (e) => {
    state.query = e.target.value.trim().toLowerCase();
    renderGames();
  });

  document.querySelectorAll(".segmented button").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll(".segmented button").forEach((i) => {
        i.classList.remove("is-selected");
        i.setAttribute("aria-pressed", "false");
      });
      button.classList.add("is-selected");
      button.setAttribute("aria-pressed", "true");
      state.filter = button.dataset.filter;
      renderGames();
    });
  });

  els.refreshBtn.addEventListener("click", rescanNow);
  if (els.updateAllBtn) els.updateAllBtn.addEventListener("click", updateAll);
  els.saveBtn.addEventListener("click", saveConfig);
  els.clearLogBtn.addEventListener("click", () => { state.logs = []; renderLogs(); });
  if (els.connMinus)
    els.connMinus.addEventListener("click", () => setConnections(clampConn(state.config.max_connections) - 1));
  if (els.connPlus)
    els.connPlus.addEventListener("click", () => setConnections(clampConn(state.config.max_connections) + 1));
}

function fillLanguageSelect() {
  const sel = document.getElementById("language");
  if (!sel) return;
  const current = languageChoice();
  sel.replaceChildren(...LANGUAGES.map(([code, name]) => {
    const opt = document.createElement("option");
    opt.value = code;
    opt.textContent = code === "auto" ? t("settings.languageAuto") : name;
    if (code !== "auto") opt.lang = code;
    opt.selected = code === current;
    return opt;
  }));
  sel.addEventListener("change", () => setLanguage(sel.value));
}

function setView(view) {
  state.view = view;
  document.querySelectorAll(".nav-link").forEach((b) => {
    const on = b.dataset.view === view;
    b.classList.toggle("is-active", on);
    if (on) b.setAttribute("aria-current", "page");
    else b.removeAttribute("aria-current");
  });
  document.querySelectorAll(".view").forEach((s) => s.classList.toggle("is-active", s.dataset.view === view));
  if (view === "settings") { loadStorage(); loadDrives(); }
}

async function loadInitialData({ quiet = false } = {}) {
  state.usingFallback = false;
  const [status, config, titles, downloads] = await Promise.all([
    getJson(API.status, fallback.status),
    getJson(API.config, fallback.config),
    getJson(API.titles, fallback.titles),
    getJson(API.downloads, fallback.downloads),
  ]);

  // /api/titles has no client-only flags. carry them over or a running job
  // flips back to a clickable button. the job list fixes the rest below
  const prev = new Map(state.titles.map((g) => [g.title_id, g]));
  titles.forEach((g) => {
    const old = prev.get(g.title_id);
    // the console writes the new version mid-install, so only the install
    // poll ends an install
    if (old && old.installing) {
      g.installing = true;
      g.installStatus = old.installStatus;
      g.installProgress = old.installProgress;
      g.installDone = old.installDone;
      g.installTotal = old.installTotal;
    }
    // up_to_date / incompatible_fw: nothing left to fetch, drop stale flags
    if (old && g.status !== "up_to_date" &&
        (g.status !== "incompatible_fw" || g.manual_version)) {
      if (old._autoInstalled) g._autoInstalled = true;
      if (old._localDownloading) g._localDownloading = true;
      if (old._wasActive) g._wasActive = true;
    }
  });
  // a game being replaced drops out of the console's list for a moment,
  // its card stays until the install is over
  freshInstalling.forEach((name, id) => {
    if (titles.some((g) => g.title_id.startsWith(id))) return;
    const old = [...prev.values()].find((g) => g.title_id.startsWith(id));
    if (old) titles.push(old);
  });

  // one failed request on a quiet reload shouldn't swap in the demo data
  if (quiet && state.usingFallback) { state.usingFallback = false; return; }
  state = { ...state, status, config, titles, downloads };
  reconcileFromJobs(downloads);

  render();
  if (downloads.some((j) => j.state === "active" || j.state === "queued") ||
      state.titles.some((g) => g._localDownloading))
    startDownloadPolling();
  if (state.titles.some((g) => g.installing)) startInstallPolling();
  if (!quiet) refreshInstallStatus();
  if (!quiet)
    showToast(state.usingFallback ? t("toast.demoData") : t("toast.refreshed"));
}

async function getJson(url, fallbackValue) {
  try {
    const response = await fetch(url, { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } catch (error) {
    state.usingFallback = true;
    return clone(fallbackValue);
  }
}

function render() {
  renderStatus();
  renderSettings();
  renderGames();
  renderLogs();
}

function renderStatus() {
  els.firmwareValue.textContent = state.status.firmware || "--";
  els.firmwareBuild.textContent = state.status.firmware_build || t("metric.firmwareBuild");
  els.dnsValue.textContent = state.status.dns_guard || "--";
  els.resolverValue.textContent = state.status.resolver || "--";
  const space = formatMb(state.status.free_space_mb);
  els.spaceValue.textContent = space;
  const kept = Number(state.status.downloads_bytes) || 0;
  if (kept > 0) {
    els.downloadDirValue.innerHTML =
      `<button type="button" class="link-button">${escapeHtml(t("metric.downloadsManage", { size: formatBytes(kept) }))}</button>`;
    els.downloadDirValue.querySelector("button").addEventListener("click", () => setView("settings"));
  } else {
    els.downloadDirValue.textContent = state.status.download_dir || state.config.download_dir || t("metric.downloadTarget");
  }
  if (els.railFw) els.railFw.textContent = `FW ${state.status.firmware || "--"}`;
  if (els.railSpace) els.railSpace.textContent = t("rail.free", { space });
  if (els.brandVersion)
    els.brandVersion.textContent = state.status.version ? `v${state.status.version}` : "v--";
}

const CONN_MIN = 1, CONN_MAX = 16;
function clampConn(n) {
  n = parseInt(n, 10);
  if (!Number.isFinite(n)) n = 4;
  return Math.max(CONN_MIN, Math.min(CONN_MAX, n));
}

function renderConnStepper() {
  const n = clampConn(state.config.max_connections);
  if (els.connValue) els.connValue.textContent = String(n);
  if (els.connMinus) els.connMinus.disabled = n <= CONN_MIN;
  if (els.connPlus) els.connPlus.disabled = n >= CONN_MAX;
}

let connSaveTimer = null;
// debounced, posts only this field so other unsaved settings stay put.
// the server picks it up live
function setConnections(n) {
  const v = clampConn(n);
  if (v === clampConn(state.config.max_connections)) { renderConnStepper(); return; }
  state.config.max_connections = v;
  renderConnStepper();
  clearTimeout(connSaveTimer);
  connSaveTimer = setTimeout(async () => {
    try {
      await postJson(API.config, { max_connections: v });
      showToast(t("toast.connections", { count: v }));
    } catch (e) {
      showToast(t("toast.connectionsFailed"));
    }
  }, 450);
}

function renderSettings() {
  els.defaultPolicy.value = state.config.default_policy || "deny";
  renderDrives();
  els.installAfterDownload.checked = Boolean(state.config.install_after_download);
  els.deleteAfterInstall.checked = Boolean(state.config.delete_pkg_after_install);
  if (els.verifyDownloads) els.verifyDownloads.checked = Boolean(state.config.verify_downloads);
  if (els.homeShortcut) els.homeShortcut.checked = state.config.home_shortcut !== false;
  renderConnStepper();
  els.allowlistHosts.replaceChildren(...(state.config.cdn_allowlist || []).map((host) => {
    const chip = document.createElement("span");
    chip.className = "host-chip";
    chip.textContent = host;
    return chip;
  }));
  renderSourcePolicies();
}

/* games */

function renderGames() {
  renderGlobalStatus();
  const counts = { updates: 0, uptodate: 0, blocked: 0, all: state.titles.length };
  state.titles.forEach((g) => { counts[gameCategory(g)]++; });
  document.querySelectorAll(".segmented button").forEach((b) => {
    const c = b.querySelector(".chip-count");
    if (c) c.textContent = String(counts[b.dataset.filter] ?? "");
  });
  const visible = state.titles.filter(matchesFilter).filter(matchesQuery)
    .sort((a, b) => (a.name || a.title_id).localeCompare(b.name || b.title_id, undefined, { sensitivity: "base", numeric: true }));
  els.gameGrid.replaceChildren();

  if (!visible.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = t("games.empty");
    els.gameGrid.appendChild(empty);
    return;
  }
  visible.forEach((game) => els.gameGrid.appendChild(createGameCard(game)));
}

function isPs4(game) { return (game.title_id || "").startsWith("CUSA"); }

function gameCategory(game) {
  const policy = sourcePolicy(game);
  if (game.patch_title_match === false || !policy.allow_install || game.status === "blocked")
    return "blocked";
  if (game.downloading || game.resumable || game.downloaded || game.installing || game._jobState)
    return "updates";
  if (game.status === "checking" || game.status === "available" || hasOlderPatch(game))
    return "updates";
  return "uptodate";
}

// sony's newest needs newer fw, but prospero has an older one that runs here
// and still beats the installed one
function hasOlderPatch(game) {
  return game.status === "incompatible_fw" && Boolean(game.prospero_version) &&
    game.prospero_version > (game.installed_version || "");
}

// a link pasted before for this version, PatchDL keeps them
function hasSavedLink(game, version) {
  return Boolean(version) && (game.saved_versions || []).includes(version);
}

function rememberLink(game, version) {
  if (!hasSavedLink(game, version)) game.saved_versions = [...(game.saved_versions || []), version];
}

function matchesFilter(game) {
  if (state.filter === "all") return true;
  return gameCategory(game) === state.filter;
}

function matchesQuery(game) {
  if (!state.query) return true;
  return [game.name, game.title_id, game.content_id, game.source_type, game.source_path, game.mount_from]
    .filter(Boolean)
    .some((v) => v.toLowerCase().includes(state.query));
}

function createGameCard(game) {
  const card = document.createElement("article");
  card.className = "game-card";
  card.dataset.titleId = game.title_id;
  if (game.downloading) card.classList.add("is-downloading");
  if (game.installing) card.classList.add("is-installing");

  const row = document.createElement("div");
  row.className = "card-row";

  const lead = document.createElement("div");
  lead.className = "lead";
  const cover = document.createElement("div");
  cover.className = "cover";
  cover.textContent = initials(game.name);
  if (game.has_icon) {
    // cards re-render on every poll, reuse the loaded icon or it flashes
    const loaded = iconCache.get(game.title_id);
    if (loaded) {
      cover.replaceChildren(loaded.cloneNode());
    } else {
      const img = new Image();
      img.alt = "";
      img.decoding = "async";
      img.onload = () => { iconCache.set(game.title_id, img); cover.replaceChildren(img.cloneNode()); };
      img.src = `/api/icon/${encodeURIComponent(game.title_id)}`;
    }
  }
  lead.appendChild(cover);
  if (sourcePolicy(game).allow_install) lead.appendChild(buildToggle(game));

  const body = document.createElement("div");
  body.className = "card-body";
  body.innerHTML = `
    <h3>${escapeHtml(game.name)}</h3>
    <div class="pills">
      <span class="tid" title="${escapeHtml(game.content_id || "")}">${escapeHtml(game.title_id)}</span>
      ${isPs4(game) ? `<span class="pill">PS4</span>` : ""}
      ${game.downloading && game._jobState === "queued" ? `<span class="pill">${t("pill.queued")}</span>` : ""}
      ${game.downloading && game._jobState !== "queued" ? `<span class="pill live">${t("pill.downloading")}</span>` : ""}
      ${game.resumable && !game.downloading ? `<span class="pill warn">${t("pill.paused")}</span>` : ""}
      ${statusPill(game)}
      ${sourcePill(game)}
      ${game.sideloaded ? `<span class="pill warn" title="${escapeHtml(t("pill.sideloadedTitle"))}">${t("pill.sideloaded")}</span>` : ""}
    </div>
    ${versionTrackHtml(game)}
    ${cardNotesHtml(game)}
  `;

  const actions = document.createElement("div");
  actions.className = "card-actions";
  [primaryButton(game), stopButton(game)].forEach((act) => {
    if (!act) return;
    const btn = document.createElement("button");
    btn.className = `row-button is-${act.variant}`;
    btn.textContent = act.label;
    if (act.hint) btn.title = act.hint;
    if (act.disabled) btn.disabled = true;
    else btn.addEventListener("click", () => runTitleAction(game.title_id, act.action));
    actions.appendChild(btn);
  });
  if (canPickVersion(game, "99") && !game.manual_version && game.status !== "blocked") {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "row-button is-ghost";
    btn.dataset.versions = game.title_id;
    btn.innerHTML = `${icon("layers")}<span>${t("versions.title")}</span>`;
    actions.appendChild(btn);
  }

  row.append(lead, body, actions);
  card.appendChild(row);

  if (game.downloading) {
    const d = state.downloads.find((x) => x.title_id === game.title_id) || {};
    const prog = document.createElement("div");
    prog.className = "card-progress";
    prog.innerHTML = `
      <div class="progress"><i style="width:${pctOf(d)}%"></i></div>
      <div class="progress-meta">${progressMetaHtml(d)}</div>
    `;
    card.appendChild(prog);
  } else if (game.installing) {
    const pct = Math.max(0, Math.min(100, Number(game.installProgress) || 0));
    const indet = game.installStatus === "finishing" || game.installStatus === "waiting";
    const note = document.createElement("div");
    note.className = "card-progress";
    note.innerHTML = `
      <div class="progress${indet ? " is-indeterminate" : ""}"><i style="width:${indet ? 32 : pct}%${indet ? `;animation-delay:-${Date.now() % INDET_MS}ms` : ""}"></i></div>
      <div class="progress-meta">${installProgressHtml(game)}</div>
    `;
    card.appendChild(note);
  } else if (game.resumable && game.partial_bytes > 0) {
    // paused partial, survives a reboot
    const note = document.createElement("div");
    note.className = "card-progress";
    note.innerHTML = `
      <div class="progress-meta">
        <span>${t("card.pausedDownloaded", { size: formatBytes(game.partial_bytes) })}</span>
        <span>${t("card.resumeToContinue")}</span>
      </div>
    `;
    card.appendChild(note);
  }

  return card;
}

function buildToggle(game) {
  const toggle = document.createElement("label");
  toggle.className = "toggle";
  const cb = document.createElement("input");
  cb.type = "checkbox";
  cb.checked = game.enabled !== false;
  cb.setAttribute("aria-label", t("card.enableAria", { name: game.name }));
  const track = document.createElement("span");
  track.className = "track";
  const lbl = document.createElement("span");
  lbl.className = "label";
  lbl.textContent = cb.checked ? t("card.updatesOn") : t("card.updatesOff");
  cb.addEventListener("change", () => {
    lbl.textContent = cb.checked ? t("card.updatesOn") : t("card.updatesOff");
    updateGame(game.title_id, { enabled: cb.checked });
  });
  toggle.append(cb, track, lbl);
  return toggle;
}

function primaryButton(game) {
  if (game.installing) return { label: t("btn.installing"), variant: "ghost", disabled: true };
  if (game.downloading) return { label: t("btn.pause"), action: "pause", variant: "pause", hint: t("btn.pauseHint") };
  if (game.patch_title_match === false) return null;
  if (canGetOlderPatch(game) && hasSavedLink(game, game.prospero_version))
    return { label: t("btn.download"), action: "saved", variant: "update", hint: t("btn.downloadHint") };
  if (canGetOlderPatch(game))
    return { label: t("btn.oldFw"), action: "guide", variant: "update", hint: t("btn.oldFwHint", { version: game.prospero_version }) };
  if (game.resumable && isDownloadAllowed(game))
    return { label: t("btn.resume"), action: "download", variant: "update", hint: t("btn.resumeHint") };
  const hasPatch = game.status === "available" || Boolean(game.manual_version);
  if (game.downloaded && hasPatch && isInstallAllowed(game))
    return { label: t("btn.install"), action: "install", variant: "update", hint: t("btn.installHint") };
  if (game.downloaded && hasPatch) return null;
  if (!hasPatch) return null;
  if (!isDownloadAllowed(game)) return null;
  return state.config.install_after_download && isInstallAllowed(game)
    ? { label: t("btn.update"), action: "update", variant: "update", hint: t("btn.updateHint") }
    : { label: t("btn.download"), action: "download", variant: "update", hint: t("btn.downloadHint") };
}

// cancel deletes the partial, pause keeps it
function stopButton(game) {
  if (game.installing) return null;
  if (game.downloaded && !game.downloading)
    return { label: t("btn.delete"), action: "cancel", variant: "cancel", hint: t("btn.deleteHint") };
  if (game.downloading || game.resumable)
    return { label: t("btn.cancel"), action: "cancel", variant: "cancel", hint: t("btn.cancelHint") };
  return null;
}

function versionTrackHtml(game) {
  const step = (label, version, note, cls = "") => `
    <div class="vstep ${cls}"><span>${label}</span><b>${escapeHtml(version)}</b>${note ? `<em>${note}</em>` : ""}</div>`;
  const parts = [step(t("card.lblInstalled"), game.installed_version || "--", "")];
  let offered = "";
  if (game.manual_version) {
    offered = game.manual_version;
    parts.push(step(t("card.lblUpdate"), offered, "", "is-target"));
  } else if (game.status === "available" && game.compatible_version) {
    offered = game.compatible_version;
    parts.push(step(t("card.lblUpdate"), offered, "", "is-target"));
  } else if (hasOlderPatch(game)) {
    offered = game.prospero_version;
    parts.push(step(t("card.lblUpdate"), offered,
      game.prospero_required_fw ? t("card.needsFw", { fw: escapeHtml(game.prospero_required_fw) }) : "", "is-target"));
  }
  if (game.latest_version && game.latest_version !== offered && game.latest_version !== game.installed_version)
    parts.push(step(t("card.lblNewest"), game.latest_version,
      game.latest_required_fw ? t("card.needsFw", { fw: escapeHtml(game.latest_required_fw) }) : "", "is-dim"));
  const arrow = `<span class="vtrack-arrow">${icon("arrow")}</span>`;
  return `<div class="vtrack">${offered ? parts[0] + arrow + parts.slice(1).join("") : parts.join("")}</div>`;
}

function cardNotesHtml(game) {
  const notes = [];
  const job = state.downloads.find((d) => d.title_id === game.title_id);
  if (job && job.state === "error" && Number(job.rc) === -3)
    notes.push(`<div class="callout is-warn">${icon("alert")}<span>${escapeHtml(noSpaceText(job.need_bytes, job.free_bytes, job.space_install))}</span></div>`);
  else if (job && job.state === "error")
    notes.push(`<div class="callout is-warn">${icon("alert")}<span>${escapeHtml(t("card.downloadFailed"))}${job.fail_step ? " " + escapeHtml(failStepText(job)) : ""}</span>
      <button type="button" class="link-button" data-diag="${escapeHtml(game.title_id)}">${t("card.details")}</button></div>`);
  if (!game.manual_version && !hasOlderPatch(game) && game.status === "incompatible_fw" && !game.prospero_done)
    notes.push(`<div class="callout is-quiet"><span class="spinner" aria-hidden="true"></span><span>${t("card.lookingForPatch")}</span></div>`);
  if (game.sideloaded)
    notes.push(`<div class="callout is-warn">${icon("alert")}<span>${escapeHtml(t("card.sideloadedNote"))}</span></div>`);
  return notes.join("");
}

function statusPill(game) {
  if (game.installing) return `<span class="pill warn">${t("pill.installing")}</span>`;
  if (game.status === "checking") return `<span class="pill">${t("pill.checking")}</span>`;
  if (game.status === "blocked" || !sourcePolicy(game).allow_install)
    return `<span class="pill">${t("pill.notSupported")}</span>`;
  if (game.patch_title_match === false) return `<span class="pill blocked">${t("pill.titleMismatch")}</span>`;
  // the badge says "get a link first", with a link it's a normal update
  if (game.manual_version || (hasOlderPatch(game) && hasSavedLink(game, game.prospero_version)))
    return `<span class="pill ok">${t("pill.available")}</span>`;
  if (hasOlderPatch(game))
    return `<span class="pill prospero">${t("pill.via", { site: isPs4(game) ? "Orbis" : "Prospero" })}</span>`;
  if (game.status === "available") return `<span class="pill ok">${t("pill.available")}</span>`;
  if (game.status === "incompatible_fw")
    return `<span class="pill">${t("pill.newestNeedsFw", { fw: escapeHtml(game.latest_required_fw || "?") })}</span>`;
  if (game.status === "up_to_date") return `<span class="pill">${t("pill.upToDate")}</span>`;
  return `<span class="pill">${t("pill.noInfo")}</span>`;
}

function sourcePill(game) {
  const info = sourceInfo(game);
  const type = SOURCE_TYPES[sourceType(game)] ? sourceType(game) : "unknown";
  if (type === "official") return "";
  return `<span class="pill ${info.className}">${escapeHtml(sourceLabel(type))}</span>`;
}
function sourceInfo(game) { return SOURCE_TYPES[sourceType(game)] || SOURCE_TYPES.unknown; }
function sourceType(game) { return game.source_type || "unknown"; }

/* download progress */

function pctOf(d) {
  const done = Number(d.bytes) || 0;
  const total = Number(d.total_bytes) || 0;
  if (total > 0) return Math.max(0, Math.min(100, Math.round((done * 100) / total)));
  return Math.max(0, Math.min(100, Number(d.progress) || 0));
}

function progressMetaHtml(d) {
  const done = Number(d.bytes) || 0;
  const total = Number(d.total_bytes) || 0;
  const speed = Number(d._speed) || 0;
  if (d.state === "queued") return `<span>${t("progress.queued")}</span>`;
  const parts = [];
  if (d.verifying) parts.push(`<span><b>${t("progress.verifying")}</b></span>`);
  if (d.waiting && !(Number(d._speed) > 0)) parts.push(`<span><b>${t("progress.retrying")}</b></span>`);
  parts.push(`<span><b>${formatBytes(done)}</b>${total > 0 ? ` / ${formatBytes(total)}` : ""}</span>`);
  if (speed > 0) parts.push(`<span><b>${formatBytes(speed)}/s</b></span>`);
  if (speed > 0 && total > done) parts.push(`<span>${t("progress.eta", { eta: formatEta((total - done) / speed) })}</span>`);
  else if (!total) parts.push(`<span>${t("progress.fetchingManifest")}</span>`);
  parts.push(`<span><b>${pctOf(d)}%</b></span>`);
  return parts.join("");
}

// one sweep of the indeterminate bar. the negative delay from the clock
// keeps a rebuilt card's bar from starting over
const INDET_MS = 1600;

const INSTALL_PHASES = ["waiting", "reading", "finishing"];

function installProgressHtml(game) {
  const status = game.installStatus || "waiting";
  const done = Number(game.installDone) || 0;
  const total = Number(game.installTotal) || 0;
  const phase = INSTALL_PHASES.includes(status) ? t(`install.phase.${status}`) : "";
  if (phase) {
    const parts = [`<span><b>${phase}</b></span>`];
    if (status === "reading" && total > 0) {
      parts.push(`<span><b>${formatBytes(done)}</b> / ${formatBytes(total)}</span>`);
      parts.push(`<span><b>${Math.max(0, Math.min(100, Number(game.installProgress) || 0))}%</b></span>`);
    }
    return parts.join("");
  }
  const parts = [`<span>${t("install.status", { status: escapeHtml(status) })}</span>`];
  if (total > 0) parts.push(`<span><b>${formatBytes(done)}</b> / ${formatBytes(total)}</span>`);
  parts.push(`<span><b>${Math.max(0, Math.min(100, Number(game.installProgress) || 0))}%</b></span>`);
  return parts.join("");
}

function startDownloadPolling() {
  emptyPolls = 0;
  if (downloadPollTimer) return;
  downloadPollTimer = setInterval(refreshDownloads, 2000);
  refreshDownloads();
}

function stopDownloadPolling() {
  if (!downloadPollTimer) return;
  clearInterval(downloadPollTimer);
  downloadPollTimer = null;
}

function reconcileFromJobs(jobs) {
  const byId = new Map((jobs || []).map((j) => [j.title_id, j]));
  state.titles.forEach((g) => {
    const j = byId.get(g.title_id);
    if (!j) {
      // pool never picked up the local start (server restart, odd response),
      // time it out so the card doesn't hang on Downloading
      if (g._localDownloading && g._localSince &&
          Date.now() - g._localSince > 12000) {
        g._localDownloading = false;
      }
      if (g.downloading && !g._localDownloading) g.downloading = false;
      g._jobState = null;
      return;
    }
    // started here counts as watched, even if no poll saw it running
    if (g._localDownloading) g._wasActive = true;
    g._localDownloading = false;
    g._jobState = j.state;
    if (j.state === "active" || j.state === "queued") {
      g._spaceWarned = false;
      g.downloading = true;
      g.resumable = false;
      g._wasActive = true;
    } else if (j.state === "paused") {
      g.downloading = false;
      g.resumable = true;
      g.partial_bytes = Number(j.bytes) || g.partial_bytes || 0;
      g._wasActive = false;
    } else if (j.state === "done") {
      // auto-install once, only if this page saw it finish and the update is
      // still pending. done jobs stay in the pool, or every poll would retry
      const justFinished = g._wasActive;
      const pending = g.status === "available" || Boolean(g.manual_version);
      g.downloading = false;
      g.resumable = false;
      g.downloaded = true;
      g._wasActive = false;
      if (justFinished && pending && state.config.install_after_download &&
          isInstallAllowed(g) && !g.installing && !g._autoInstalled) {
        g._autoInstalled = true;
        doInstall(g);
      }
    } else if (j.state === "error") {
      // server keeps partial + sidecar after giving up, so offer Resume/Cancel
      const bytes = Number(j.bytes) || 0;
      if (Number(j.rc) === -3) {
        if (!g._spaceWarned) showToast(t("toast.nameMessage", { name: g.name, message: noSpaceText(j.need_bytes, j.free_bytes, j.space_install) }));
        g._spaceWarned = true;
      } else if (g._wasActive) {
        const why = j.fail_step ? ` ${failStepText(j)}` : "";
        showToast(t(bytes > 0 ? "toast.downloadFailedPartial" : "toast.downloadFailed", { name: g.name, why }));
        if (j.fail_step) {
          addLog("log.fetchFailed", { id: g.title_id, step: j.fail_step, curl: j.last_curl_rc, http: j.last_http_code });
          renderLogs();
        }
      }
      g._wasActive = false;
      g.downloading = false;
      g.resumable = bytes > 0;
      g.partial_bytes = bytes || g.partial_bytes || 0;
    }
  });
}

function failStepText(j) {
  const http = Number(j.last_http_code) || 0;
  // connect: DNS worked, but nobody took the connection
  const step = j.fail_step === "connect" ? "network" : j.fail_step;
  const key = `failstep.${step}`;
  return step && step !== "unknown" && tHas(key)
    ? t(key, { http })
    : t("failstep.unknown", { step });
}

function startInstallPolling() {
  if (installPollTimer) return;
  installPollTimer = setInterval(refreshInstallStatus, 2000);
  refreshInstallStatus();
}

function stopInstallPolling() {
  if (!installPollTimer) return;
  clearInterval(installPollTimer);
  installPollTimer = null;
}

function installEndText(st) {
  if (st.phase === "stalled") return t("install.msg.stalled");
  if (!st.verified) return t("install.msg.unconfirmed");
  return t(st.deleted ? "install.msg.verifiedDeleted"
    : state.config.delete_pkg_after_install ? "install.msg.verifiedDeleting"
    : "install.msg.verifiedKept");
}

async function refreshInstallStatus() {
  let s;
  try {
    const response = await fetch(API.installStatus, { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    s = await response.json();
  } catch (error) {
    return;
  }

  // streams come along even before the installer ever ran (a replace whose
  // uninstall failed), so only bail when there's nothing at all
  if (!s || (!s.active && !(Array.isArray(s.streams) && s.streams.length))) {
    if (!state.titles.some((g) => g.installing) && !freshInstalling.size) stopInstallPolling();
    return;
  }

  // streamed installs: own byte count beats Sony's status query, which has
  // nothing useful for these
  const streams = Array.isArray(s.streams) ? s.streams : [];
  if (streams.length) {
    let ended = false, changed = false;
    streams.forEach((st) => {
      const game = state.titles.find((g) => g.title_id.startsWith(st.title_id));
      if (!game) {
        // a fresh install from Downloads: no card until the console registers it
        if (freshInstalling.has(st.title_id) && (st.phase === "done" || st.phase === "stalled")) {
          const name = freshInstalling.get(st.title_id) || st.title_id;
          freshInstalling.delete(st.title_id);
          const msg = installEndText(st);
          addLog("log.installEnded", { id: st.title_id, msg });
          showToast(t("toast.installEnded", { name, msg }));
          ended = true;
        }
        return;
      }
      // a replaced game: its card follows the install until the end
      if (freshInstalling.has(st.title_id)) game.installing = true;
      const over = st.phase === "done" || st.phase === "stalled";
      if (over && !game.installing) return;   // finished before this page watched it
      const total = Number(st.total) || 0;
      const read = Math.min(Number(st.read) || 0, total || Infinity);
      const pct = total ? Math.floor((read * 100) / total) : 0;
      if (game.installing !== !over || game.installStatus !== st.phase ||
          game.installProgress !== pct) changed = true;
      game.installing = !over;
      game.installStatus = st.phase;
      game.installProgress = pct;
      game.installDone = read;
      game.installTotal = total;
      if (over) {
        freshInstalling.delete(st.title_id);
        const msg = installEndText(st);
        addLog("log.installEnded", { id: game.title_id, msg });
        showToast(t("toast.installEnded", { name: game.name, msg }));
        ended = true;
      }
    });
    if (changed) renderGames();
    if (state.titles.some((g) => g.installing) || freshInstalling.size) startInstallPolling();
    if (ended) {
      renderLogs();
      if (!state.titles.some((g) => g.installing) && !freshInstalling.size) stopInstallPolling();
      loadInitialData({ quiet: true });
      loadStorage();
    }
    return;
  }

  const titleId = s.target_title_id || "";
  const game = state.titles.find((g) => g.title_id === titleId || g.title_id.slice(0, 9) === titleId.slice(0, 9));
  if (!game) return;

  game.installing = !s.terminal;
  game.installStatus = s.status || "running";
  game.installProgress = Number(s.progress) || 0;
  game.installDone = Number(s.downloaded_size) || 0;
  game.installTotal = Number(s.total_size) || 0;
  renderGames();

  if (s.terminal) {
    const ok = s.status === "playable";
    addLog(ok ? "log.installCompleted" : "log.installStopped", {
      id: game.title_id,
      status: s.status || t("common.unknown"),
      code: s.error_code ? ` (0x${Number(s.error_code >>> 0).toString(16)})` : "",
    });
    renderLogs();
    stopInstallPolling();
    if (ok) loadInitialData();
  }
}

async function refreshDownloads() {
  let jobs;
  try {
    const response = await fetch(API.downloads, { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    jobs = await response.json();
  } catch (error) {
    return; // blip, keep the last state
  }

  const now = Date.now();
  const ids = new Set();
  jobs.forEach((j) => {
    ids.add(j.title_id);
    const done = Number(j.bytes) || 0;
    const prev = dlMeta[j.title_id];
    if (prev && now > prev.t) {
      if (done >= prev.bytes) {
        const inst = ((done - prev.bytes) * 1000) / (now - prev.t); // bytes/s
        prev.speed = prev.speed ? prev.speed * 0.5 + inst * 0.5 : inst; // smoothed
      } else {
        prev.speed = 0; // counter went backwards, start over
      }
    }
    const meta = prev || (dlMeta[j.title_id] = { speed: 0 });
    meta.bytes = done;
    meta.t = now;
    j._speed = meta.speed || 0;
  });
  Object.keys(dlMeta).forEach((id) => { if (!ids.has(id)) delete dlMeta[id]; });

  state.downloads = jobs;
  const before = downloadingIds();
  reconcileFromJobs(jobs);
  if (downloadingIds() !== before) renderGames();
  else applyDownloadProgress();

  const busy = jobs.some((j) => j.state === "active" || j.state === "queued") ||
               state.titles.some((g) => g._localDownloading);
  if (!busy) { if (++emptyPolls >= 3) stopDownloadPolling(); }
  else emptyPolls = 0;
}

function downloadingIds() {
  return state.titles.filter((g) => g.downloading).map((g) => g.title_id).join(",");
}

// only while something is queued or active. done jobs linger a poll or two
// before the pool reaps them, that's where "5 of 9" comes from
function renderGlobalStatus() {
  const el = els.globalDl;
  if (!el) return;
  const jobs   = state.downloads || [];
  const batch  = jobs.filter((j) => ["queued", "active", "done"].includes(j.state));
  const flying = batch.filter((j) => j.state === "queued" || j.state === "active");

  if (flying.length === 0) { el.hidden = true; return; }
  el.hidden = false;

  const active = batch.find((j) => j.state === "active") || flying[0];
  const total  = batch.length;
  const done   = batch.filter((j) => j.state === "done").length;
  const pos    = Math.min(total, done + 1);
  const isActive = active && active.state === "active";

  els.globalDlState.textContent = !isActive ? t("dl.queued") : active.verifying ? t("dl.verifying") : t("dl.downloading");
  const activeGame = state.titles.find((g) => g.title_id === active.title_id);
  els.globalDlName.textContent  = active.name || (activeGame && activeGame.name) || active.title_id || "—";

  if (total > 1) {
    els.globalDlPosition.hidden = false;
    els.globalDlPosition.textContent = t("dl.position", { pos, total });
  } else {
    els.globalDlPosition.hidden = true;
  }

  const pct   = pctOf(active);
  const speed = Number(active._speed) || 0;
  const done_ = Number(active.bytes) || 0;
  const total_ = Number(active.total_bytes) || 0;
  els.globalDlPct.innerHTML   = isActive ? `<b>${pct}%</b>` : `<b>—</b> ${t("dl.waiting")}`;
  els.globalDlSpeed.innerHTML = isActive && speed > 0
    ? `<b>${formatBytes(speed)}/s</b>`
    : (isActive && !total_ ? t("dl.fetchingManifest") : "—");
  els.globalDlEta.innerHTML = isActive && speed > 0 && total_ > done_
    ? t("progress.eta", { eta: formatEta((total_ - done_) / speed) })
    : "";

  // no total yet: still fetching the manifest
  if (isActive && total_ > 0) {
    els.globalDlBar.classList.remove("is-indeterminate");
    els.globalDlBar.style.width = pct + "%";
  } else {
    els.globalDlBar.classList.add("is-indeterminate");
  }
}

function applyDownloadProgress() {
  renderGlobalStatus();
  let needRender = false;
  state.downloads.forEach((d) => {
    // paused/done/error jobs have no bar, don't let them force a rebuild
    const g = state.titles.find((t) => t.title_id === d.title_id);
    if (!g || !g.downloading) return;
    const card = els.gameGrid.querySelector(`[data-title-id="${d.title_id}"]`);
    const bar = card && card.querySelector(".card-progress .progress > i");
    const meta = card && card.querySelector(".card-progress .progress-meta");
    if (!bar || !meta) { needRender = true; return; }
    bar.style.width = pctOf(d) + "%";
    meta.innerHTML = progressMetaHtml(d);
  });
  if (needRender) renderGames();
}

/* settings */

const STORAGE_STATE = {
  complete: { className: "ok" },
  paused: { className: "warn" },
  downloading: { className: "live" },
  installing: { className: "live" },
  failed: { className: "blocked" },
};

/* download drive */

let drives = null;   // from /api/drives: [{path, free_mb, total_mb}]

function driveLabel(path) {
  return path === "/data" ? t("settings.driveInternal")
    : t("settings.driveNamed", { name: path.replace(/^\/mnt\//, "") });
}

function renderDrives() {
  const sel = els.downloadDrive;
  if (!sel) return;
  const current = state.config.download_drive || "/data";
  const list = drives || [{ path: current }];
  sel.replaceChildren(...list.map((d) => {
    const opt = document.createElement("option");
    opt.value = d.path;
    opt.textContent = d.free_mb != null
      ? `${driveLabel(d.path)} · ${t("rail.free", { space: formatMb(d.free_mb) })}`
      : driveLabel(d.path);
    opt.selected = d.path === current;
    return opt;
  }));
}

async function loadDrives() {
  const data = await fetchJson("/api/drives");
  if (data && Array.isArray(data.drives)) drives = data.drives;
  renderDrives();
}

// delete works even when the game is gone
async function loadStorage() {
  if (!els.storageList) return;
  let data;
  try {
    const response = await fetch(API.storage, { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    data = await response.json();
  } catch (error) {
    els.storageList.innerHTML = `<p class="storage-empty">${t("storage.readFailed")}</p>`;
    return;
  }
  const items = (data.items || []).sort((a, b) => b.bytes - a.bytes);
  els.storageTotal.textContent = items.length ? t("storage.total", { size: formatBytes(data.total_bytes) }) : "";
  if (!items.length) {
    els.storageList.innerHTML = `<p class="storage-empty">${t("storage.empty")}</p>`;
    return;
  }
  els.storageList.replaceChildren(...items.map((item) => {
    const stateKey = STORAGE_STATE[item.state] ? item.state : "complete";
    const info = STORAGE_STATE[stateKey];
    const busy = item.state === "installing" || item.state === "downloading";
    const row = document.createElement("div");
    row.className = "storage-row";
    row.innerHTML = `
      <span><strong>${escapeHtml(item.name || item.title_id)}</strong><br>
        <em>${escapeHtml(item.title_id)}${item.version ? ` · ${escapeHtml(item.version)}` : ""} · ${escapeHtml(storageRelation(item))}${item.drive && item.drive !== "/data" ? ` · ${escapeHtml(driveLabel(item.drive))}` : ""}</em></span>
      <span class="pill ${info.className}">${t(`storage.state.${stateKey}`)}</span>
      <b>${formatBytes(item.bytes)}</b>
    `;
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "row-button is-cancel";
    btn.textContent = t("btn.delete");
    btn.disabled = busy;
    btn.title = busy ? t("storage.busy") : t("storage.deleteTitle", { size: formatBytes(item.bytes), name: item.name || item.title_id });
    btn.addEventListener("click", () => deleteStorage(item));
    row.appendChild(btn);
    return row;
  }));
}

function storageRelation(item) {
  if (!item.installed) return t("storage.rel.notInstalled");
  if (!item.version || !item.installed_version) return t("storage.rel.versionUnknown");
  return item.version > item.installed_version ? t("storage.rel.newer") : t("storage.rel.installed");
}

async function deleteStorage(item) {
  const label = item.name || item.title_id;
  if (!window.confirm(t("storage.confirmDelete", { name: label, size: formatBytes(item.bytes) }))) return;
  try {
    await postJson(API.storageDelete(item.title_id), { drive: item.drive || "" });
    showToast(t("toast.storageDeleted", { name: label }));
  } catch (error) {
    showToast(t("toast.nameMessage", { name: label, message: reasonText(error) }));
  }
  await loadStorage();
  await loadInitialData({ quiet: true });
}

function renderSourcePolicies() {
  const rows = Object.keys(SOURCE_TYPES).map((type) => {
    const info = SOURCE_TYPES[type];
    const policy = sourcePolicyForType(type);
    const row = document.createElement("div");
    row.className = "policy-row";
    row.innerHTML = `
      <span class="pill ${info.className}">${escapeHtml(sourceLabel(type))}</span>
      <strong>${t(policy.allow_install ? "policy.installAllowed" : "policy.installBlocked")}</strong>
      <em>${t(policy.allow_download ? "policy.downloadAllowed" : "policy.downloadBlocked")} - ${escapeHtml(sourceDescription(type))}</em>
    `;
    return row;
  });
  els.sourcePolicyList.replaceChildren(...rows);
}

// key + vars: the Logs view gets translated, the report stays English
function addLog(key, vars) {
  state.logs.push({ time: timeNow(), key, vars });
}

function logLine(entry, tr) {
  return `[${entry.time}] ${tr(entry.key, entry.vars)}`;
}

function renderLogs() {
  els.logOutput.textContent = state.logs.length
    ? state.logs.map((e) => logLine(e, t)).join("\n") : t("logs.empty");
}

async function saveConfig() {
  const config = {
    ...state.config,
    default_policy: els.defaultPolicy.value,
    download_drive: els.downloadDrive.value || state.config.download_drive || "/data",
    install_after_download: els.installAfterDownload.checked,
    delete_pkg_after_install: els.deleteAfterInstall.checked,
    verify_downloads: els.verifyDownloads ? els.verifyDownloads.checked : Boolean(state.config.verify_downloads),
    home_shortcut: els.homeShortcut ? els.homeShortcut.checked : state.config.home_shortcut !== false,
    max_connections: clampConn(state.config.max_connections),
  };
  try {
    await postJson(API.config, config);
    state.config = config;
    showToast(t("toast.configSaved"));
  } catch (error) {
    state.config = config;
    showToast(t("toast.configLocal"));
  }
  renderSettings();
  renderGames(); // install_after_download changes the button label
}

/* actions */

// installable only: shadowmounts would pull tens of GB that AppInstUtil
// refuses anyway (no real source medium). double clicks are fine server side
async function updateAll() {
  const targets = state.titles.filter((g) =>
    g.status === "available" && isInstallAllowed(g) &&
    !g.downloading && !g.downloaded);
  if (!targets.length) {
    showToast(t("toast.noUpdates"));
    return;
  }
  showToast(t(targets.length === 1 ? "toast.queueingOne" : "toast.queueingMany", { count: targets.length }));
  for (const g of targets) {
    // one at a time keeps the queue order
    try { await doDownload(g); } catch (_) { /* doDownload toasts its own errors */ }
  }
}

// pool answers 202 right away, reconcileFromJobs does the rest on poll
async function doDownload(game) {
  game.downloading = true;
  game._localDownloading = true;   // until the pool has a job for it
  game._localSince = Date.now();   // times out in reconcileFromJobs
  game._autoInstalled = false;
  state.downloads = state.downloads.filter((i) => i.title_id !== game.title_id);
  state.downloads.push({ title_id: game.title_id, name: game.name,
                         version: game.compatible_version || "",
                         state: "queued", progress: 0, bytes: 0, total_bytes: 0 });
  renderGames();
  startDownloadPolling();

  try {
    const r = await postJson(API.action(game.title_id, "download"), {});
    if (r && r.downloaded && r.already) {
      game.downloading = false;
      game._localDownloading = false;
      game.downloaded = true;
      renderGames();
    } else {
      addLog("log.downloadQueued", { id: game.title_id, version: game.compatible_version || "" });
      renderLogs();
    }
  } catch (error) {
    game.downloading = false;
    game._localDownloading = false;
    state.downloads = state.downloads.filter((i) => i.title_id !== game.title_id);
    const why = reasonText(error);
    addLog("log.downloadBlocked", { id: game.title_id, why });
    showToast(t("toast.nameMessage", { name: game.name, message: why }));
    renderGames(); renderLogs();
  }
}

async function doInstall(game, force = false, replace = false) {
  const wasDownloaded = game.downloaded;
  game.installing = true;
  game.installStatus = "starting";
  game.installProgress = 0;
  game.downloaded = false;
  renderGames();
  // the game drops out of the list while it's replaced, keep its card from
  // the moment the request goes out
  if (replace) freshInstalling.set(game.title_id.slice(0, 9), game.name);
  try {
    const q = [force && "force=1", replace && "replace=1"].filter(Boolean).join("&");
    await postJson(API.action(game.title_id, "install") + (q ? `?${q}` : ""), {});
  } catch (error) {
    game.downloaded = wasDownloaded;   // refused, package untouched
    const b = (error && error.body) || {};
    if (replace) freshInstalling.delete(game.title_id.slice(0, 9));
    // a reload during the request may have put a fresh object on the card,
    // it copied installing over. nothing started, so clear it everywhere
    if (b.reason !== "install_running")
      state.titles.filter((g) => g.title_id === game.title_id && g !== game)
        .forEach((g) => { g.installing = false; g.installStatus = undefined; g.downloaded = wasDownloaded; });
    if (b.reason === "install_space" && !force) {
      // tight on the game's drive, the console would likely stop right after
      // the header. let the user decide
      game.installing = false;
      renderGames();
      if (window.confirm(t("install.lowSpace", {
            name: game.name, need: formatBytes(b.need_bytes), free: formatBytes(b.free_bytes) })))
        return doInstall(game, true, replace);
      addLog("log.installBlocked", { id: game.title_id, why: t("reason.install_space") });
      renderLogs();
      return false;
    }
    if (b.reason === "needs_reinstall" && !replace) {
      // the update doesn't build on the installed version (a disc build, say).
      // it only goes on as the whole game, one question and the rest is the same
      game.installing = false;
      renderGames();
      if (window.confirm(t("install.confirmReplace", { name: game.name })))
        return doInstall(game, force, true);
      return false;
    }
    if (error.body && error.body.reason === "install_running") {
      // another tab or device started it, just follow along
      startInstallPolling();
    } else {
      game.installing = false;
    }
    const why = reasonText(error);
    addLog("log.installBlocked", { id: game.title_id, why });
    showToast(t("toast.nameMessage", { name: game.name, message: why }));
    renderGames(); renderLogs();
    return false;
  }
  addLog("log.installStarted", { id: game.title_id, version: game.compatible_version });
  showToast(t("toast.installing", { name: game.name }));
  startInstallPolling();
  renderGames(); renderLogs();
  return true;
}

// aborts and deletes a running download, or deletes a finished pkg
async function cancelDownload(titleId) {
  const game = state.titles.find((g) => g.title_id === titleId);
  try {
    await postJson(API.action(titleId, "cancel"), {});
    showToast(t("toast.cancelled", { name: game ? game.name : titleId }));
  } catch (error) {
    showToast(t("toast.nameMessage", { name: game ? game.name : titleId, message: reasonText(error) }));
    return;   // refused, the console may be installing from it
  }
  if (game) {
    game.downloading = false;
    game._localDownloading = false;
    game.downloaded = false;
    game.resumable = false;
    game.partial_bytes = 0;
    game.manual_version = null;   // the server drops the pasted link on cancel
  }
  state.downloads = state.downloads.filter((i) => i.title_id !== titleId);
  addLog("log.cancelled", { id: titleId });
  renderGames(); renderLogs();
  refreshDownloads();
}

async function runTitleAction(titleId, action) {
  const game = state.titles.find((i) => i.title_id === titleId);
  if (!game) return;
  // update = download, the reconciler installs once it's done
  if (action === "download" || action === "update") await doDownload(game);
  else if (action === "install") await doInstall(game);
  else if (action === "pause") await doPause(game);
  else if (action === "cancel") await cancelDownload(titleId);
  else if (action === "guide") openGuide(game);
  else if (action === "saved") await savedDownload(game, game.prospero_version, game.prospero_size || "");
}

// only sends the signal, the next poll flips the card to paused
async function doPause(game) {
  try {
    await postJson(API.action(game.title_id, "pause"), {});
    showToast(t("toast.pausing", { name: game.name }));
  } catch (error) {
    showToast(t("toast.nameMessage", { name: game.name, message: reasonText(error) }));
  }
}

function updateGame(titleId, patch) {
  const game = state.titles.find((i) => i.title_id === titleId);
  if (!game) return;
  Object.assign(game, patch);
  renderGames();

  const wantEnabled = game.enabled !== false;
  postJson(API.action(titleId, wantEnabled ? "enable" : "disable"), {})
    .then(() => { addLog(wantEnabled ? "log.savedEnabled" : "log.savedDisabled", { id: titleId }); renderLogs(); })
    .catch(() => showToast(t("toast.toggleFailed", { id: titleId })));
}

/* policy */

function isInstallBlocked(game) { return !sourcePolicy(game).allow_install; }
function isDownloadAllowed(game) {
  return Boolean(
    game.enabled !== false &&
    (game.compatible_version || game.manual_version) &&
    game.patch_title_match !== false &&
    sourcePolicy(game).allow_download
  );
}
function isInstallAllowed(game) {
  return Boolean(
    game.enabled !== false &&
    (game.compatible_version || game.manual_version) &&
    game.patch_title_match !== false &&
    sourcePolicy(game).allow_install
  );
}
function sourcePolicy(game) { return sourcePolicyForType(sourceType(game)); }
function sourcePolicyForType(type) {
  const fb = fallback.config.source_policy[type] || fallback.config.source_policy.unknown;
  const cfg = (state.config.source_policy || {})[type] || {};
  return { ...fb, ...cfg };
}

async function postJson(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const err = new Error(data.reason || data.message || `HTTP ${response.status}`);
    err.body = data;
    err.status = response.status;
    throw err;
  }
  return data;
}

// server keeps 2 GB free on top of the package. install: the download fit,
// the install afterwards wouldn't
function noSpaceText(need, free, install) {
  return t(install ? "reason.noSpaceInstall" : "reason.noSpace",
    { need: formatBytes(need), free: formatBytes(free) });
}

function reasonText(error) {
  const r = error && error.body && error.body.reason;
  return (r && r !== "fallback" && r !== "noSpace" && tHas(`reason.${r}`) ? t(`reason.${r}`) : "") ||
    (error && error.message) || t("reason.fallback");
}

/* QR code: byte mode, ECC M, versions 1-6, ~100 bytes is plenty for a link.
   ISO/IEC 18004, structured after Project Nayuki's encoder. no npm here */

const QR_ECC_M = [0, 10, 16, 26, 18, 24, 16];      // ECC codewords per block
const QR_BLOCKS_M = [0, 1, 1, 1, 2, 2, 4];         // number of blocks

function qrRawModules(ver) {
  let n = (16 * ver + 128) * ver + 64;
  if (ver >= 2) {
    const align = Math.floor(ver / 7) + 2;
    n -= (25 * align - 10) * align - 55;
  }
  return n;
}

function qrDataCodewords(ver) {
  return Math.floor(qrRawModules(ver) / 8) - QR_ECC_M[ver] * QR_BLOCKS_M[ver];
}

function qrGfMul(x, y) {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z;
}

function qrRsDivisor(degree) {
  const r = new Array(degree - 1).fill(0);
  r.push(1);
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < r.length; j++) {
      r[j] = qrGfMul(r[j], root);
      if (j + 1 < r.length) r[j] ^= r[j + 1];
    }
    root = qrGfMul(root, 0x02);
  }
  return r;
}

function qrRsRemainder(data, divisor) {
  const r = divisor.map(() => 0);
  for (const b of data) {
    const factor = b ^ r.shift();
    r.push(0);
    divisor.forEach((coef, i) => { r[i] ^= qrGfMul(coef, factor); });
  }
  return r;
}

// square bool matrix, true = dark. null if the text doesn't fit
function qrEncode(text) {
  const bytes = Array.from(new TextEncoder().encode(text));
  let ver = 1;
  while (ver <= 6 && 4 + 8 + bytes.length * 8 > qrDataCodewords(ver) * 8) ver++;
  if (ver > 6) return null;

  // byte mode, 8-bit length, payload, terminator, padding
  const bits = [];
  const push = (val, len) => { for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1); };
  push(0x4, 4);
  push(bytes.length, 8);
  bytes.forEach((b) => push(b, 8));
  const cap = qrDataCodewords(ver) * 8;
  push(0, Math.min(4, cap - bits.length));
  push(0, (8 - (bits.length % 8)) % 8);
  for (let pad = 0xec; bits.length < cap; pad ^= 0xec ^ 0x11) push(pad, 8);
  const data = [];
  for (let i = 0; i < bits.length; i += 8) data.push(parseInt(bits.slice(i, i + 8).join(""), 2));

  // blocks, Reed-Solomon ECC, interleave
  const numBlocks = QR_BLOCKS_M[ver];
  const eccLen = QR_ECC_M[ver];
  const rawCodewords = Math.floor(qrRawModules(ver) / 8);
  const numShort = numBlocks - (rawCodewords % numBlocks);
  const shortLen = Math.floor(rawCodewords / numBlocks);
  const divisor = qrRsDivisor(eccLen);
  const blocks = [];
  for (let i = 0, k = 0; i < numBlocks; i++) {
    const dat = data.slice(k, k + shortLen - eccLen + (i < numShort ? 0 : 1));
    k += dat.length;
    const ecc = qrRsRemainder(dat, divisor);
    if (i < numShort) dat.push(0);
    blocks.push(dat.concat(ecc));
  }
  const codewords = [];
  for (let i = 0; i < blocks[0].length; i++)
    blocks.forEach((blk, j) => {
      if (i !== shortLen - eccLen || j >= numShort) codewords.push(blk[i]);
    });

  const size = ver * 4 + 17;
  const mod = Array.from({ length: size }, () => new Array(size).fill(false));
  const fn = Array.from({ length: size }, () => new Array(size).fill(false));
  const set = (x, y, dark) => { mod[y][x] = dark; fn[y][x] = true; };
  for (let i = 0; i < size; i++) { set(6, i, i % 2 === 0); set(i, 6, i % 2 === 0); }
  [[3, 3], [size - 4, 3], [3, size - 4]].forEach(([cx, cy]) => {
    for (let dy = -4; dy <= 4; dy++)
      for (let dx = -4; dx <= 4; dx++) {
        const x = cx + dx, y = cy + dy;
        if (x < 0 || x >= size || y < 0 || y >= size) continue;
        const d = Math.max(Math.abs(dx), Math.abs(dy));
        set(x, y, d !== 2 && d !== 4);
      }
  });
  if (ver >= 2) {
    const pos = [6, size - 7];   // versions 2-6 have one alignment pattern
    const c = pos[1];
    for (let dy = -2; dy <= 2; dy++)
      for (let dx = -2; dx <= 2; dx++)
        set(c + dx, c + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
  }
  const drawFormat = (mask) => {
    const data5 = (0 << 3) | mask;          // ECC level M = 0b00
    let rem = data5;
    for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    const f = ((data5 << 10) | rem) ^ 0x5412;
    const bit = (i) => ((f >>> i) & 1) === 1;
    for (let i = 0; i <= 5; i++) set(8, i, bit(i));
    set(8, 7, bit(6));
    set(8, 8, bit(7));
    set(7, 8, bit(8));
    for (let i = 9; i < 15; i++) set(14 - i, 8, bit(i));
    for (let i = 0; i < 8; i++) set(size - 1 - i, 8, bit(i));
    for (let i = 8; i < 15; i++) set(8, size - 15 + i, bit(i));
    set(8, size - 8, true);
  };
  drawFormat(0);   // reserve the format areas before placing data

  // data: zigzag in column pairs from the bottom right
  let i = 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vert = 0; vert < size; vert++)
      for (let j = 0; j < 2; j++) {
        const x = right - j;
        const upward = ((right + 1) & 2) === 0;
        const y = upward ? size - 1 - vert : vert;
        if (!fn[y][x] && i < codewords.length * 8) {
          mod[y][x] = ((codewords[i >>> 3] >>> (7 - (i & 7))) & 1) === 1;
          i++;
        }
      }
  }

  const maskFn = [
    (x, y) => (x + y) % 2 === 0,
    (x, y) => y % 2 === 0,
    (x) => x % 3 === 0,
    (x, y) => (x + y) % 3 === 0,
    (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0,
    (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
    (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0,
    (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
  ];
  const applyMask = (m) => {
    for (let y = 0; y < size; y++)
      for (let x = 0; x < size; x++)
        if (!fn[y][x] && maskFn[m](x, y)) mod[y][x] = !mod[y][x];
  };
  // simplified penalty (runs, 2x2, balance), good enough to pick a mask
  const penalty = () => {
    let p = 0, dark = 0;
    for (let a = 0; a < size; a++) {
      let runR = 1, runC = 1;
      for (let b = 0; b < size; b++) {
        if (mod[a][b]) dark++;
        if (b > 0) {
          runR = mod[a][b] === mod[a][b - 1] ? runR + 1 : 1;
          runC = mod[b][a] === mod[b - 1][a] ? runC + 1 : 1;
          if (runR === 5) p += 3; else if (runR > 5) p++;
          if (runC === 5) p += 3; else if (runC > 5) p++;
        }
        if (a > 0 && b > 0) {
          const c = mod[a][b];
          if (c === mod[a - 1][b] && c === mod[a][b - 1] && c === mod[a - 1][b - 1]) p += 3;
        }
      }
    }
    const total = size * size;
    p += Math.floor(Math.abs(dark * 20 - total * 10) / total) * 10;
    return p;
  };
  let best = 0, bestScore = Infinity;
  for (let m = 0; m < 8; m++) {
    applyMask(m);
    drawFormat(m);
    const score = penalty();
    if (score < bestScore) { best = m; bestScore = score; }
    applyMask(m);   // XOR again to undo
  }
  applyMask(best);
  drawFormat(best);
  return mod;
}

// dark on white with the 4-module quiet zone scanners want
function qrSvg(matrix) {
  const n = matrix.length, q = 4, s = n + q * 2;
  let d = "";
  matrix.forEach((row, y) => row.forEach((dark, x) => {
    if (dark) d += `M${x + q},${y + q}h1v1h-1z`;
  }));
  return `<svg xmlns="http://www.w3.org/2000/svg" class="qr" viewBox="0 0 ${s} ${s}" shape-rendering="crispEdges" role="img" aria-label="${escapeHtml(t("qr.aria"))}"><rect width="${s}" height="${s}" fill="#fff" stroke="none"/><path d="${d}" fill="#000" stroke="none"/></svg>`;
}

/* older patch guide */

// version.xml only lists the newest patch. prospero has older ones, behind a
// human check, so a human copies one link and PatchDL does the rest

const guide = { el: null, game: null, pick: null, fromLink: false, started: false, busy: false,
                lastUrl: "", timer: null, returnFocus: null, onKey: null };

function pickFor(game, version, size) {
  const ps4 = isPs4(game);
  const site = ps4 ? "Orbis Patches" : "Prospero Patches";
  const page = `https://${ps4 ? "orbispatches.com" : "prosperopatches.com"}/${encodeURIComponent(game.title_id.slice(0, 9))}`;
  if (version)
    return { version, size: size || "", fw: "", site, page, ps4, chosen: true };
  return { version: game.prospero_version, size: game.prospero_size || "",
           fw: game.prospero_required_fw || "", site, page, ps4, chosen: false };
}

function canPickVersion(game, version) {
  return !game.downloading && !game.downloaded && !game.resumable && !game.installing &&
    isDownloadAllowed({ ...game, manual_version: version });
}

function canGetOlderPatch(game) {
  return hasOlderPatch(game) &&
    !game.manual_version && !game.downloading && !game.downloaded &&
    !game.resumable && !game.installing &&
    isDownloadAllowed({ ...game, manual_version: game.prospero_version });
}

// on the PS5 the page runs on 127.0.0.1, phones need the LAN address
function phoneLink(game, pick) {
  const h = location.hostname;
  let base = location.origin;
  if (!h || h === "localhost" || h === "127.0.0.1" || h === "[::1]") {
    if (!state.status.lan_ip) return null;
    base = `http://${state.status.lan_ip}:${state.status.http_port || location.port || 12880}`;
  }
  const extra = pick && pick.chosen
    ? `/${encodeURIComponent(pick.version)}/${encodeURIComponent(pick.size)}` : "";
  return `${base}/#get/${encodeURIComponent(game.title_id)}${extra}`;
}

function openGuideFromHash() {
  const m = location.hash.match(/^#get\/([A-Za-z0-9_.-]+)(?:\/([0-9.]+)\/([A-Za-z0-9. %]*))?$/);
  if (!m) return;
  const game = state.titles.find((g) => g.title_id === m[1]);
  if (!game) { showToast(t("toast.notInstalled")); clearGuideHash(); return; }
  if (m[2]) {
    // a version picked under "Other versions" on the console
    let size = m[3] || "";
    try { size = decodeURIComponent(size); } catch (_) { /* keep it as it came */ }
    const pick = pickFor(game, m[2], size);
    if (!canPickVersion(game, pick.version)) {
      showToast(t("toast.alreadyOnWay", { name: game.name }));
      clearGuideHash();
      return;
    }
    openGuide(game, true, pick);
    return;
  }
  if (!canGetOlderPatch(game)) {
    showToast(game.manual_version || game.downloading || game.downloaded
      ? t("toast.olderOnWay", { name: game.name })
      : t("toast.noOlderPatch", { name: game.name }));
    clearGuideHash();
    return;
  }
  openGuide(game, true);
}

function clearGuideHash() {
  if (location.hash.startsWith("#get/"))
    history.replaceState(null, "", location.pathname + location.search);
}

// the home tile opens the page on 127.0.0.1
function isConsoleBrowser() {
  const h = location.hostname;
  return /PlayStation/i.test(navigator.userAgent) || h === "127.0.0.1" || h === "localhost";
}

function openGuide(game, fromLink = false, pick = null) {
  closeGuide();
  pick = pick || pickFor(game);
  Object.assign(guide, { game, pick, fromLink, started: false, busy: false, lastUrl: "",
                         returnFocus: document.activeElement });
  const ver = escapeHtml(pick.version);
  const size = pick.size ? ` (${escapeHtml(pick.size)})` : "";
  const site = escapeHtml(pick.site);
  const onConsole = !fromLink && isConsoleBrowser();
  const link = fromLink ? null : phoneLink(game, pick);
  const matrix = link ? qrEncode(link) : null;

  const head = `
      <header class="guide-head">
        <div>
          <p class="eyebrow">${t(pick.chosen ? "guide.eyebrowOther" : "guide.eyebrowOld")}</p>
          <h2 id="guideTitle">${t("guide.title", { version: ver })}</h2>
          <p class="guide-game">${escapeHtml(game.name)}</p>
        </div>
        ${closeButtonHtml()}
      </header>`;

  let body;
  if (onConsole) {
    body = matrix
      ? `<div class="guide-handoff">${qrSvg(matrix)}
           <p>${t("guide.scanConsole")}</p>
           <code>${escapeHtml(link)}</code>
         </div>`
      : `<p class="guide-why">${t("guide.openOnPhone", { port: escapeHtml(String(state.status.http_port || 12880)) })}</p>`;
    body += `<div class="guide-status" role="status" aria-live="polite"></div>`;
  } else {
    const handoff = matrix
      ? `<div class="guide-qr">${qrSvg(matrix)}<div>
           <strong>${t("guide.easier")}</strong>
           <span>${t("guide.easierText")}</span>
           <code>${escapeHtml(link)}</code>
         </div></div>`
      : "";
    const why = pick.chosen
      ? t("guide.whyChosen", { site, version: ver, size })
      : t("guide.whyOld", {
          latest: escapeHtml(game.latest_version || t("guide.newestPatch")),
          fw: escapeHtml(game.latest_required_fw || "?"),
          version: ver,
          pickFw: escapeHtml(pick.fw || "?"),
        });
    const copyStep = pick.ps4
      ? `<strong>${t("guide.copyLinks")}</strong>
            <span>${t("guide.copyLinksText")}</span>`
      : `<strong>${t("guide.copySc")}</strong>
            <span>${t("guide.copyScText")}</span>`;
    body = `
      <p class="guide-why">${why}</p>
      ${handoff}
      <ol class="guide-steps">
        <li>
          <div class="guide-step-text"><strong>${t("guide.openSite", { site })}</strong>
            <span>${t("guide.tapVersion", { version: ver, size })}</span></div>
          <a class="row-button is-update guide-open" href="${escapeHtml(pick.page)}" target="_blank" rel="noopener">${t("guide.openSite", { site: pick.ps4 ? "Orbis" : "Prospero" })}</a>
        </li>
        <li>
          <div class="guide-step-text">${copyStep}</div>
        </li>
        <li>
          <div class="guide-step-text"><strong>${t("guide.paste")}</strong>
            <span>${t("guide.pasteText")}</span></div>
          <div class="guide-paste">
            <input class="guide-input" type="url" inputmode="url" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="${pick.ps4 ? "http://…_0.pkg" : "https://…_sc.pkg"}" aria-label="${escapeHtml(t("guide.linkAria"))}">
            <button class="row-button guide-start" type="button">${t("guide.start")}</button>
          </div>
          <div class="guide-status" role="status" aria-live="polite"></div>
        </li>
      </ol>`;
  }

  const wrap = document.createElement("div");
  wrap.className = "guide-backdrop";
  wrap.innerHTML = `<section class="guide${onConsole ? " is-handoff" : ""}" role="dialog" aria-modal="true" aria-labelledby="guideTitle">${head}${body}</section>`;
  document.body.appendChild(wrap);
  guide.el = wrap;

  const input = wrap.querySelector(".guide-input");
  if (input) {
    const tryInput = () => {
      const url = extractLink(input.value);
      if (url && url !== guide.lastUrl && /\.(pkg|crc|json)$/i.test(url)) guideSubmit(url, false);
    };
    input.addEventListener("focus", () => input.select());   // a paste then replaces the old link
    input.addEventListener("input", tryInput);
    input.addEventListener("paste", () => setTimeout(tryInput, 0));
    wrap.querySelector(".guide-start").addEventListener("click",
      () => guideSubmit(extractLink(input.value), false));
  }
  wrap.querySelector(".guide-close").addEventListener("click", closeGuide);
  wrap.addEventListener("click", (e) => { if (e.target === wrap) closeGuide(); });
  guide.onKey = (e) => { if (e.key === "Escape") closeGuide(); };
  document.addEventListener("keydown", guide.onKey);

  guideStatus("idle", matrix ? t("guide.waitingPhone") : "");
  guide.timer = setInterval(guidePoll, 2000);
  (fromLink ? wrap.querySelector(".guide-open") : wrap.querySelector(".guide-close")).focus();
}

function closeGuide() {
  if (!guide.el) return;
  clearInterval(guide.timer);
  document.removeEventListener("keydown", guide.onKey);
  guide.el.remove();
  guide.el = null;
  guide.game = null;
  clearGuideHash();
  if (guide.returnFocus && document.contains(guide.returnFocus)) guide.returnFocus.focus();
}

// last link wins, so pasting next to a rejected one still works
function extractLink(text) {
  const all = String(text || "").match(/https?:\/\/(?:(?!https?:\/\/)[^\s"'<>])+/g) || [];
  const pkgs = all.filter((u) => /\.(pkg|crc|json)$/i.test(u));
  return (pkgs.length ? pkgs[pkgs.length - 1] : all[all.length - 1]) || "";
}

function guideStatus(kind, message, action) {
  if (!guide.el) return;
  const box = guide.el.querySelector(".guide-status");
  box.innerHTML = message ? `<p class="guide-msg is-${kind}">${message}</p>` : "";
  if (action) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "row-button is-ghost guide-action";
    b.textContent = action.label;
    b.addEventListener("click", action.run);
    box.appendChild(b);
  }
}

async function guideSubmit(url, force) {
  const game = guide.game;
  if (!game || guide.busy) return;
  const pick = guide.pick;
  if (!url) { guideStatus("error", t(pick.ps4 ? "guide.pasteOrbis" : "guide.pasteSc")); return; }
  guide.busy = true;
  guide.lastUrl = url;
  const start = guide.el.querySelector(".guide-start");
  start.disabled = true;
  guideStatus("busy", t("guide.checkingLink"));
  try {
    await postJson("/api/download_url", {
      title_id: game.title_id, url, version: pick.version, size: pick.size, force,
    });
  } catch (error) {
    guide.busy = false;
    if (!guide.el) return;
    start.disabled = false;
    const b = (error && error.body) || {};
    if (b.reason === "no_space") {
      guideStatus("error", escapeHtml(noSpaceText(b.need_bytes, b.free_bytes)));
    } else if (b.reason === "size_mismatch") {
      guideStatus("warn",
        t("guide.sizeMismatch", {
          found: formatBytes(b.found_bytes),
          pieces: Number(b.pieces) || "?",
          version: escapeHtml(pick.version),
          expected: escapeHtml(b.expected || "?"),
        }),
        { label: t("guide.downloadAnyway"), run: () => guideSubmit(url, true) });
    } else if (pick.ps4 && (b.reason === "not_an_sc_link" || b.reason === "url_not_allowed")) {
      // Orbis offers piece links, not Prospero's SC link
      guideStatus("error", escapeHtml(t("reason.notOrbisLink")));
    } else {
      guideStatus("error", escapeHtml(reasonText(error)) + (b.detail ? ` (${escapeHtml(b.detail)})` : ""));
    }
    addLog("log.linkRefused", { site: pick.site, id: game.title_id, why: reasonText(error) });
    renderLogs();
    return;
  }
  guide.busy = false;
  rememberLink(game, pick.version);
  manualDownloadStarted(game, pick.version);
  if (!guide.fromLink) {
    showToast(t("toast.downloadStarted", { name: game.name, version: pick.version }));
    closeGuide();
    return;
  }
  guide.started = true;
  guideStatus("ok", t("guide.started"));
}

// the server checks a saved link like a pasted one. a dead link gets dropped
// and it's back to the browser
async function savedDownload(game, version, size, force = false) {
  if (!canPickVersion(game, version)) return;
  try {
    await postJson("/api/download_url", { title_id: game.title_id, version, size, saved: true, force });
  } catch (error) {
    const b = (error && error.body) || {};
    const pick = pickFor(game, version, size);
    if (b.reason === "no_space") {
      showToast(noSpaceText(b.need_bytes, b.free_bytes));
      return;
    }
    if (b.reason === "saved_link_gone") {
      game.saved_versions = (game.saved_versions || []).filter((v) => v !== version);
      showToast(t("toast.savedLinkGone", { site: pick.site }));
      renderGames();
      openGuide(game, false, pick);
    } else if (b.reason === "size_mismatch" && !force) {
      // same question as when the link was pasted, it was probably answered
      // with "download anyway" back then
      if (window.confirm(t("guide.sizeMismatch", {
            found: formatBytes(b.found_bytes), pieces: Number(b.pieces) || "?",
            version, expected: b.expected || "?" }) + "\n\n" + t("guide.downloadAnyway") + "?"))
        return savedDownload(game, version, size, true);
    } else {
      showToast(t("toast.nameMessage", { name: game.name, message: reasonText(error) }));
    }
    return;
  }
  manualDownloadStarted(game, version);
  showToast(t("toast.downloadStarted", { name: game.name, version }));
}

function manualDownloadStarted(game, version) {
  game.manual_version = version;
  game.downloading = true;
  game._localDownloading = true;
  game._localSince = Date.now();
  game._autoInstalled = false;
  state.downloads = state.downloads.filter((i) => i.title_id !== game.title_id);
  state.downloads.push({ title_id: game.title_id, name: game.name, version: game.manual_version,
                         state: "queued", progress: 0, bytes: 0, total_bytes: 0 });
  addLog("log.downloadQueuedFrom", { site: isPs4(game) ? "Orbis" : "Prospero", id: game.title_id, version: game.manual_version });
  renderGames(); renderLogs();
  startDownloadPolling();
}

async function guidePoll() {
  const game = guide.game;
  if (!game) return;
  let jobs;
  try {
    const r = await fetch(API.downloads, { cache: "no-store" });
    if (!r.ok) return;
    jobs = await r.json();
  } catch (error) {
    return;
  }
  if (guide.game !== game) return;
  const j = (jobs || []).find((x) => x.title_id === game.title_id);
  if (!j) return;
  if (!guide.started) {
    // only a running job means a link came in from elsewhere, not an old one
    if (j.state !== "queued" && j.state !== "active") return;
    manualDownloadStarted(game, guide.pick.version);
    if (!guide.fromLink) {
      showToast(t("toast.linkReceived", { name: game.name, version: guide.pick.version }));
      closeGuide();
      return;
    }
    guide.started = true;
  }
  const total = Number(j.total_bytes) || 0;
  const pct = total ? Math.min(100, Math.round((Number(j.bytes) || 0) * 100 / total)) : 0;
  const note = {
    queued: () => t("guide.note.queued"),
    active: () => t("guide.note.active"),
    paused: () => t("guide.note.paused"),
    done: () => t(state.config.install_after_download ? "guide.note.doneInstall" : "guide.note.doneManual"),
    error: () => t("guide.note.error"),
  }[j.state];
  const noteText = note ? note() : "";
  guideStatus(j.state === "error" ? "error" : "ok",
    `${noteText}<span class="guide-progress"><span class="progress"><i style="width:${pct}%"></i></span>` +
    `<span>${total ? `${formatBytes(j.bytes)} / ${formatBytes(total)} · ` : ""}${pct}%</span></span>`);
}

/* formatting */

function initials(name) {
  return (name || "PD").split(/\s+/).filter(Boolean).slice(0, 2).map((p) => p[0]).join("").toUpperCase();
}

function formatBytes(bytes) {
  const n = Number(bytes);
  if (!Number.isFinite(n) || n < 0) return "--";
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB", "PB"];
  let v = n / 1024, i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
}

function formatMb(mb) {
  const n = Number(mb);
  if (!Number.isFinite(n)) return "--";
  return formatBytes(n * 1024 * 1024);
}

function formatEta(seconds) {
  const s = Math.round(Number(seconds) || 0);
  if (!Number.isFinite(s) || s <= 0) return "--";
  if (s < 60) return t("fmt.etaSec", { s });
  const m = Math.floor(s / 60);
  if (m < 60) return t("fmt.etaMin", { m, s: s % 60 });
  const h = Math.floor(m / 60);
  return t("fmt.etaHour", { h, m: m % 60 });
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function clone(value) { return JSON.parse(JSON.stringify(value)); }
function timeNow() { return new Date().toLocaleTimeString("en-US", { hour12: false }); }

let toastTimer;
function showToast(message) {
  els.toast.textContent = message;
  els.toast.classList.add("is-visible");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => els.toast.classList.remove("is-visible"), 2600);
}
