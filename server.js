/**
 * Check Point Management API — Mock Server v2 (untuk testing block/unblock IOC via SOAR n8n)
 *
 * BUKAN produk resmi Check Point. Skema & perilaku disusun manual berdasarkan:
 *  - Management API Reference resmi: https://sc1.checkpoint.com/documents/latest/APIs/
 *  - sk120633 (Domain Objects R80.10+)
 *  - Konfirmasi pola JSON add/remove untuk set-group & set-access-rule dari thread resmi
 *    CheckMates (community.checkpoint.com), yang menunjukkan body request/response asli.
 *
 * PENTING — batas kejujuran mock ini:
 *  Ini TIDAK dijamin "sama persis" dengan Management Server asli. Tidak ada cara untuk
 *  memverifikasi itu tanpa akses ke server asli untuk diff langsung. Yang direplikasi di
 *  sini adalah KONTRAK API (nama field, method, alur wajib, semantik add/remove, pola
 *  async task) berdasarkan dokumentasi & contoh nyata — bukan seluruh perilaku internal
 *  (licensing, locking sesi multi-admin, DNS resolution asli untuk domain object, dst).
 *
 * Use case yang didukung (block & unblock IOC tipe IP dan Domain):
 *  BLOCK IP     : login -> add-host -> set-access-rule (source.add ke rule IP) -> publish -> install-policy -> poll show-task
 *  UNBLOCK IP   : login -> set-access-rule (source.remove) -> [opsional delete-host] -> publish -> install-policy -> poll show-task
 *  BLOCK DOMAIN : login -> add-dns-domain -> set-group (members.add ke group domain) -> publish -> install-policy -> poll show-task
 *  UNBLOCK DOMAIN: login -> set-group (members.remove) -> [opsional delete-dns-domain] -> publish -> install-policy -> poll show-task
 *
 * Catatan penting: pola "domain lewat group, IP langsung ke rule" BUKAN keharusan teknis
 * Check Point (Domain object bisa langsung dipakai di source/destination rule, sama seperti
 * host) — ini kemungkinan besar keputusan arsitektur dari sistem legacy kalian. Mock ini
 * MENDUKUNG KEDUANYA (host langsung ke rule, ATAU host/domain lewat group) supaya kamu bisa
 * uji pola yang benar-benar dipakai legacy-mu, bukan asumsi saya.
 */

const express = require("express");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");
const YAML = require("js-yaml");
const swaggerUi = require("swagger-ui-express");

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 4010;
const API_VERSION = "v1.9"; // dilaporkan di response login/session, bukan wajib di path

// Router berisi semua command Check Point. Di-mount di DUA path sekaligus supaya
// mock ini menerima kedua gaya pemanggilan nyata:
//   - /web_api/login              (tanpa version — pola paling umum di dokumentasi resmi)
//   - /web_api/v1.9/login         (dengan version eksplisit — juga valid, version diabaikan)
const router = express.Router();

// ---------- In-memory state ----------
const sessions = new Map(); // sid -> { uid }
const apiKeys = new Map([["test-api-key-12345", { uid: crypto.randomUUID() }]]); // pre-seeded

const hosts = new Map(); // name -> { uid, name, ip-address, type }
const dnsDomains = new Map(); // name -> { uid, name, type: 'dns-domain' }
const groups = new Map(); // name -> { uid, name, members: [names], type: 'group' }
const accessRules = new Map(); // name -> { uid, name, layer, source:[names], destination:[names], service:[names], action, enabled }
const tasks = new Map();
let pendingChanges = 0;

// Pre-seed objek yang lazim sudah ada di setup produksi nyata (rule/group statis,
// bukan dibuat ulang tiap kali block) — supaya kamu bisa langsung tes pola
// "domain lewat group + IP langsung ke rule" seperti legacy-mu:
groups.set("Blocked_Domains_Group", {
  uid: crypto.randomUUID(),
  name: "Blocked_Domains_Group",
  members: [],
  type: "group",
});
accessRules.set("Blocked_IPs_Rule", {
  uid: crypto.randomUUID(),
  name: "Blocked_IPs_Rule",
  layer: "Network",
  source: [],
  destination: ["Any"],
  service: ["Any"],
  action: "Drop",
  enabled: true,
});
accessRules.set("Blocked_Domains_Rule", {
  uid: crypto.randomUUID(),
  name: "Blocked_Domains_Rule",
  layer: "Network",
  source: ["Any"],
  destination: ["Blocked_Domains_Group"],
  service: ["Any"],
  action: "Drop",
  enabled: true,
});

const uid = () => crypto.randomUUID();
const now = () => ({ posix: Date.now(), "iso-8601": new Date().toISOString() });

// ================= KATALOG ERROR =================
// Setiap entri ditandai VERIFIED (ada laporan request/response nyata dari pengguna
// Check Point yang saya kutip) atau INFERRED (mengikuti pola penamaan generic_err_*
// yang konsisten, TAPI belum ada contoh nyata persis yang saya temukan). Ini supaya
// kamu tahu persis mana yang bisa diandalkan sebagai kontrak API, dan mana yang masih
// asumsi saya — jangan diperlakukan sama.
//
// Sumber VERIFIED:
//  - object_not_found: CheckMates "WebAPI Issue with show-host" (2019) +
//    "API WebServices show-access-layer returning 404" (2020) — HTTP 404 eksplisit disebut.
//  - login_failed: CheckMates "Enabling web api" — output mgmt_cli asli.
//  - invalid_syntax: CheckMates "Web API problem" thread — HTTP 400 eksplisit disebut 2x.
//  - invalid_parameter_name: CheckMates "Web API problem" thread.
//  - object_locked: CheckMates "Locked session on web api call" — response JSON asli.
//  - wrong_session_id (pesan saja): CheckMates "API returning Wrong session ID".
//  - too_many_requests (pesan saja): CheckMates "Heads-up: Management API Remote calls
//    frequency limit".
const ERRORS = {
  OBJECT_NOT_FOUND: (name) => ({
    status: 404, // VERIFIED
    code: "generic_err_object_not_found", // VERIFIED
    message: `Requested object [${name}] not found`, // VERIFIED (format asli)
  }),
  LOGIN_FAILED: () => ({
    status: 400, // INFERRED — HTTP status tidak eksplisit di sumber (itu output mgmt_cli,
    // bukan HTTP response mentah). 400 dipilih karena konsisten dengan pola error
    // fungsional Check Point lainnya yang terkonfirmasi.
    code: "err_login_failed", // VERIFIED
    message: "Authentication to server failed.", // VERIFIED
  }),
  INVALID_SYNTAX: (detail) => ({
    status: 400, // VERIFIED
    code: "generic_err_invalid_syntax", // VERIFIED
    message: detail || "Payload is not valid", // VERIFIED
  }),
  INVALID_PARAMETER_NAME: (param) => ({
    status: 400, // INFERRED (konsisten dgn invalid_syntax yg terkonfirmasi 400, tapi
    // HTTP status utk kasus spesifik ini sendiri tidak eksplisit di sumber)
    code: "generic_err_invalid_parameter_name", // VERIFIED
    message: `Unrecognized parameter [${param}]`, // VERIFIED (format asli)
  }),
  OBJECT_LOCKED: (name) => ({
    status: 400, // INFERRED — sumber tidak menyebutkan HTTP status eksplisit
    code: "generic_error", // VERIFIED
    message: `Action cannot be executed on object: ${name} due to: Object '${name}' is locked by another session.`, // VERIFIED
  }),
  WRONG_SESSION_ID: (sid) => ({
    status: 401, // INFERRED
    code: "generic_err_invalid_session_id", // INFERRED — nama code tidak ketemu di sumber manapun
    message: `Wrong session id [${sid}]. Session may be expired. Please check session id and resend the request.`, // VERIFIED
  }),
  LOGIN_REQUIRED: () => ({
    status: 401, // INFERRED
    code: "generic_err_login_required", // INFERRED — tidak ada contoh nyata utk kasus
    // "header X-chkp-sid tidak dikirim sama sekali" (beda dari sid salah/expired di atas)
    message: "This API call requires a valid session id (X-chkp-sid header).",
  }),
  TOO_MANY_REQUESTS: () => ({
    status: 429, // INFERRED — sumber cuma sebut pesannya, bukan HTTP status
    code: "generic_err_too_many_requests", // INFERRED
    message: "Too many requests in a given amount of time", // VERIFIED
  }),
  MISSING_PARAM: (detail) => ({
    status: 400, // INFERRED
    code: "generic_err_missing_param", // INFERRED — TIDAK ketemu contoh nyata, sekadar
    // tebakan pola. Kalau kamu punya contoh nyata dari legacy/testing, tolong koreksi.
    message: detail,
  }),
  OBJECT_EXISTS: (name) => ({
    status: 400, // INFERRED
    code: "generic_err_object_already_exists", // INFERRED — TIDAK ketemu contoh nyata.
    message: `Object with name '${name}' already exists.`,
  }),
  COMMAND_NOT_FOUND: (command) => ({
    status: 404,
    code: "generic_err_command_not_found", // MOCK-ONLY — ini bukan dari Check Point,
    // ini fallback saya sendiri untuk command yang belum diimplementasi di mock ini.
    message: `Command '${command}' is not implemented in this mock.`,
  }),
};

function sendError(res, errObj) {
  return res.status(errObj.status).json({ code: errObj.code, message: errObj.message });
}

// ---------- Simulasi "object locked by another session" ----------
// Trigger deterministik: kirim "simulate": "locked" di body request manapun yang
// mengubah state (add-*/set-*/delete-*). Berguna untuk testing branch error-handling
// n8n tanpa perlu benar-benar membuka 2 sesi/SmartConsole bersamaan.
function checkSimulatedLock(req, res, objectName) {
  if (req.body && req.body.simulate === "locked") {
    sendError(res, ERRORS.OBJECT_LOCKED(objectName || req.body.name || "unknown"));
    return true;
  }
  return false;
}

// ---------- Simulasi rate-limit login (login berulang dalam waktu singkat) ----------
// Check Point secara resmi menyarankan login SEKALI lalu reuse sid, bukan login di
// setiap call. Ini mensimulasikan konsekuensi kalau workflow n8n tidak mengikuti
// praktik itu (misal: login dipanggil ulang di setiap iterasi loop block/unblock).
const loginTimestamps = [];
const LOGIN_RATE_LIMIT = 3; // maks N login
const LOGIN_RATE_WINDOW_MS = 5000; // dalam window T ms
function checkLoginRateLimit() {
  const nowMs = Date.now();
  while (loginTimestamps.length && nowMs - loginTimestamps[0] > LOGIN_RATE_WINDOW_MS) {
    loginTimestamps.shift();
  }
  loginTimestamps.push(nowMs);
  return loginTimestamps.length > LOGIN_RATE_LIMIT;
}

// ---------- Auth middleware ----------
function requireSession(req, res, next) {
  const sid = req.header("X-chkp-sid");
  if (!sid) {
    return sendError(res, ERRORS.LOGIN_REQUIRED());
  }
  if (!sessions.has(sid)) {
    return sendError(res, ERRORS.WRONG_SESSION_ID(sid));
  }
  req.session = sessions.get(sid);
  req.sid = sid;
  next();
}

// ---------- Helper: resolve list field dengan semantik replace / add / remove ----------
function resolveListField(current, payload) {
  if (payload === undefined) return current;
  if (Array.isArray(payload)) return [...payload];
  const result = new Set(current);
  if (payload.add) payload.add.forEach((m) => result.add(m));
  if (payload.remove) payload.remove.forEach((m) => result.delete(m));
  return [...result];
}

// ================= AUTH =================

router.post("/login", (req, res) => {
  if (checkLoginRateLimit()) {
    return sendError(res, ERRORS.TOO_MANY_REQUESTS());
  }

  const { user, password, "api-key": apiKey } = req.body || {};
  let sessionUid = null;

  if (apiKey) {
    const entry = apiKeys.get(apiKey);
    if (!entry) return sendError(res, ERRORS.LOGIN_FAILED());
    sessionUid = entry.uid;
  } else {
    if (user !== "admin" || password !== "admin123") {
      return sendError(res, ERRORS.LOGIN_FAILED());
    }
    sessionUid = uid();
  }

  const sid = uid();
  sessions.set(sid, { uid: sessionUid });
  res.json({
    uid: sessionUid,
    sid,
    url: `https://localhost:${PORT}${req.baseUrl}`,
    "session-timeout": 600,
    "last-login-was-at": now(),
    "api-server-version": API_VERSION,
  });
});

router.post("/logout", requireSession, (req, res) => {
  sessions.delete(req.sid);
  res.json({ message: "OK" });
});

router.post("/show-session", requireSession, (req, res) => {
  res.json({ uid: req.session.uid, "session-timeout": 600, changes: pendingChanges });
});

// ================= HOST OBJECTS (IOC tipe IP) =================

router.post("/add-host", requireSession, (req, res) => {
  const { name, "ip-address": ip, comments } = req.body || {};
  if (!name || !ip) {
    return sendError(res, ERRORS.MISSING_PARAM("'name' and 'ip-address' are required."));
  }
  if (hosts.has(name)) {
    return sendError(res, ERRORS.OBJECT_EXISTS(name));
  }
  const obj = { uid: uid(), name, "ip-address": ip, type: "host", comments: comments || "" };
  hosts.set(name, obj);
  pendingChanges++;
  res.json(obj);
});

router.post("/show-host", requireSession, (req, res) => {
  const obj = hosts.get(req.body?.name);
  if (!obj) return sendError(res, ERRORS.OBJECT_NOT_FOUND(req.body?.name));
  res.json(obj);
});

router.post("/set-host", requireSession, (req, res) => {
  const obj = hosts.get(req.body?.name);
  if (!obj) return sendError(res, ERRORS.OBJECT_NOT_FOUND(req.body?.name));
  if (req.body["ip-address"]) obj["ip-address"] = req.body["ip-address"];
  pendingChanges++;
  res.json(obj);
});

router.post("/delete-host", requireSession, (req, res) => {
  const { name } = req.body || {};
  if (!hosts.has(name)) return sendError(res, ERRORS.OBJECT_NOT_FOUND(name));
  hosts.delete(name);
  pendingChanges++;
  res.json({ message: "OK" });
});

// ================= DNS DOMAIN OBJECTS (IOC tipe Domain) =================

router.post("/add-dns-domain", requireSession, (req, res) => {
  const { name, comments } = req.body || {};
  if (!name) return sendError(res, ERRORS.MISSING_PARAM("'name' is required."));
  if (dnsDomains.has(name)) {
    return sendError(res, ERRORS.OBJECT_EXISTS(name));
  }
  const obj = { uid: uid(), name, type: "dns-domain", comments: comments || "" };
  dnsDomains.set(name, obj);
  pendingChanges++;
  res.json(obj);
});

router.post("/show-dns-domain", requireSession, (req, res) => {
  const obj = dnsDomains.get(req.body?.name);
  if (!obj) return sendError(res, ERRORS.OBJECT_NOT_FOUND(req.body?.name));
  res.json(obj);
});

router.post("/delete-dns-domain", requireSession, (req, res) => {
  const { name } = req.body || {};
  if (!dnsDomains.has(name)) {
    return sendError(res, ERRORS.OBJECT_NOT_FOUND(name));
  }
  dnsDomains.delete(name);
  pendingChanges++;
  res.json({ message: "OK" });
});

// ================= GROUP OBJECTS =================

router.post("/add-group", requireSession, (req, res) => {
  const { name, comments } = req.body || {};
  if (!name) return sendError(res, ERRORS.MISSING_PARAM("'name' is required."));
  if (groups.has(name)) {
    return sendError(res, ERRORS.OBJECT_EXISTS(name));
  }
  const obj = { uid: uid(), name, members: [], type: "group", comments: comments || "" };
  groups.set(name, obj);
  pendingChanges++;
  res.json(obj);
});

router.post("/show-group", requireSession, (req, res) => {
  const obj = groups.get(req.body?.name);
  if (!obj) return sendError(res, ERRORS.OBJECT_NOT_FOUND(req.body?.name));
  res.json(obj);
});

router.post("/set-group", requireSession, (req, res) => {
  const obj = groups.get(req.body?.name);
  if (!obj) return sendError(res, ERRORS.OBJECT_NOT_FOUND(req.body?.name));
  if (checkSimulatedLock(req, res, req.body.name)) return;
  obj.members = resolveListField(obj.members, req.body.members);
  pendingChanges++;
  res.json(obj);
});

router.post("/delete-group", requireSession, (req, res) => {
  const { name } = req.body || {};
  if (!groups.has(name)) return sendError(res, ERRORS.OBJECT_NOT_FOUND(name));
  groups.delete(name);
  pendingChanges++;
  res.json({ message: "OK" });
});

// ================= ACCESS RULES =================

router.post("/add-access-rule", requireSession, (req, res) => {
  const { name, layer, position, source, destination, service, action } = req.body || {};
  if (!name || !layer) {
    return sendError(res, ERRORS.MISSING_PARAM("'name' and 'layer' are required."));
  }
  const rule = {
    uid: uid(),
    name,
    layer,
    position: position || "top",
    source: Array.isArray(source) ? source : source ? [source] : ["Any"],
    destination: Array.isArray(destination) ? destination : destination ? [destination] : ["Any"],
    service: Array.isArray(service) ? service : service ? [service] : ["Any"],
    action: action || "Drop",
    enabled: true,
  };
  accessRules.set(name, rule);
  pendingChanges++;
  res.json(rule);
});

router.post("/show-access-rule", requireSession, (req, res) => {
  const rule = accessRules.get(req.body?.name);
  if (!rule) return sendError(res, ERRORS.OBJECT_NOT_FOUND(req.body?.name));
  res.json(rule);
});

router.post("/set-access-rule", requireSession, (req, res) => {
  const rule = accessRules.get(req.body?.name);
  if (!rule) return sendError(res, ERRORS.OBJECT_NOT_FOUND(req.body?.name));
  if (checkSimulatedLock(req, res, req.body.name)) return;

  if (req.body.source !== undefined) rule.source = resolveListField(rule.source, req.body.source);
  if (req.body.destination !== undefined)
    rule.destination = resolveListField(rule.destination, req.body.destination);
  if (req.body.service !== undefined) rule.service = resolveListField(rule.service, req.body.service);
  if (req.body.action !== undefined) rule.action = req.body.action;
  if (req.body.enabled !== undefined) rule.enabled = req.body.enabled;

  pendingChanges++;
  res.json(rule);
});

router.post("/delete-access-rule", requireSession, (req, res) => {
  const { name } = req.body || {};
  if (!accessRules.has(name)) {
    return sendError(res, ERRORS.OBJECT_NOT_FOUND(name));
  }
  accessRules.delete(name);
  pendingChanges++;
  res.json({ message: "OK" });
});

// ================= PUBLISH & INSTALL-POLICY (async) =================

router.post("/publish", requireSession, (req, res) => {
  const taskId = uid();
  pendingChanges = 0;
  tasks.set(taskId, { status: "succeeded", pollCount: 0, kind: "publish" });
  res.json({ "task-id": taskId });
});

router.post("/install-policy", requireSession, (req, res) => {
  const { "policy-package": pkg, "target-name": target } = req.body || {};
  if (!pkg || !target) {
    return sendError(res, ERRORS.MISSING_PARAM("'policy-package' and 'target-name' are required."));
  }
  const taskId = uid();
  tasks.set(taskId, { status: "in progress", pollCount: 0, kind: "install-policy" });
  res.json({ "task-id": taskId });
});

router.post("/show-task", requireSession, (req, res) => {
  const { "task-id": taskId } = req.body || {};
  const task = tasks.get(taskId);
  if (!task) return sendError(res, ERRORS.OBJECT_NOT_FOUND(taskId));

  if (task.kind === "install-policy" && task.status === "in progress") {
    task.pollCount++;
    if (task.pollCount >= 2) task.status = "succeeded";
  }

  res.json({
    tasks: [
      {
        "task-id": taskId,
        status: task.status,
        "task-name": task.kind,
        "progress-percentage": task.status === "succeeded" ? 100 : 50,
      },
    ],
  });
});

// ================= Reset state (khusus mock, BUKAN command resmi Check Point) =================
app.post(`/mock/reset`, (req, res) => {
  sessions.clear();
  hosts.clear();
  dnsDomains.clear();
  groups.clear();
  accessRules.clear();
  tasks.clear();
  pendingChanges = 0;
  groups.set("Blocked_Domains_Group", { uid: uid(), name: "Blocked_Domains_Group", members: [], type: "group" });
  accessRules.set("Blocked_IPs_Rule", {
    uid: uid(),
    name: "Blocked_IPs_Rule",
    layer: "Network",
    source: [],
    destination: ["Any"],
    service: ["Any"],
    action: "Drop",
    enabled: true,
  });
  accessRules.set("Blocked_Domains_Rule", {
    uid: uid(),
    name: "Blocked_Domains_Rule",
    layer: "Network",
    source: ["Any"],
    destination: ["Blocked_Domains_Group"],
    service: ["Any"],
    action: "Drop",
    enabled: true,
  });
  res.json({ message: "Mock state reset." });
});

// ================= Fallback: command tidak dikenal =================
router.post("/:command", (req, res) => {
  sendError(res, ERRORS.COMMAND_NOT_FOUND(req.params.command));
});

// Mount router di kedua gaya path (lihat catatan di deklarasi router di atas)
app.use("/web_api", router);
app.use("/web_api/:version", router);

// ================= Swagger UI (dokumentasi interaktif mock ini) =================
// PENTING: jangan bungkus log sukses di luar blok if ini — kalau file openapi.yaml
// tidak ketemu (mis. lupa di-COPY di Dockerfile), harus KETAHUAN jelas di log,
// bukan diam-diam skip tanpa pesan apapun (ini bug yang sempat lolos sebelumnya).
const openapiPath = path.join(__dirname, "openapi.yaml");
let swaggerReady = false;
if (fs.existsSync(openapiPath)) {
  try {
    const openapiDoc = YAML.load(fs.readFileSync(openapiPath, "utf8"));
    app.get("/openapi.yaml", (req, res) => res.sendFile(openapiPath));
    app.use("/docs", swaggerUi.serve, swaggerUi.setup(openapiDoc));
    swaggerReady = true;
  } catch (err) {
    console.error(`[SWAGGER] Gagal parse openapi.yaml: ${err.message}`);
  }
} else {
  console.error(
    `[SWAGGER] openapi.yaml TIDAK DITEMUKAN di ${openapiPath}. ` +
      `Route /docs TIDAK akan aktif. Cek apakah file ini ikut ter-COPY ke image ` +
      `(lihat Dockerfile) atau ikut ter-mount kalau pakai volume.`
  );
}

// ================= Error handler global: JSON body malformed =================
// Kalau express.json() gagal parse body (JSON rusak/bukan JSON sama sekali),
// Express lempar SyntaxError. Ini ditangkap di sini dan dibalikin dalam bentuk
// yang VERIFIED cocok dengan Check Point asli, bukan HTML error page default Express.
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed" || err instanceof SyntaxError) {
    return sendError(res, ERRORS.INVALID_SYNTAX());
  }
  next(err);
});

app.listen(PORT, () => {
  console.log(`Check Point Management API mock listening on http://localhost:${PORT}/web_api (version di path opsional, mis. /web_api/v1.9 juga diterima)`);
  if (swaggerReady) {
    console.log(`Swagger UI (dokumentasi interaktif): http://localhost:${PORT}/docs`);
  } else {
    console.log(`Swagger UI: TIDAK AKTIF (lihat pesan error di atas).`);
  }
  console.log(`Login user/password: admin / admin123   |   api-key: test-api-key-12345`);
});
