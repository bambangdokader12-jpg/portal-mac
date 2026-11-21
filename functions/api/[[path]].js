// Portal Daftar HP Julfikar.Com Wifi (APP-NET) — backend Cloudflare Pages Functions + D1
// Binding: DB (D1). Secrets: ADMIN_PASSWORD, SYNC_KEY.

const TOKEN_TTL_MS = 12 * 60 * 60 * 1000;
const MAX_PENDING = 300;
const STATUSES = ["aktif", "menunggu", "nonaktif"];
const TZ_OFFSET = "+8 hours"; // WITA
const enc = new TextEncoder();

const DEFAULT_PAKET = [
  ["2GB 1 Hari", 5000, 1], ["5GB 7 Hari", 25000, 7], ["10GB 14 Hari", 50000, 14],
  ["15GB 20 Hari", 75000, 20], ["20GB 1 Bulan", 100000, 30], ["50GB 1 Bulan", 175000, 30],
  ["100GB 1 Bulan", 300000, 30],
];

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" } });
const text = (body, status = 200) =>
  new Response(body, { status, headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" } });

// ---------- Bantuan ----------
export function normMac(s) {
  const hex = String(s || "").toUpperCase().replace(/[^0-9A-F]/g, "");
  if (hex.length !== 12 || hex === "000000000000" || hex === "FFFFFFFFFFFF") return null;
  return hex.match(/../g).join(":");
}
const isRandomMac = (mac) => (parseInt(mac[1], 16) & 2) === 2;
function clean(s, max = 60) {
  return String(s ?? "").replace(/[\u0000-\u001f\u007f;"\\$]/g, " ").replace(/\s+/g, " ").trim().slice(0, max);
}
const asciiName = (s) => clean(s, 40).replace(/[^A-Za-z0-9 ._\-]/g, "").replace(/\s+/g, " ").trim() || "tanpa-nama";
const int = (v, def = 0) => { const n = Math.round(Number(v)); return Number.isFinite(n) ? n : def; };
function safeEqual(a, b) {
  a = String(a); b = String(b);
  let r = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) r |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return r === 0;
}
const toHex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
async function hmac(key, msg) {
  const k = await crypto.subtle.importKey("raw", enc.encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return toHex(await crypto.subtle.sign("HMAC", k, enc.encode(msg)));
}
const newId = () => toHex(crypto.getRandomValues(new Uint8Array(6)));
const now = () => new Date().toISOString();
const validIso = (s) => typeof s === "string" && !isNaN(Date.parse(s));

// ---------- Akun login ----------
// Akun utama "admin" memakai ADMIN_PASSWORD (tidak bisa dihapus). Akun lain disimpan di tabel pengguna.
const ROLES = ["admin", "operator", "lihat"];
const RANK = { lihat: 1, operator: 2, admin: 3 };
const b64u = (str) => btoa(unescape(encodeURIComponent(str))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64u = (s) => decodeURIComponent(escape(atob(s.replace(/-/g, "+").replace(/_/g, "/"))));
const cleanUser = (u) => String(u || "").trim().toLowerCase().replace(/[^a-z0-9._-]/g, "").slice(0, 30);
async function hashPassword(password, saltHex) {
  const salt = saltHex || toHex(crypto.getRandomValues(new Uint8Array(16)));
  const key = await crypto.subtle.importKey("raw", enc.encode(String(password)), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: enc.encode(salt), iterations: 10000 }, key, 256);
  return salt + ":" + toHex(bits);
}
async function makeToken(secret, username) {
  const exp = String(Date.now() + TOKEN_TTL_MS);
  const u = b64u(username);
  return u + "." + exp + "." + (await hmac(secret, "u:" + username + ":" + exp));
}
async function readToken(request, secret) {
  if (!secret) return null;
  const t = (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
  const [u, exp, sig] = t.split(".");
  if (!u || !exp || !sig || Number(exp) < Date.now()) return null;
  let username; try { username = unb64u(u); } catch { return null; }
  return safeEqual(sig, await hmac(secret, "u:" + username + ":" + exp)) ? username : null;
}
async function readBody(req) { try { return await req.json(); } catch { return {}; } }

// HP dianggap "habis" kalau punya masa aktif, putus otomatis menyala, dan tanggalnya sudah lewat
const expired = (d) => !!d.aktif_sampai && !!d.putus_otomatis && Date.parse(d.aktif_sampai) <= Date.now();
const row = (r) => r && { ...r, acak: !!r.acak, putus_otomatis: !!r.putus_otomatis, habis: expired(r) };

// Kecepatan "upload/download" seperti MikroTik: 2M/5M, 512k/1M. "" = ikut default, "0/0" = tanpa batas.
function normRate(v) {
  const s = String(v ?? "").trim().replace(/\s+/g, "").replace(/mbps/gi, "M").replace(/kbps/gi, "k");
  if (!s) return "";
  const m = s.match(/^(\d+(?:\.\d+)?)([kKmMgG]?)\/(\d+(?:\.\d+)?)([kKmMgG]?)$/);
  if (!m) return null;
  const u = (x) => (x === "k" || x === "K" ? "k" : x.toUpperCase());
  if (Number(m[1]) === 0 && Number(m[3]) === 0) return "0/0";
  return m[1] + u(m[2]) + "/" + m[3] + u(m[4]);
}
const RATE_ERR = "Format kecepatan salah. Contoh: 2M/5M (upload/download), 512k/1M, atau 0/0 untuk tanpa batas.";

let schemaReady = false;
async function ensureSchema(db) {
  if (schemaReady) return;
  await db.prepare(`CREATE TABLE IF NOT EXISTS perangkat (
      id TEXT PRIMARY KEY, mac TEXT UNIQUE NOT NULL, nama TEXT, hp TEXT, ket TEXT,
      status TEXT NOT NULL, acak INTEGER DEFAULT 0, dibuat TEXT, diubah TEXT)`).run();
  for (const sql of [
    "ALTER TABLE perangkat ADD COLUMN aktif_sampai TEXT",
    "ALTER TABLE perangkat ADD COLUMN putus_otomatis INTEGER DEFAULT 1",
    "ALTER TABLE perangkat ADD COLUMN kecepatan TEXT",
  ]) { try { await db.prepare(sql).run(); } catch {} }
  await db.prepare(`CREATE TABLE IF NOT EXISTS paket (
      id TEXT PRIMARY KEY, nama TEXT NOT NULL, harga INTEGER NOT NULL DEFAULT 0,
      hari INTEGER NOT NULL DEFAULT 0, urutan INTEGER DEFAULT 0)`).run();
  await db.prepare(`CREATE TABLE IF NOT EXISTS pembayaran (
      id TEXT PRIMARY KEY, perangkat_id TEXT, mac TEXT, nama TEXT, paket TEXT,
      harga INTEGER NOT NULL DEFAULT 0, hari INTEGER DEFAULT 0, tanggal TEXT NOT NULL,
      dari TEXT, sampai TEXT, catatan TEXT)`).run();
  try { await db.prepare("ALTER TABLE paket ADD COLUMN kecepatan TEXT").run(); } catch {}
  try { await db.prepare("ALTER TABLE pembayaran ADD COLUMN kecepatan TEXT").run(); } catch {}
  try { await db.prepare("ALTER TABLE pembayaran ADD COLUMN status TEXT").run(); } catch {}
  try { await db.prepare("ALTER TABLE pembayaran ADD COLUMN tanggal_lunas TEXT").run(); } catch {}
  await db.prepare("UPDATE pembayaran SET status = 'lunas', tanggal_lunas = tanggal WHERE status IS NULL OR status = ''").run();
  await db.prepare("CREATE TABLE IF NOT EXISTS pengaturan (kunci TEXT PRIMARY KEY, nilai TEXT)").run();
  await db.prepare(`CREATE TABLE IF NOT EXISTS pengguna (username TEXT PRIMARY KEY, nama TEXT, password TEXT NOT NULL,
      role TEXT NOT NULL, aktif INTEGER DEFAULT 1, dibuat TEXT, login_terakhir TEXT)`).run();
  try { await db.prepare("ALTER TABLE pembayaran ADD COLUMN oleh TEXT").run(); } catch {}
  try { await db.prepare("ALTER TABLE perangkat ADD COLUMN oleh TEXT").run(); } catch {}
  const { n } = await db.prepare("SELECT COUNT(*) AS n FROM paket").first();
  if (!n) {
    await db.batch(DEFAULT_PAKET.map(([nama, harga, hari], i) =>
      db.prepare("INSERT INTO paket (id,nama,harga,hari,urutan) VALUES (?,?,?,?,?)").bind(newId(), nama, harga, hari, i)));
  }
  schemaReady = true;
}

const PERANGKAT_COLS = ["id", "mac", "nama", "hp", "ket", "status", "acak", "dibuat", "diubah", "aktif_sampai", "putus_otomatis", "kecepatan", "oleh"];
const PAKET_COLS = ["id", "nama", "harga", "hari", "urutan", "kecepatan"];
const BAYAR_COLS = ["id", "perangkat_id", "mac", "nama", "paket", "harga", "hari", "tanggal", "dari", "sampai", "catatan", "kecepatan", "status", "tanggal_lunas", "oleh"];
const insertSql = (table, cols) => `INSERT INTO ${table} (${cols.join(",")}) VALUES (${cols.map(() => "?").join(",")})`;

const ROUTER_SCRIPT = ":local base \"https://portal-mac.pages.dev/api\";\n:local key \"bambangdk1993\";\n:local tag \"WEBMAC\";\n:local srv \"dhcp1\";\n:local pre \"192.161.100.\";\n:local res;\n:do { :set res [/tool fetch url=($base . \"/mikrotik?key=\" . $key) check-certificate=no output=user as-value]; } on-error={ :log warning \"[WEBMAC] gagal mengambil daftar\"; :error \"fetch gagal\"; };\n:if (($res->\"status\") != \"finished\") do={ :log warning \"[WEBMAC] fetch gagal\"; :error \"fetch gagal\"; };\n:local data ($res->\"data\");\n:if ([:typeof [:find $data \"END\"]] = \"nil\" || [:typeof [:find $data \"ERROR\"]] != \"nil\") do={ :log warning \"[WEBMAC] data tidak valid\"; :error \"data tidak valid\"; };\n:local wanted \",\";\n:local rates [:toarray \"\"];\n:local pos 0;\n:local total [:len $data];\n:while ($pos < $total) do={ :local nl [:find $data \"\\n\" ($pos - 1)]; :if ([:typeof $nl] = \"nil\") do={ :set nl $total; }; :local line [:pick $data $pos $nl]; :set pos ($nl + 1); :if ([:len $line] > 0 && [:pick $line ([:len $line] - 1)] = \"\\r\") do={ :set line [:pick $line 0 ([:len $line] - 1)]; }; :if ([:len $line] > 17 && [:pick $line 17 18] = \";\") do={ :local mac [:pick $line 0 17]; :local rest [:pick $line 18 [:len $line]]; :local nama $rest; :local rate \"\"; :local sc [:find $rest \";\"]; :if ([:typeof $sc] != \"nil\") do={ :set nama [:pick $rest 0 $sc]; :set rate [:pick $rest ($sc + 1) [:len $rest]]; }; :set wanted ($wanted . $mac . \",\"); :set ($rates->$mac) $rate; :if ([:len [/ip dhcp-server lease find where mac-address=$mac server=$srv dynamic=no]] = 0) do={ :local got \"\"; :for i from=20 to=250 do={ :if ([:len $got] = 0) do={ :local cand [:toip ($pre . $i)]; :if ([:len [/ip dhcp-server lease find where address=$cand]] = 0 && [:len [/ip arp find where address=$cand]] = 0) do={ :set got $cand; }; }; }; :if ([:len $got] > 0) do={ :do { /ip dhcp-server lease remove [find where mac-address=$mac dynamic=yes]; } on-error={}; /ip dhcp-server lease add mac-address=$mac address=$got server=$srv comment=($tag . \" \" . $nama); :log info (\"[WEBMAC] HP didaftarkan: \" . $nama . \" \" . $mac . \" -> \" . $got); } else={ :log warning \"[WEBMAC] IP habis\"; }; }; }; };\n:foreach l in=[/ip dhcp-server lease find where comment~(\"^\" . $tag) dynamic=no] do={ :local m [/ip dhcp-server lease get $l mac-address]; :if ([:typeof [:find $wanted (\",\" . $m . \",\")]] = \"nil\") do={ :local ip [/ip dhcp-server lease get $l address]; /ip dhcp-server lease remove $l; :do { /ip arp remove [find where address=$ip dynamic=yes]; } on-error={}; :log info (\"[WEBMAC] HP dicabut: \" . $m); }; };\n:do { /ip arp remove [find where comment=$tag]; } on-error={};\n:foreach l in=[/ip dhcp-server lease find where dynamic=yes server=$srv] do={ :do { /ip dhcp-server lease remove $l; } on-error={}; };\n:local qwanted \",\";\n:local report \"\";\n:foreach l in=[/ip dhcp-server lease find where comment~(\"^\" . $tag) status=bound] do={ :local m [/ip dhcp-server lease get $l mac-address]; :local ip [:tostr [/ip dhcp-server lease get $l address]]; :local hn [/ip dhcp-server lease get $l host-name]; :local by \"\"; :local r ($rates->$m); :if ([:typeof $r] = \"str\" && [:len $r] > 0) do={ :local qn ($tag . \"-\" . $m); :set qwanted ($qwanted . $qn . \",\"); :local t ($ip . \"/32\"); :local q [/queue simple find where name=$qn]; :if ([:len $q] = 0) do={ :local first [/queue simple find]; :if ([:len $first] > 0) do={ /queue simple add name=$qn target=$t max-limit=$r comment=$tag place-before=[:pick $first 0]; } else={ /queue simple add name=$qn target=$t max-limit=$r comment=$tag; }; } else={ :if ([/queue simple get $q max-limit] != $r) do={ /queue simple set $q max-limit=$r; }; :if ([:tostr [/queue simple get $q target]] != $t) do={ /queue simple set $q target=$t; }; :set by [:tostr [/queue simple get $q bytes]]; }; }; :set report ($report . $m . \";\" . $ip . \";\" . $hn . \";\" . $by . \"\\n\"); };\n:foreach q in=[/queue simple find where name~(\"^\" . $tag . \"-\")] do={ :local n [/queue simple get $q name]; :if ([:typeof [:find $qwanted (\",\" . $n . \",\")]] = \"nil\") do={ /queue simple remove $q; }; };\n:if ([:len $report] = 0) do={ :set report \"-\"; };\n:do { /tool fetch url=($base . \"/online?key=\" . $key) check-certificate=no http-method=post http-header-field=\"Content-Type: text/plain\" http-data=$report output=none; } on-error={ :log warning \"[WEBMAC] gagal kirim user aktif\"; };\n";

// ---------- Handler utama ----------
export async function onRequest({ request, env }) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/api/, "").replace(/\/+$/, "") || "/";
  const method = request.method.toUpperCase();
  const db = env.DB;
  const pw = env.ADMIN_PASSWORD || "";
  if (!db) return json({ ok: false, pesan: "Database belum disambungkan (binding DB)." }, 500);

  try {
    await ensureSchema(db);
    const byMac = (mac) => db.prepare("SELECT * FROM perangkat WHERE mac = ?").bind(mac).first();
    const byId = (id) => db.prepare("SELECT * FROM perangkat WHERE id = ?").bind(id).first();
    const insertPerangkat = (d) => db.prepare(insertSql("perangkat", PERANGKAT_COLS))
      .bind(...PERANGKAT_COLS.map((c) => c === "acak" || c === "putus_otomatis" ? (d[c] ? 1 : 0) : (d[c] ?? null))).run();

    const getDefaultRate = async () => ((await db.prepare("SELECT nilai FROM pengaturan WHERE kunci = 'kecepatan_default'").first()) || {}).nilai || "";
    const rateOf = (d, def) => { const r = d.kecepatan || def || ""; return r === "0/0" ? "" : r; };

    // ===== Untuk MikroTik: HP aktif yang belum habis masa aktifnya =====
    if (path === "/mikrotik" && method === "GET") {
      const key = env.SYNC_KEY || "";
      if (!key || !safeEqual(url.searchParams.get("key") || "", key)) return text("ERROR kunci salah\n", 403);
      const { results } = await db.prepare("SELECT * FROM perangkat WHERE status = 'aktif' ORDER BY mac").all();
      const def = await getDefaultRate();
      const lines = results.filter((d) => !expired(d)).map((d) => d.mac + ";" + asciiName(d.nama) + ";" + rateOf(d, def));
      return text(lines.join("\n") + "\nEND\n");
    }

    // ===== Dari MikroTik: laporan HP yang sedang tersambung =====
    // Isi (text): satu baris per HP "MAC;IP;nama-host;bytes-upload/bytes-download"
    if (path === "/online" && method === "POST") {
      const key = env.SYNC_KEY || "";
      if (!key || !safeEqual(url.searchParams.get("key") || "", key)) return text("ERROR kunci salah\n", 403);
      const raw = (await request.text()).slice(0, 200000);
      const list = [];
      for (const line of raw.split(/\r?\n/)) {
        const parts = line.split(";");
        const mac = normMac(parts[0]);
        if (!mac) continue;
        const ip = /^\d{1,3}(\.\d{1,3}){3}$/.test(parts[1] || "") ? parts[1] : "";
        const host = clean(parts.slice(2, parts.length > 3 ? -1 : undefined).join(";"), 40);
        const bm = String(parts.length > 3 ? parts[parts.length - 1] : "").match(/^(\d+)\/(\d+)$/);
        list.push({ mac, ip, host, up: bm ? Number(bm[1]) : null, down: bm ? Number(bm[2]) : null });
        if (list.length >= 2000) break;
      }
      await db.prepare("INSERT INTO pengaturan (kunci, nilai) VALUES ('online', ?) ON CONFLICT(kunci) DO UPDATE SET nilai = excluded.nilai")
        .bind(JSON.stringify({ waktu: now(), list })).run();
      return text("OK " + list.length + "\n");
    }

    // ===== Script router (diunduh MikroTik) =====
    if (path === "/script" && method === "GET") {
      const key = env.SYNC_KEY || "";
      if (!key || !safeEqual(url.searchParams.get("key") || "", key)) return text("ERROR kunci salah\n", 403);
      return text(ROUTER_SCRIPT);
    }

    // ===== Publik =====
    if (path === "/daftar" && method === "POST") {
      return json({ ok: false, pesan: "Pendaftaran hanya dilakukan oleh admin. Silakan hubungi admin." }, 403);
    }
    if (path === "/daftar-lama" && method === "POST") {
      const b = await readBody(request);
      const mac = normMac(b.mac);
      const nama = clean(b.nama, 50);
      if (!mac) return json({ ok: false, pesan: "Format MAC Address tidak valid. Contoh: A4:5E:60:12:34:56" }, 400);
      if (nama.length < 2) return json({ ok: false, pesan: "Nama wajib diisi." }, 400);
      const ada = await byMac(mac);
      if (ada) return json({ ok: true, pesan: "MAC ini sudah terdaftar dengan status: " + ada.status.toUpperCase() + ".", status: ada.status });
      const { n } = await db.prepare("SELECT COUNT(*) AS n FROM perangkat WHERE status = 'menunggu'").first();
      if (n >= MAX_PENDING) return json({ ok: false, pesan: "Antrian pendaftaran penuh. Silakan hubungi admin." }, 429);
      await insertPerangkat({ id: newId(), mac, nama, hp: clean(b.hp, 20), ket: clean(b.ket, 80), status: "menunggu",
        acak: isRandomMac(mac), dibuat: now(), diubah: now(), aktif_sampai: null, putus_otomatis: true });
      return json({ ok: true, pesan: "Pendaftaran terkirim. Tunggu persetujuan admin.", status: "menunggu" });
    }

    if (path === "/cek" && method === "GET") {
      const mac = normMac(url.searchParams.get("mac"));
      if (!mac) return json({ ok: false, pesan: "Format MAC Address tidak valid." }, 400);
      const d = await byMac(mac);
      if (!d) return json({ ok: true, mac, status: "tidak-terdaftar" });
      return json({ ok: true, mac, status: expired(d) ? "habis" : d.status, aktif_sampai: d.aktif_sampai || null });
    }

    if (path === "/login" && method === "POST") {
      if (!pw) return json({ ok: false, pesan: "ADMIN_PASSWORD belum diatur di Cloudflare." }, 500);
      const b = await readBody(request);
      const username = cleanUser(b.username) || "admin";
      let okLogin = false, info = null;
      if (username === "admin") { okLogin = safeEqual(b.password || "", pw); info = { username: "admin", nama: "Admin Utama", role: "admin" }; }
      else {
        const u = await db.prepare("SELECT * FROM pengguna WHERE username = ?").bind(username).first();
        if (u && u.aktif) {
          const [salt] = String(u.password).split(":");
          okLogin = safeEqual(await hashPassword(b.password || "", salt), u.password);
          info = { username: u.username, nama: u.nama, role: u.role };
        }
      }
      if (!okLogin) {
        await new Promise((r) => setTimeout(r, 800));
        return json({ ok: false, pesan: "Username atau password salah." }, 401);
      }
      if (username !== "admin") await db.prepare("UPDATE pengguna SET login_terakhir = ? WHERE username = ?").bind(now(), username).run();
      return json({ ok: true, token: await makeToken(pw, username), user: info });
    }

    // ===== Semua di bawah ini perlu login =====
    let me = null;
    const tokUser = await readToken(request, pw);
    if (tokUser === "admin") me = { username: "admin", nama: "Admin Utama", role: "admin" };
    else if (tokUser) {
      const u = await db.prepare("SELECT username, nama, role, aktif FROM pengguna WHERE username = ?").bind(tokUser).first();
      if (u && u.aktif) me = { username: u.username, nama: u.nama, role: u.role };
    }
    if (!me) {
      const known = ["/kecepatan", "/saya", "/pengguna", "/lunas", "/perangkat", "/paket", "/bayar", "/pembayaran", "/keuangan", "/backup", "/restore", "/pengaturan", "/online"];
      if (known.some((p) => path === p || path.startsWith(p + "/"))) return json({ ok: false, pesan: "Sesi habis, silakan login lagi." }, 401);
      return json({ ok: false, pesan: "Alamat tidak dikenal." }, 404);
    }
    const seg = path.split("/");
    const id = seg[2];

    // ----- Hak akses -----
    const butuh = (role) => (RANK[me.role] || 0) >= RANK[role];
    const tolak = () => json({ ok: false, pesan: "Akun Anda (" + me.role + ") tidak punya izin untuk ini." }, 403);
    const hanyaAdmin = seg[1] === "pengguna" || (path === "/kecepatan" && method !== "GET") || path === "/restore" || path === "/backup"
      || (path === "/pengaturan" && method !== "GET") || (method === "DELETE");
    if (hanyaAdmin && !butuh("admin")) return tolak();
    if (method !== "GET" && !butuh("operator")) return tolak();

    if (path === "/saya") return json({ ok: true, user: me });

    // ----- Pengguna (akun login) -----
    if (seg[1] === "pengguna") {
      if (!id && method === "GET") {
        const { results } = await db.prepare("SELECT username, nama, role, aktif, dibuat, login_terakhir FROM pengguna ORDER BY dibuat").all();
        return json({ ok: true, data: [{ username: "admin", nama: "Admin Utama", role: "admin", aktif: 1, utama: true }, ...results] });
      }
      if (!id && method === "POST") {
        const b = await readBody(request);
        const username = cleanUser(b.username);
        if (username.length < 3) return json({ ok: false, pesan: "Username minimal 3 huruf (a-z, 0-9, titik, strip)." }, 400);
        if (username === "admin") return json({ ok: false, pesan: "Username 'admin' sudah dipakai akun utama." }, 409);
        if (String(b.password || "").length < 6) return json({ ok: false, pesan: "Password minimal 6 karakter." }, 400);
        const role = ROLES.includes(b.role) ? b.role : "operator";
        if (await db.prepare("SELECT 1 FROM pengguna WHERE username = ?").bind(username).first()) return json({ ok: false, pesan: "Username sudah ada." }, 409);
        await db.prepare("INSERT INTO pengguna (username, nama, password, role, aktif, dibuat) VALUES (?, ?, ?, ?, 1, ?)")
          .bind(username, clean(b.nama, 40) || username, await hashPassword(b.password), role, now()).run();
        return json({ ok: true, pesan: "Pengguna " + username + " dibuat." });
      }
      const uname = cleanUser(decodeURIComponent(id || ""));
      if (uname === "admin") return json({ ok: false, pesan: "Akun utama 'admin' diatur lewat ADMIN_PASSWORD di Cloudflare." }, 400);
      const u = await db.prepare("SELECT * FROM pengguna WHERE username = ?").bind(uname).first();
      if (!u) return json({ ok: false, pesan: "Pengguna tidak ditemukan." }, 404);
      if (method === "PATCH") {
        const b = await readBody(request);
        if (b.role !== undefined) { if (!ROLES.includes(b.role)) return json({ ok: false, pesan: "Hak akses tidak valid." }, 400); u.role = b.role; }
        if (b.nama !== undefined) u.nama = clean(b.nama, 40) || u.nama;
        if (b.aktif !== undefined) u.aktif = b.aktif ? 1 : 0;
        if (b.password) {
          if (String(b.password).length < 6) return json({ ok: false, pesan: "Password minimal 6 karakter." }, 400);
          u.password = await hashPassword(b.password);
        }
        await db.prepare("UPDATE pengguna SET nama=?, role=?, aktif=?, password=? WHERE username=?").bind(u.nama, u.role, u.aktif, u.password, u.username).run();
        return json({ ok: true, pesan: "Pengguna " + u.username + " diperbarui." });
      }
      if (method === "DELETE") {
        await db.prepare("DELETE FROM pengguna WHERE username = ?").bind(u.username).run();
        return json({ ok: true, pesan: "Pengguna " + u.username + " dihapus." });
      }
    }

    // ----- Perangkat -----
    if (seg[1] === "perangkat") {
      if (!id && method === "GET") {
        const { results } = await db.prepare("SELECT * FROM perangkat ORDER BY dibuat DESC").all();
        const { results: ut } = await db.prepare("SELECT perangkat_id, SUM(harga) AS t, COUNT(*) AS n FROM pembayaran WHERE status = 'utang' GROUP BY perangkat_id").all();
        const { results: lb } = await db.prepare("SELECT perangkat_id, MAX(tanggal) AS tgl FROM pembayaran GROUP BY perangkat_id").all();
        const U = Object.fromEntries(ut.map((x) => [x.perangkat_id, x])), LB = Object.fromEntries(lb.map((x) => [x.perangkat_id, x.tgl]));
        return json({ ok: true, data: results.map((r) => ({ ...row(r), utang: U[r.id]?.t || 0, utang_n: U[r.id]?.n || 0, bayar_terakhir: LB[r.id] || null })),
          kecepatan_default: await getDefaultRate() });
      }
      if (!id && method === "POST") {
        const b = await readBody(request);
        const mac = normMac(b.mac);
        if (!mac) return json({ ok: false, pesan: "Format MAC tidak valid." }, 400);
        if (await byMac(mac)) return json({ ok: false, pesan: "MAC sudah ada di daftar." }, 409);
        const item = { id: newId(), mac, nama: clean(b.nama, 50) || "tanpa nama", hp: clean(b.hp, 20), ket: clean(b.ket, 80),
          status: STATUSES.includes(b.status) ? b.status : "aktif", acak: isRandomMac(mac), dibuat: now(), diubah: now(),
          aktif_sampai: validIso(b.aktif_sampai) ? new Date(b.aktif_sampai).toISOString() : null, putus_otomatis: b.putus_otomatis !== false, kecepatan: normRate(b.kecepatan), oleh: me.username };
        if (item.kecepatan === null) return json({ ok: false, pesan: RATE_ERR }, 400);
        await insertPerangkat(item);
        return json({ ok: true, data: row(item) });
      }
      const d = await byId(id);
      if (!d) return json({ ok: false, pesan: "Data tidak ditemukan." }, 404);
      if (method === "PATCH") {
        const b = await readBody(request);
        if (b.status !== undefined) {
          if (!STATUSES.includes(b.status)) return json({ ok: false, pesan: "Status tidak valid." }, 400);
          d.status = b.status;
        }
        if (b.nama !== undefined) d.nama = clean(b.nama, 50) || d.nama;
        if (b.hp !== undefined) d.hp = clean(b.hp, 20);
        if (b.ket !== undefined) d.ket = clean(b.ket, 80);
        if (b.aktif_sampai !== undefined) d.aktif_sampai = validIso(b.aktif_sampai) ? new Date(b.aktif_sampai).toISOString() : null;
        if (b.putus_otomatis !== undefined) d.putus_otomatis = b.putus_otomatis ? 1 : 0;
        if (b.kecepatan !== undefined) { const r = normRate(b.kecepatan); if (r === null) return json({ ok: false, pesan: RATE_ERR }, 400); d.kecepatan = r; }
        d.diubah = now();
        await db.prepare("UPDATE perangkat SET status=?, nama=?, hp=?, ket=?, aktif_sampai=?, putus_otomatis=?, kecepatan=?, diubah=? WHERE id=?")
          .bind(d.status, d.nama, d.hp, d.ket, d.aktif_sampai, d.putus_otomatis ? 1 : 0, d.kecepatan ?? "", d.diubah, d.id).run();
        return json({ ok: true, data: row(d) });
      }
      if (method === "DELETE") {
        await db.prepare("DELETE FROM perangkat WHERE id = ?").bind(id).run();
        return json({ ok: true });
      }
    }

    // ----- Paket -----
    if (seg[1] === "paket") {
      if (!id && method === "GET") {
        const { results } = await db.prepare("SELECT * FROM paket ORDER BY urutan, harga").all();
        return json({ ok: true, data: results });
      }
      if (!id && method === "POST") {
        const b = await readBody(request);
        const nama = clean(b.nama, 40);
        if (!nama) return json({ ok: false, pesan: "Nama paket wajib diisi." }, 400);
        const item = { id: newId(), nama, harga: Math.max(0, int(b.harga)), hari: Math.max(0, int(b.hari)), urutan: int(b.urutan, 99), kecepatan: normRate(b.kecepatan) };
        if (item.kecepatan === null) return json({ ok: false, pesan: RATE_ERR }, 400);
        await db.prepare(insertSql("paket", PAKET_COLS)).bind(...PAKET_COLS.map((c) => item[c])).run();
        return json({ ok: true, data: item });
      }
      const p = await db.prepare("SELECT * FROM paket WHERE id = ?").bind(id).first();
      if (!p) return json({ ok: false, pesan: "Paket tidak ditemukan." }, 404);
      if (method === "PATCH") {
        const b = await readBody(request);
        if (b.nama !== undefined) p.nama = clean(b.nama, 40) || p.nama;
        if (b.harga !== undefined) p.harga = Math.max(0, int(b.harga));
        if (b.hari !== undefined) p.hari = Math.max(0, int(b.hari));
        if (b.kecepatan !== undefined) { const r = normRate(b.kecepatan); if (r === null) return json({ ok: false, pesan: RATE_ERR }, 400); p.kecepatan = r; }
        await db.prepare("UPDATE paket SET nama=?, harga=?, hari=?, kecepatan=? WHERE id=?").bind(p.nama, p.harga, p.hari, p.kecepatan ?? "", p.id).run();
        return json({ ok: true, data: p });
      }
      if (method === "DELETE") {
        await db.prepare("DELETE FROM paket WHERE id = ?").bind(id).run();
        return json({ ok: true });
      }
    }

    // ----- Catat pembayaran (memperpanjang masa aktif) -----
    if (path === "/bayar" && method === "POST") {
      const b = await readBody(request);
      const d = await byId(b.perangkat_id);
      if (!d) return json({ ok: false, pesan: "Perangkat tidak ditemukan." }, 404);
      let kecepatan = "";
      let paketNama = clean(b.paket, 40) || "Pembayaran", harga = Math.max(0, int(b.harga)), hari = Math.max(0, int(b.hari));
      if (b.paket_id) {
        const p = await db.prepare("SELECT * FROM paket WHERE id = ?").bind(b.paket_id).first();
        if (!p) return json({ ok: false, pesan: "Paket tidak ditemukan." }, 404);
        paketNama = p.nama; harga = p.harga; hari = p.hari; kecepatan = p.kecepatan || "";
        if (b.harga !== undefined && b.harga !== "") harga = Math.max(0, int(b.harga)); // boleh diskon
      }
      if (b.kecepatan !== undefined && b.kecepatan !== null) { const r = normRate(b.kecepatan); if (r === null) return json({ ok: false, pesan: RATE_ERR }, 400); if (r) kecepatan = r; }
      const kecBaru = kecepatan || d.kecepatan || "";
      const tanggal = validIso(b.tanggal) ? new Date(b.tanggal).toISOString() : now();
      const stBayar = b.status === "utang" ? "utang" : "lunas";
      let dari = null, sampai = d.aktif_sampai || null;
      if (hari > 0) {
        const base = d.aktif_sampai && Date.parse(d.aktif_sampai) > Date.now() ? Date.parse(d.aktif_sampai) : Date.now();
        dari = new Date(base).toISOString();
        sampai = new Date(base + hari * 86400000).toISOString();
      }
      const bayar = { id: newId(), perangkat_id: d.id, mac: d.mac, nama: d.nama, paket: paketNama, harga, hari, tanggal, dari, sampai, catatan: clean(b.catatan, 80), kecepatan: kecBaru,
        status: stBayar, tanggal_lunas: stBayar === "lunas" ? tanggal : null, oleh: me.username };
      await db.batch([
        db.prepare(insertSql("pembayaran", BAYAR_COLS)).bind(...BAYAR_COLS.map((c) => bayar[c])),
        db.prepare("UPDATE perangkat SET status='aktif', aktif_sampai=?, kecepatan=?, diubah=? WHERE id=?").bind(sampai, kecBaru, now(), d.id),
      ]);
      return json({ ok: true, data: bayar, pesan: (stBayar === "utang" ? "Dicatat sebagai UTANG." : "Pembayaran LUNAS dicatat.") + (sampai ? " Aktif sampai " + sampai.slice(0, 10) + "." : "") + (kecepatan ? " Kecepatan " + kecepatan + "." : "") });
    }

    // ----- Lunasi semua utang satu pelanggan -----
    if (path === "/lunas" && method === "POST") {
      const b = await readBody(request);
      const { t, n } = await db.prepare("SELECT COALESCE(SUM(harga),0) AS t, COUNT(*) AS n FROM pembayaran WHERE status = 'utang' AND perangkat_id = ?").bind(b.perangkat_id).first();
      if (!n) return json({ ok: false, pesan: "Tidak ada utang." }, 400);
      await db.prepare("UPDATE pembayaran SET status = 'lunas', tanggal_lunas = ? WHERE status = 'utang' AND perangkat_id = ?").bind(now(), b.perangkat_id).run();
      return json({ ok: true, pesan: "Lunas. Rp " + Number(t).toLocaleString("id-ID") + " masuk pendapatan hari ini." });
    }

    // ----- Riwayat pembayaran -----
    if (seg[1] === "pembayaran") {
      if (!id && method === "GET") {
        const bulan = url.searchParams.get("bulan"); // YYYY-MM (WITA)
        const st = url.searchParams.get("status");
        const m = (col) => `strftime('%Y-%m', datetime(${col}, '${TZ_OFFSET}'))`;
        let q;
        if (st === "utang") q = db.prepare("SELECT * FROM pembayaran WHERE status = 'utang' ORDER BY tanggal DESC");
        else if (/^\d{4}-\d{2}$/.test(bulan || "")) q = db.prepare(`SELECT * FROM pembayaran WHERE ${m("tanggal")} = ?1 OR (status = 'lunas' AND ${m("tanggal_lunas")} = ?1) ORDER BY tanggal DESC`).bind(bulan);
        else q = db.prepare("SELECT * FROM pembayaran ORDER BY tanggal DESC LIMIT 2000");
        const { results } = await q.all();
        return json({ ok: true, data: results });
      }
      if (id && method === "PATCH") {
        const b = await readBody(request);
        const x = await db.prepare("SELECT * FROM pembayaran WHERE id = ?").bind(id).first();
        if (!x) return json({ ok: false, pesan: "Pembayaran tidak ditemukan." }, 404);
        if (b.status === "lunas") {
          const harga = b.harga !== undefined && b.harga !== "" ? Math.max(0, int(b.harga)) : x.harga;
          await db.prepare("UPDATE pembayaran SET status = 'lunas', tanggal_lunas = ?, harga = ? WHERE id = ?").bind(now(), harga, id).run();
          return json({ ok: true, pesan: "Lunas. " + harga.toLocaleString("id-ID") + " masuk pendapatan hari ini." });
        }
        if (b.status === "utang") {
          await db.prepare("UPDATE pembayaran SET status = 'utang', tanggal_lunas = NULL WHERE id = ?").bind(id).run();
          return json({ ok: true, pesan: "Dikembalikan menjadi utang." });
        }
        return json({ ok: false, pesan: "Status tidak valid." }, 400);
      }
      if (id && method === "DELETE") {
        await db.prepare("DELETE FROM pembayaran WHERE id = ?").bind(id).run();
        return json({ ok: true, pesan: "Catatan pembayaran dihapus. Masa aktif HP tidak berubah; ubah lewat Edit bila perlu." });
      }
    }

    // ----- Ringkasan keuangan -----
    if (path === "/keuangan" && method === "GET") {
      const L = `strftime(%F, datetime(tanggal_lunas, '${TZ_OFFSET}'))`;
      const at = (f) => L.replace("%F", f);
      const skr = (f, extra = "") => `strftime(${f}, datetime('now', '${TZ_OFFSET}'${extra}))`;
      const sum = (cond) => db.prepare(`SELECT COALESCE(SUM(harga),0) AS t, COUNT(*) AS n FROM pembayaran WHERE status = 'lunas' AND ${cond}`).first();
      const hari_ini = await sum(`${at("'%Y-%m-%d'")} = ${skr("'%Y-%m-%d'")}`);
      const bulan_ini = await sum(`${at("'%Y-%m'")} = ${skr("'%Y-%m'")}`);
      const bulan_lalu = await sum(`${at("'%Y-%m'")} = ${skr("'%Y-%m'", ", 'start of month', '-1 month'")}`);
      const total = await sum("1=1");
      const utang = await db.prepare("SELECT COALESCE(SUM(harga),0) AS t, COUNT(*) AS n FROM pembayaran WHERE status = 'utang'").first();
      const { results: per_bulan } = await db.prepare(
        `SELECT ${at("'%Y-%m'")} AS bulan, SUM(harga) AS total, COUNT(*) AS jumlah FROM pembayaran WHERE status = 'lunas' GROUP BY bulan ORDER BY bulan DESC LIMIT 12`).all();
      const { results: utang_list } = await db.prepare(
        "SELECT perangkat_id, mac, nama, SUM(harga) AS total, COUNT(*) AS jumlah FROM pembayaran WHERE status = 'utang' GROUP BY perangkat_id ORDER BY total DESC LIMIT 50").all();
      const { results: semua } = await db.prepare("SELECT * FROM perangkat").all();
      const in7 = Date.now() + 7 * 86400000;
      const hampir = semua.filter((d) => d.status === "aktif" && d.aktif_sampai && !expired(d) && Date.parse(d.aktif_sampai) <= in7)
        .map(row).sort((x, y) => x.aktif_sampai.localeCompare(y.aktif_sampai));
      return json({ ok: true, data: {
        hari_ini, bulan_ini, bulan_lalu, total, utang, utang_list, per_bulan: per_bulan.reverse(),
        jumlah_habis: semua.filter((d) => d.status === "aktif" && expired(d)).length, hampir_habis: hampir,
      } });
    }

    // ----- User aktif (laporan terakhir dari router) -----
    if (path === "/online" && method === "GET") {
      const r = await db.prepare("SELECT nilai FROM pengaturan WHERE kunci = 'online'").first();
      let rep = { waktu: null, list: [] };
      try { if (r && r.nilai) rep = JSON.parse(r.nilai); } catch {}
      const { results } = await db.prepare("SELECT * FROM perangkat").all();
      const def = await getDefaultRate();
      const byM = Object.fromEntries(results.map((d) => [d.mac, d]));
      const data = rep.list.map((o) => {
        const d = byM[o.mac];
        return { ...o, terdaftar: !!d, id: d?.id || null, nama: d?.nama || null, hp: d?.hp || null,
          status: d ? (expired(d) ? "habis" : d.status) : null, aktif_sampai: d?.aktif_sampai || null,
          kecepatan: d ? (rateOf(d, def) || "") : "" };
      });
      return json({ ok: true, waktu: rep.waktu, data });
    }

    // ----- Daftar pilihan kecepatan -----
    if (path === "/kecepatan") {
      const getList = async () => { try { return JSON.parse(((await db.prepare("SELECT nilai FROM pengaturan WHERE kunci = 'kecepatan_list'").first()) || {}).nilai || "[]"); } catch { return []; } };
      if (method === "GET") return json({ ok: true, data: await getList(), kecepatan_default: await getDefaultRate() });
      if (method === "PUT") {
        const b = await readBody(request);
        if (!Array.isArray(b.data)) return json({ ok: false, pesan: "Data tidak valid." }, 400);
        const list = [];
        for (const x of b.data.slice(0, 50)) {
          const nama = clean(x && x.nama, 30), r = normRate(x && x.rate);
          if (!nama) return json({ ok: false, pesan: "Nama kecepatan wajib diisi." }, 400);
          if (!r || r === "0/0") return json({ ok: false, pesan: "Kecepatan '" + nama + "': " + RATE_ERR }, 400);
          list.push({ nama, rate: r });
        }
        await db.prepare("INSERT INTO pengaturan (kunci, nilai) VALUES ('kecepatan_list', ?) ON CONFLICT(kunci) DO UPDATE SET nilai = excluded.nilai").bind(JSON.stringify(list)).run();
        return json({ ok: true, data: list, pesan: "Daftar kecepatan disimpan." });
      }
    }

    // ----- Pengaturan (kecepatan default) -----
    if (path === "/pengaturan") {
      if (method === "GET") return json({ ok: true, data: { kecepatan_default: await getDefaultRate() } });
      if (method === "PATCH") {
        const b = await readBody(request);
        const r = normRate(b.kecepatan_default);
        if (r === null) return json({ ok: false, pesan: RATE_ERR }, 400);
        await db.prepare("INSERT INTO pengaturan (kunci, nilai) VALUES ('kecepatan_default', ?) ON CONFLICT(kunci) DO UPDATE SET nilai = excluded.nilai").bind(r).run();
        return json({ ok: true, data: { kecepatan_default: r }, pesan: r && r !== "0/0" ? "Kecepatan default: " + r : "Kecepatan default: tanpa batas" });
      }
    }

    // ----- Backup & restore -----
    if (path === "/backup" && method === "GET") {
      const all = async (t) => (await db.prepare(`SELECT * FROM ${t}`).all()).results;
      return json({ aplikasi: "portal-mac", versi: 4, dibuat: now(), pengaturan: await all("pengaturan"), pengguna: await all("pengguna"),
        perangkat: await all("perangkat"), paket: await all("paket"), pembayaran: await all("pembayaran") });
    }
    if (path === "/restore" && method === "POST") {
      const b = await readBody(request);
      if (b.aplikasi !== "portal-mac" || !Array.isArray(b.perangkat)) return json({ ok: false, pesan: "File backup tidak dikenali." }, 400);
      const pick = (o, cols) => cols.map((c) => (o[c] === undefined ? null : o[c]));
      const stmts = [db.prepare("DELETE FROM perangkat"), db.prepare("DELETE FROM paket"), db.prepare("DELETE FROM pembayaran")];
      if (Array.isArray(b.pengguna)) {
        stmts.push(db.prepare("DELETE FROM pengguna"));
        for (const x of b.pengguna) if (x && x.username && x.password && ROLES.includes(x.role))
          stmts.push(db.prepare("INSERT INTO pengguna (username, nama, password, role, aktif, dibuat, login_terakhir) VALUES (?,?,?,?,?,?,?)")
            .bind(cleanUser(x.username), String(x.nama || x.username), String(x.password), x.role, x.aktif ? 1 : 0, x.dibuat || now(), x.login_terakhir || null));
      }
      if (Array.isArray(b.pengaturan)) {
        stmts.push(db.prepare("DELETE FROM pengaturan"));
        for (const x of b.pengaturan) if (x && x.kunci) stmts.push(db.prepare("INSERT INTO pengaturan (kunci, nilai) VALUES (?, ?)").bind(String(x.kunci), String(x.nilai ?? "")));
      }
      for (const d of b.perangkat) {
        const mac = normMac(d.mac);
        if (!mac || !d.id) continue;
        stmts.push(db.prepare(insertSql("perangkat", PERANGKAT_COLS)).bind(...pick({ ...d, mac,
          acak: d.acak ? 1 : 0, putus_otomatis: d.putus_otomatis === undefined ? 1 : (d.putus_otomatis ? 1 : 0),
          status: STATUSES.includes(d.status) ? d.status : "menunggu" }, PERANGKAT_COLS)));
      }
      for (const p of b.paket || []) if (p.id && p.nama) stmts.push(db.prepare(insertSql("paket", PAKET_COLS)).bind(...pick(p, PAKET_COLS)));
      for (const p of b.pembayaran || []) if (p.id && p.tanggal) stmts.push(db.prepare(insertSql("pembayaran", BAYAR_COLS)).bind(...pick(p, BAYAR_COLS)));
      await db.batch(stmts);
      return json({ ok: true, pesan: `Restore selesai: ${b.perangkat.length} perangkat, ${(b.paket || []).length} paket, ${(b.pembayaran || []).length} pembayaran.` });
    }

    return json({ ok: false, pesan: "Alamat tidak dikenal." }, 404);
  } catch (e) {
    return json({ ok: false, pesan: "Kesalahan server: " + e.message }, 500);
  }
}
