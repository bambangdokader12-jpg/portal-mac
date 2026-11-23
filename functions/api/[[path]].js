// Portal Daftar HP Julfikar.Com Wifi (APP-NET) — backend Cloudflare Pages Functions + D1
// Versi 3 cabang: APP-BHP (bhp), APP-KHL2 (khl2), APP-BSI (bsi).
// Binding: DB (D1). Secrets: ADMIN_PASSWORD, SYNC_KEY.
//
// Cabang dipilih lewat header "x-cabang" (panel web) atau "?cabang=" (router MikroTik).
// Kalau tidak disebut, dianggap "bhp" — jadi router BHP yang lama tetap jalan tanpa diubah.
// Data lama (sebelum versi cabang) otomatis menjadi data APP-BHP.

const TOKEN_TTL_MS = 12 * 60 * 60 * 1000;
const MAX_PENDING = 300;
const STATUSES = ["aktif", "menunggu", "nonaktif"];
const KATEGORI = ["pelanggan", "pribadi", "keluarga"]; // jenis HP
const normKat = (v) => (KATEGORI.includes(String(v || "").toLowerCase()) ? String(v).toLowerCase() : "pelanggan");
const TZ_OFFSET = "+8 hours"; // WITA
const enc = new TextEncoder();

const CABANG = { bhp: "APP-BHP", khl2: "APP-KHL2", bsi: "APP-BSI" };
const CABANG_IDS = Object.keys(CABANG);
const CABANG_DEFAULT = "bhp";

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
// Masa aktif dalam hari, boleh pecahan (mis. 3 jam = 0.125 hari)
const hariNum = (v) => { const n = Number(v); return Number.isFinite(n) && n > 0 ? Math.round(n * 10000) / 10000 : 0; };
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

// Kode cabang dari teks bebas. null = tidak dikenal.
const normCab = (v) => { const c = String(v ?? "").trim().toLowerCase(); return CABANG_IDS.includes(c) ? c : null; };
// Daftar cabang tersimpan sebagai teks "bhp,khl2". Kosong = akun lama = hanya BHP.
const parseCabList = (s) => { const l = String(s || "").split(",").map(normCab).filter(Boolean); return l.length ? [...new Set(l)] : [CABANG_DEFAULT]; };
const cleanCabList = (arr) => (Array.isArray(arr) ? [...new Set(arr.map(normCab).filter(Boolean))] : []);

// ---------- Akun login ----------
// Akun utama "admin" memakai ADMIN_PASSWORD (tidak bisa dihapus) dan boleh masuk ke semua cabang.
// Akun lain disimpan di tabel pengguna, masing-masing dengan daftar cabang yang boleh dibuka.
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
  // --- Versi cabang: semua data lama otomatis menjadi data APP-BHP ---
  for (const t of ["perangkat", "pembayaran", "paket"]) {
    try { await db.prepare(`ALTER TABLE ${t} ADD COLUMN cabang TEXT DEFAULT '${CABANG_DEFAULT}'`).run(); } catch {}
    await db.prepare(`UPDATE ${t} SET cabang = '${CABANG_DEFAULT}' WHERE cabang IS NULL OR cabang = ''`).run();
    try { await db.prepare(`CREATE INDEX IF NOT EXISTS idx_${t}_cabang ON ${t}(cabang)`).run(); } catch {}
  }
  try { await db.prepare("ALTER TABLE pengguna ADD COLUMN cabang TEXT").run(); } catch {}
  try { await db.prepare("ALTER TABLE perangkat ADD COLUMN kategori TEXT DEFAULT 'pelanggan'").run(); } catch {}
  await db.prepare("UPDATE perangkat SET kategori = 'pelanggan' WHERE kategori IS NULL OR kategori = ''").run();
  // Grup: beberapa HP milik satu pelanggan (Paket 2/3/4 HP) berbagi status, masa aktif, dan kecepatan
  try { await db.prepare("ALTER TABLE perangkat ADD COLUMN grup TEXT").run(); } catch {}
  try { await db.prepare("ALTER TABLE pembayaran ADD COLUMN grup TEXT").run(); } catch {}
  const { n } = await db.prepare("SELECT COUNT(*) AS n FROM paket").first();
  if (!n) {
    await db.batch(DEFAULT_PAKET.map(([nama, harga, hari], i) =>
      db.prepare("INSERT INTO paket (id,nama,harga,hari,urutan,cabang) VALUES (?,?,?,?,?,?)").bind(newId(), nama, harga, hari, i, CABANG_DEFAULT)));
  }
  schemaReady = true;
}

const PERANGKAT_COLS = ["id", "mac", "nama", "hp", "ket", "status", "acak", "dibuat", "diubah", "aktif_sampai", "putus_otomatis", "kecepatan", "oleh", "cabang", "kategori", "grup"];
const PAKET_COLS = ["id", "nama", "harga", "hari", "urutan", "kecepatan", "cabang"];
const BAYAR_COLS = ["id", "perangkat_id", "mac", "nama", "paket", "harga", "hari", "tanggal", "dari", "sampai", "catatan", "kecepatan", "status", "tanggal_lunas", "oleh", "cabang", "grup"];
const insertSql = (table, cols, orIgnore = false) => `INSERT${orIgnore ? " OR IGNORE" : ""} INTO ${table} (${cols.join(",")}) VALUES (${cols.map(() => "?").join(",")})`;

// Pengaturan per cabang. Cabang BHP memakai kunci lama (tanpa akhiran) supaya data lama tetap terbaca.
const kunci = (k, cab) => (cab === CABANG_DEFAULT ? k : k + ":" + cab);
const PENGATURAN_CABANG = ["online", "kecepatan_default", "kecepatan_list"];

// Script router contoh. Ganti "bhp" dengan kode cabang router itu (bhp / khl2 / bsi) dan AP-KUOTA dengan interface pelanggan.
const routerScript = (cab) => ":local base \"https://portal-mac.pages.dev/api\";\n:local key \"bambangdk1993\";\n:local cabang \"" + cab + "\";\n:local tag \"WEBMAC\";\n:local res;\n:do { :set res [/tool fetch url=($base . \"/mikrotik?key=\" . $key . \"&cabang=\" . $cabang) check-certificate=no output=user as-value]; } on-error={ :log warning \"[WEBMAC] gagal mengambil daftar\"; :error \"fetch gagal\"; };\n:if (($res->\"status\") != \"finished\") do={ :log warning \"[WEBMAC] fetch gagal\"; :error \"fetch gagal\"; };\n:local data ($res->\"data\");\n:if ([:typeof [:find $data \"END\"]] = \"nil\" || [:typeof [:find $data \"ERROR\"]] != \"nil\") do={ :log warning \"[WEBMAC] data tidak valid\"; :error \"data tidak valid\"; };\n:local wanted \",\";\n:local rates [:toarray \"\"];\n:local pos 0;\n:local total [:len $data];\n:while ($pos < $total) do={ :local nl [:find $data \"\\n\" ($pos - 1)]; :if ([:typeof $nl] = \"nil\") do={ :set nl $total; }; :local line [:pick $data $pos $nl]; :set pos ($nl + 1); :if ([:len $line] > 0 && [:pick $line ([:len $line] - 1)] = \"\\r\") do={ :set line [:pick $line 0 ([:len $line] - 1)]; }; :if ([:len $line] > 17 && [:pick $line 17 18] = \";\") do={ :local mac [:pick $line 0 17]; :local rest [:pick $line 18 [:len $line]]; :local rate \"\"; :local sc [:find $rest \";\"]; :if ([:typeof $sc] != \"nil\") do={ :set rate [:pick $rest ($sc + 1) [:len $rest]]; }; :set wanted ($wanted . $mac . \",\"); :set ($rates->$mac) $rate; }; };\n:local okArp \",\";\n:local qwanted \",\";\n:local report \"\";\n:local blocked 0;\n:foreach l in=[/ip dhcp-server lease find where status=bound dynamic=yes] do={ :local m [/ip dhcp-server lease get $l mac-address]; :local ip [:tostr [/ip dhcp-server lease get $l address]]; :local hn [/ip dhcp-server lease get $l host-name]; :if ([:typeof [:find $wanted (\",\" . $m . \",\")]] = \"nil\") do={ :do { /ip dhcp-server lease remove $l; } on-error={}; :set blocked ($blocked + 1); } else={ :set okArp ($okArp . $ip . \",\"); :local a [/ip arp find where address=$ip]; :if ([:len $a] = 0) do={ /ip arp add address=$ip mac-address=$m interface=AP-KUOTA comment=$tag; } else={ :local am [/ip arp get [:pick $a 0] mac-address]; :local ac [:tostr [/ip arp get [:pick $a 0] comment]]; :if ($ac = $tag && $am != $m) do={ /ip arp set [:pick $a 0] mac-address=$m; }; }; :local by \"\"; :local r ($rates->$m); :if ([:typeof $r] = \"str\" && [:len $r] > 0) do={ :local qn ($tag . \"-\" . $m); :set qwanted ($qwanted . $qn . \",\"); :local t ($ip . \"/32\"); :local q [/queue simple find where name=$qn]; :if ([:len $q] = 0) do={ :local first [/queue simple find]; :if ([:len $first] > 0) do={ /queue simple add name=$qn target=$t max-limit=$r comment=$tag place-before=[:pick $first 0]; } else={ /queue simple add name=$qn target=$t max-limit=$r comment=$tag; }; } else={ :if ([/queue simple get $q max-limit] != $r) do={ /queue simple set $q max-limit=$r; }; :if ([:tostr [/queue simple get $q target]] != $t) do={ /queue simple set $q target=$t; }; :set by [:tostr [/queue simple get $q bytes]]; }; }; :set report ($report . $m . \";\" . $ip . \";\" . $hn . \";\" . $by . \"\\n\"); }; };\n:foreach a in=[/ip arp find where comment=$tag] do={ :local ip [:tostr [/ip arp get $a address]]; :if ([:typeof [:find $okArp (\",\" . $ip . \",\")]] = \"nil\") do={ /ip arp remove $a; }; };\n:foreach q in=[/queue simple find where name~(\"^\" . $tag . \"-\")] do={ :local n [/queue simple get $q name]; :if ([:typeof [:find $qwanted (\",\" . $n . \",\")]] = \"nil\") do={ /queue simple remove $q; }; };\n:if ([:len $report] = 0) do={ :set report \"-\"; };\n:do { /tool fetch url=($base . \"/online?key=\" . $key . \"&cabang=\" . $cabang) check-certificate=no http-method=post http-header-field=\"Content-Type: text/plain\" http-data=$report output=none; } on-error={ :log warning \"[WEBMAC] gagal kirim user aktif\"; };\n:if ($blocked > 0) do={ :log info (\"[WEBMAC] HP tidak terdaftar ditolak: \" . $blocked); };\n";

// ---------- Handler utama ----------
export async function onRequest({ request, env }) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/api/, "").replace(/\/+$/, "") || "/";
  const method = request.method.toUpperCase();
  const db = env.DB;
  const pw = env.ADMIN_PASSWORD || "";
  if (!db) return json({ ok: false, pesan: "Database belum disambungkan (binding DB)." }, 500);

  // Cabang permintaan ini: header x-cabang (panel) atau ?cabang= (router). Kosong = BHP.
  const cabRaw = request.headers.get("x-cabang") || url.searchParams.get("cabang") || "";
  const cab = cabRaw ? normCab(cabRaw) : CABANG_DEFAULT;
  if (!cab) return path === "/mikrotik" || path === "/online" || path === "/script"
    ? text("ERROR cabang tidak dikenal\n", 400)
    : json({ ok: false, pesan: "Cabang tidak dikenal." }, 400);
  const namaCab = CABANG[cab];

  try {
    await ensureSchema(db);
    const byMac = (mac) => db.prepare("SELECT * FROM perangkat WHERE mac = ?").bind(mac).first();
    const byId = (id) => db.prepare("SELECT * FROM perangkat WHERE id = ? AND cabang = ?").bind(id, cab).first();
    const perangkatStmt = (d) => db.prepare(insertSql("perangkat", PERANGKAT_COLS))
      .bind(...PERANGKAT_COLS.map((c) => c === "acak" || c === "putus_otomatis" ? (d[c] ? 1 : 0) : (d[c] ?? null)));
    const insertPerangkat = (d) => perangkatStmt(d).run();
    const getSet = async (k) => ((await db.prepare("SELECT nilai FROM pengaturan WHERE kunci = ?").bind(kunci(k, cab)).first()) || {}).nilai;
    const putSet = (k, v) => db.prepare("INSERT INTO pengaturan (kunci, nilai) VALUES (?, ?) ON CONFLICT(kunci) DO UPDATE SET nilai = excluded.nilai").bind(kunci(k, cab), v).run();

    const getDefaultRate = async () => (await getSet("kecepatan_default")) || "";
    const rateOf = (d, def) => { const r = d.kecepatan || def || ""; return r === "0/0" ? "" : r; };
    const macDipakai = (d) => "MAC ini sudah terdaftar" + (d.cabang && d.cabang !== cab ? " di cabang " + (CABANG[d.cabang] || d.cabang) : "") + " atas nama " + (d.nama || "-") + ".";

    // ===== Untuk MikroTik: HP aktif cabang ini yang belum habis masa aktifnya =====
    if (path === "/mikrotik" && method === "GET") {
      const key = env.SYNC_KEY || "";
      if (!key || !safeEqual(url.searchParams.get("key") || "", key)) return text("ERROR kunci salah\n", 403);
      const { results } = await db.prepare("SELECT * FROM perangkat WHERE status = 'aktif' AND cabang = ? ORDER BY mac").bind(cab).all();
      const def = await getDefaultRate();
      const lines = results.filter((d) => !expired(d)).map((d) => d.mac + ";" + asciiName(d.nama) + ";" + rateOf(d, def));
      return text(lines.join("\n") + "\nEND\n");
    }

    // ===== Dari MikroTik: laporan HP yang sedang tersambung di cabang ini =====
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
      await putSet("online", JSON.stringify({ waktu: now(), list }));
      return text("OK " + namaCab + " " + list.length + "\n");
    }

    // ===== Script router (diunduh MikroTik), sudah berisi kode cabang =====
    if (path === "/script" && method === "GET") {
      const key = env.SYNC_KEY || "";
      if (!key || !safeEqual(url.searchParams.get("key") || "", key)) return text("ERROR kunci salah\n", 403);
      return text(routerScript(cab));
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
        acak: isRandomMac(mac), dibuat: now(), diubah: now(), aktif_sampai: null, putus_otomatis: true, cabang: cab, kategori: "pelanggan" });
      return json({ ok: true, pesan: "Pendaftaran terkirim. Tunggu persetujuan admin.", status: "menunggu" });
    }

    if (path === "/cek" && method === "GET") {
      const mac = normMac(url.searchParams.get("mac"));
      if (!mac) return json({ ok: false, pesan: "Format MAC Address tidak valid." }, 400);
      const d = await byMac(mac);
      if (!d) return json({ ok: true, mac, status: "tidak-terdaftar" });
      return json({ ok: true, mac, status: expired(d) ? "habis" : d.status, aktif_sampai: d.aktif_sampai || null, cabang: CABANG[d.cabang] || d.cabang });
    }

    // Data akun dari database (null = tidak ada / diblokir)
    const akun = async (username) => {
      if (username === "admin") return { username: "admin", nama: "Admin Utama", role: "admin", utama: true, cabang: [...CABANG_IDS] };
      const u = await db.prepare("SELECT * FROM pengguna WHERE username = ?").bind(username).first();
      if (!u || !u.aktif) return null;
      return { username: u.username, nama: u.nama, role: u.role, cabang: parseCabList(u.cabang), _hash: u.password };
    };
    const publik = (u) => { const { _hash, ...rest } = u; return rest; };
    const tanpaAkses = (u) => "Akun " + u.username + " tidak punya akses ke cabang " + namaCab + ".";

    if (path === "/login" && method === "POST") {
      if (!pw) return json({ ok: false, pesan: "ADMIN_PASSWORD belum diatur di Cloudflare." }, 500);
      const b = await readBody(request);
      const username = cleanUser(b.username) || "admin";
      const u = await akun(username);
      let okLogin = false;
      if (u && u.utama) okLogin = safeEqual(b.password || "", pw);
      else if (u) { const [salt] = String(u._hash).split(":"); okLogin = safeEqual(await hashPassword(b.password || "", salt), u._hash); }
      if (!okLogin) {
        await new Promise((r) => setTimeout(r, 800));
        return json({ ok: false, pesan: "Username atau password salah." }, 401);
      }
      if (!u.cabang.includes(cab)) return json({ ok: false, pesan: tanpaAkses(u) }, 403);
      if (!u.utama) await db.prepare("UPDATE pengguna SET login_terakhir = ? WHERE username = ?").bind(now(), username).run();
      return json({ ok: true, token: await makeToken(pw, username), user: publik(u) });
    }

    // ===== Semua di bawah ini perlu login =====
    const tokUser = await readToken(request, pw);
    const me = tokUser ? await akun(tokUser) : null;
    if (!me) {
      const known = ["/kecepatan", "/saya", "/pengguna", "/lunas", "/perangkat", "/paket", "/bayar", "/pembayaran", "/keuangan", "/backup", "/restore", "/pengaturan", "/online"];
      if (known.some((p) => path === p || path.startsWith(p + "/"))) return json({ ok: false, pesan: "Sesi habis, silakan login lagi." }, 401);
      return json({ ok: false, pesan: "Alamat tidak dikenal." }, 404);
    }
    // /saya boleh dari cabang mana saja (panel memakainya untuk tahu cabang mana yang boleh dibuka)
    if (path === "/saya") return json({ ok: true, user: publik(me) });
    // Penjaga utama: akun hanya boleh membaca/mengubah data cabang yang diizinkan
    if (!me.cabang.includes(cab)) return json({ ok: false, pesan: tanpaAkses(me) }, 403);

    const seg = path.split("/");
    const id = seg[2];

    // ----- Hak akses -----
    const butuh = (role) => (RANK[me.role] || 0) >= RANK[role];
    const tolak = () => json({ ok: false, pesan: "Akun Anda (" + me.role + ") tidak punya izin untuk ini." }, 403);
    const hanyaAdmin = seg[1] === "pengguna" || (path === "/kecepatan" && method !== "GET") || path === "/restore" || path === "/backup"
      || (path === "/pengaturan" && method !== "GET") || (method === "DELETE");
    if (hanyaAdmin && !butuh("admin")) return tolak();
    if (method !== "GET" && !butuh("operator")) return tolak();

    // ----- Pengguna (akun login, berlaku untuk semua cabang) -----
    if (seg[1] === "pengguna") {
      // Hanya akun utama yang boleh mengatur akun lain, supaya admin satu cabang tidak bisa memberi dirinya akses ke cabang lain
      if (!me.utama) return json({ ok: false, pesan: "Hanya akun utama yang bisa mengatur pengguna." }, 403);
      if (!id && method === "GET") {
        const { results } = await db.prepare("SELECT username, nama, role, aktif, dibuat, login_terakhir, cabang FROM pengguna ORDER BY dibuat").all();
        return json({ ok: true, data: [{ username: "admin", nama: "Admin Utama", role: "admin", aktif: 1, utama: true, cabang: [...CABANG_IDS] },
          ...results.map((u) => ({ ...u, cabang: parseCabList(u.cabang) }))] });
      }
      if (!id && method === "POST") {
        const b = await readBody(request);
        const username = cleanUser(b.username);
        if (username.length < 3) return json({ ok: false, pesan: "Username minimal 3 huruf (a-z, 0-9, titik, strip)." }, 400);
        if (username === "admin") return json({ ok: false, pesan: "Username 'admin' sudah dipakai akun utama." }, 409);
        if (String(b.password || "").length < 6) return json({ ok: false, pesan: "Password minimal 6 karakter." }, 400);
        const role = ROLES.includes(b.role) ? b.role : "operator";
        const cabList = cleanCabList(b.cabang);
        if (!cabList.length) return json({ ok: false, pesan: "Pilih minimal 1 cabang untuk akun ini." }, 400);
        if (await db.prepare("SELECT 1 FROM pengguna WHERE username = ?").bind(username).first()) return json({ ok: false, pesan: "Username sudah ada." }, 409);
        await db.prepare("INSERT INTO pengguna (username, nama, password, role, aktif, dibuat, cabang) VALUES (?, ?, ?, ?, 1, ?, ?)")
          .bind(username, clean(b.nama, 40) || username, await hashPassword(b.password), role, now(), cabList.join(",")).run();
        return json({ ok: true, pesan: "Pengguna " + username + " dibuat (" + cabList.map((c) => CABANG[c]).join(", ") + ")." });
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
        if (b.cabang !== undefined) {
          const cabList = cleanCabList(b.cabang);
          if (!cabList.length) return json({ ok: false, pesan: "Pilih minimal 1 cabang untuk akun ini." }, 400);
          u.cabang = cabList.join(",");
        }
        if (b.password) {
          if (String(b.password).length < 6) return json({ ok: false, pesan: "Password minimal 6 karakter." }, 400);
          u.password = await hashPassword(b.password);
        }
        await db.prepare("UPDATE pengguna SET nama=?, role=?, aktif=?, password=?, cabang=? WHERE username=?")
          .bind(u.nama, u.role, u.aktif, u.password, u.cabang ?? null, u.username).run();
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
        const { results } = await db.prepare("SELECT * FROM perangkat WHERE cabang = ? ORDER BY dibuat DESC").bind(cab).all();
        const { results: ut } = await db.prepare("SELECT perangkat_id, SUM(harga) AS t, COUNT(*) AS n FROM pembayaran WHERE status = 'utang' AND cabang = ? GROUP BY perangkat_id").bind(cab).all();
        const { results: lb } = await db.prepare("SELECT perangkat_id, MAX(tanggal) AS tgl FROM pembayaran WHERE cabang = ? GROUP BY perangkat_id").bind(cab).all();
        const U = Object.fromEntries(ut.map((x) => [x.perangkat_id, x])), LB = Object.fromEntries(lb.map((x) => [x.perangkat_id, x.tgl]));
        const G = {}, GB = {};
        for (const r of results) if (r.grup) { G[r.grup] = (G[r.grup] || 0) + 1; const t = LB[r.id]; if (t && (!GB[r.grup] || t > GB[r.grup])) GB[r.grup] = t; }
        return json({ ok: true, data: results.map((r) => ({ ...row(r), grup_n: r.grup ? G[r.grup] : 1, utang: U[r.id]?.t || 0, utang_n: U[r.id]?.n || 0, bayar_terakhir: (r.grup ? GB[r.grup] : LB[r.id]) || null })),
          kecepatan_default: await getDefaultRate() });
      }
      if (!id && method === "POST") {
        const b = await readBody(request);
        // satu HP: {mac}; beberapa HP satu pelanggan: {macs:[...]}
        const raw = Array.isArray(b.macs) && b.macs.length ? b.macs : [b.mac];
        if (raw.length > 10) return json({ ok: false, pesan: "Maksimal 10 HP sekaligus." }, 400);
        const macs = raw.map(normMac);
        const banyak = macs.length > 1;
        const ke = (i) => (banyak ? "HP ke-" + (i + 1) + ": " : "");
        for (let i = 0; i < macs.length; i++) if (!macs[i]) return json({ ok: false, pesan: ke(i) + "Format MAC tidak valid." }, 400);
        if (new Set(macs).size !== macs.length) return json({ ok: false, pesan: "Ada MAC yang sama dimasukkan dua kali." }, 400);
        for (let i = 0; i < macs.length; i++) { const ada = await byMac(macs[i]); if (ada) return json({ ok: false, pesan: ke(i) + macDipakai(ada) }, 409); }
        const kecepatan = normRate(b.kecepatan);
        if (kecepatan === null) return json({ ok: false, pesan: RATE_ERR }, 400);
        const nama = clean(b.nama, 44) || "tanpa nama", grup = banyak ? newId() : null;
        const items = macs.map((mac, i) => ({ id: newId(), mac, nama: banyak ? nama + " HP" + (i + 1) : nama, hp: clean(b.hp, 20), ket: clean(b.ket, 80),
          status: STATUSES.includes(b.status) ? b.status : "aktif", acak: isRandomMac(mac), dibuat: now(), diubah: now(),
          aktif_sampai: validIso(b.aktif_sampai) ? new Date(b.aktif_sampai).toISOString() : null, putus_otomatis: b.putus_otomatis !== false,
          kecepatan, oleh: me.username, cabang: cab, kategori: normKat(b.kategori), grup }));
        await db.batch(items.map(perangkatStmt));
        return json({ ok: true, data: row(items[0]), items: items.map(row), grup });
      }
      const d = await byId(id);
      if (!d) return json({ ok: false, pesan: "Data tidak ditemukan di cabang " + namaCab + "." }, 404);
      if (method === "PATCH") {
        const b = await readBody(request);
        if (b.status !== undefined) {
          if (!STATUSES.includes(b.status)) return json({ ok: false, pesan: "Status tidak valid." }, 400);
          d.status = b.status;
        }
        if (b.nama !== undefined) d.nama = clean(b.nama, 50) || d.nama;
        if (b.hp !== undefined) d.hp = clean(b.hp, 20);
        if (b.ket !== undefined) d.ket = clean(b.ket, 80);
        if (b.kategori !== undefined) d.kategori = normKat(b.kategori);
        if (b.aktif_sampai !== undefined) d.aktif_sampai = validIso(b.aktif_sampai) ? new Date(b.aktif_sampai).toISOString() : null;
        if (b.putus_otomatis !== undefined) d.putus_otomatis = b.putus_otomatis ? 1 : 0;
        if (b.kecepatan !== undefined) { const r = normRate(b.kecepatan); if (r === null) return json({ ok: false, pesan: RATE_ERR }, 400); d.kecepatan = r; }
        d.diubah = now();
        await db.prepare("UPDATE perangkat SET status=?, nama=?, hp=?, ket=?, aktif_sampai=?, putus_otomatis=?, kecepatan=?, kategori=?, diubah=? WHERE id=? AND cabang=?")
          .bind(d.status, d.nama, d.hp, d.ket, d.aktif_sampai, d.putus_otomatis ? 1 : 0, d.kecepatan ?? "", normKat(d.kategori), d.diubah, d.id, cab).run();
        if (d.grup && ["status", "aktif_sampai", "putus_otomatis", "kecepatan"].some((k) => b[k] !== undefined))
          await db.prepare("UPDATE perangkat SET status=?, aktif_sampai=?, putus_otomatis=?, kecepatan=?, diubah=? WHERE grup=? AND cabang=? AND id!=?")
            .bind(d.status, d.aktif_sampai, d.putus_otomatis ? 1 : 0, d.kecepatan ?? "", d.diubah, d.grup, cab, d.id).run();
        return json({ ok: true, data: row(d) });
      }
      if (method === "DELETE") {
        await db.prepare("DELETE FROM perangkat WHERE id = ? AND cabang = ?").bind(id, cab).run();
        return json({ ok: true });
      }
    }

    // ----- Paket -----
    if (seg[1] === "paket") {
      if (!id && method === "GET") {
        const { results } = await db.prepare("SELECT * FROM paket WHERE cabang = ? ORDER BY urutan, harga").bind(cab).all();
        return json({ ok: true, data: results });
      }
      if (!id && method === "POST") {
        const b = await readBody(request);
        const nama = clean(b.nama, 40);
        if (!nama) return json({ ok: false, pesan: "Nama paket wajib diisi." }, 400);
        const item = { id: newId(), nama, harga: Math.max(0, int(b.harga)), hari: Math.max(0, int(b.hari)), urutan: int(b.urutan, 99), kecepatan: normRate(b.kecepatan), cabang: cab };
        if (item.kecepatan === null) return json({ ok: false, pesan: RATE_ERR }, 400);
        await db.prepare(insertSql("paket", PAKET_COLS)).bind(...PAKET_COLS.map((c) => item[c])).run();
        return json({ ok: true, data: item });
      }
      const p = await db.prepare("SELECT * FROM paket WHERE id = ? AND cabang = ?").bind(id, cab).first();
      if (!p) return json({ ok: false, pesan: "Paket tidak ditemukan." }, 404);
      if (method === "PATCH") {
        const b = await readBody(request);
        if (b.nama !== undefined) p.nama = clean(b.nama, 40) || p.nama;
        if (b.harga !== undefined) p.harga = Math.max(0, int(b.harga));
        if (b.hari !== undefined) p.hari = Math.max(0, int(b.hari));
        if (b.kecepatan !== undefined) { const r = normRate(b.kecepatan); if (r === null) return json({ ok: false, pesan: RATE_ERR }, 400); p.kecepatan = r; }
        await db.prepare("UPDATE paket SET nama=?, harga=?, hari=?, kecepatan=? WHERE id=? AND cabang=?").bind(p.nama, p.harga, p.hari, p.kecepatan ?? "", p.id, cab).run();
        return json({ ok: true, data: p });
      }
      if (method === "DELETE") {
        await db.prepare("DELETE FROM paket WHERE id = ? AND cabang = ?").bind(id, cab).run();
        return json({ ok: true });
      }
    }

    // ----- Catat pembayaran (memperpanjang masa aktif) -----
    if (path === "/bayar" && method === "POST") {
      const b = await readBody(request);
      const d = await byId(b.perangkat_id);
      if (!d) return json({ ok: false, pesan: "Perangkat tidak ditemukan di cabang " + namaCab + "." }, 404);
      let kecepatan = "";
      let paketNama = clean(b.paket, 40) || "Pembayaran", harga = Math.max(0, int(b.harga)), hari = hariNum(b.hari);
      if (b.paket_id) {
        const p = await db.prepare("SELECT * FROM paket WHERE id = ? AND cabang = ?").bind(b.paket_id, cab).first();
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
        sampai = new Date(base + Math.round(hari * 86400000)).toISOString();
      }
      const bayar = { id: newId(), perangkat_id: d.id, mac: d.mac, nama: d.nama, paket: paketNama, harga, hari, tanggal, dari, sampai, catatan: clean(b.catatan, 80), kecepatan: kecBaru,
        status: stBayar, tanggal_lunas: stBayar === "lunas" ? tanggal : null, oleh: me.username, cabang: cab, grup: d.grup || null };
      const nGrup = d.grup ? ((await db.prepare("SELECT COUNT(*) AS n FROM perangkat WHERE grup = ? AND cabang = ?").bind(d.grup, cab).first()) || {}).n || 1 : 1;
      await db.batch([
        db.prepare(insertSql("pembayaran", BAYAR_COLS)).bind(...BAYAR_COLS.map((c) => bayar[c])),
        db.prepare("UPDATE perangkat SET status='aktif', aktif_sampai=?, kecepatan=?, diubah=? WHERE cabang=? AND (id=? OR (grup IS NOT NULL AND grup=?))").bind(sampai, kecBaru, now(), cab, d.id, d.grup || ""),
      ]);
      return json({ ok: true, data: bayar, pesan: (stBayar === "utang" ? "Dicatat sebagai UTANG." : "Pembayaran LUNAS dicatat.") + (sampai ? " Aktif sampai " + new Date(sampai).toLocaleString("id-ID", { timeZone: "Asia/Makassar", day: "2-digit", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" }) + "." : "") + (kecepatan ? " Kecepatan " + kecepatan + "." : "") + (nGrup > 1 ? " Berlaku untuk " + nGrup + " HP." : "") });
    }

    // ----- Lunasi semua utang satu pelanggan -----
    if (path === "/lunas" && method === "POST") {
      const b = await readBody(request);
      const { t, n } = await db.prepare("SELECT COALESCE(SUM(harga),0) AS t, COUNT(*) AS n FROM pembayaran WHERE status = 'utang' AND perangkat_id = ? AND cabang = ?").bind(b.perangkat_id, cab).first();
      if (!n) return json({ ok: false, pesan: "Tidak ada utang." }, 400);
      await db.prepare("UPDATE pembayaran SET status = 'lunas', tanggal_lunas = ? WHERE status = 'utang' AND perangkat_id = ? AND cabang = ?").bind(now(), b.perangkat_id, cab).run();
      return json({ ok: true, pesan: "Lunas. Rp " + Number(t).toLocaleString("id-ID") + " masuk pendapatan hari ini." });
    }

    // ----- Riwayat pembayaran -----
    if (seg[1] === "pembayaran") {
      if (!id && method === "GET") {
        const bulan = url.searchParams.get("bulan"); // YYYY-MM (WITA)
        const st = url.searchParams.get("status");
        const m = (col) => `strftime('%Y-%m', datetime(${col}, '${TZ_OFFSET}'))`;
        let q;
        if (st === "utang") q = db.prepare("SELECT * FROM pembayaran WHERE status = 'utang' AND cabang = ?1 ORDER BY tanggal DESC").bind(cab);
        else if (/^\d{4}-\d{2}$/.test(bulan || "")) q = db.prepare(`SELECT * FROM pembayaran WHERE cabang = ?2 AND (${m("tanggal")} = ?1 OR (status = 'lunas' AND ${m("tanggal_lunas")} = ?1)) ORDER BY tanggal DESC`).bind(bulan, cab);
        else q = db.prepare("SELECT * FROM pembayaran WHERE cabang = ?1 ORDER BY tanggal DESC LIMIT 2000").bind(cab);
        const { results } = await q.all();
        return json({ ok: true, data: results });
      }
      if (id && method === "PATCH") {
        const b = await readBody(request);
        const x = await db.prepare("SELECT * FROM pembayaran WHERE id = ? AND cabang = ?").bind(id, cab).first();
        if (!x) return json({ ok: false, pesan: "Pembayaran tidak ditemukan." }, 404);
        if (b.status === "lunas") {
          const harga = b.harga !== undefined && b.harga !== "" ? Math.max(0, int(b.harga)) : x.harga;
          await db.prepare("UPDATE pembayaran SET status = 'lunas', tanggal_lunas = ?, harga = ? WHERE id = ? AND cabang = ?").bind(now(), harga, id, cab).run();
          return json({ ok: true, pesan: "Lunas. " + harga.toLocaleString("id-ID") + " masuk pendapatan hari ini." });
        }
        if (b.status === "utang") {
          await db.prepare("UPDATE pembayaran SET status = 'utang', tanggal_lunas = NULL WHERE id = ? AND cabang = ?").bind(id, cab).run();
          return json({ ok: true, pesan: "Dikembalikan menjadi utang." });
        }
        return json({ ok: false, pesan: "Status tidak valid." }, 400);
      }
      if (id && method === "DELETE") {
        await db.prepare("DELETE FROM pembayaran WHERE id = ? AND cabang = ?").bind(id, cab).run();
        return json({ ok: true, pesan: "Catatan pembayaran dihapus. Masa aktif HP tidak berubah; ubah lewat Edit bila perlu." });
      }
    }

    // ----- Ringkasan keuangan (per cabang) -----
    if (path === "/keuangan" && method === "GET") {
      const L = `strftime(%F, datetime(tanggal_lunas, '${TZ_OFFSET}'))`;
      const at = (f) => L.replace("%F", f);
      const skr = (f, extra = "") => `strftime(${f}, datetime('now', '${TZ_OFFSET}'${extra}))`;
      const sum = (cond) => db.prepare(`SELECT COALESCE(SUM(harga),0) AS t, COUNT(*) AS n FROM pembayaran WHERE status = 'lunas' AND cabang = ? AND ${cond}`).bind(cab).first();
      const hari_ini = await sum(`${at("'%Y-%m-%d'")} = ${skr("'%Y-%m-%d'")}`);
      const bulan_ini = await sum(`${at("'%Y-%m'")} = ${skr("'%Y-%m'")}`);
      const bulan_lalu = await sum(`${at("'%Y-%m'")} = ${skr("'%Y-%m'", ", 'start of month', '-1 month'")}`);
      const total = await sum("1=1");
      const utang = await db.prepare("SELECT COALESCE(SUM(harga),0) AS t, COUNT(*) AS n FROM pembayaran WHERE status = 'utang' AND cabang = ?").bind(cab).first();
      const { results: per_bulan } = await db.prepare(
        `SELECT ${at("'%Y-%m'")} AS bulan, SUM(harga) AS total, COUNT(*) AS jumlah FROM pembayaran WHERE status = 'lunas' AND cabang = ? GROUP BY bulan ORDER BY bulan DESC LIMIT 12`).bind(cab).all();
      const { results: utang_list } = await db.prepare(
        "SELECT perangkat_id, mac, nama, SUM(harga) AS total, COUNT(*) AS jumlah FROM pembayaran WHERE status = 'utang' AND cabang = ? GROUP BY perangkat_id ORDER BY total DESC LIMIT 50").bind(cab).all();
      const { results: semua } = await db.prepare("SELECT * FROM perangkat WHERE cabang = ?").bind(cab).all();
      const in7 = Date.now() + 7 * 86400000;
      const hampir = semua.filter((d) => d.status === "aktif" && d.aktif_sampai && !expired(d) && Date.parse(d.aktif_sampai) <= in7)
        .map(row).sort((x, y) => x.aktif_sampai.localeCompare(y.aktif_sampai));
      return json({ ok: true, data: {
        hari_ini, bulan_ini, bulan_lalu, total, utang, utang_list, per_bulan: per_bulan.reverse(),
        jumlah_habis: semua.filter((d) => d.status === "aktif" && expired(d)).length, hampir_habis: hampir,
      } });
    }

    // ----- User aktif (laporan terakhir dari router cabang ini) -----
    if (path === "/online" && method === "GET") {
      let rep = { waktu: null, list: [] };
      try { const v = await getSet("online"); if (v) rep = JSON.parse(v); } catch {}
      const { results } = await db.prepare("SELECT * FROM perangkat WHERE cabang = ?").bind(cab).all();
      const def = await getDefaultRate();
      const byM = Object.fromEntries(results.map((d) => [d.mac, d]));
      const data = rep.list.map((o) => {
        const d = byM[o.mac];
        return { ...o, terdaftar: !!d, id: d?.id || null, nama: d?.nama || null, hp: d?.hp || null, kategori: d ? normKat(d.kategori) : null,
          status: d ? (expired(d) ? "habis" : d.status) : null, aktif_sampai: d?.aktif_sampai || null,
          kecepatan: d ? (rateOf(d, def) || "") : "" };
      });
      return json({ ok: true, waktu: rep.waktu, data });
    }

    // ----- Daftar pilihan kecepatan (per cabang) -----
    if (path === "/kecepatan") {
      const getList = async () => { try { return JSON.parse((await getSet("kecepatan_list")) || "[]"); } catch { return []; } };
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
        await putSet("kecepatan_list", JSON.stringify(list));
        return json({ ok: true, data: list, pesan: "Daftar kecepatan disimpan." });
      }
    }

    // ----- Pengaturan (kecepatan default, per cabang) -----
    if (path === "/pengaturan") {
      if (method === "GET") return json({ ok: true, data: { kecepatan_default: await getDefaultRate() } });
      if (method === "PATCH") {
        const b = await readBody(request);
        const r = normRate(b.kecepatan_default);
        if (r === null) return json({ ok: false, pesan: RATE_ERR }, 400);
        await putSet("kecepatan_default", r);
        return json({ ok: true, data: { kecepatan_default: r }, pesan: r && r !== "0/0" ? "Kecepatan default: " + r : "Kecepatan default: tanpa batas" });
      }
    }

    // ----- Backup & restore (per cabang) -----
    // Backup berisi data cabang yang dipilih saja. Akun login tidak ikut di-restore (diatur di menu Pengguna).
    if (path === "/backup" && method === "GET") {
      const all = async (t) => (await db.prepare(`SELECT * FROM ${t} WHERE cabang = ?`).bind(cab).all()).results;
      const pengaturan = [];
      for (const k of PENGATURAN_CABANG) { const v = await getSet(k); if (v !== undefined && v !== null) pengaturan.push({ kunci: k, nilai: v }); }
      return json({ aplikasi: "portal-mac", versi: 5, cabang: cab, nama_cabang: namaCab, dibuat: now(), pengaturan,
        perangkat: await all("perangkat"), paket: await all("paket"), pembayaran: await all("pembayaran") });
    }
    if (path === "/restore" && method === "POST") {
      const b = await readBody(request);
      if (b.aplikasi !== "portal-mac" || !Array.isArray(b.perangkat)) return json({ ok: false, pesan: "File backup tidak dikenali." }, 400);
      if (b.cabang && normCab(b.cabang) && normCab(b.cabang) !== cab)
        return json({ ok: false, pesan: "File ini backup cabang " + (CABANG[normCab(b.cabang)]) + ", bukan " + namaCab + ". Pilih cabang yang sesuai dulu." }, 400);
      const pick = (o, cols) => cols.map((c) => (o[c] === undefined ? null : o[c]));
      const stmts = [
        db.prepare("DELETE FROM perangkat WHERE cabang = ?").bind(cab),
        db.prepare("DELETE FROM paket WHERE cabang = ?").bind(cab),
        db.prepare("DELETE FROM pembayaran WHERE cabang = ?").bind(cab),
      ];
      if (Array.isArray(b.pengaturan)) {
        for (const k of PENGATURAN_CABANG) stmts.push(db.prepare("DELETE FROM pengaturan WHERE kunci = ?").bind(kunci(k, cab)));
        for (const x of b.pengaturan) {
          // backup lama memakai kunci tanpa akhiran; ambil hanya pengaturan milik cabang
          const k = String((x && x.kunci) || "").split(":")[0];
          if (PENGATURAN_CABANG.includes(k)) stmts.push(db.prepare("INSERT OR REPLACE INTO pengaturan (kunci, nilai) VALUES (?, ?)").bind(kunci(k, cab), String(x.nilai ?? "")));
        }
      }
      // MAC yang sudah dipakai cabang lain dilewati (satu HP hanya boleh di satu cabang)
      const { results: lain } = await db.prepare("SELECT mac FROM perangkat WHERE cabang != ?").bind(cab).all();
      const macLain = new Set(lain.map((x) => x.mac));
      let nPerangkat = 0, dilewati = 0;
      const seen = new Set();
      for (const d of b.perangkat) {
        const mac = normMac(d.mac);
        if (!mac || !d.id || seen.has(mac)) continue;
        if (macLain.has(mac)) { dilewati++; continue; }
        seen.add(mac); nPerangkat++;
        stmts.push(db.prepare(insertSql("perangkat", PERANGKAT_COLS, true)).bind(...pick({ ...d, mac, cabang: cab,
          kategori: normKat(d.kategori), acak: d.acak ? 1 : 0, putus_otomatis: d.putus_otomatis === undefined ? 1 : (d.putus_otomatis ? 1 : 0),
          status: STATUSES.includes(d.status) ? d.status : "menunggu" }, PERANGKAT_COLS)));
      }
      for (const p of b.paket || []) if (p.id && p.nama) stmts.push(db.prepare(insertSql("paket", PAKET_COLS, true)).bind(...pick({ ...p, cabang: cab }, PAKET_COLS)));
      for (const p of b.pembayaran || []) if (p.id && p.tanggal) stmts.push(db.prepare(insertSql("pembayaran", BAYAR_COLS, true)).bind(...pick({ ...p, cabang: cab }, BAYAR_COLS)));
      await db.batch(stmts);
      return json({ ok: true, pesan: `Restore ${namaCab} selesai: ${nPerangkat} perangkat, ${(b.paket || []).length} paket, ${(b.pembayaran || []).length} pembayaran.`
        + (dilewati ? ` ${dilewati} HP dilewati karena sudah terdaftar di cabang lain.` : "") });
    }

    return json({ ok: false, pesan: "Alamat tidak dikenal." }, 404);
  } catch (e) {
    return json({ ok: false, pesan: "Kesalahan server: " + e.message }, 500);
  }
}
