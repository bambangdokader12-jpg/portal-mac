// Portal Daftar MAC Address HP — backend untuk Cloudflare Pages Functions + D1
// Yang WAJIB diatur di Cloudflare (Pages project > Settings):
//   Bindings  : D1 database, Variable name = DB
//   Variables : ADMIN_PASSWORD (password admin), SYNC_KEY (kunci untuk MikroTik)

const TOKEN_TTL_MS = 12 * 60 * 60 * 1000; // login admin berlaku 12 jam
const MAX_PENDING = 300;
const STATUSES = ["aktif", "menunggu", "nonaktif"];
const enc = new TextEncoder();

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
const text = (body, status = 200) =>
  new Response(body, {
    status,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
  });

// ---------- Bantuan ----------
export function normMac(s) {
  const hex = String(s || "").toUpperCase().replace(/[^0-9A-F]/g, "");
  if (hex.length !== 12 || hex === "000000000000" || hex === "FFFFFFFFFFFF") return null;
  return hex.match(/../g).join(":");
}
const isRandomMac = (mac) => (parseInt(mac[1], 16) & 2) === 2;

function clean(s, max = 60) {
  return String(s || "").replace(/[\u0000-\u001f\u007f;"\\$]/g, " ").replace(/\s+/g, " ").trim().slice(0, max);
}
const asciiName = (s) => clean(s, 40).replace(/[^A-Za-z0-9 ._\-]/g, "").replace(/\s+/g, " ").trim() || "tanpa-nama";

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

async function makeToken(pw) {
  const exp = String(Date.now() + TOKEN_TTL_MS);
  return exp + "." + (await hmac(pw, "admin:" + exp));
}
async function isAdmin(request, pw) {
  if (!pw) return false;
  const t = (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
  const [exp, sig] = t.split(".");
  if (!exp || !sig || Number(exp) < Date.now()) return false;
  return safeEqual(sig, await hmac(pw, "admin:" + exp));
}
async function readBody(req) {
  try { return await req.json(); } catch { return {}; }
}
const row = (r) => r && { ...r, acak: !!r.acak };

let schemaReady = false;
async function ensureSchema(db) {
  if (schemaReady) return;
  await db.prepare(
    `CREATE TABLE IF NOT EXISTS perangkat (
      id TEXT PRIMARY KEY, mac TEXT UNIQUE NOT NULL, nama TEXT, hp TEXT, ket TEXT,
      status TEXT NOT NULL, acak INTEGER DEFAULT 0, dibuat TEXT, diubah TEXT)`
  ).run();
  schemaReady = true;
}

// ---------- Handler utama ----------
export async function onRequest({ request, env }) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/api/, "").replace(/\/+$/, "") || "/";
  const method = request.method.toUpperCase();
  const db = env.DB;
  const pw = env.ADMIN_PASSWORD || "";

  if (!db) return json({ ok: false, pesan: "Database belum disambungkan. Tambahkan binding D1 dengan nama DB di Cloudflare." }, 500);

  try {
    await ensureSchema(db);
    const byMac = (mac) => db.prepare("SELECT * FROM perangkat WHERE mac = ?").bind(mac).first();
    const byId = (id) => db.prepare("SELECT * FROM perangkat WHERE id = ?").bind(id).first();
    const insert = (d) =>
      db.prepare("INSERT INTO perangkat (id,mac,nama,hp,ket,status,acak,dibuat,diubah) VALUES (?,?,?,?,?,?,?,?,?)")
        .bind(d.id, d.mac, d.nama, d.hp, d.ket, d.status, d.acak ? 1 : 0, d.dibuat, d.diubah).run();

    // ===== Untuk MikroTik =====
    if (path === "/mikrotik" && method === "GET") {
      const key = env.SYNC_KEY || "";
      if (!key || !safeEqual(url.searchParams.get("key") || "", key)) return text("ERROR kunci salah\n", 403);
      const { results } = await db.prepare("SELECT mac, nama FROM perangkat WHERE status = 'aktif' ORDER BY mac").all();
      return text(results.map((d) => d.mac + ";" + asciiName(d.nama)).join("\n") + "\nEND\n");
    }

    // ===== Publik: pendaftaran =====
    if (path === "/daftar" && method === "POST") {
      const b = await readBody(request);
      const mac = normMac(b.mac);
      const nama = clean(b.nama, 50);
      if (!mac) return json({ ok: false, pesan: "Format MAC Address tidak valid. Contoh: A4:5E:60:12:34:56" }, 400);
      if (nama.length < 2) return json({ ok: false, pesan: "Nama wajib diisi." }, 400);
      const ada = await byMac(mac);
      if (ada) return json({ ok: true, pesan: "MAC ini sudah terdaftar dengan status: " + ada.status.toUpperCase() + ".", status: ada.status });
      const { n } = await db.prepare("SELECT COUNT(*) AS n FROM perangkat WHERE status = 'menunggu'").first();
      if (n >= MAX_PENDING) return json({ ok: false, pesan: "Antrian pendaftaran penuh. Silakan hubungi admin." }, 429);
      await insert({ id: newId(), mac, nama, hp: clean(b.hp, 20), ket: clean(b.ket, 80), status: "menunggu", acak: isRandomMac(mac), dibuat: now(), diubah: now() });
      return json({ ok: true, pesan: "Pendaftaran terkirim. Tunggu persetujuan admin.", status: "menunggu" });
    }

    // ===== Publik: cek status =====
    if (path === "/cek" && method === "GET") {
      const mac = normMac(url.searchParams.get("mac"));
      if (!mac) return json({ ok: false, pesan: "Format MAC Address tidak valid." }, 400);
      const d = await byMac(mac);
      return json({ ok: true, mac, status: d ? d.status : "tidak-terdaftar" });
    }

    // ===== Login admin =====
    if (path === "/login" && method === "POST") {
      if (!pw) return json({ ok: false, pesan: "ADMIN_PASSWORD belum diatur di Cloudflare." }, 500);
      const b = await readBody(request);
      if (!safeEqual(b.password || "", pw)) {
        await new Promise((r) => setTimeout(r, 800));
        return json({ ok: false, pesan: "Password salah." }, 401);
      }
      return json({ ok: true, token: await makeToken(pw) });
    }

    // ===== Khusus admin =====
    if (path === "/perangkat" || path.startsWith("/perangkat/")) {
      if (!(await isAdmin(request, pw))) return json({ ok: false, pesan: "Sesi habis, silakan login lagi." }, 401);
      const id = path.split("/")[2];

      if (!id && method === "GET") {
        const { results } = await db.prepare("SELECT * FROM perangkat ORDER BY dibuat DESC").all();
        return json({ ok: true, data: results.map(row) });
      }

      if (!id && method === "POST") {
        const b = await readBody(request);
        const mac = normMac(b.mac);
        if (!mac) return json({ ok: false, pesan: "Format MAC tidak valid." }, 400);
        if (await byMac(mac)) return json({ ok: false, pesan: "MAC sudah ada di daftar." }, 409);
        const item = {
          id: newId(), mac, nama: clean(b.nama, 50) || "tanpa nama", hp: clean(b.hp, 20), ket: clean(b.ket, 80),
          status: STATUSES.includes(b.status) ? b.status : "aktif", acak: isRandomMac(mac), dibuat: now(), diubah: now(),
        };
        await insert(item);
        return json({ ok: true, data: item });
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
        d.diubah = now();
        await db.prepare("UPDATE perangkat SET status=?, nama=?, hp=?, ket=?, diubah=? WHERE id=?")
          .bind(d.status, d.nama, d.hp, d.ket, d.diubah, d.id).run();
        return json({ ok: true, data: row(d) });
      }

      if (method === "DELETE") {
        await db.prepare("DELETE FROM perangkat WHERE id = ?").bind(id).run();
        return json({ ok: true });
      }
    }

    return json({ ok: false, pesan: "Alamat tidak dikenal." }, 404);
  } catch (e) {
    return json({ ok: false, pesan: "Kesalahan server: " + e.message }, 500);
  }
}
