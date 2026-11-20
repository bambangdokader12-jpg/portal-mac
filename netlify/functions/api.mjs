// Portal Daftar MAC Address HP — backend (Netlify Function + Netlify Blobs)
// Variabel lingkungan yang WAJIB diisi di Netlify (Site settings > Environment variables):
//   ADMIN_PASSWORD : password untuk masuk halaman admin
//   SYNC_KEY       : kunci rahasia yang dipakai script MikroTik untuk mengambil daftar MAC
import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

const STORE_NAME = "mac-portal";
const DATA_KEY = "perangkat";
const TOKEN_TTL_MS = 12 * 60 * 60 * 1000; // login admin berlaku 12 jam
const MAX_PENDING = 300; // batas pendaftaran yang menunggu persetujuan (anti-spam)

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
  if (hex.length !== 12) return null;
  if (hex === "000000000000" || hex === "FFFFFFFFFFFF") return null;
  return hex.match(/../g).join(":");
}

// Bit "locally administered" menyala = MAC acak (Private Address) dari HP
export function isRandomMac(mac) {
  return (parseInt(mac[1], 16) & 2) === 2;
}

function clean(s, max = 60) {
  return String(s || "")
    .replace(/[\u0000-\u001f\u007f;"\\$]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, max);
}

// Nama untuk MikroTik: hanya karakter aman
function asciiName(s) {
  return clean(s, 40).replace(/[^A-Za-z0-9 ._\-]/g, "").trim() || "tanpa-nama";
}

function safeEqual(a, b) {
  const A = Buffer.from(String(a));
  const B = Buffer.from(String(b));
  return A.length === B.length && crypto.timingSafeEqual(A, B);
}

function sign(payload) {
  return crypto.createHmac("sha256", process.env.ADMIN_PASSWORD || "").update(payload).digest("hex");
}

function makeToken() {
  const exp = String(Date.now() + TOKEN_TTL_MS);
  return exp + "." + sign("admin:" + exp);
}

function isAdmin(req) {
  if (!process.env.ADMIN_PASSWORD) return false;
  const t = (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
  const [exp, sig] = t.split(".");
  if (!exp || !sig || Number(exp) < Date.now()) return false;
  return safeEqual(sig, sign("admin:" + exp));
}

async function readBody(req) {
  try {
    return await req.json();
  } catch {
    return {};
  }
}

const now = () => new Date().toISOString();
const newId = () => crypto.randomBytes(6).toString("hex");

// ---------- Handler utama ----------
export default async (req) => {
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/api/, "").replace(/\/+$/, "") || "/";
  const method = req.method.toUpperCase();
  const store = getStore({ name: STORE_NAME, consistency: "strong" });

  const load = async () => (await store.get(DATA_KEY, { type: "json" })) || [];
  const save = (list) => store.setJSON(DATA_KEY, list);

  try {
    // ===== Untuk MikroTik: daftar MAC yang aktif, format "MAC;nama" per baris =====
    if (path === "/mikrotik" && method === "GET") {
      const key = process.env.SYNC_KEY || "";
      if (!key || !safeEqual(url.searchParams.get("key") || "", key)) return text("ERROR kunci salah\n", 403);
      const list = await load();
      const lines = list.filter((d) => d.status === "aktif").map((d) => d.mac + ";" + asciiName(d.nama));
      return text(lines.join("\n") + "\nEND\n");
    }

    // ===== Publik: pendaftaran oleh pelanggan =====
    if (path === "/daftar" && method === "POST") {
      const b = await readBody(req);
      const mac = normMac(b.mac);
      const nama = clean(b.nama, 50);
      const hp = clean(b.hp, 20);
      if (!mac) return json({ ok: false, pesan: "Format MAC Address tidak valid. Contoh: A4:5E:60:12:34:56" }, 400);
      if (nama.length < 2) return json({ ok: false, pesan: "Nama wajib diisi." }, 400);

      const list = await load();
      const ada = list.find((d) => d.mac === mac);
      if (ada) {
        return json({ ok: true, pesan: "MAC ini sudah terdaftar dengan status: " + ada.status.toUpperCase() + ".", status: ada.status });
      }
      if (list.filter((d) => d.status === "menunggu").length >= MAX_PENDING) {
        return json({ ok: false, pesan: "Antrian pendaftaran penuh. Silakan hubungi admin." }, 429);
      }
      list.push({
        id: newId(), mac, nama, hp, ket: clean(b.ket, 80),
        status: "menunggu", acak: isRandomMac(mac), dibuat: now(), diubah: now(),
      });
      await save(list);
      return json({ ok: true, pesan: "Pendaftaran terkirim. Tunggu persetujuan admin.", status: "menunggu" });
    }

    // ===== Publik: cek status =====
    if (path === "/cek" && method === "GET") {
      const mac = normMac(url.searchParams.get("mac"));
      if (!mac) return json({ ok: false, pesan: "Format MAC Address tidak valid." }, 400);
      const d = (await load()).find((x) => x.mac === mac);
      return json({ ok: true, mac, status: d ? d.status : "tidak-terdaftar" });
    }

    // ===== Login admin =====
    if (path === "/login" && method === "POST") {
      if (!process.env.ADMIN_PASSWORD) return json({ ok: false, pesan: "ADMIN_PASSWORD belum diatur di Netlify." }, 500);
      const b = await readBody(req);
      if (!safeEqual(b.password || "", process.env.ADMIN_PASSWORD)) {
        await new Promise((r) => setTimeout(r, 800));
        return json({ ok: false, pesan: "Password salah." }, 401);
      }
      return json({ ok: true, token: makeToken() });
    }

    // ===== Semua di bawah ini khusus admin =====
    if (path.startsWith("/perangkat")) {
      if (!isAdmin(req)) return json({ ok: false, pesan: "Sesi habis, silakan login lagi." }, 401);
      const list = await load();
      const id = path.split("/")[2];

      if (!id && method === "GET") return json({ ok: true, data: list });

      if (!id && method === "POST") {
        const b = await readBody(req);
        const mac = normMac(b.mac);
        if (!mac) return json({ ok: false, pesan: "Format MAC tidak valid." }, 400);
        if (list.some((d) => d.mac === mac)) return json({ ok: false, pesan: "MAC sudah ada di daftar." }, 409);
        const item = {
          id: newId(), mac, nama: clean(b.nama, 50) || "tanpa nama", hp: clean(b.hp, 20), ket: clean(b.ket, 80),
          status: ["aktif", "menunggu", "nonaktif"].includes(b.status) ? b.status : "aktif",
          acak: isRandomMac(mac), dibuat: now(), diubah: now(),
        };
        list.push(item);
        await save(list);
        return json({ ok: true, data: item });
      }

      const idx = list.findIndex((d) => d.id === id);
      if (idx < 0) return json({ ok: false, pesan: "Data tidak ditemukan." }, 404);

      if (method === "PATCH") {
        const b = await readBody(req);
        const d = list[idx];
        if (b.status !== undefined) {
          if (!["aktif", "menunggu", "nonaktif"].includes(b.status)) return json({ ok: false, pesan: "Status tidak valid." }, 400);
          d.status = b.status;
        }
        if (b.nama !== undefined) d.nama = clean(b.nama, 50) || d.nama;
        if (b.hp !== undefined) d.hp = clean(b.hp, 20);
        if (b.ket !== undefined) d.ket = clean(b.ket, 80);
        d.diubah = now();
        await save(list);
        return json({ ok: true, data: d });
      }

      if (method === "DELETE") {
        list.splice(idx, 1);
        await save(list);
        return json({ ok: true });
      }
    }

    return json({ ok: false, pesan: "Alamat tidak dikenal." }, 404);
  } catch (e) {
    console.error(e);
    return json({ ok: false, pesan: "Kesalahan server: " + e.message }, 500);
  }
};

export const config = { path: "/api/*" };
