# Portal Daftar MAC Address HP — Julfikar.Com Wifi

Alurnya: pelanggan mendaftarkan MAC di website, admin menyetujui, lalu MikroTik mengambil daftar MAC yang **aktif** tiap 2 menit dan memasukkannya ke User Manager (RADIUS) atau Hotspot IP Binding.

```
HP pelanggan ──► Website (Netlify) ◄── MikroTik ambil daftar tiap 2 menit (/tool fetch)
                   │
                Netlify Blobs (data tersimpan di server, sama di HP & laptop)
```

Data disimpan di server (Netlify Blobs), bukan di browser, jadi yang diinput dari HP langsung terlihat di laptop.

## Isi folder
| File | Fungsi |
|---|---|
| `public/index.html` | Halaman website (Daftar, Cek Status, Admin) |
| `netlify/functions/api.mjs` | Backend: simpan data, login admin, daftar untuk MikroTik |
| `netlify.toml`, `package.json` | Pengaturan Netlify |
| `mikrotik/sync-webmac.rsc` | Script MikroTik |

## 1. Upload ke GitHub & Netlify
1. Buat repository baru di GitHub, upload **semua isi folder ini** (dengan struktur folder yang sama).
2. Di Netlify: **Add new site → Import from Git →** pilih repo tersebut. Build command dikosongkan, publish directory `public` (sudah diatur di `netlify.toml`).
   - Kalau mau tetap pakai situs `resapi-apsyakila`: buka situs itu → **Site configuration → Build & deploy → Link repository**.
3. **Site configuration → Environment variables**, tambahkan:
   - `ADMIN_PASSWORD` = password admin (buat yang panjang)
   - `SYNC_KEY` = kunci acak panjang untuk MikroTik, misalnya `wM8q2Lx7Pa91Kd4Z`
4. **Deploys → Trigger deploy → Clear cache and deploy site**.
5. Tes: buka `https://NAMA-SITUS.netlify.app/api/mikrotik?key=SYNC_KEY_BAPAK` — harus muncul tulisan `END`.

> Upload dengan cara drag & drop **tidak bisa** menjalankan backend. Harus lewat GitHub (atau Netlify CLI).

## 2. Pasang di MikroTik (RouterOS v7)
1. Winbox → **System → Scripts → +**
   - Name: `sync-webmac`
   - Policy: centang `ftp, read, write, policy, test`
   - Source: tempel isi `mikrotik/sync-webmac.rsc`, lalu **ganti URL dan SYNC_KEY** di baris paling atas.
   - Pilih `mode`: `usermanager` (DHCP use RADIUS) atau `hotspot` (IP Binding bypass).
2. Klik **Run Script** sekali, lalu cek **Log**, dan cek **User Manager → Users** (atau IP → Hotspot → IP Bindings).
3. Buat jadwal otomatis lewat Terminal:
   ```
   /system scheduler add name=sync-webmac interval=2m on-event="/system script run sync-webmac" policy=ftp,read,write,policy,test
   ```

### Kalau pakai mode `usermanager` (DHCP use RADIUS)
Pastikan sudah ada:
```
/radius add service=dhcp address=127.0.0.1 secret=RAHASIA_RADIUS
/user-manager set enabled=yes
/user-manager router add name=lokal address=127.0.0.1 shared-secret=RAHASIA_RADIUS
/ip dhcp-server set [find name=NAMA_DHCP] use-radius=yes
```
MikroTik mengirim MAC HP sebagai username (format `AA:BB:CC:DD:EE:FF`), dan script membuat user dengan nama persis seperti itu. **Uji dulu dengan 1 HP** sebelum dipakai semua pelanggan. Sebaiknya *lease time* DHCP dibuat pendek (30 menit–1 jam) supaya HP yang dinonaktifkan cepat terputus.

## Catatan keamanan
- Script hanya menghapus entri yang komentarnya diawali `WEBMAC`. User atau binding yang dibuat manual tidak akan disentuh.
- Kalau website error atau datanya terpotong, script **membatalkan sinkron** dan tidak menghapus apa pun.
- Jangan sebarkan `SYNC_KEY`. Kalau bocor, ganti di Netlify dan di script.
