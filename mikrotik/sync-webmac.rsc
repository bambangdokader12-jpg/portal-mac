# =====================================================================
#  SYNC MAC ADDRESS DARI WEBSITE -> MIKROTIK  (RouterOS v7)
#  Tempel isi ini di: Winbox > System > Scripts > + > Name: sync-webmac
#  Policy yang dicentang: ftp, read, write, policy, test
# =====================================================================

# ---------- PENGATURAN (ubah sesuai jaringan Bapak) ----------
:local url "https://resapi-apsyakila.netlify.app/api/mikrotik?key=GANTI_DENGAN_SYNC_KEY"
# mode: "usermanager" = DHCP Server use RADIUS + User Manager (MAC jadi username)
#       "hotspot"     = IP Hotspot > IP Bindings type=bypassed
:local mode "usermanager"
:local umGroup "default"
:local tag "WEBMAC"
# -------------------------------------------------------------

:local res
:do {
  :set res [/tool fetch url=$url check-certificate=no output=user as-value]
} on-error={
  :log warning "[WEBMAC] gagal mengambil daftar dari website"
  :error "fetch gagal"
}

:if (($res->"status") != "finished") do={
  :log warning "[WEBMAC] fetch belum selesai / gagal"
  :error "fetch gagal"
}

:local data ($res->"data")

# Pengaman: kalau data terpotong / kunci salah, JANGAN hapus apa-apa
:if ([:typeof [:find $data "END"]] = "nil" || [:typeof [:find $data "ERROR"]] != "nil") do={
  :log warning "[WEBMAC] data dari website tidak lengkap, sinkron dibatalkan"
  :error "data tidak valid"
}

:local wanted ","
:local added 0
:local removed 0
:local pos 0
:local total [:len $data]

# ---------- Tambah MAC yang aktif di website ----------
:while ($pos < $total) do={
  :local nl [:find $data "\n" ($pos - 1)]
  :if ([:typeof $nl] = "nil") do={ :set nl $total }
  :local line [:pick $data $pos $nl]
  :set pos ($nl + 1)
  :if ([:len $line] > 0 && [:pick $line ([:len $line] - 1)] = "\r") do={ :set line [:pick $line 0 ([:len $line] - 1)] }

  :if ([:len $line] > 17 && [:pick $line 17 18] = ";") do={
    :local mac [:pick $line 0 17]
    :local nama [:pick $line 18 [:len $line]]
    :set wanted ($wanted . $mac . ",")

    :if ($mode = "usermanager") do={
      :if ([:len [/user-manager user find where name=$mac]] = 0) do={
        /user-manager user add name=$mac group=$umGroup comment=($tag . " " . $nama)
        :set added ($added + 1)
      }
    }
    :if ($mode = "hotspot") do={
      :if ([:len [/ip hotspot ip-binding find where mac-address=$mac]] = 0) do={
        /ip hotspot ip-binding add mac-address=$mac type=bypassed comment=($tag . " " . $nama)
        :set added ($added + 1)
      }
    }
  }
}

# ---------- Hapus MAC yang sudah tidak aktif / dihapus di website ----------
# (hanya yang dibuat oleh script ini, ditandai komentar WEBMAC)
:if ($mode = "usermanager") do={
  :foreach i in=[/user-manager user find where comment~("^" . $tag)] do={
    :local m [/user-manager user get $i name]
    :if ([:typeof [:find $wanted ("," . $m . ",")]] = "nil") do={
      /user-manager user remove $i
      # putuskan juga lease DHCP-nya supaya HP langsung terputus
      :do { /ip dhcp-server lease remove [find where mac-address=$m dynamic=yes] } on-error={}
      :set removed ($removed + 1)
    }
  }
}
:if ($mode = "hotspot") do={
  :foreach i in=[/ip hotspot ip-binding find where comment~("^" . $tag)] do={
    :local m [/ip hotspot ip-binding get $i mac-address]
    :if ([:typeof [:find $wanted ("," . $m . ",")]] = "nil") do={
      /ip hotspot ip-binding remove $i
      :set removed ($removed + 1)
    }
  }
}

:if ($added > 0 || $removed > 0) do={
  :log info ("[WEBMAC] sinkron selesai: tambah " . $added . ", hapus " . $removed)
}
