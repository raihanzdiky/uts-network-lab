# Dokumentasi Hasil UTS Praktikum Network Security (Pertemuan 1–7)

Dokumentasi ini merangkum keseluruhan pelaksanaan, struktur lab, ringkasan hasil pengujian, serta status pengerjaan Ujian Tengah Semester (UTS) Praktikum *Network Security* dari Pertemuan 1 hingga Pertemuan 7.

---

## 1. Identitas Mahasiswa & Penentuan Studi Kasus

| Parameter | Keterangan |
| :--- | :--- |
| **Nama Mahasiswa** | Diky Raihan Subagja |
| **NIM** | `24552011194` |
| **Perhitungan Kasus** | $2 + 4 + 5 + 5 + 2 + 0 + 1 + 1 + 1 + 9 + 4 = 34 \rightarrow 34 \bmod 10 = 4$ |
| **Studi Kasus** | **Kasus 4 (`k4`)** |
| **Domain Eksfiltrasi** | `k4.exfil.lab` |
| **Berkas Laporan Utama** | `jawaban.md` |

---

## 2. Struktur Direktori Proyek

Seluruh praktikum dijalankan di dalam lingkungan jaringan terisolasi (`internal: true` / *user-defined bridge*) menggunakan Docker dan Docker Compose tanpa mengubah struktur bawaan repositori:

```text
uts-network-lab/
├── README.md                  # Panduan & ringkasan dokumentasi praktikum
├── jawaban.md                 # Laporan lengkap berisi perintah, output log, dan analisis
├── images/                    # Definisi Docker image praktikum
│   ├── uts-openssl/           # Tools kriptografi OpenSSL
│   ├── uts-kali-tools/        # Tools jaringan & keamanan (hping3, dsniff, scapy, aircrack-ng, tcpdump, dig)
│   └── uts-dnsmasq/           # Server DNS lokal untuk simulasi eksfiltrasi
├── b/                         # Lingkungan Docker Compose Bagian B & C
│   ├── b1-compose/            # Lab jaringan terisolasi (target & attacker)
│   ├── b3-syn-flood/          # Lab simulasi serangan SYN Flood & TCP Handshake
│   └── b4-dns-exfil/          # Lab simulasi DNS Tunneling / Exfiltration
└── kasus/                     # Skrip pendukung studi kasus
    ├── k5-scapy/kirim_icmp.py # Pengirim paket ICMP Echo Request berbasis Scapy
    └── k9-dns-detect/analisis_dns.py # Penganalisis log DNS untuk deteksi eksfiltrasi
```

---

## 3. Ringkasan Hasil Pengerjaan (Awal – Akhir)

### Bagian A: Soal Mudah (Dasar Docker, Kriptografi & Jaringan)
1. **A1 — Container Dasar & Port Mapping:** Menjalankan `nginx:alpine` (`web-uts`) pada port host `8088:80`, memverifikasi respons HTTP `200 OK` via `curl`, dan memeriksa konfigurasi `/etc/nginx/nginx.conf`.
2. **A2 — Persistensi Volume:** Menyimpan NIM `24552011194` ke volume `data-uts` (`/data/catatan.txt`), menghapus container pembuatnya (`w1`), dan membuktikan data tetap persisten saat diakses container baru.
3. **A3 — Integritas File dengan Hash:** Membuktikan *avalanche effect* melalui perubahan nilai hash MD5 dan SHA-256 secara drastis hanya akibat perubahan satu huruf (`pesan` $\rightarrow$ `pesaN`).
4. **A4 — Enkripsi Simetris OpenSSL:** Mengamankan berkas menggunakan algoritma `AES-256-CBC` dengan derivasi kunci `PBKDF2` dan *salt*, memvalidasi kegagalan dekripsi pada sandi salah (`bad decrypt`), serta menghasilkan format *ciphertext* Base64.
5. **A5 — Jaringan Bridge & Resolusi DNS Internal:** Menghubungkan `host-a`, `host-b`, dan `dvwa` ke jaringan `lab-net` sehingga komunikasi ICMP dan permintaan HTTP berhasil dilakukan menggunakan nama container.

---

### Bagian B: Soal Medium (Isolasi Lab, PKI & Analisis Serangan)
1. **B1 — Jaringan Terisolasi dengan Docker Compose:** Mengoperasikan layanan `target` dan `attacker` pada jaringan `internal: true` tanpa eksposur port ke jaringan publik/host.
2. **B2 — Kriptografi Asimetris RSA & Sertifikat X.509:** Membuat pasangan kunci RSA 2048-bit, melakukan penandatanganan digital SHA-256 (`Verified OK` vs `Verification failure` saat berkas dimodifikasi), serta menerbitkan sertifikat *self-signed* (`CN=lab.uts.local`).
3. **B3 — SYN Flood & Deteksinya:** Mengamati lonjakan koneksi setengah terbuka (`SYN_RECV`) dari `0` menjadi `193` akibat serangan `hping3 --flood`, serta menerapkan mitigasi `net.ipv4.tcp_syncookies=1`.
4. **B4 — DNS Tunneling / Exfiltration:** Mengonversi NIM `24552011194` ke representasi heksadesimal (`3234353532303131313934`), mengirimkannya sebagai subdomain `3234353532303131313934.exfil.lab`, dan mendekodenya kembali.

---

### Bagian C: Studi Kasus 4 (`k4` — Pertemuan 1–7)

| Tugas | Topik Praktikum | Ringkasan Bukti & Analisis | Status |
| :--- | :--- | :--- | :---: |
| **Tugas 1** | Docker & Volume (`k4`) | Persistensi NIM `24552011194` pada volume `vol-k4` (`/data/laporan-k4.txt`) dan akses internal `http://target` pada project `k4`. | Selesai |
| **Tugas 2** | Kriptografi (`k4`) | Enkripsi `laporan-k4.txt` dengan sandi `kunci-k4-2026`, verifikasi kesamaan hash SHA-256 (`5b821312...`) pasca-dekripsi, dan sertifikat `CN=k4.uts.local`. | Selesai |
| **Tugas 3** | ARP Spoofing & Static ARP | ARP *cache poisoning* pada `lab-arp-k4` mengubah MAC gateway `172.20.0.3` ke MAC penyerang (`Flags 0x2`), lalu dipulihkan secara permanen (`Flags 0x6`) dengan *Static ARP*. | Selesai |
| **Tugas 4** | Analisis Handshake WPA2 | Berkas `handshake-k4.cap` & `wordlist-k4.txt` tidak tersedia di direktori praktikum; dilengkapi analisis lengkap 4 langkah proses *4-way handshake* WPA2 (ANonce, SNonce, PTK, MIC, GTK). | Analisis Lengkap |
| **Tugas 5** | ICMP dengan Scapy | Pengiriman paket ICMP *Echo Request* ke `172.20.0.2` menghasilkan balasan tipe `0` (*Echo Reply*) dengan `TTL=64`, disertai analisis mekanisme & mitigasi *Smurf Attack*. | Selesai |
| **Tugas 6** | SYN Flood & TCP Handshake | Lonjakan antrean `SYN_RECV` dari `0` ke `193` saat banjir paket SYN, serta penangkapan urutan paket *Three-Way Handshake* (`Flags [S]`, `Flags [S.]`, `Flags [.]`) via `tcpdump`. | Selesai |
| **Tugas 7** | DNS Exfiltration (`k4.exfil.lab`) | Query eksfiltrasi `3234353532303131313934.k4.exfil.lab` terekam di `dns-k4.log`, terdeteksi oleh `analisis_dns.py`, dan berhasil didekode kembali menjadi NIM `24552011194`. | Selesai |

---

## 4. Pembersihan Lingkungan (Cleanup)

Setelah seluruh rangkaian pengujian selesai, seluruh container dan jaringan sementara telah dihentikan dan dihapus (`docker compose down -v` / `docker rm -f`) agar tidak membebani sumber daya sistem host.
