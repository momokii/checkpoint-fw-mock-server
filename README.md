# Check Point Management API — Mock Server v4 (block/unblock IOC: IP & Domain)

Mock server untuk testing workflow SOAR di n8n saat kamu tidak punya akses ke Check
Point Management Server sungguhan. **Bukan produk resmi Check Point.**

## Koreksi v6: host vs network untuk blokir IP — sudah dianalisis, keduanya didukung

Sempat ditanya kenapa block IP pakai `add-host`, bukan `add-network` seperti di data
legacy. Hasil analisis:

- Thread CheckMates **"Block ip address using api rest"** (jawaban paling on-point utk
  kasus "blokir 1 IP via API") pakai `add-host` — **bukan** `add-network`.
- Tapi ditemukan juga tool komunitas (`IPaddressFeed2CheckPoint` di GitHub) yang
  menghasilkan **network objects** untuk populate blocklist dari feed IP.
- Beda teknis (dari Admin Guide resmi): Host object **tidak punya** kemampuan
  routing/anti-spoofing (murni representasi satu endpoint). Network object
  didefinisikan oleh network-address + subnet-mask (representasi sebuah *network*).
- Kesimpulan: `add-host` lebih umum direkomendasikan spesifik untuk kasus "1 IP",
  tapi `add-network` dengan mask `/32` (`255.255.255.255`) **secara fungsional**
  match persis 1 IP yang sama di access rule — bukan salah, cuma beda representasi.
  Tidak bisa dipastikan tanpa lihat legacy code langsung kenapa sistem lama pakai
  yang mana.

**Mock ini sekarang mendukung KEDUANYA** — `add-network`/`show-network`/`set-network`/
`delete-network` (parameter `subnet` + `subnet-mask` atau `mask-length`, VERIFIED dari
modul Ansible resmi `cp_mgmt_network`) ditambahkan sebagai alternatif `add-host`. Pakai
yang mana saja sesuai yang benar-benar dipanggil legacy-mu.

## Koreksi v5: verifikasi ulang flow domain, tambah parameter `is-sub-domain`

Sempat ditanya ulang apakah urutan `add-dns-domain` → `set-group` untuk block domain
itu benar. Sekarang punya sumber yang jauh lebih kuat dari sebelumnya: **admin resmi
Check Point (PhoneBoy) di CheckMates thread "mgmt_cli: Creation of Multiple Domain
Objects"** secara eksplisit menjelaskan urutan API domain object:
`add-dns-domain` (buat objek) → `add-group` (kalau group belum ada) → `set-group`
(tambah member). Ini mengkonfirmasi urutan yang sudah diimplementasikan di mock ini.

Juga ditemukan (dari modul Ansible resmi `check_point.mgmt.cp_mgmt_dns_domain`)
parameter **`is-sub-domain`** yang sebelumnya tidak diimplementasikan di mock ini:
`true` = domain tsb DAN semua sub-domainnya ikut match (blokir `evil.com` otomatis
blokir `mail.evil.com`, `www.evil.com`); `false`/default = cuma hostname persis itu
saja. Ini relevan untuk keputusan blocking SOC — sudah ditambahkan ke `add-dns-domain`
dan `set-dns-domain` (command terakhir ini juga baru ditambahkan, sebelumnya belum ada).

**Catatan penting soal istilah**: ada command LAIN bernama `add-domain` (tanpa "dns")
yang TIDAK BERHUBUNGAN — itu untuk administrative domain di Multi-Domain Security
Management (MDS), konsep multi-tenancy Check Point, bukan untuk DNS domain object
buat firewall rule. Jangan tertukar kalau riset sendiri ke dokumentasi Check Point.

## Koreksi v4: versi API yang dilaporkan (v1.9 → 2.0)

Mock ini sebelumnya melaporkan `"api-server-version": "v1.9"` di response login —
itu versi R81.20, **bukan latest**. Setelah dicek: **R82 adalah versi "recommended
untuk semua deployment" saat ini** (sk173903), dan R82 = **Management API v2.0**
(dikonfirmasi dari CheckMates: "R82 will be API version 2"). Mock ini sekarang
melaporkan `"2.0"`.

**Mekanisme versioning di path** (yang sudah diimplementasikan sejak v3) ternyata
justru **dikonfirmasi resmi** oleh dokumentasi CheckMates "Management API Versioning":
tanpa version di path = pakai versi terbaru; dengan version eksplisit (`/web_api/v1/...`)
= dikunci ke versi itu untuk backward compatibility. Jadi arsitektur routing mock ini
sudah benar, cuma angka versi yang dilaporkan yang perlu dikoreksi.

**Batasan yang harus kamu sadari**: mock ini **tidak** mengimplementasikan behavior
berbeda antar versi API — baik kamu panggil tanpa version, `v1.9`, atau `v2`, semua
diproses SAMA oleh mock ini. Check Point sendiri mengakui *"the behavior of some
commands may be changed in incompatible way"* antar versi mayor. Saya cek daftar
perubahan v1.9→v2.0 yang saya temukan (VSX provisioning, Maestro Security Group,
CIFS resource, bandwidth Limit objects) — **tidak ada yang menyentuh command yang
diimplementasikan di mock ini** (host/dns-domain/group/access-rule/publish/
install-policy), jadi kemungkinan besar kontraknya tetap sama. Tapi ini **inferensi
dari ketiadaan bukti sebaliknya**, bukan konfirmasi langsung — saya tidak berhasil
mengakses isi lengkap dokumentasi API v2.0 (halamannya di-render via JavaScript,
tidak bisa saya fetch isinya untuk diff eksplisit per-command).

## Koreksi v3 (setelah cek ulang data legacy)

1. **Endpoint sekarang menerima path TANPA version** — `/web_api/login`,
   `/web_api/add-host`, dst. Ini dikonfirmasi sebagai pola paling umum di dokumentasi
   resmi Check Point (`https://<Management Server>/web_api/<command>`, tanpa version).
   Path dengan version eksplisit (`/web_api/v1.9/login`) **tetap diterima** juga —
   version di path itu opsional, bukan wajib, persis seperti server asli.
2. **Auth dikonfirmasi tetap model Check Point** (`X-chkp-sid` berbasis sesi, login
   pakai user/password ATAU api-key). Sempat ada temuan header `X-PAN-KEY` di data
   legacy — itu **bukan punya Check Point**, itu header otentikasi resmi Palo Alto
   Networks (per-request static key, model stateless). Setelah dicek ulang, ternyata
   itu ke-carry dari workflow n8n lain yang memang untuk Palo Alto — jadi tidak dipakai
   di mock ini. Kalau suatu saat kamu memang butuh mock untuk firewall Palo Alto,
   itu perlu dibangun terpisah karena strukturnya beda total (candidate-config →
   commit, bukan publish → install-policy).
3. Fix bug Dockerfile yang lupa `COPY openapi.yaml` (menyebabkan `/docs` sempat 404).

## Koreksi dari versi pertama (v1 → v2)

Versi pertama mock ini **belum** mendukung use case block/unblock IOC (IP & domain).
v2 menambahkan objek Domain, Group, semantik `add`/`remove` yang benar di
`set-access-rule`/`set-group`, auth via api-key, flow unblock, dan Swagger UI.

## Soal klaim "domain butuh group, IP tidak" dari sistem legacy kalian

Domain object **bisa** dipakai langsung di source/destination rule, sama seperti host
— **tidak ada keharusan teknis** dari Check Point yang mewajibkan domain lewat group
sementara IP tidak (lihat sk120633). Asimetri ini kemungkinan besar keputusan
arsitektur dari sistem legacy kalian, bukan requirement API. Mock ini mendukung
**kedua pola** (host/domain langsung ke rule, ATAU lewat group).

## Apakah prosesnya "sama persis" dengan Check Point asli?

**Tidak bisa saya jamin itu.** Saya tidak punya akses ke Management Server asli untuk
diff langsung, dan server asli punya banyak perilaku yang tidak direplikasi di sini
(locking sesi multi-admin, validasi lisensi, resolusi DNS asli, quirk validasi field
tertentu). Yang **bisa** saya jamin: field name, method, dan alur kerja di sini
mengikuti dokumentasi resmi dan contoh request/response nyata yang saya kutip.

## Katalog Error — mana yang VERIFIED, mana yang INFERRED

Ini bagian paling penting kalau kamu mau testing error-handling n8n secara serius.
Saya cek satu per satu ke laporan request/response nyata dari pengguna Check Point
(CheckMates), bukan cuma tebak pola. Status di bawah jujur soal mana yang punya bukti
dan mana yang masih asumsi:

| Skenario | `code` | HTTP | `message` | Status |
|---|---|---|---|---|
| Object tidak ditemukan | `generic_err_object_not_found` | 404 | `Requested object [<name>] not found` | **VERIFIED** (2 laporan independen, HTTP 404 eksplisit disebut) |
| Password/user salah | `err_login_failed` | 400* | `Authentication to server failed.` | **VERIFIED** (dari output `mgmt_cli` asli); *HTTP status diinferensikan |
| JSON body rusak | `generic_err_invalid_syntax` | 400 | `Payload is not valid` | **VERIFIED** (2 laporan, HTTP 400 eksplisit) |
| Parameter tidak dikenal | `generic_err_invalid_parameter_name` | 400* | `Unrecognized parameter [<name>]` | **VERIFIED** format pesan; *HTTP status diinferensikan |
| **Object dikunci sesi lain** | `generic_error` | 400* | `Action cannot be executed on object: <name> due to: Object '<name>' is locked by another session.` | **VERIFIED** — response JSON asli dari laporan pengguna |
| Session id salah/expired | `generic_err_invalid_session_id` | 401* | `Wrong session id [<sid>]. Session may be expired. Please check session id and resend the request.` | Pesan **VERIFIED**; code & HTTP *diinferensikan* |
| Header X-chkp-sid tidak dikirim | `generic_err_login_required` | 401* | `This API call requires a valid session id (X-chkp-sid header).` | **INFERRED** — tidak ada contoh nyata utk kasus ini spesifik |
| Login terlalu sering | `generic_err_too_many_requests` | 429* | `Too many requests in a given amount of time` | Pesan **VERIFIED** dari panduan resmi soal rate-limit; code & HTTP *diinferensikan* |
| Parameter wajib kosong | `generic_err_missing_param` | 400* | (custom per command) | **INFERRED** — tidak ketemu contoh nyata |
| Object dengan nama itu sudah ada | `generic_err_object_already_exists` | 400* | (custom per command) | **INFERRED** — tidak ketemu contoh nyata |
| Command tidak dikenal | `generic_err_command_not_found` | 404 | (custom) | **MOCK-ONLY** — bukan dari Check Point, ini fallback saya sendiri |

`*` = HTTP status code-nya sendiri tidak eksplisit disebutkan di sumber yang saya
temukan (sumbernya kadang cuma output `mgmt_cli`, bukan raw HTTP response). Saran
praktis: **kunci logic error-handling n8n kamu ke field `code` di body JSON**, bukan
cuma HTTP status number — ini juga konsisten dengan catatan resmi Check Point sendiri
("*For bulk requests, the HTTP status code is always 200*"), yang mengindikasikan
HTTP status di ekosistem Check Point tidak selalu jadi sinyal utama yang bisa diandalkan.

### Cara testing skenario "object locked by another session"

Ini skenario nyata yang relevan banget buat SOAR: dua proses (mis. dua eksekusi n8n
yang tumpang tindih, atau SOC engineer lagi buka rule yang sama di SmartConsole)
mencoba ubah objek yang sama bersamaan. Untuk memicu error ini secara deterministik
tanpa perlu 2 sesi asli, tambahkan `"simulate": "locked"` di body `set-access-rule`
atau `set-group`:

```json
{"name":"Blocked_IPs_Rule","source":{"add":["Mal_IP"]},"simulate":"locked"}
```

### Cara testing rate-limit login

Check Point secara resmi menyarankan login SEKALI per sesi kerja, reuse `sid` untuk
semua command, bukan login ulang di setiap call. Mock ini akan balikin
`generic_err_too_many_requests` kalau `/login` dipanggil lebih dari 3x dalam 5 detik —
supaya kamu bisa ketahuan kalau workflow n8n-mu punya anti-pattern "login di setiap
iterasi loop block/unblock" alih-alih login sekali di awal.

## Server dinamis di Swagger UI (`MOCK_SERVER_URL`)

Default-nya, Swagger UI (`/docs`) dan `/openapi.yaml` menunjukkan `http://localhost:4010`
sebagai server — sesuai isi `openapi.yaml`. Kalau mock ini diakses dari tempat lain
(mis. n8n di container Docker lain yang manggil lewat hostname `checkpoint-mock`, atau
di-expose lewat reverse proxy/ngrok), `localhost` itu tidak relevan buat fitur
"Try it out" di Swagger UI.

Set environment variable `MOCK_SERVER_URL` untuk menambahkan server itu sebagai pilihan
**pertama/default** di dropdown Swagger UI, tanpa perlu edit `openapi.yaml`:

```bash
MOCK_SERVER_URL=http://checkpoint-mock:4010 node server.js
```

Atau di `docker-compose.yml` (lihat komentar di file itu, tinggal uncomment):

```yaml
environment:
  - MOCK_SERVER_URL=http://checkpoint-mock:4010
```

`localhost:4010` tetap ada sebagai pilihan kedua di dropdown — env var ini menambahkan,
bukan menggantikan. `/openapi.yaml` (raw spec) juga otomatis konsisten dengan apa yang
ditampilkan di `/docs`, karena keduanya di-generate dari objek yang sama di memori,
bukan dari file statis.

## Menjalankan

```bash
npm install
node server.js
# atau
docker compose up --build -d
```

- API: `http://localhost:4010/web_api/v1.9/...`
- **Swagger UI (dokumentasi interaktif, bisa langsung dicoba):** `http://localhost:4010/docs`
- Raw OpenAPI spec: `http://localhost:4010/openapi.yaml`
- Reset state testing: `POST http://localhost:4010/mock/reset`

## Login

```json
// Opsi 1 — user/password
{"user": "admin", "password": "admin123"}

// Opsi 2 — api-key
{"api-key": "test-api-key-12345"}
```

## Flow BLOCK IP (host langsung ke rule)

1. `POST /web_api/login` → simpan `sid`  *(atau `/web_api/v1.9/login` — sama saja)*
2. `POST /web_api/add-host` — `{"name":"Malicious_1.2.3.4","ip-address":"1.2.3.4"}`
3. `POST /web_api/set-access-rule` — `{"name":"Blocked_IPs_Rule","source":{"add":["Malicious_1.2.3.4"]}}`
4. `POST /web_api/publish`
5. `POST /web_api/install-policy` — `{"policy-package":"Standard","target-name":"gw-cluster-1"}` → simpan `task-id`
6. `POST /web_api/show-task` berulang (pakai n8n Wait + IF node) sampai `status: "succeeded"`

## Flow UNBLOCK IP

1. `POST /web_api/set-access-rule` — `{"name":"Blocked_IPs_Rule","source":{"remove":["Malicious_1.2.3.4"]}}`
2. (opsional) `POST /web_api/delete-host` — `{"name":"Malicious_1.2.3.4"}`
3. `POST /web_api/publish` → `POST /web_api/install-policy` → poll `show-task`

## Flow BLOCK DOMAIN (via group)

1. `POST /web_api/add-dns-domain` — `{"name":".malicious-domain.com"}`
2. `POST /web_api/set-group` — `{"name":"Blocked_Domains_Group","members":{"add":[".malicious-domain.com"]}}`
3. `POST /web_api/publish` → `POST /web_api/install-policy` → poll `show-task`

## Flow UNBLOCK DOMAIN

1. `POST /web_api/set-group` — `{"name":"Blocked_Domains_Group","members":{"remove":[".malicious-domain.com"]}}`
2. (opsional) `POST /web_api/delete-dns-domain`
3. `POST /web_api/publish` → `POST /web_api/install-policy` → poll `show-task`

Rule `Blocked_IPs_Rule` dan group `Blocked_Domains_Group` sudah di-pre-seed saat server
start (mensimulasikan setup produksi yang sudah ada, bukan dibuat ulang tiap kali).

## Referensi yang dipakai untuk menyusun mock ini

- Management API Reference resmi — https://sc1.checkpoint.com/documents/latest/APIs/
- sk120633 — Domain Objects R80.10+ (domain bisa langsung dipakai di source/destination)
- Thread CheckMates "API set-access-rule Adding/removing Source or destination" —
  konfirmasi bentuk JSON asli `{"source":{"add":[...]}}`
- Thread CheckMates "API call for removing object from a group" — konfirmasi bentuk
  JSON asli `{"members":{"remove":[...]}}`
- Thread CheckMates "Support for api key" — konfirmasi login mendukung `api-key`
  sejak R80.40

## Batasan yang belum direplikasi (tahu batasnya, bukan pura-pura lengkap)

- Tidak ada validasi `"Add Any is not allowed"` (quirk API v1.7+).
- Tidak ada locking/konflik multi-admin.
- Domain object tidak benar-benar melakukan resolusi DNS (real Check Point melakukan
  forward/reverse DNS lookup asli).
- Tidak ada validasi format FQDN (real Check Point mewajibkan format `.contoh.com`
  untuk mode FQDN — mock ini menerima string apapun sebagai nama).
- State in-memory — restart = hilang semua (pakai `/mock/reset` untuk restart skenario
  tanpa restart container).
