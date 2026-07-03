# Check Point Management API — Mock Server v3 (block/unblock IOC: IP & Domain)

Mock server untuk testing workflow SOAR di n8n saat kamu tidak punya akses ke Check
Point Management Server sungguhan. **Bukan produk resmi Check Point.**

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
