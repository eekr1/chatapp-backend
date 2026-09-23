# TalkX Wave 02 Plan — Core Platform ve Admin Erişim Temeli

> Bu belge yalnız Wave 02 için hazırlanmış uygulama planıdır.
> Canonical ayrıntı Plan B ve Plan C stable ID maddelerindedir; burada yeni ürün veya sonraki-wave mimarisi üretilmez.
> Wave 02 Sale Release kapsamı 2026-09-23 tarihinde auto-verified/committed/manual-QA-deferred kapanışına ulaştı. Wave 03 başlatılmadı.

## 1. Durum ve yürütme sınırı

- **Wave:** 02
- **Wave adı:** Core API, auth, logging, abuse, socket ve admin erişim temeli
- **Plan durumu:** Uygulandı
- **Wave durumu:** Auto-verified / committed / manual-QA-deferred
- **Uygulama durumu:** Sale Release çekirdeği tamamlandı
- **Uygulama yetkisi:** 2026-09-23 tarihinde açıkça verildi
- **Giriş kapısı:** Wave 01 **AUTO-VERIFIED / COMMITTED** ve kullanıcıdan açık “Wave 02'yi başlat” talimatı
- **Mevcut blokaj:** Yok
- **Önceki wave:** Wave 01 — auto-verified / committed / manual-QA-deferred
- **Sonraki wave:** Wave 03 — ayrı kullanıcı talimatıyla planı hazırlandı; aktif değil ve uygulanmayacak

Bu dosyanın hazırlanması Wave 02 aktivasyonu, kod değişikliği, test altyapısı kurulumu, migration, canlı config, admin credential değişimi, deploy veya Wave 03 aktivasyonu/uygulaması için yetki değildir.

## 1.1 Sale Release override — TAM / ÇEKİRDEK

- **Satış öncesi uygulanır:** API/error response standardı, session/logout/password-change davranışı, socket identity/session sahipliği, rate-limit/abuse koruması, hassas log redaction ve admin brute-force/access sertleştirmesi.
- **Post-acquisition Roadmap / Deferred:** Büyük backend refactor'ı, enterprise capability/pagination framework'ü ve satış riskini azaltmayan platformlaştırma.
- **Kapanış:** Zorunlu backend testleri/syntax kontrolleri ve ilgili client build geçer, tek Wave 02 commit'i alınır ve **DUR**. Manuel QA Checkpoint A/Wave 19'a gider.
- Canonical stable ID'ler korunur; bu override satış öncesi alt kapsamı belirler ve deferred kriterleri tamamlanmış saymaz.

## 2. Canonical referanslar

Uygulama sırası değişmez:

1. `B-API-001` — Plan B / API-event schema ve hata sözleşmesi / bütün kabul kriterleri
2. `B-AUTH-001` — Plan B / session ve çoklu cihaz yaşam döngüsü / bütün kabul kriterleri
3. `B-OBS-001` — Plan B / structured logging ve hassas veri maskesi / bütün kabul kriterleri
4. `B-SEC-002` — Plan B / rate-limit ve abuse sınırları / bütün kabul kriterleri
5. `B-WS-001` — Plan B / authenticated socket ve bağlantı sahipliği / bütün kabul kriterleri
6. `C-ADMIN-001` — Plan C / admin auth, yetki ve ortak bilgi kabuğu / bütün kabul kriterleri

Yürütme kaynağı: `../TALKX_WAVE_MAP.md` / Wave 02.
Canonical ayrıntı kaynakları: `../TALKX_PLAN_B_PLATFORM_REALTIME_DATA.md` ve `../TALKX_PLAN_C_ADMIN_TRUST_RELEASE.md`.
Kilitli karar ve kanıt kaynağı: `../TALKX_MASTER_BACKLOG.md` / §7–§9, QA-006 ve ilgili güvenlik/operasyon bulguları.

## 3. Wave sonucu

Wave 02 sonunda:

- Kritik HTTP endpointleri ve WebSocket eventleri sürüm, kararlı hata kodu, request/event kimliği, server time ve capability bilgisi taşıyan açık sözleşmelere sahip olacak.
- Mevcut client geriye uyumu kontrollü geçiş katmanıyla korunacak; frontend backend'in serbest metin hata mesajını yorumlamayacak.
- Session oluşturma, current-session logout, tüm cihazlardan çıkış, şifre değişimi ve revoke etkileri tek deterministik policy ile çalışacak.
- Her authenticated socket değişmez kullanıcı/session/device/platform/release bağlamına sahip olacak; aynı socket başka kullanıcı kimliğine geçirilemeyecek.
- HTTP, WebSocket ve admin kötüye kullanım sınırları proxy gerçeğini, NAT kullanıcılarını ve kullanıcı/device boyutlarını yanlış birleştirmeden uygulanacak.
- Rate-limit cevabı kararlı kod ve gerçek retry süresi verecek; limit kontrolü yan etkiden önce çalışacak.
- Operasyon logları içerik sızdırmadan request/event/session yolculuğunu ilişkilendirebilecek.
- Admin yüzeyi server-side yetki, brute-force koruması, güvenli oturum/yeniden doğrulama kararı ve ortak durum kabuğu kazanacak.
- Wave 03 client görsel temeline, Wave 04 health/DB runtime'a ve Wave 05 reconnect/presence davranışına taşılmayacak.

## 4. Doğrulanmış başlangıç fotoğrafı

### 4.1 Repo ve değişiklik güvenliği

- Repo kökünde kullanıcıya ait geniş ve önceden var olan dirty/untracked durum bulunuyor.
- Güncel `chatapp-backend/`, `chatapp-frontend/` ve `docs/` ağaçları Git görünümünde untracked.
- Wave 02 bu mevcut kullanıcı değişikliklerini sahiplenmez, temizlemez, geri almaz veya toplu biçimde formatlamaz.
- Uygulama başlangıcında hedef dosyalar için hash/status fotoğrafı alınır; kapanışta yalnız Wave 02 farkları raporlanır.

### 4.2 B-API-001 mevcut gerçek

- Backend `sendApiError` yardımcısı `{ error, code }` biçimi üretiyor; bazı route'lar aynı biçimi elle kuruyor.
- Frontend `src/api.js`, hem `code` hem `errorCode` alanını okuyabiliyor fakat bütün HTTP/WS akışları tek canonical envelope kullanmıyor.
- WebSocket eventleri çoğunlukla düz ve sürümsüz `{ type, ...fields }` biçiminde.
- `/health` yalnız `{ ok: true }` döndürüyor; readiness/release kimliği `B-API-002` / Wave 04 kapsamı.
- Request ID telemetry için bazı HTTP yollarında üretiliyor fakat response ve hata sözleşmesine sistematik bağlanmıyor.
- Pagination, cursor, stable ordering, idempotency ve capability davranışları endpoint bazında dağınık.
- `chatapp-backend/index.js` yaklaşık 108 KB ve birçok sorumluluğu aynı dosyada taşıyor.
- Backend `package.json` içinde test komutu yok; büyük modül ayrımı için mevcut güvenlik ağı yetersiz.

### 4.3 B-AUTH-001 mevcut gerçek

- Login rastgele session token üretiyor, hash'ini `sessions` tablosunda saklıyor ve yaklaşık 30 günlük süre veriyor.
- Logout yalnız sunulan token hash'ine ait session satırını siliyor; current/all-device policy kullanıcı sözleşmesi olarak görünür değil.
- Session sorgusu HTTP auth yardımcıları ve WebSocket handshake içinde tekrarlanıyor.
- Şifre değişiminden sonra session revoke davranışı canonical olarak uygulanmış görünmüyor.
- `device_id` client tarafından geliyor ve `unknown` fallback'i bulunuyor; güven sınırı ve normalizasyon policy'si açık değil.
- Çoklu cihaz, aynı cihaz retry ve duplicate session davranışı için otomatik kanıt yok.
- Revoked/expired session'a bağlı açık socketleri anında sonlandıran merkezi registry bulunmuyor.
- Hesap silme sırasında bütün session ve socketlerin kapatılması merkezi sözleşmeye bağlanmış değil.

### 4.4 B-OBS-001 mevcut gerçek

- HTTP request telemetry için dakika rollup ve örneklenmiş event kayıtları bulunuyor.
- Behavior eventleri ve bazı request kimlikleri mevcut; HTTP, WebSocket ve admin yolculukları tek correlation sözleşmesine bağlı değil.
- Kod genelinde serbest biçimli `console.log/warn/error` kullanımı yaygın.
- Bazı loglar exception nesnesi, kullanıcı kimliği, nickname veya conversation bilgisi yazabiliyor.
- Mesaj, token, Authorization, fotoğraf, push token, tam IP ve serbest rapor/destek metni için merkezi redaction katmanı yok.
- Log level, sampling, hacim sınırı ve staging/production ayrımı tek modülde uygulanmıyor.

### 4.5 B-SEC-002 mevcut gerçek

- `/auth` için 10 dakikada IP başına 50; `/api` ve `/friends` için 300 istek sınırı var.
- Support route kullanıcı/IP key'i, standart header ve reset zamanı olan ayrı limiter kullanıyor.
- `trust proxy` için doğrulanmış Express ayarı görünmüyor; bazı route'lar `x-forwarded-for` değerini doğrudan okuyabiliyor.
- NAT, proxy zinciri, spoof edilmiş forwarded header ve IPv6 davranışı kanıtlanmış değil.
- WebSocket socket başına saniyede 5 event soft, 10 event hard sınırı kullanıyor; event maliyeti ve user/device boyutu ayrılmıyor.
- WebSocket limit sonucu genel `RATE_LIMIT`/close üretiyor; kararlı retry zamanı ve policy kimliği yok.
- Queue, message/media ve report eventleri ayrı maliyet sınıflarına bağlı görünmüyor.
- Admin Basic Auth denemelerinde ayrı brute-force limiter bulunmuyor.

### 4.6 B-WS-001 mevcut gerçek

- Her socket için UUID `clientId`, `hello`/`hello_ack`, heartbeat ve `activeClients` kaydı bulunuyor.
- Auth öncesi `hello_ack` dışındaki protected eventler işlenmiyor.
- Wave 01 hedefindeki legacy/guest fallback kapanışı, Wave 02 başlangıcında yeniden doğrulanmalı.
- Active client user, device, platform, locale ve connection zamanı taşıyor; session kimliği ve capability bağlamı parçalı.
- Aynı socket üzerinde ikinci `hello_ack` ile kimlik değiştirmeyi açıkça engelleyen state machine yok.
- Çoklu socket/device sahipliği ve duplicate connection policy'si açık değil.
- Stale cleanup var; session revoke, queue/room/presence invariantları test altında değil.
- `ws.send` için merkezi backpressure/bufferedAmount policy'si yok.

### 4.7 C-ADMIN-001 mevcut gerçek

- Admin route'ları tek Basic Auth kullanıcı/parola çiftiyle korunuyor.
- Production'da panel explicit enable ve güvenli parola yoksa 503 ile kapanıyor; bu koruma korunacak.
- Development fallback'i `admin/admin123`; production kontrolü yalnız parola değerini değerlendiriyor.
- Rol/yetki matrisi, server-side capability kontrolü, session timeout, CSRF ve kritik işlem re-auth katmanı bulunmuyor.
- Admin brute-force denemeleri public API'den ayrı limiter policy'sine bağlı değil.
- `admin.html` büyük ve tek dosyalı; ortak loading/empty/error/stale/no-data sözleşmesi tamamlanmış değil.
- Bazı admin hataları teknik düz metin veya ham backend mesajı döndürüyor.
- Hassas veri maskesi ve reveal/copy davranışı bütün ekranlarda tek standarda bağlı değil.

## 5. Kilitli Wave 02 sözleşmeleri

### 5.1 API ve event sürümleme sınırı

- HTTP ve WebSocket sözleşme sürümü merkezi sabit/config kaynağından gelir.
- Kritik akışlar önce envanterlenir; tek seferde bütün route'lar yeniden yazılmaz.
- Canonical hata en az `errorCode`, `message`, `retryable`, `requestId` ve gerekiyorsa `retryAfterMs` taşır.
- Desteklenen eski client için `code`/`error` alias'ları kontrollü tutulabilir; bu wave içinde sessiz kaldırılmaz.
- Kullanıcı metni client locale katmanından gelir; backend message yalnız güvenli fallback/diagnostic anlam taşır.
- Unknown, stale, not-found, conflict, validation, auth, permission ve rate-limit durumları ayrı kodlardır.
- Server time belgeli tek formatta taşınır; capability yokluğu güvenli temel davranışa düşer.
- Pagination stable ordering ve opaque cursor kullanır; offset kullanan mevcut ekran geçiş adaptörüyle korunur.
- Idempotency yalnız tekrarın yan etki üretebildiği kritik yazma yollarında kullanılır.

### 5.2 Session ve çoklu cihaz policy'si

- Çoklu cihaz desteklenir; her session tek kullanıcıya ve normalize edilmiş device bağlamına aittir.
- Normal logout yalnız current session'ı; açık “tüm cihazlardan çıkış” bütün sessionları revoke eder.
- Şifre değişimi bütün mevcut sessionları revoke eder; yeni giriş açıkça gerekir.
- Account deletion/revocation bütün sessionları ve bunlara bağlı canlı socketleri sonlandırır.
- Aynı login retry'sinin duplicate session üretmemesi için açık idempotency/retry davranışı belirlenir.
- Token yalnız hash olarak saklanır ve loglanmaz; raw token yalnız oluşturma response'unda bulunur.
- Session validation HTTP ve WebSocket tarafından aynı merkezi yardımcı/servisten tüketilir.
- Yeni kolon/index gerekirse Wave 04 migration otoritesiyle çakışma raporlanır; ad-hoc production DDL yapılmaz.

### 5.3 Structured logging ve redaction sözleşmesi

- Her HTTP request için `requestId`, socket için `connectionId`, event için `eventId` bulunur.
- Loglar allowlist alanlarla structured biçimde üretilir: timestamp, level, environment, release, component, operation, result ve duration.
- Kullanıcı/session referansı gerekiyorsa pseudonymous tanımlayıcı kullanılır.
- Şifre, raw token, Authorization, cookie, mesaj, fotoğraf/base64, push token, tam IP ve free text varsayılan loga girmez.
- Exception güvenli sınıf/kod ve kontrollü message ile yazılır; kontrolsüz object/body dump yapılmaz.
- Auth/rate-limit/event logları sampling ve hacim sınırına tabidir.
- Admin audit ile operasyon diagnostic logu ayrı kalır.

### 5.4 Rate-limit ve abuse policy'si

- Proxy güven modeli önce staging/Render gerçek header zinciriyle doğrulanır; `trust proxy` kör açılmaz.
- IP tek sinyal değildir; uygun akışta IP + user/session + device + connection boyutları katmanlı kullanılır.
- NAT kullanıcıları yalnız ortak IP nedeniyle topluca kilitlenmez; unauthenticated brute-force için IP/device dengesi korunur.
- Public API, auth, support, WebSocket ve admin ayrı policy gruplarıdır.
- Event limiter yan etkiden önce çalışır; reddedilen event queue/room/DB kaydı üretmez.
- Message/media/report gibi farklı maliyetli eventler ayrı ağırlık veya bucket kullanır.
- Canonical sonuç `RATE_LIMITED`, `retryable: true`, `retryAfterMs` ve güvenli metadata taşır.
- Limit key/log içinde tam IP veya raw token tutulmaz.
- In-memory bucketlar TTL, eviction ve üst sınır taşır.
- Shadow ban ve normal ban semantiği rate limiter içine gizlenmez.
### 5.5 Socket sahipliği ve state machine

Socket phase'leri:

1. `connected_untrusted`
2. `authenticating`
3. `authenticated`
4. `closing`
5. `closed`

Kurallar:

- Protected event yalnız `authenticated` phase'inde işlenir.
- Bir socket en fazla bir başarılı handshake yapar; ikinci `hello_ack` kimlik değiştirmez.
- Registry en az connection/client ID, session ID, user ID, device ID, platform, locale, app version/release, capabilities ve bağlanma zamanını taşır.
- Platform/locale/release yalnız allowlist/normalize edilmiş değerlerdir; yetki veya hassas veri kaynağı değildir.
- Session revoke edildiğinde ona bağlı bütün socketler kontrollü reason ile kapanır.
- Duplicate connection policy user, session ve device boyutunda belgelenir; rastgele socket düşürülmez.
- Heartbeat timeout queue/room/presence kalıntısı bırakmaz.
- Merkezi send helper `readyState`, `bufferedAmount`, payload sınırı ve kontrollü close/backpressure davranışı uygular.
- Reconnect state recovery `B-WS-002` / Wave 05'e aittir; bu wave yalnız güvenli sahiplik temelini kurar.

### 5.6 Admin güvenlik ve ortak kabuk sınırı

- Basic Auth yeterlilik kararı kanıtla verilir; rol, timeout, CSRF ve re-auth gereksinimlerini karşılamıyorsa kalıcı çözüm sayılmaz.
- Server-side permission middleware route bazında uygulanır; yalnız menü/buton gizlemek yetki değildir.
- Minimum capability matrisi mevcut route'lardan üretilir: read, sensitive-read, moderation/action, content/publish, account/deletion ve system/operations.
- Kritik/destructive işlem target, etki, gerekçe ve re-auth/policy kapısı olmadan çalışmaz.
- Admin auth denemeleri production proxy gerçeğine uygun ayrı brute-force limiter kullanır.
- Session/cookie seçilirse `HttpOnly`, `Secure`, uygun `SameSite`, timeout ve CSRF birlikte tasarlanır.
- Production disable-by-default koruması kaldırılmaz.
- Günlük görevler ile seyrek sistem alanları navigasyonda ayrılır; noktalama karakteri ikon olmaz.
- Ortak loading, empty, error, stale, no-data ve forbidden durumları ham stack/JSON göstermeyen kabukta birleşir.
- Mobil drawer/focus ve desktop navigation erişilebilir olur; ayrıntılı admin özellik ekranları Wave 14–16'da kalır.

## 6. Uygulama paketleri

### Paket 02A — B-API-001 sözleşme çekirdeği

Muhtemel hedef yüzeyler:

- `chatapp-backend/index.js`
- `chatapp-backend/routes/auth.js`, `profile.js`, `friends.js`, `push.js`, `support.js`
- Yeni ortak contract/schema yardımcıları için `chatapp-backend/utils/`
- `chatapp-frontend/src/api.js`
- `chatapp-frontend/src/App.jsx` WebSocket adaptörü
- Odaklı backend contract testleri ve `chatapp-backend/package.json`

İş sırası:

1. Kritik HTTP route ve WS event envanterini request/response/error/capability tablosuna dönüştür.
2. Mevcut client'ın tükettiği alanları compatibility fixture olarak kilitle.
3. Ortak success/error envelope, request ID, server time ve capability yardımcılarını oluştur.
4. Validation, auth, permission, conflict, stale/not-found ve rate-limit kodlarını merkezi katalogda tanımla.
5. Elle yazılmış kritik error response'larını ortak helper'a geçir.
6. Frontend HTTP/WS adapterını canonical `errorCode` tüketimine geçir; kullanıcı metnini locale anahtarından çöz.
7. Stable pagination/cursor ve idempotency gereken kritik yolları uygula.
8. `index.js` ayrımı gerekirse önce characterization testi yaz; testsiz toplu modül taşıma yapma.

### Paket 02B — B-AUTH-001 session yaşam döngüsü

Muhtemel hedef yüzeyler:

- `chatapp-backend/routes/auth.js`
- Tekrarlanan auth middleware kullanan route'lar
- `chatapp-backend/index.js` WebSocket handshake/revoke bağlantısı
- `chatapp-backend/utils/security.js` ve yeni merkezi session/auth servisi
- `chatapp-frontend/src/api.js` ve yalnız gerekli logout/session adapterı

İş sırası:

1. Register/login/logout/session doğrulama ve revoke yollarının characterization testlerini yaz.
2. Session lookup ve Bearer parsing'i tek güvenli yardımcı/serviste merkezileştir.
3. Current-session logout ile all-sessions logout intentini ayır.
4. Şifre değişimi ve account deletion revoke hook'unu merkezi servise bağla.
5. Retry/idempotency davranışını session sayısı ve device bağlamıyla testle.
6. Revoked/expired session'ın HTTP ve WS protected event yetkisi taşımadığını kanıtla.
7. Revoke edilen session'a bağlı socket kapatmayı Paket 02E registry'sine bağla.
8. Yeni DB yapısı gerekiyorsa dur ve Wave 04 bağımlılığını raporla.

### Paket 02C — B-OBS-001 güvenli gözlemlenebilirlik

Muhtemel hedef yüzeyler:

- `chatapp-backend/index.js`, `admin.js` ve `routes/`
- Yeni `chatapp-backend/utils/logger.js`, redaction ve correlation yardımcıları
- Focused log/redaction testleri

İş sırası:

1. Mevcut console/log alanlarını hassas veri ve hacim riskiyle envanterle.
2. Allowlist tabanlı structured logger ve correlation context oluştur.
3. HTTP request ID'yi response header/error envelope'a bağla.
4. WebSocket connection/event ID'lerini güvenli operation sonuçlarıyla ilişkilendir.
5. Token, password, Authorization, cookie, içerik, medya, push token, tam IP ve free-text redaction testlerini kur.
6. Auth/rate-limit/event loglarına sampling ve seviye policy'si uygula.
7. Mevcut telemetry tablolarını yeniden tasarlamadan yeni sözleşmenin tüketicisi yap.
8. Admin audit ile diagnostic log sınırını belge/testle koru.

### Paket 02D — B-SEC-002 rate-limit ve abuse katmanı

Muhtemel hedef yüzeyler:

- `chatapp-backend/index.js`, `admin.js`, `routes/support.js`
- Auth/public/admin route mount noktaları
- Yeni merkezi limiter policy/key-store yardımcıları
- Proxy, NAT, spoof ve bucket eviction testleri

İş sırası:

1. Staging/Render proxy zincirini read-only doğrula; güvenilen hop sayısını kaydet.
2. Public, auth, support, WebSocket ve admin policy matrisini oluştur.
3. Güvenli IP çözümü ve pseudonymous user/session/device key üretimini merkezileştir.
4. Auth ve admin brute-force limitlerini ayrı uygula.
5. WebSocket eventlerini maliyet grubuna ayır; limiter'ı yan etkiden önce çalıştır.
6. Canonical `RATE_LIMITED` + `retryAfterMs` cevabını HTTP ve WS'de eşle.
7. Bucket TTL/eviction/üst sınırını uygula ve sahte key yükünü testle.
8. NAT, IP rotation, duplicate event ve retry davranışını iki-client testleriyle doğrula.

### Paket 02E — B-WS-001 authenticated socket sahipliği

Muhtemel hedef yüzeyler:

- `chatapp-backend/index.js`
- Yeni socket auth/registry/send yardımcıları
- `chatapp-frontend/src/App.jsx` handshake capability alanları
- Focused WebSocket integration testleri

İş sırası:

1. Wave 01 auth/input güvenliği kapanışını yeniden doğrula.
2. Socket phase state machine'ini ve tek başarılı handshake invariantını uygula.
3. Registry'yi connection/session/user/device/platform/release/capability indeksleriyle kur.
4. Duplicate socket ve çoklu cihaz policy'sini test altında uygula.
5. Session revoke → socket close bağlantısını merkezi hook ile kur.
6. Heartbeat/stale cleanup'ı queue, room ve registry için idempotent yap.
7. Merkezi send/backpressure helper'ıyla yavaş tüketici ve buffered payload davranışını sınırla.
8. Reconnect/search/match semantiğini değiştirmeden temel akışı compatibility testleriyle koru.

### Paket 02F — C-ADMIN-001 admin erişim ve ortak bilgi kabuğu

Muhtemel hedef yüzeyler:

- `chatapp-backend/admin.js`
- `chatapp-backend/admin.html`
- `chatapp-backend/public/admin/`
- Admin auth/session/permission/CSRF yardımcıları
- Admin route ve mobil navigation testleri

İş sırası:

1. Bütün admin route/aksiyonları capability matrisine çıkar.
2. Basic Auth yeterlilik kararını threat model ve kabul kriterleriyle kaydet.
3. Seçilen modelde server-side permission, timeout, brute-force, CSRF ve re-auth kapılarını birlikte uygula.
4. Production disable-by-default ve güvenli credential kontrollerini koru.
5. Günlük görev/seyrek sistem navigasyonunu mevcut içerikleri kaybetmeden ortak kabuğa yerleştir.
6. Noktalama ikonlarını gerçek erişilebilir ikon sistemine geçir.
7. Ortak loading/empty/error/stale/no-data/forbidden durumlarını kur.
8. Hassas veri görünümü ve destructive aksiyonların target/etki/gerekçe/audit standardını uygula.
9. Desktop, mobil drawer, klavye ve focus davranışını kanıtla.
10. Dashboard/profil/rapor/analitik/Release Health ayrıntısına girme; yalnız güvenli kabuğu sağla.

## 7. Dosya ve servis etki sınırı

### Birincil backend alanı

- `chatapp-backend/index.js`
- `chatapp-backend/admin.js`
- `chatapp-backend/admin.html`
- `chatapp-backend/package.json`
- `chatapp-backend/routes/`
- `chatapp-backend/utils/`
- Yalnız Wave 02 focused test dosyaları

### Kontrollü client uyumluluk alanı

- `chatapp-frontend/src/api.js`
- `chatapp-frontend/src/App.jsx`
- Yalnız hata/capability/session/handshake adapterı için gereken locale anahtarları

### Varsayılan olarak değişmeyecek alanlar

- Match/search/offer ekranlarının görsel tasarımı
- Android version/signing/release dosyaları
- Production DB şeması ve migration geçmişi
- Dashboard/analytics/profile/report özellik içerikleri
- Legal publish ve notification campaign akışları

## 8. Açık kapsam dışı

- `B-API-002` liveness/readiness/release kimliği
- `B-WS-002` reconnect ve active-state recovery
- `B-MM-001/002/003` search, Global/Country ve pending offer protokolleri
- `B-PRES-001` gerçek presence/last seen
- `B-DB-001` migration ve DB runtime mimarisi
- Plan A Wave 03 client shell, tema/state ve auth UX çalışması
- QA-014, QA-017 ve QA-003 ekran/işlev değişiklikleri
- Admin dashboard, aktivite, profil, rapor, notification, legal ve Release Health ayrıntıları
- Yeni SSO sağlayıcısı veya kullanıcı e-posta/kurtarma sistemi
- Canlı credential rotasyonu, Render config, restart veya deploy
- Production DB DDL/migration
- Wave 03 aktivasyonu veya uygulaması

## 9. Otomatik doğrulama planı

### Statik ve mevcut repo kapıları

- `node --check chatapp-backend/index.js`
- `node --check chatapp-backend/admin.js`
- Değişen route/utils/test dosyalarında `node --check`
- `npm --prefix chatapp-frontend run lint`
- `npm --prefix chatapp-frontend run build`
- `npm run check:text-encoding`

### B-API-001 contract matrisi

- Canonical success/error envelope snapshotları
- Legacy `code/error` alanları olan client compatibility testi
- Unknown, validation, stale, not-found, conflict, auth, permission ve rate-limit kodları
- Request ID response/error eşliği ve server time formatı
- Capability var/yok ve eski client davranışı
- Stable pagination ordering/cursor gereken seçili endpointler
- Idempotency retry'da tek yan etki
- Backend message değişse bile client locale metninin sabit kalması

### B-AUTH-001 session matrisi

- Login ile tek session üretimi ve token hash doğrulaması
- Aynı request/idempotency retry'da duplicate session olmaması
- Current logout yalnız hedef session'ı revoke ediyor
- All-device logout bütün sessionları revoke ediyor
- Expired/revoked session HTTP/WS yetkisi taşımıyor
- Şifre değişimi bütün eski sessionları sonlandırıyor
- Account deletion hook bütün session/socketleri kapatıyor
- Çoklu cihaz ve aynı cihazdaki birden fazla client davranışı
- Raw token/password log veya fixture çıktısında bulunmuyor

### B-OBS-001 redaction matrisi

- Authorization, cookie, password ve token
- Mesaj/typing metni
- Fotoğraf/base64 ve push token
- Tam IP
- Support/report free text
- Exception object ve kontrolsüz request body
- Request/event correlation zinciri
- Sampling, log level ve hacim üst sınırı
- Staging/production ayrımı

### B-SEC-002 abuse matrisi

- Doğrudan bağlantı, güvenilen proxy ve spoof edilmiş forwarded header
- Aynı NAT altındaki farklı kullanıcı/device
- Aynı user'ın IP değiştirmesi
- Auth brute-force ve admin brute-force ayrımı
- Public/support/admin policy izolasyonu
- WebSocket event ağırlıkları
- Limit öncesi/sonrası DB, queue, room ve teslim yan etkisi
- `retryAfterMs` doğruluğu
- Bucket TTL/eviction ve çok sayıda sahte key
- Shadow ban ile normal rate-limit ayrımı

### B-WS-001 iki-client matrisi

- Auth öncesi protected event
- Geçerli/expired/revoked session handshake
- Aynı sockette ikinci `hello_ack`
- Aynı session ile birden fazla socket
- Aynı kullanıcı farklı cihaz
- Session revoke sırasında açık socket
- Heartbeat timeout ve idempotent cleanup
- Slow consumer/backpressure
- Platform/locale/release/capability allowlist
- Mevcut temel connect/message/leave akışında regresyon olmaması

### C-ADMIN-001 matrisi

- Production disable-by-default
- Credential yok/zayıf/doğru/yanlış
- Brute-force limit ve retry zamanı
- Her capability için allow/deny server sonucu
- UI gizli olsa bile doğrudan endpoint erişiminin reddi
- Session timeout, CSRF ve kritik işlem re-auth
- Hassas veri maskeli/gösterme/kopyalama policy'si
- Loading/empty/error/stale/no-data/forbidden durumları
- Desktop/mobile/keyboard/focus navigasyonu
- Teknik ham hata/stack/JSON sızıntısı olmaması

Focused backend testleri tekrar üretilebilir tek komuta bağlanır. Wave 17'nin bütünleşik CI zinciri bu wave içinde kurulmaz.

## 10. Manuel QA havuzu — Checkpoint A / Wave 19 (commit kapısı değil)

### HTTP ve frontend compatibility

- Desteklenen Web ve Android build ile register/login/logout temel akışı
- TR/EN hata metninin error string tahmini olmadan doğru görünmesi
- Offline, timeout, rate-limit, revoked session ve permission durumları
- Request ID'nin kullanıcı yüzeyini boğmadan destek kanıtında bulunabilmesi
- Capability taşımayan eski client'ın temel akışı

### Çoklu cihaz ve WebSocket

- İki tarayıcı profiliyle aynı kullanıcı / farklı session
- Aynı session'ın iki tab/socket davranışı
- Current logout ve tüm cihazlardan çıkış farkı
- Session revoke sırasında canlı socketin kontrollü kapanması
- Heartbeat/stale bağlantı sonrası queue/room kalıntısı olmaması
- Yavaş bağlantıda servis çökmeden kontrollü backpressure

### Proxy ve rate-limit

- Staging/Render üzerinde gerçek client IP zinciri read-only doğrulaması
- NAT benzetiminde iki kullanıcının birbirini kilitlememesi
- IP rotation ile user/device limitinin aşılamaması
- Auth/public/support/admin limitlerinin birbirine karışmaması
- Limit mesajında doğru retry süresi ve güvenli kullanıcı aksiyonu

### Admin

- Yetkisiz, yanlış credential, düşük yetki ve tam yetki senaryoları
- Doğrudan endpoint çağrısında server-side deny
- Session timeout, CSRF ve kritik aksiyon re-auth
- Beş saniyede günlük görevlerin bulunması
- Mobil drawer, klavye sırası, focus return ve ekran okuyucu adları
- Loading, empty, partial error, stale, no-data ve forbidden durumları
- Hassas verinin varsayılan maskeli olması
- Destructive aksiyonda hedef, etki, gerekçe ve audit sonucunun görünmesi

Canlı production credential/config değişikliği veya gerçek destructive admin aksiyonu bu manuel QA listesiyle otomatik yetkilendirilmez.

## 11. Kanıt ve kabul eşlemesi

| Plan ref | Gerekli kanıt | Kapanış şartı |
|---|---|---|
| B-API-001 | Contract envanteri, schema/fixture testleri, legacy client sonucu, error/capability örnekleri | Yedi canonical kabul kriteri kanıtlı |
| B-AUTH-001 | Session/revoke matrisi, DB satır etkisi, çoklu cihaz ve socket sonucu | Altı canonical kabul kriteri kanıtlı |
| B-OBS-001 | Structured log örnekleri, redaction negatif testleri, correlation ve hacim kanıtı | Beş canonical kabul kriteri kanıtlı |
| B-SEC-002 | Proxy/NAT/IP-user-device/admin/WS limit testleri ve retry kanıtı | Altı canonical kabul kriteri kanıtlı |
| B-WS-001 | State machine, registry, revoke, stale cleanup ve backpressure iki-client testleri | Altı canonical kabul kriteri kanıtlı |
| C-ADMIN-001 | Threat model kararı, route permission matrisi, auth/CSRF/re-auth ve responsive durum kanıtı | Yedi canonical kabul kriteri kanıtlı |

Checkbox yalnız ilgili canonical kabul kriteri gerçek kanıtla kapandığında işaretlenir. Paket tamamlandı iddiası bütün stable ID'nin otomatik kapandığı anlamına gelmez.

## 12. Riskler ve rollback

| Risk | Koruma | Rollback/durma davranışı |
|---|---|---|
| Contract geçişi eski clientı kırar | Compatibility fixture ve dual-read/alias dönemi | Yeni adaptörü geri al; eski alanları sessiz kaldırma |
| Session revoke kullanıcıyı beklenmedik çıkarır | Current/all-device policy testleri | Revoke çağrısını durdur; token güvenliğini gevşetme |
| Proxy ayarı herkesi aynı IP yapar/spoof'a açar | Gerçek Render zinciri ve NAT/spoof testi | `trust proxy` değişikliğini geri al |
| Limiter meşru kullanıcıyı kilitler | Katmanlı key, ölçüm ve retry süresi | İlgili policy'yi geri al; bütün limitleri global kapatma |
| In-memory limiter bellek büyütür | TTL, max key ve eviction testi | Yeni store'u kapatıp önceki kontrollü limite dön |
| Logger hassas içerik sızdırır | Allowlist ve negatif redaction testi | Yeni sink'i kapat; ham body dump'a dönme |
| Socket registry akışı bozar | Characterization ve iki-client testleri | Registry katmanını geri al; Wave 05'i burada yamama |
| Admin auth geçişi erişimi kilitler | Break-glass/runbook ve staging kanıtı | Önceki production-disabled güvenli moda dön |
| Admin CSRF/re-auth yanlış korur | Route capability matrisi | Etkilenen mutation'ı kapat; korumayı bypass etme |
| DB şema ihtiyacı çıkar | Wave 04 dependency guard | Ad-hoc DDL yapmadan dur |
| Dirty repo kullanıcı işini örter | Başlangıç hash/status | Yalnız Wave 02 farkını geri al |

## 13. Canlı işlem ve migration sınırı

Aşağıdakiler Wave 02 planının veya başlangıç talimatının doğal uzantısı değildir; ayrıca açık yetki ister:

- Render environment/config ve `trust proxy` üretim değişikliği
- Admin kullanıcı/parola/secret rotasyonu
- Canlı sessionların toplu revoke edilmesi
- Production DB migration, index veya DDL
- Render restart/redeploy
- Gerçek kullanıcı veya admin hesabında destructive aksiyon
- Production trafik üzerinde agresif load/brute-force testi

Önce local/staging kanıtı üretilir. Canlı değişiklik öncesi hedef, etki, rollback ve gözlem penceresi kullanıcıya açıkça sunulur.

## 14. Başlangıç kapısı

Wave 02 uygulamasına geçmeden önce:

- [x] Wave 01 **AUTO-VERIFIED / COMMITTED**; açık canonical/manual maddeler Checkpoint A/Wave 19 havuzunda.
- [x] Kullanıcı açıkça “Wave 02'yi başlat” dedi.
- [x] İki bağımsız repo temiz `sale-release` başlangıç fotoğrafıyla kaydedildi.
- [x] Wave 01'in auth/input/origin/payload sözleşmesi güncel kod ve 6 regresyon testiyle yeniden doğrulandı.
- [x] Desteklenen Web build ve canonical Android bundled asset compatibility fixture olarak doğrulandı.
- [x] Proxy güven modeli forwarded header'a kör güvenmeden remote peer + pseudonymous user/device/session anahtarlarıyla kuruldu; gerçek Render zinciri staging QA'ya ertelendi.
- [x] Admin auth geçişi production disable-by-default ve önceki güvenli kapalı moda rollback davranışını korudu.
- [x] DB schema ihtiyacı çıkarsa Wave 04 sınırında durulacağı kabul edildi; migration gerekmedi.
- [x] Canlı config, credential, revoke, migration ve deploy işlemlerinin ayrıca onay istediği kabul edildi; hiçbiri yapılmadı.
- [x] Wave 03 kapsamına taşma olmadığı tekrar kontrol edildi.

Bu kutular plan hazırlanırken işaretlenmez.

## 15. Sonuç alanı

- **Başlangıç zamanı:** 2026-09-23
- **Tamamlanan Plan refs:** B-API-001, B-AUTH-001, B-OBS-001, B-SEC-002, B-WS-001 ve C-ADMIN-001 Sale Release çekirdeği; roadmap/manual kriterler açık bırakıldı
- **Değişen dosyalar:** Backend contract/logger/session/abuse/socket/admin yardımcıları, ilgili route/index/admin entegrasyonları, focused testler ve canonical planlar; frontend API/WS adapterı ile TR/EN hata anahtarları
- **Otomatik kanıt:** Backend 19/19; tüm değişen backend dosyaları `node --check`; frontend lint 0 hata/9 mevcut uyarı; Vite build başarılı; text encoding temiz; frontend audit 0; backend audit high eşiğinde exit 0 (8 moderate transitif bulgu); Android `testDebugUnitTest` başarılı
- **İki-client kanıtı:** Aynı session'a bağlı iki socket revoke sırasında 1008 ile kontrollü kapandı; immutable handshake, expiry ve backpressure focused testlerle geçti
- **Manuel QA:** Checkpoint A / Wave 19'a ertelendi
- **Canlı/staging kanıtı:** Yapılmadı; Render proxy zinciri ve gerçek admin/session senaryoları Wave 19 manuel QA havuzunda
- **Kullanıcı onayı:** Wave 02 başlangıç yetkisi 2026-09-23
- **Wave durumu:** AUTO-VERIFIED / COMMITTED / MANUAL-QA-DEFERRED
- **Sonraki wave:** Başlatılmadı

## 16. Durma kuralı

Bu belge hazırlandıktan sonra durulur. Wave 01 **AUTO-VERIFIED / COMMITTED** olmadan ve kullanıcı açıkça Wave 02'yi başlatmadan:

- Kod, dependency, test altyapısı veya config değiştirilmez.
- Session revoke, admin credential veya production proxy işlemi yapılmaz.
- Migration, restart veya deploy yapılmaz.
- Wave Map'te Wave 02 `Aktif` yapılmaz.
- Wave 03 yalnız ayrı açık planlama talimatıyla belgelenebilir; aktive edilmez veya uygulanmaz.
