# TalkX Wave 04 Plan — Health, DB Runtime ve Operasyon Güvenliği

> Bu belge yalnız Wave 04 için hazırlanmış uygulama planıdır.
> Canonical ayrıntı Plan B ve Plan C stable ID maddelerindedir; burada sonraki-wave realtime veya ürün özelliği üretilmez.
> Plan hazırdır. Wave 04 aktif değildir, Wave 01–03 kapanmamıştır ve uygulama başlamamıştır.

## 1. Durum ve yürütme sınırı

- **Wave:** 04
- **Wave adı:** Health, performans verisi, DB runtime ve operasyon güvenliği
- **Plan durumu:** Hazır
- **Wave durumu:** Bekliyor
- **Uygulama durumu:** Başlamadı
- **Uygulama yetkisi:** Verilmedi
- **Giriş kapısı:** Wave 03 `QA kapalı` ve kullanıcıdan açık “Wave 04'ü başlat” talimatı
- **Mevcut blokaj:** Wave 01–03 uygulanıp kapanmadı; Wave 04 uygulanamaz
- **Önceki wave:** Wave 03 — planı hazır, aktif değil
- **Sonraki wave:** Wave 05 — planı ayrı talimatla hazırlandı; aktif değil ve uygulanmadı

Bu dosyanın hazırlanması Wave 04 aktivasyonu, DB sorgusu/migrationı, backup/restore, canlı config, Render restart/deploy veya Wave 05 aktivasyonu/uygulaması için yetki değildir.

## 2. Canonical referanslar

Uygulama sırası değişmez: `B-API-002 → B-ANL-002 → B-DB-001 → C-PERF-001 → C-OPS-001 → C-OPS-002`.

1. `B-API-002` — Plan B / liveness, readiness ve release kimliği / bütün kabul kriterleri
2. `B-ANL-002` — Plan B / performance ve SLO veri sözleşmesi / bütün kabul kriterleri
3. `B-DB-001` — Plan B / sürümlü migration ve DB runtime / bütün kabul kriterleri
4. `C-PERF-001` — Plan C / QA-011 karar odaklı performans özeti / bütün kabul kriterleri
5. `C-OPS-001` — Plan C / canlı servis, config ve deploy runbook / bütün kabul kriterleri
6. `C-OPS-002` — Plan C / backup, restore ve felaket kurtarma / bütün kabul kriterleri

Yürütme kaynağı: `../TALKX_WAVE_MAP.md` / Wave 04.
Canonical ayrıntı kaynakları: `../TALKX_PLAN_B_PLATFORM_REALTIME_DATA.md` ve `../TALKX_PLAN_C_ADMIN_TRUST_RELEASE.md`.
Kilitli karar ve kanıt kaynağı: `../TALKX_MASTER_BACKLOG.md` / §8, §10–§12, QA-011 ve ilgili operasyon kayıtları.

Bağımlılık yorumu:

- `B-OBS-001` ve `B-API-001`, Wave 02'de QA kapalı olmalıdır; health, performance ve hata cevapları aynı request/release sözleşmesini tüketir.
- `C-ADMIN-001`, Wave 02'de QA kapalı olmalıdır; C-PERF-001 yalnız güvenli admin kabuğuna eklenir.
- Wave 04 DB migration otoritesidir fakat canlı DB işlemi yine ayrıca açık kullanıcı yetkisi ister.
- Önceki TalkX Neon restore kanıtı tarihsel referanstır; mevcut endpoint, credential, schema ve satır sayıları uygulama anında yeniden doğrulanmadan güncel kabul edilmez.

## 3. Wave sonucu

Wave 04 sonunda:

- Process canlılığı ile servisin trafik almaya hazır olması ayrı ve makinece yorumlanabilir endpoint/state olacak.
- Readiness PostgreSQL erişimi, bounded timeout, beklenen `public` schema ve migration durumunu kontrol edecek; credential veya connection string açığa çıkarmayacak.
- Health cevabı environment ve gerçek deploy commit/app version bilgisini güvenli allowlist alanlarla taşıyacak.
- Request/performance verisi count, error rate, latency percentile, SLO/threshold, önceki dönem, platform/release, sample/confidence ve stale/partial/no-data anlamına sahip olacak.
- Örnek bulunmayan P50/P95/P99 değeri `0 ms` gibi gösterilmeyecek; az örnek kritik alarm üretmeyecek.
- Tek büyük `ensureTables()` yerine checksum'lı, sıralı, kilitli ve tekrar çalıştırılabilir PostgreSQL migration zinciri kurulacak.
- Boş DB ve mevcut TalkX DB aynı canonical migration geçmişine güvenle bağlanabilecek; partial failure görünür olacak.
- Pool size, connect/query/statement timeout ve shutdown davranışı Render/Neon sınırlarıyla açık config sözleşmesine bağlanacak.
- Frontend, backend, Android ve docs sahipliği ile commit/config/release ilişkisi runbook'ta kanıtlanabilir olacak.
- Backup custom/compressed, erişimi kısıtlı, doğrulanmış ve staging restore ile test edilmiş olacak; kritik sayımlar source/target karşılaştırılacak.
- Canlı cutover/restart/restore işlemleri plan dosyasının varlığıyla yetkilendirilmeyecek.

## 4. Doğrulanmış başlangıç fotoğrafı

### 4.1 Repo ve sahiplik gerçeği

- Kök `C:\Users\Enis\Desktop\chatapp` çalışma alanı geniş dirty durum taşıyor.
- `chatapp-backend/` ve `chatapp-frontend/` kendi `.git` dizinlerine sahip; kök Git görünümü güncel ağaçları untracked ve tarihsel `backend/`/`frontend/` ağacını silinmiş gösteriyor.
- Kök `package.json`, Capacitor/Android komutlarını ve backend GitHub repository bilgisini taşıyor; tek repo sahipliği izlenimi yanıltıcı olabilir.
- Wave 04 hiçbir kullanıcı değişikliğini temizlemez; üç Git bağlamı ayrı status/remote/branch/commit fotoğrafıyla kaydedilir.
- `render.yaml` kökte bulunmadı; gerçek Render service ayarı repo dışı/live panel kanıtı gerektiriyor.

### 4.2 B-API-002 mevcut gerçek

- Backend yalnız `GET /health` üzerinden `{ ok: true }` döndürüyor.
- Bu endpoint DB, schema, migration, dependency timeout, environment, commit veya version kontrol etmiyor.
- Mevcut `/health`, liveness ile readiness ayrımı yapmadığı için process açıkken DB kullanılamaz olsa da sağlıklı görünebilir.
- Startup `ensureTables()` başarısızsa process çıkıyor; kısa DB sorunu ile migration/schema problemi ayrılmıyor.
- `package.json` backend versionı `1.0.0`; deploy commit SHA ve environment için doğrulanmış response alanı yok.
- Health cevabında credential sızıntısı yok; bu minimum güvenlik korunacak.

### 4.3 B-ANL-002 mevcut gerçek

- `http_request_metrics_minute` sayım, hata, slow count ve toplam duration rollup'ı taşıyor.
- `http_request_events` örneklenmiş request duration/status kayıtlarıyla percentile hesaplamasında kullanılıyor.
- Admin `/performance/overview`, `/timeseries` ve `/slow-requests` endpointleri mevcut.
- Overview percentile sorgusu veri yokken SQL `COALESCE(..., 0)` ve JS `Number(...) || 0` ile P50/P95/P99'u sıfır gösterebiliyor.
- Average latency veri yokken `0`, error rate trafik yokken `0` dönüyor; no-data ile gerçek sıfır ayrılmıyor.
- Route sıralaması slow sample veya error count üzerinden parçalı; trafik, hata, latency ve etki tek canonical score/sözleşmede değil.
- Sample sayısı, confidence, threshold/SLO, previous-period ve stale/partial göstergeleri eksik veya parçalı.
- Admin sorgu hataları bazı yerlerde `e.message` ile doğrudan response'a çıkabiliyor.

### 4.4 B-DB-001 mevcut gerçek

- `db.js` tek `DATABASE_URL` ile `pg.Pool` oluşturuyor; SSL `rejectUnauthorized: false` kullanıyor.
- Pool size, connection timeout, idle timeout, query timeout ve statement timeout açık config olarak yazılmamış.
- Yaklaşık 27 KB'lık `db.js`, büyük `createTablesQuery` içinde table, ALTER, DO block ve index işlemlerini bir arada taşıyor.
- Startup her seferinde `ensureTables()` çağırıyor; migration ledger/version/checksum bulunmuyor.
- Bazı ALTER işlemleri exception yakalayıp notice ile devam edebiliyor; partial schema drift merkezi durumda görünmüyor.
- Aynı anda birden fazla instance migration çalıştırmasını önleyen advisory lock görünmüyor.
- `current_schema()` bazı constraint işlemlerinde kullanılıyor fakat startup'ta `public` schema invariantı açık doğrulanmıyor.
- Tarihsel doğrulanmış Neon geçişinde direct endpoint + role `search_path=public` çalıştı; `-pooler` endpoint boş search_path nedeniyle `relation users does not exist` üretti.

### 4.5 C-PERF-001 mevcut gerçek

- Admin performance yüzeyi ve veri endpointleri bulunuyor; sıfırdan yeni dashboard gerekmiyor.
- Ham totals, percentile, slow route ve error route bilgisi mevcut fakat karar hiyerarşisi eşik → etki → güven → aksiyon şeklinde kilitli değil.
- Zaman penceresi `hours` ile seçilebiliyor; kullanıcıya threshold, previous-period ve sample güveni tam açıklanmıyor.
- P95 yokluğu sıfıra çevrildiği için “çok hızlı” ile “ölçüm yok” karışabiliyor.
- API/DB/client ve Release Health ayrımı bütün görünümde canonical değil.
- Ham bucket/detail'e geri izleme var fakat özet iddiasının kaynağı/zamanı daha açık olmalı.

### 4.6 C-OPS-001 mevcut gerçek

- Ayrı frontend/backend Git repoları var; kök Android/docs dosyalarının release sahipliği net runbook'ta birleşmiyor.
- Mevcut docs altında Android emulator/build, static routing ve support debug notları bulunuyor.
- Render service, environment variable, deploy hook, branch ve health check ayarlarının güncel canonical envanteri bulunmuyor.
- Config değişikliğinin restart/redeploy gerektirip gerektirmediği değişken bazında belgeli değil.
- Deploy edilen backend commit/version ile frontend/Android artifact eşliğini tek kanıt paketi göstermiyor.
- Rollback hedef commit/artifact, migration compatibility ve smoke adımları tek protokolde birleşmemiş.

### 4.7 C-OPS-002 mevcut gerçek

- `backup/talkx_chatapp_reports_20260807.dump` adlı custom dump ve `backup/.gitignore` mevcut; dump yaklaşık 485 KB.
- Tarihsel restore 23 table data bölümü, 63 index, `pgcrypto` ve kritik counts ile doğrulanmıştı; bu sayılar güncel canlı sayı olarak kullanılamaz.
- Önceki restore `--no-owner --no-privileges --exit-on-error --single-transaction` seçenekleriyle başarılı oldu.
- Direct Neon endpoint ve `current_schema()=public` doğrulaması tarihsel olarak başarılı; pooler/search_path sorunu kayda geçmiş.
- Backup encryption, harici storage/access, retention, düzenli restore rehearsal, RPO/RTO ve son doğrulama tarihi tek canonical runbook'ta görünmüyor.
- Canlı `DATABASE_URL` cutover sonrası backend restart ve kullanıcı smoke gerekliliği biliniyor fakat otomatik yetki değildir.

## 5. Kilitli Wave 04 sözleşmeleri

### 5.1 Liveness, readiness ve startup modeli

- Liveness yalnız process/event-loop'un cevap verebildiğini gösterir; DB sorgulamaz ve kısa DB kesintisinde restart döngüsü üretmez.
- Readiness bounded timeout ile DB bağlantısı, basit query, `current_schema()=public` ve beklenen migration head durumunu kontrol eder.
- Bir alt kontrol başarısızsa readiness non-2xx döner; liveness mümkünse çalışmaya devam eder.
- Startup migration başarısızsa trafik kabul edilmez; hata structured logda güvenli code ile görünür olur.
- Mevcut `/health` consumerları envanterlenmeden semantik sessizce değiştirilmez; compatibility alias veya kontrollü geçiş kullanılır.
- Health response yalnız allowlist alanlar taşır: status, service, appVersion, commitSha, environment, timestamp ve safe check sonuçları.
- Credential, hostname içeren connection string, token, secret, raw exception veya internal SQL response'a çıkmaz.
- DB check ve diğer dependencyler birbirini sonsuza kadar beklemez; her biri açık timeout taşır.

### 5.2 Release kimliği

- Backend app version package/build kaynağından gelir; elle farklı iki yerde tutulmaz.
- Commit SHA deploy ortamının immutable değeriyle taşınır; yoksa `unknown` açıkça görünür, uydurulmaz.
- Environment allowlist ile `development`, `staging`, `production` gibi güvenli değere normalize edilir.
- Readiness response ile admin/release kaydı aynı release ID'yi tüketir.
- Frontend ve Android ayrı artifact kimliklerini korur; backend versionına eşitmiş gibi gösterilmez.
### 5.3 Performance ve SLO veri sözleşmesi

Canonical özet en az şunları taşır:

- Ölçüm penceresi ve karşılaştırılan önceki dönem
- Route/operation ve service katmanı
- Request/sample count
- Error count/rate
- P50/P95/P99 yalnız yeterli örnek varsa
- SLO/threshold ve değerlendirme sonucu
- Platform/release kırılımı varsa gerçek kaynak
- `fresh`, `stale`, `partial`, `no_data` veri durumu
- Sample/confidence etiketi
- Etki sırası ve ham kanıt bağlantısı

Kurallar:

- Percentile örneği yoksa değer `null`; `0` değildir.
- Az örnek threshold aşsa bile doğrudan kritik alarm değil, `low_confidence` sonucudur.
- Route etkisi yalnız en yüksek latency ile değil trafik × hata × latency bağlamıyla yorumlanır.
- Sampling ile full rollup aynı kesinlikte sunulmaz.
- DB, backend API, client ve Release Health metrikleri aynı ölçüm gibi birleştirilmez.
- Previous-period eksikse değişim yüzdesi uydurulmaz.
- Stale eşiği son başarılı bucket zamanı ve seçilen pencereye göre deterministiktir.
- C-PERF-001 özet metni yalnız bu sözleşmeden üretilir; admin client ham rowlardan yeni anlam tahmin etmez.

### 5.4 Migration yaşam döngüsü

- `schema_migrations` ledger'ı version/name/checksum/applied_at/duration/result bilgisini taşır.
- Migrationlar değişmez, sıralı ve tek sorumlulukludur; uygulanmış dosya geriye dönük düzenlenmez.
- Runner PostgreSQL advisory lock ile çoklu instance yarışını engeller.
- Transaction destekleyen migration atomik çalışır; transaction dışı adım açıkça işaretlenir ve ayrı rollback/forward-fix ister.
- Checksum uyuşmazlığı, sıra boşluğu ve failed/partial durum startup readiness'i başarısız yapar.
- Empty DB canonical zinciri baştan çalıştırır.
- Mevcut DB için baseline, gerçek schema inventory karşılaştırılmadan “uygulanmış” yazılmaz.
- `ensureTables()` tek seferde kaldırılmaz; migration parity testi ve geçiş kapısı tamamlandıktan sonra startup runner'a devredilir.
- Rollback yalnız güvenliyse uygulanır; veri kaybı riski olan değişiklik forward-fix ve açık onay ister.
- Production migration öncesi doğrulanmış backup, staging rehearsal, etki/lock süresi ve rollback hedefi gerekir.

### 5.5 DB runtime sözleşmesi

- `DATABASE_URL` değeri hiçbir log, docs veya health response'a yazılmaz.
- TalkX için direct Neon endpoint ve `search_path=public` varsayımı uygulama anında read-only kontrolle yeniden doğrulanır.
- Pooler/direct seçimi alışkanlıkla değil session/transaction/search_path ve provider sınırlarıyla gerekçelendirilir.
- Pool max, idle timeout, connection timeout, query timeout ve statement timeout environment-aware güvenli defaultlara sahiptir.
- Config sayısal allowlist/min-max sınırından geçer; bozuk değer sınırsız bağlantıya dönüşmez.
- Startup, graceful shutdown ve pool error davranışı testlidir.
- Slow query kanıtı query shape/operation etiketiyle tutulur; SQL parametresi veya hassas veri loglanmaz.
- Büyüyen telemetry/audit/message tabloları için ölçüm ve sonraki karar görünürdür; Wave 04 retention silme policy'si icat etmez.

### 5.6 Operasyon ve release sahipliği

| Alan | Canonical sahiplik kanıtı |
|---|---|
| Backend | İç Git remote/branch/commit, package version, Render service/config snapshot |
| Frontend | İç Git remote/branch/commit, build artifact kimliği ve hosting route smoke |
| Android | Kök/native dosya sahipliği, web asset kaynağı ve release artifact kimliği |
| Docs/runbook | Hangi repo/commit ile birlikte güncellendiği ve son doğrulama tarihi |
| Database | Provider/project/database/schema/migration head; credential değeri olmadan |

- Her environment variable için amaç, owner, required/optional, hassasiyet ve restart/redeploy etkisi belgelenir; değer yazılmaz.
- Deploy öncesi hedef commit/artifact, migration uyumu ve rollback noktası bilinir.
- Deploy sonrası health/readiness tek başına yeterli değildir; gerçek auth + WebSocket + kritik kullanıcı smoke'u gerekir.
- Static frontend fallback/routing, CORS/origin ve domain/deep-link smoke'u runbook'ta bulunur.
- Incident notu zaman, release, etki, karar, rollback ve kanıtı taşır.
- Runbook komutları/endpointleri son doğrulama tarihi olmadan güncel varsayılmaz.

### 5.7 Backup, restore ve disaster recovery sözleşmesi

- Backup source kimliği provider/database/schema/migration head ile; target restore ortamı ayrı kimlikle kaydedilir.
- `pg_dump` custom/compressed format, tool/server version ve SHA-256 doğrulaması taşır.
- Dump şifresiz ve erişimi belirsiz dağınık dosya olarak bırakılmaz; encryption, storage, access owner ve retention belgelenir.
- `pg_restore --list` arşiv okunabilirliğinin ilk kapısıdır; başarılı backup iddiası restore rehearsal olmadan tamamlanmaz.
- Restore önce izole staging/temporary DB'de yapılır; boş schema oluşturmak restore başarısı sayılmaz.
- Role/owner/privilege, extension, trigger, index, FK ve `current_schema()=public` doğrulanır.
- Kritik count seti uygulama anında source'tan ölçülür; users, profiles, sessions, friendships, conversations/messages, reports, legal, push, support, audit/analytics gibi sınıflar source/target karşılaştırılır.
- Tarihsel counts örnek/evidence'tır; güncel beklenen değer olarak hard-code edilmez.
- RPO/RTO hedefi, restore süresi, veri kaybı penceresi ve son rehearsal tarihi kayıtlıdır.
- Cutover; backup → restore verify → readiness → config change → restart → user smoke → observation sırasını izler.
- Canlı restore/cutover ve credential rotasyonu ayrıca açık kullanıcı yetkisi ister.

## 6. Uygulama paketleri

### Paket 04A — B-API-002 health/readiness/release kimliği

Muhtemel hedefler:

- `chatapp-backend/index.js`
- `chatapp-backend/package.json`
- Yeni health/config/release yardımcıları
- Focused endpoint ve startup testleri
- Render service health-check ayarı için ayrı live kanıt

İş sırası:

1. Mevcut `/health` consumer ve provider envanterini çıkar.
2. Liveness/readiness contract fixture'larını yaz.
3. Process-only liveness'i DB sorunundan ayır.
4. Readiness'e bounded DB query, schema ve migration-head kontrolü ekle.
5. Version/commit/environment/server-time alanlarını güvenli release helper'dan üret.
6. Timeout, DB down, wrong schema, migration pending/failed ve unknown release durumlarını testle.
7. Legacy `/health` davranışını compatibility planıyla koru.
8. Render health-check değişikliğini local/staging kanıtından sonra ayrı yetki kapısında tut.

### Paket 04B — B-ANL-002 performance/SLO sağlayıcısı

Muhtemel hedefler:

- `chatapp-backend/index.js` request telemetry
- `chatapp-backend/admin.js` performance endpointleri
- Performance query/contract yardımcıları
- Focused SQL fixture ve API contract testleri

İş sırası:

1. Metrics rollup ve sampled events veri kalitesini envanterle.
2. Window, threshold, minimum sample, stale ve confidence kurallarını merkezi configte tanımla.
3. No-data percentile'ı `null` yap; gerçek 0 ile ayır.
4. Previous-period, route traffic/error/latency ve impact ordering sorgularını kur.
5. Sampled percentile ile full request count'un güven farkını response'ta taşı.
6. Platform/release alanı kaynakta yoksa `unknown` de; tahmin etme.
7. Partial query failure'da kullanılabilir alt sonucu koru ve eksikliği açıkla.
8. Response'u C-PERF-001'in tek veri sözleşmesi yap.

### Paket 04C — B-DB-001 migration runner ve DB runtime

Muhtemel hedefler:

- `chatapp-backend/db.js`
- Yeni `chatapp-backend/migrations/`
- Migration runner/CLI ve focused DB testleri
- `chatapp-backend/package.json`
- Environment config örneği; gerçek credential olmadan

İş sırası:

1. Mevcut schema/table/index/constraint inventory ve `ensureTables()` parity snapshotı çıkar.
2. Migration ledger, checksum ve advisory-lock runner'ı test DB üzerinde kur.
3. Mevcut DB baseline kararını schema diff kanıtıyla uygula; yalnız dosya var diye işaretleme.
4. Empty DB migration zincirini sıfırdan çalıştır ve mevcut schema ile karşılaştır.
5. Partial failure, checksum mismatch, duplicate instance ve retry testlerini yap.
6. Startup'ı migration-head/readiness sözleşmesine bağla.
7. Pool/timeout/graceful shutdown configini min-max doğrulamayla kur.
8. `ensureTables()` parity tamamlanınca legacy bootstrap'ı kaldır; aynı adımda özellik schema değişikliği yapma.
9. Staging rehearsal ve backup kapısı olmadan production migration çalıştırma.

### Paket 04D — C-PERF-001 QA-011 karar görünümü

Muhtemel hedefler:

- `chatapp-backend/admin.html`
- `chatapp-backend/admin.js`
- Admin performance component/style/helper alanları
- Focused admin contract/render testleri

İş sırası:

1. QA-011 current ekranını durum → etki → aksiyon → kanıt sırasıyla yeniden düzenle.
2. Window, threshold, sample/confidence ve last-updated bilgisini özet yanında göster.
3. No-data, low-confidence, stale ve partial durumlarını ayrı render et.
4. Route etkisini traffic/error/latency birlikte göstererek sırala.
5. API, DB, client ve Release Health anlamlarını görsel/metinsel olarak ayır.
6. Ham bucket/detail drill-down'ını koru; varsayılan ekranı veri deposuna çevirme.
7. Teknik stack/SQL/error message göstermeden request ID ve güvenli retry sun.
8. Desktop/mobile/keyboard/large-text davranışını C-ADMIN-001 kabuğunda kanıtla.

### Paket 04E — C-OPS-001 deploy/config runbook

Hedef çıktı:

- Canonical environment/repo/release/deploy/rollback runbook'u
- Credential içermeyen config envanteri
- Frontend/backend/Android/docs sahiplik matrisi
- Local/staging/production smoke ve observation checklist'i

İş sırası:

1. Kök ve iki iç repo remote/branch/commit/default-branch sahipliğini doğrula.
2. Hosting/Render service, build/start command, deploy branch ve health endpointini panel kanıtıyla eşle.
3. Environment variable amaç/owner/restart etkisini değer yazmadan kaydet.
4. Static route, CORS/origin, domain ve deep-link smoke adımlarını birleştir.
5. Deploy öncesi migration/backup/rollback kapısını yaz.
6. Deploy sonrası readiness + gerçek auth/socket/user smoke ve observation penceresini yaz.
7. Rollback hedef commit/artifact/config/migration uyumunu açıklaştır.
8. Tarih, owner ve evidence linki olmayan stale komutu güncel sayma.

### Paket 04F — C-OPS-002 backup/restore/DR runbook

Hedef çıktı:

- Backup alma, doğrulama, şifreleme, saklama ve retention prosedürü
- İzole staging restore rehearsal prosedürü
- Critical table/count ve schema doğrulama script/checklist'i
- RPO/RTO, cutover, rollback ve credential rotation kapıları

İş sırası:

1. Source/target kimliğini credential olmadan read-only doğrula.
2. Güncel critical count snapshotı ve migration head'i kaydet.
3. Version uyumlu `pg_dump` ile custom/compressed backup al; hash ve archive list doğrula.
4. Backup'ı erişim/şifreleme/retention policy'sine göre sakla.
5. İzole DB'ye single-transaction restore rehearsal yap.
6. Schema, extension, role/privilege, trigger/index/FK ve critical count eşliğini doğrula.
7. Direct/pooler ve `search_path=public` kararını gerçek Node `pg` testiyle doğrula.
8. Restore süresi ve veri penceresinden RPO/RTO kanıtı çıkar.
9. Canlı cutover/restart/smoke'u yalnız ayrıca yetkilendirilirse uygula.
## 7. Dosya ve servis etki sınırı

### Birincil backend ve DB alanı

- `chatapp-backend/index.js`
- `chatapp-backend/db.js`
- `chatapp-backend/package.json`
- Yeni health/config/performance/migration yardımcıları
- Yeni `chatapp-backend/migrations/` ve focused test araçları

### Admin ve operasyon belgesi alanı

- `chatapp-backend/admin.js`
- `chatapp-backend/admin.html`
- Mevcut `docs/` operasyon notları
- Yeni canonical deploy/config ve backup/restore runbook çıktıları
- Credential taşımayan environment/release/smoke checklistleri

### Read-only harici alan

- Render service/config/deploy/health ekranları
- Neon project/database/role/schema/connection mode bilgisi
- Git remotes/branches/commits
- Backup storage/access policy kanıtı

### Varsayılan olarak değişmeyecek alanlar

- Frontend kullanıcı UI/UX ve Wave 03 foundation kodu
- Realtime reconnect/presence ve matchmaking
- Android build/version/signing/artifact
- Legal, notification ve admin feature ekranları
- Canlı infrastructure state'i açık izin olmadan

## 8. Açık kapsam dışı

- `B-WS-002` reconnect/active-state recovery
- `B-PRES-001` presence/last seen
- `B-MM-001/002/003` search, Global/Country ve pending offer
- `B-DATA-001/002/003` retention, canonical country ve hesap silme
- `B-ANL-001` davranış analitiği
- `B-OBS-002` Release Health ingestion
- `C-ANL-001/002`, `C-ADMIN-002–006`, `C-REL-001` özellikleri
- Performance ekranına tahmine dayalı AI önerisi
- Telemetry retention politikasını kanıtsız belirleme veya veri silme
- Production migration/restore/cutover/restart/deploy
- Canlı credential okuma, yazma veya sohbet/log içine taşıma
- Frontend/backend/Android release yayınlama
- Wave 05 aktivasyonu veya uygulaması

## 9. Otomatik doğrulama planı

### Statik ve mevcut kapılar

- `node --check chatapp-backend/index.js`
- `node --check chatapp-backend/db.js`
- `node --check chatapp-backend/admin.js`
- Değişen migration/runner/utils/test JS dosyalarında `node --check`
- `npm run check:text-encoding`
- Runbook link, endpoint ve placeholder-secret taraması

### B-API-002 health matrisi

- Process healthy / DB healthy
- Process healthy / DB down
- DB timeout
- Wrong/empty `search_path`
- Migration current/pending/failed/checksum mismatch
- Commit/version present ve absent (`unknown`)
- Environment allowlist/fallback
- Credential/connection string/raw error negatif sızıntı testi
- Legacy `/health` compatibility
- Graceful shutdown sırasında readiness değişimi

### B-ANL-002 veri matrisi

- Gerçek latency `0` ile no-data `null` ayrımı
- Yeterli/yetersiz percentile sample
- Traffic var/error yok; error var/az traffic; high traffic/high latency
- Current ve previous period
- Stale, partial ve failed alt sorgu
- Sampled event ile full rollup count farkı
- Route stable ordering ve impact ranking
- Platform/release known/unknown
- Threshold/SLO boundary
- API response → C-PERF-001 render eşliği

### B-DB-001 migration matrisi

- Empty DB full migration
- Mevcut TalkX schema baseline
- Aynı migration ikinci kez
- İki runner/advisory lock yarışı
- Transaction rollback
- Non-transaction migration failure policy
- Checksum mismatch ve version gap
- Partial/failed ledger görünürlüğü
- `current_schema()=public`
- Extension, table, column, constraint, index ve trigger parity
- Pool max/connect/query/statement timeout config sınırları
- SIGTERM/graceful pool shutdown
- Credential/log redaction

### C-PERF-001 render matrisi

- Healthy, warning, critical ve low-confidence
- No-data/stale/partial/error
- Threshold/window/sample/last-updated görünürlüğü
- Route impact ordering
- API/DB/client/Release Health ayrımı
- Ham kanıta drill-down
- Teknik hata/SQL/stack sızıntısı olmaması
- Desktop/mobile/keyboard/large-text

### C-OPS-001 runbook doğrulaması

- Her repo remote/branch/commit ve sahiplik
- Build/start/deploy command doğruluğu
- Environment variable adı/owner/restart etkisi; değer yok
- Health/readiness endpoint smoke
- Auth/WebSocket/user journey smoke
- Static routing/CORS/origin/domain/deep-link
- Target commit/artifact ve rollback hedefi
- Son doğrulama tarihi/owner/evidence

### C-OPS-002 backup/restore doğrulaması

- Tool/server version uyumu
- Custom archive format ve SHA-256
- `pg_restore --list`
- Encryption/storage/access/retention
- İzole target ve single-transaction restore
- Role/privilege/extension/schema/index/FK/trigger
- Source/target critical counts
- Direct Neon endpoint ve `current_schema()=public`
- Restore duration, RPO ve RTO
- Cutover sonrası readiness + gerçek kullanıcı smoke

## 10. Manuel ve staging QA planı

### Health ve release

- Local/staging liveness ile readiness'i ayrı çağır.
- DB erişimini kontrollü keserek liveness'in açık, readiness'in başarısız kaldığını doğrula.
- Commit SHA/app version/environment değerini gerçek deploy ile karşılaştır.
- Health response ve loglarda secret/connection string/internal SQL bulunmadığını incele.
- Render health check'in doğru endpoint ve timeout'u kullandığını panelden doğrula.

### Performance QA-011

- 24 saat ve seçilebilir diğer pencere sonuçlarını gerçek query ile karşılaştır.
- No-data'da percentile'ın sıfır görünmediğini doğrula.
- Az sample'ın kritik alarm üretmediğini kontrol et.
- En etkili route sırasını traffic/error/latency kaynağına geri izle.
- Stale/partial durumunda son güncelleme ve eksik veri açıklamasını kontrol et.
- Desktop/mobile/keyboard/large text ile özet → detay akışını doğrula.

### Migration ve DB runtime

- Empty test DB ve mevcut schema kopyasını aynı migration head'e getir.
- İki runner'ı eşzamanlı başlatıp advisory lock davranışını gözle.
- Kontrollü failed migration ile readiness ve ledger sonucunu doğrula.
- Pool exhaustion/query timeout/graceful shutdown davranışını staging'de test et.
- Direct Neon bağlantıda schema ve kritik read-only query smoke'u yap.

### Operasyon ve disaster recovery

- Runbook'u temiz bir terminal/context ile adım adım dry-run et.
- Credential değeri kopyalamadan repo/release/config sahipliğini bulabildiğini doğrula.
- Yeni custom dump'ı listele ve hashle; erişim/encryption policy'sini kontrol et.
- İzole restore targetında schema ve güncel critical counts eşliğini doğrula.
- Restore süresini, RPO/RTO sonucunu ve rollback adımını kaydet.
- Canlı cutover/restart/restore adımlarını açık kullanıcı izni yokken çalıştırma.

## 11. Kanıt ve kabul eşlemesi

| Plan ref | Gerekli kanıt | Kapanış şartı |
|---|---|---|
| B-API-002 | Health contract testleri, DB-down/timeout/schema/migration sonuçları, release karşılaştırması | Beş canonical kabul kriteri kanıtlı |
| B-ANL-002 | SQL/API fixtures, sample/confidence/no-data/threshold/impact sonuçları | Beş canonical kabul kriteri kanıtlı |
| B-DB-001 | Empty/existing DB migration, lock/checksum/failure, pool/timeout ve schema kanıtı | Yedi canonical kabul kriteri kanıtlı |
| C-PERF-001 | QA-011 API/render karşılaştırması, state matrisi, drill-down ve responsive kanıt | Yedi canonical kabul kriteri kanıtlı |
| C-OPS-001 | Repo/config/deploy/rollback runbook dry-run ve live panel eşlemesi | Yedi canonical kabul kriteri kanıtlı |
| C-OPS-002 | Dump/hash/list, staging restore, critical counts, schema ve RPO/RTO kanıtı | Sekiz canonical kabul kriteri kanıtlı |

Checkbox yalnız ilgili canonical kabul kriteri gerçek kanıtla kapandığında işaretlenir. Tarihsel restore kanıtı yeni backup/restore rehearsal yerine geçmez.

## 12. Riskler ve rollback

| Risk | Koruma | Rollback/durma davranışı |
|---|---|---|
| `/health` semantiği mevcut monitorü kırar | Consumer envanteri ve compatibility alias | Yeni route/config geçişini geri al |
| Readiness DB dalgalanmasında false negative üretir | Bounded timeout ve ayrı liveness | Threshold'u kanıtla ayarla; DB kontrolünü gizleme |
| Release kimliği yanlış deploy gösterir | Immutable env + gerçek commit karşılaştırması | `unknown` göster; uydurma version yazma |
| No-data sıfır görünerek yanlış karar üretir | Null/data-state contract testleri | Eski özet yerine güvenli no-data state'e dön |
| Percentile sampling yanıltır | Sample/confidence ve full-count ayrımı | Alarmı low-confidence yap; ham kanıtı koru |
| Baseline mevcut DB'yi yanlış işaretler | Schema inventory/parity ve backup | Ledger yazmadan dur |
| Migration iki instance'ta yarışır | Advisory lock ve concurrency testi | Startup migrationı kapat, tek runner'a dön |
| Migration veri kaybı yaratır | Backup, staging, transaction/forward-fix kapısı | Canlı işlemi durdur; doğrulanmış artifact'a dön |
| Pool config Neon limitini aşar | Provider sınırı ve min-max config | Önceki güvenli pool configine dön |
| Pooler/search_path tekrar boş schema gösterir | Direct endpoint ve `current_schema()` check | Cutover yapma/geri al; credential paylaşma |
| Dump okunur ama restore edilemez | Archive list + izole rehearsal | Backup'ı geçersiz say ve yeniden üret |
| Runbook stale endpoint/command taşır | Tarih/owner/evidence ve dry-run | İlgili adımı bloke olarak işaretle |
| Dirty repo kullanıcı işini örter | Üç Git bağlamında başlangıç snapshotı | Yalnız Wave 04 farkını geri al |
## 13. Canlı işlem ve destructive sınır

Wave 04'ün planlanmış olması aşağıdaki işlemler için yetki vermez. Her biri hedefi ve etkisi doğrulandıktan sonra ayrıca açık kullanıcı onayı gerektirir:

- Production veritabanında read-only doğrulamanın ötesine geçen query, DDL veya migration
- Canlı veri içeren yeni backup üretimi, indirilmesi, taşınması ya da silinmesi
- Staging veya başka bir dış hedefte restore ile mevcut state'in değiştirilmesi
- Render environment variable, `DATABASE_URL`, health check, restart veya redeploy değişikliği
- Neon role, privilege, endpoint, connection mode veya `search_path` değişikliği
- Cutover, credential rotation veya production load/performance testi
- Mevcut backup artifact'ının silinmesi ya da üzerine yazılması

Yürütme sırası önce read-only kapsam ve etki analizi, sonra local otomatik testler, ardından izole staging rehearsal şeklindedir. Canlı değişiklik ancak bunların kanıtı görüldükten ve ilgili işlem ayrıca onaylandıktan sonra yapılır.

## 14. Başlangıç kapısı

Bu maddeler plan hazırlanırken işaretlenmez; yalnız Wave 04 gerçekten başlatılırken güncel kanıtla kapatılır:

- [ ] Wave 01–03 QA kapanışları ve kullanıcı onayı doğrulandı.
- [ ] Kullanıcı açıkça “Wave 04'ü başlat” talimatı verdi.
- [ ] Root, backend ve frontend Git bağlamlarının status/remote/branch/commit snapshot'ı alındı.
- [ ] Wave 02 API/observability sözleşmeleri ile Plan C admin provider sınırı güncel kodda yeniden doğrulandı.
- [ ] Mevcut `/health` consumer, monitor ve deploy health-check envanteri çıkarıldı.
- [ ] Güncel DB schema, migration/runtime ve connection mode read-only olarak kaydedildi.
- [ ] Tarihsel Neon/restore kanıtlarının güncelliği yeniden doğrulandı; eski sayımlar güncel gerçek kabul edilmedi.
- [ ] Backup storage, encryption, retention ve izole restore hedefi belirlendi.
- [ ] Canlı sistem mutasyonları ayrı onay kapısına bağlandı.
- [ ] Wave 05 kapsamına taşma olmadığı doğrulandı.

## 15. Sonuç alanı

Wave 04 yürütülürse kapanış kaydı en az şu kanıtları içerir:

- Başlangıç/bitiş zamanı, kullanılan Plan ref'leri ve gerçek değişen dosyalar
- Git/release/config sahiplik matrisi ve doğrulanan commit/version/environment
- Liveness, readiness, DB-down, timeout, schema ve migration-drift sonuçları
- Migration ledger, checksum, advisory lock, empty/existing DB ve failure-path sonuçları
- Pool/timeout/graceful shutdown ile direct endpoint ve `current_schema()` kanıtı
- Performance API/SQL/UI karşılaştırması; sample, confidence, no-data ve threshold sonuçları
- Backup archive/hash/list/storage bilgisi, izole restore raporu, güncel kritik sayımlar ve RPO/RTO
- Runbook dry-run, staging kanıtı ve varsa ayrı onayla yapılan canlı işlem kaydı
- Kullanıcı QA onayı, son Wave durumu ve Wave 05'in başlatılmadığına dair açık durma kaydı

## 16. Durma kuralı

Wave 03 QA kapanışı ve kullanıcının açık Wave 04 başlatma talimatı birlikte gelene kadar:

- Wave 04 için kod, config, migration, DB, backup, deploy veya operasyon değişikliği yapılmaz.
- Render/Neon üzerinde hiçbir state değişikliği yapılmaz.
- Wave 04 `Aktif` işaretlenmez; bu belge yalnız `Hazır — aktif değil` durumunda kalır.
- Wave 05 yalnız ayrı açık planlama talimatıyla belgelenebilir; aktive edilmez veya uygulanmaz.