# TalkX Wave 16 Plan — QA-016 Release Health

> Bu belge yalnız Wave 16 için hazırlanmış uygulama planıdır.
> Canonical sıra Plan B `B-OBS-002` → Plan C `C-REL-001` şeklindedir.
> Ana ilke: istemci hatası içerik toplamadan gerçek release kimliği ve güven seviyesiyle ölçülür; admin önce durum, etki ve aksiyonu, sonra maskelenmiş kanıtı görür.
> Plan hazırdır. Wave 16 aktif değildir, Wave 01–15 kapanmamıştır ve uygulama başlamamıştır. Wave 17 ayrı belgede planlanmıştır; burada uygulanmaz veya başlatılmaz.

## 1. Durum ve yürütme sınırı

- **Wave:** 16
- **Wave adı:** QA-016 Release Health
- **Plan katılımı:** Plan B + Plan C
- **Canonical sıra:** `B-OBS-002 → C-REL-001`
- **Plan durumu:** Hazır
- **Wave durumu:** Bekliyor
- **Uygulama durumu:** Başlamadı
- **Uygulama yetkisi:** Verilmedi
- **Giriş kapısı:** Wave 15 **AUTO-VERIFIED / COMMITTED** ve kullanıcıdan açık "Wave 16 PAS kaydını başlat" talimatı
- **Mevcut blokaj:** Wave 15 henüz committed değil; Wave 16 PAS/roadmap kaydı kapatılamaz
- **Önceki wave:** Wave 15 — planı hazır, aktif değil
- **Sonraki wave:** Wave 17 — ayrı planı hazır; aktif değil ve başlatılmadı

Bu dosyanın hazırlanması aktivasyon, dependency/provider satın alma, telemetry açma, migration, production event toplama, source map/symbol yükleme, alarm gönderme, canlı DB sorgusu, config/secret değişikliği, deploy veya Wave 17 aktivasyonu için yetki değildir.

## 1.1 Sale Release override — PAS / POST-ACQUISITION ROADMAP

- **Satış öncesi ürün implementasyonu yoktur.** Wave 04'teki health/readiness, version/commit ve deploy identity Sale Release için yeterli baseline'dır.
- **Post-acquisition Roadmap / Deferred:** B-OBS-002 ile C-REL-001'in crash/release ingestion, redaction pipeline, health aggregation ve gelişmiş Release Health UI kapsamının tamamı korunur; silinmez veya tamamlanmış işaretlenmez.
- **Yürütme:** Kullanıcı Wave 16'yı açıkça başlattığında yalnız Wave 04 baseline'ı doğrulanır, roadmap/PAS sonucu kaydedilir ve gerekirse tek dokümantasyon commit'i alınır. Ürün kodu, schema veya UI değişmez.
- **Kapanış:** Durum **DEFERRED / ROADMAP / COMMITTED** olarak kaydedilir ve **DUR**. Wave 17 yalnız ayrı kullanıcı talimatıyla başlar; Wave 16 için manuel QA zorunlu değildir.

## 2. Canonical referanslar ve otorite

1. `B-OBS-002` — schema/allowlist, idempotency, rate limit, redaction, release/source map bağı, fingerprint, etki, sampling, offline delivery, retention ve provider adaptörü
2. `C-REL-001` — QA-016 karar modeli, admin ekranı, lifecycle, alert ve recovery bağlantısı
3. Master `QA-016` — ürün sınırı, event zarfı, gizlilik, release kimliği, grouping, sağlık durumları ve manuel test matrisi
4. Wave 02 `B-API-001/B-OBS-001/B-SEC-002/C-ADMIN-001` — schema, logging, rate limit, admin auth/RBAC/audit
5. Wave 03 `A-FND-001/A-FND-002/A-A11Y-001` — client kabuğu, ortak state/tema ve accessibility
6. Wave 04 `B-API-002/B-ANL-002/B-DB-001/C-PERF-001/C-OPS-001` — health/release, performans ayrımı, migration ve operasyon
7. Wave 05 `B-WS-002/A-MATCH-004` — reconnect ve client recovery
8. Wave 06 `B-DATA-001/B-DATA-003/C-COMP-002` — retention, deletion/anonymization ve privacy
9. Wave 10 `B-MSG-001/A-FRIEND-003` — retry/idempotency ve duplicate mesaj koruması
10. Wave 14 `B-ANL-001/C-ANL-001/C-ADMIN-002/C-ADMIN-003` — confidence/freshness ve Dashboard `provider_pending` slotu
11. Wave 15 — ortak admin section state, progressive disclosure, hassas kanıt ve audit sözleşmesi
12. `A-I18N-001/A-A11Y-001/C-CI-001/C-MOB-001` — TR/EN, responsive/a11y, artifact/version ve Android release bağları

Çelişki çözümü:

- QA-016 istemci crash görünürlüğüdür; API latency ile aynı metrik değildir.
- Normal ağ kesintisi, yanlış şifre, validation, kullanıcı iptali ve eşleşme bulunamaması crash değildir.
- Android'da Crashlytics dependency bulunması çalışan veri akışını kanıtlamaz.
- Telemetry gelmemesi `0 hata`, `Sağlıklı` veya `Çözüldü` değildir.
- Release yalnız marketing version değildir; environment, platform, build ve deploy/commit birlikte otoritedir.
- İçerik client redaction'dan önce provider/backend/log katmanına ulaşamaz.
- Grouping deterministik, sürümlü, geri alınabilir ve auditlidir.
- Düşük örnek nedensellik veya kırmızı alarm üretmez.
- Dashboard kısa karar kartıdır; araştırma Release Health detayındadır.

## 3. Wave sonucu

Wave 16 sonunda:

- Web ve Android için değişmez release kimlik sözleşmesi kurulacak.
- Backend health, client ve build artifact'ları aynı deploy/release bağını kanıtlayacak.
- Sağlayıcı kararı kayıtlı olacak; iki kontrolsüz telemetry otoritesi kurulmayacak.
- Web render/global/rejection/chunk/bootstrap ve Android fatal/native/uygunsa ANR sinyalleri sınıflandırılacak.
- Allowlist event zarfı client ve ingestion katmanında iki kez doğrulanıp redakte edilecek.
- Offline queue, retry, idempotency, throttling, sampling ve circuit breaker ürün akışını engellemeyecek.
- Source map/symbol yalnız yetkili çözümleme katmanında tam release'e bağlanacak.
- Fingerprint aynı kök nedeni birleştirip farklı nedenleri ayıracak; override auditli olacak.
- User/session/occurrence/first-last/release/screen/platform etkisi doğru hesaplanacak.
- Release kıyası eş trafik, minimum örnek ve telemetry coverage şartlarını açıklayacak.
- `Sağlıklı/İzleniyor/Bozuldu/Kritik/Veri yok` durumları deterministik config ile üretilecek.
- Dashboard pending slotu gerçek fakat güven işaretli kısa karta bağlanacak.
- Detayda öncelikli issue, release comparison, maskeli kanıt ve lifecycle bulunacak.
- Recovery teknik ayrıntı göstermeden güvenli retry/home/reopen sunacak.
- Kontrollü staging Web/Android hatası admin özetine doğru release, ekran ve etkiyle yansıyacak.
- Wave 17 başlamayacak.

## 4. Doğrulanmış başlangıç fotoğrafı

### 4.1 Release kimliği

- Frontend package sürümü `0.0.0`; Vite bunu `__APP_VERSION__` olarak build'e gömüyor.
- Root/backend `1.0.0`, Android `versionName 1.0.5` ve `versionCode 7`; ortak release kaydı yok.
- `APP_VERSION` support report ortamına ekleniyor fakat deploy/commit/build/source-map kimliği sağlamıyor.
- Backend `/health` yalnız `{ ok: true }`; release/environment/deploy kimliği yok.

### 4.2 Collector ve native durum

- Doğrulanmış kök ErrorBoundary, global `window error` veya `unhandledrejection` telemetry zinciri yok.
- API, WebSocket ve native bridge hataları yerel ele alınıyor; canonical crash taxonomy'sine bağlı değil.
- Android Gradle Crashlytics dependency ve plugin classpath içeriyor.
- Plugin yalnız `google-services.json` okunursa uygulanıyor; yoksa devre dışı kalıyor.
- Dependency varlığı collection, release mapping, symbol upload, test crash veya admin rollup kanıtı değildir.

### 4.3 Backend/admin/veri

- Client error ingestion, sürümlü schema, event-ID dedupe ve çift redaction doğrulanmadı.
- Issue/fingerprint/release/session rollup veri modeli ve retention job'ı yok.
- Wave 14 Release Health için `provider_pending/not_available` tanımlar; veri yokken yeşil/0 hata yasaktır.
- Release Health list/detail/lifecycle ve alert yüzeyi doğrulanmadı.
- Request/performance telemetry QA-016 client crash kaynağı yerine kullanılamaz.

### 4.4 Repo ve canlı sınır

- Root çalışma ağacı geniş kullanıcı değişiklikleri taşıyor; Wave 16 bunları sahiplenmez veya temizlemez.
- Muhtemel yüzeyler `chatapp-frontend/`, `chatapp-backend/`, `android/`, build/config ve `docs/` ile sınırlıdır.
- Plan aşamasında production telemetry, kullanıcı/session, provider hesabı, symbol/source map veya canlı DB sorgulanmaz.
- Migration, provider config, secret, retention cleanup, alert destination ve deploy ayrıca exact-target/impact/onay ister.

## 5. Değişmez Release Health sözleşmeleri

### 5.1 Tek otorite ve provider kararı

Yönetilen sağlayıcı ile TalkX ingestion şu boyutlarda karşılaştırılır:

| Boyut | Yönetilen sağlayıcı | TalkX ingestion | Zorunlu kanıt |
|---|---|---|---|
| Source map/native symbol | Yerleşik olabilir | Biz işletiriz | Exact release çözümü |
| Native crash/ANR | SDK desteğine bağlı | Native collector gerekir | Kontrollü cihaz testi |
| Redaction | SDK hook + server kuralı | Client + ingestion | PII fixture testi |
| Grouping | Sağlayıcı + override | Bizim motor | Collision/split testi |
| Veri bölgesi/DPA | Vendor sözleşmesi | Kendi altyapı sınırı | Privacy kaydı |
| Retention/maliyet | Plan/quota | Storage/compute | Limit ve alarm |
| Admin read model | Adaptör | Doğrudan rollup | Aynı canonical response |

Karar ADR/runbook'a provider, owner, environment, region, DPA, retention, quota, outage fallback, export/delete ve exit planıyla yazılır. Aynı event iki yere kontrolsüz gönderilmez. Provider değişse bile C-REL-001 response anlamı değişmez.

### 5.2 Release kimliği

Canonical release kaydı:

- `environment`: `local|staging|production`
- `platform`: `web|android`
- `appVersion`, `buildNumber`, `commitSha`
- `deployId/artifactId`, `bundleHash`
- `sourceMapId/symbolId`, `channel`, `deployedAt`

Kurallar:

1. `0.0.0`, `unknown`, boş commit veya tahmini deploy production release olamaz.
2. Web build manifesti, client, backend health ve source map aynı kimliği taşır.
3. Android versionName/versionCode/commit/artifact tek kayıt olur.
4. Backend client release'ini server-known manifest ile doğrular; bilinmeyeni karantinaya alır veya güveni düşürür.
5. Staging/local production rollup'ına sızmaz.
6. Source map/symbol public asset değildir; RBAC ve audit altındadır.

### 5.3 Event taxonomy

Canonical sınıflar:

- `react_render_error`, `global_runtime_error`, `unhandled_rejection`
- `chunk_load_error`, `bootstrap_config_error`
- `critical_api_flow_error`, `reconnect_exhausted`, `recovery_surface_shown`
- `android_native_fatal`, `android_startup_crash`, `android_plugin_uncaught`
- `android_anr` — yalnız destek kanıtlanırsa

Expected validation/auth failure, kullanıcı iptali, normal offline/reconnect, queue empty ve business rejection crash taxonomy'sine girmez.

### 5.4 Allowlist event zarfı

Her event yalnız şunları taşır:

- `schemaVersion`, `eventId`, `occurrenceAt`, `serverReceivedAt`
- doğrulanmış release/environment/platform/runtime
- stable `screen/route/flow` kodu
- allowlist `errorName/errorCode`, maskeli kısa mesaj
- fingerprint girdisi ve server grouping version
- maskeli stack; çözüm server/provider tarafında
- rotating pseudonymous user/session etki kimliği
- device family, OS major, browser/WebView major
- foreground/background ve coarse network state
- içeriksiz allowlist breadcrumb
- `severity`, `handled`, `fatal`, `sampleRate`
- redaction/schema/clock-skew işaretleri

Payload maksimum byte, field/string, stack frame ve breadcrumb sınırına sahiptir. Bilinmeyen alan reddedilir; serbest JSON blob yoktur.

### 5.5 Kesin gizlilik ve redaction

Hiçbir event, breadcrumb, log, alert veya admin response'unda bulunmaz:

- sohbet mesajı/medya, destek/rapor açıklaması veya form değeri
- password, session/JWT, Authorization/cookie, push token
- username/display name/contact/karşı taraf kimliği
- tam IP veya raw device fingerprint
- kontrolsüz request/response body, URL query/hash veya storage dökümü

Sıra: client allowlist → client sanitizer → transport schema → ingestion sanitizer → persistence/provider filter → admin masker. Redaction öncesi payload loglanmaz. Deny fixture eventteyse fail-closed veya `redactionStatus=modified`; politika auditlidir.

## 6. B-OBS-002 — Güvenli ingestion ve adaptör

### 6.1 Client collector

- ErrorBoundary ekran ve uygulama düzeyini ayırır.
- Global listener bir kez kurulur, cleanup edilir ve kendi telemetry hatasını yakalamaz.
- Chunk/bootstrap detector stable sinyal kullanır; tek mesaj substring'i otorite değildir.
- API/WS yalnız canonical kritik akış kuralıyla event olur.
- Native collector önceki fatal olayı sonraki güvenli açılışta teslim edebilir.
- Console monkey-patch birincil collector değildir.
- Collector ana yolculuğu bloklamaz; recovery'den bağımsızdır.

### 6.2 Offline queue ve gürültü

- Maksimum event, byte ve TTL config'tir; yalnız minimum envelope saklanır.
- Oldest-first bounded eviction, exponential backoff + jitter ve aynı `eventId` kullanılır.
- Auth/release değişiminde olay yanlış kullanıcıya bağlanmaz.
- 4xx schema/redaction hatası sonsuz retry yapmaz.
- Throttling aynı fingerprint fırtınasını keser; sampling oranı metrikte taşınır.
- Fatal/yeni kritik koruması quota ve güvenlik limitlerini geçersiz kılmaz.
- Telemetry gönderim hatası yeni telemetry hata döngüsü üretmez.

### 6.3 Ingestion pipeline

`receive → size/origin/project gate → schema → release validation → redaction → idempotency → fingerprint → persist/forward → rollup → receipt`

- Anonymous gönderim açık threat model ve project key rotation taşır.
- Endpoint ayrı rate/body/timeout/abuse sınırı kullanır.
- Server trusted project/environment/release bilgisini ekler.
- `(project, environment, eventId)` unique olur; duplicate tek occurrence verir.
- Aynı ID farklı payload ise conflict metriğidir; overwrite edilmez.
- Provider timeout ürün requestini bekletmez; bounded queue/dead-letter vardır.
- Receipt hassas/provider iç kimliği döndürmez.
- Kill switch environment/platform/release/event class düzeyinde auditlidir.

### 6.4 Storage ve retention

Mantıksal kayıtlar:

- `release_manifest`
- `client_error_event` veya provider reference
- `client_issue_group`, `client_issue_occurrence_rollup`
- `release_health_rollup`, `telemetry_ingestion_health`
- `issue_lifecycle_event`, `grouping_override`, `release_health_alert_state`

Ham event kısa, aggregate daha uzun tanımlı süre tutulur. Pseudonymous ID rotate edilir. Hesap silme/anonymization, provider export/delete, legal hold ve artifact retention B-DATA/C-COMP ile doğrulanır.

### 6.5 Fingerprint/grouping

Canonical girdi:

`groupingVersion + environment + platform + normalizedErrorType + stableErrorCode + topOwnedFrames + screen/flow`

- UUID, timestamp, sayı, query, chunk hash ve kullanıcı verisi normalize edilir.
- Source-mapped owned frame vendor frame'den önceliklidir.
- Environment birleşmez; uyumlu release'ler lineage paylaşabilir.
- Farklı stable code/owned frame yalnız benzer mesajla birleşmez.
- Merge/split/alias/ignore owner, reason, before/after, revision ve audit taşır.
- Override occurrence'ı silmez; rollup yeniden üretilebilir.
- Grouping version değişimi dry-run collision raporu ister.

### 6.6 Ingestion health

Accepted/rejected/duplicate/conflict/dropped, redacted/modified, schema dağılımı, queue age/dead-letter, provider latency/error/quota, unknown release, source-map miss, son event/session denominator zamanı ve sampling/throttle/kill-switch ayrı ölçülür. Bu zincir bozuksa C-REL-001 `Veri yok/partial/stale/telemetry_gap` gösterir; sıfır issue sağlıklı sayılmaz.

## 7. Etki, baseline ve sağlık kararı

### 7.1 Ölçüm birimleri

- **Occurrence:** idempotency sonrası tek kabul edilmiş event
- **Affected session/user:** pencerede issue alan tekil pseudonymous kimlik
- **Eligible session:** crash-free paydasına girecek minimum lifecycle sinyalli session
- **Crash-free session:** eligible session içinde fatal/unhandled crash bulunmayan session

Event count, sampling-adjusted tahmin ve kesin unique aynı alan değildir. Denominator eksikse crash-free hesaplanmaz.

### 7.2 Release karşılaştırması

Aynı environment/platform/channel, lifecycle tanımı ve eş yaş/trafik penceresi kullanılır. Predecessor manifest gerçek olmalı; minimum eligible sample sağlamalı; rollout yüzdesi, coverage, clock skew, late arrival ve adoption farkı görünmelidir. Ortak trafik yetersizse `comparison_unavailable` ve neden gösterilir. Dil "release sonrası arttı" olur; nedensellik uydurulmaz.

### 7.3 Durum motoru

`Sağlıklı|İzleniyor|Bozuldu|Kritik|Veri yok` config revision ile şu girdileri açıklar:

- minimum eligible session/user ve telemetry coverage/freshness
- crash-free hedef/düşüş ve affected-user artış eşiği
- severity/fatal ile açılış/giriş/eşleşme/sohbet ağırlığı
- new/regression eşiği, rollout oranı ve güven penceresi

Sıra: veri bütünlüğü → örnek yeterliliği → fatal/core flow → anlamlı regresyon → düşük sinyal → sağlıklı. Böylece outage yeşile, iki session kırmızıya dönüşmez.

### 7.4 Issue sınıfları

- `new`: baseline/fixed geçmişinde yok, yeterli sinyal var
- `ongoing`: önceki release'lerde devam ediyor
- `regression`: fixed release sonrası eşik üstünde döndü
- `resolved`: yeterli traffic/süre ve sağlıklı telemetry boyunca yok
- `low_sample`: karar eşiği altında
- `unknown`: lineage/coverage eksik

## 8. C-REL-001 — Admin Release Health

### 8.1 Dashboard bağı

- Tek kısa kart Web/Android durumu, crash-free veya unavailable, new/regression, affected user ve son veri/güveni özetler.
- `provider_pending/no_data/low_sample/partial/stale/telemetry_gap/unauthorized/error` yeşil sıfırdan ayrıdır.
- Ana aksiyon `Release Health'i incele`; ham stack Dashboard'a taşınmaz.
- API performance ve client crash ayrı kaynak/başlık/route kullanır.

### 8.2 Detay bilgi mimarisi

1. **Durum:** platform/release, sağlık, confidence, as-of, rollout
2. **Etki:** crash-free, affected user/session, new/regression, predecessor farkı
3. **Ana problem:** en etkili/severe issue ve çekirdek akış
4. **Aksiyon:** incele, owner ata, izle, fixed release belirt
5. **Kanıt:** source/window/completeness, ingestion health ve maskeli detail

Platform/release/channel/time allowlist URL state taşır. Filter revision değişince eski response uygulanmaz.

### 8.3 Issue listesi

Her satır title/display ID, lifecycle/severity/confidence, user/session/occurrence, release/platform/screen, comparison, first/last, new/regression/fixed, owner ve `İncele` gösterir. Sıra occurrence tek başına değil; fatal/core-flow, affected user, regression ve recency içeren açıklanabilir versioned score'dur.

### 8.4 Issue detayı

İlk görünüm durum, güven, etki, first/last, release/platform/screen, comparison ve aksiyondur. Açılır kanıt maskeli çözülmüş stack, stable code/name, device/OS/WebView dağılımı, içeriksiz breadcrumb, sample/event zamanı, deploy korelasyonu, redaction/source-map health ve audit timeline taşır. Tam kullanıcı, raw fingerprint, public map, binlerce event veya minified yığın varsayılan değildir. Partial/unauthorized section diğer özeti kapatmaz.

### 8.5 Lifecycle ve mutation

Durumlar `Yeni`, `İnceleniyor`, `Düzeltildi`, `İzleniyor`, `Bilinen/kabul edildi`, `Yanlış gruplama`, `Regresyon`, `Çözüldü`.

`inspect → preview → confirm/re-auth → idempotent command → audit → result → targeted refresh`

- `Düzeltildi` fixed release/build ister; `Çözüldü` sağlıklı telemetry ve yeterli traffic ister.
- Fixed sonrası eşik üstü dönüş regression önerisidir; insan sonucu/audit korunur.
- Owner/note/status/fixed release/grouping revision ve 409 conflict taşır.
- Merge/split preview etkilenecek issue/occurrence/rollup kapsamını gösterir.

### 8.6 Alert

Yeni fatal, core-flow affected-user artışı, crash-free düşüşü, regression, telemetry outage ve startup/ANR artışı adaydır. Her kural minimum sample, severity, release/channel, cooldown, dedupe ve recovery taşır. Alarm PII/stack içermez; durum, etki, release ve yetkili link verir. Aynı issue gürültü üretmez. Plan hazırlığı gerçek destination'a gönderim yetkisi değildir.

## 9. Kullanıcı recovery

- Screen-level hata yalnız yüzeyi fallback'e alır; app-level ErrorBoundary temiz hata ekranı gösterir.
- Aksiyon bağlama göre `Yeniden dene`, `Ana sayfaya dön`, `Uygulamayı yeniden aç` olur.
- Destek referansı doğrudan event/issue kimliği değildir; tahmin edilemez ve politikalı lookup'tır.
- Retry aynı mesaj/command'i otomatik yeniden göndermez; bilinmeyen sonuç dürüstçe belirtilir.
- Attempt sınırı/circuit breaker sonsuz reload'u engeller.
- Teknik stack kullanıcıya gösterilmez; telemetry bozulsa recovery çalışır.

## 10. API ve read-model yüzeyi

Önerilen sürümlü yüzey:

- `POST /api/v1/client-errors/events`
- `GET /api/v1/admin/release-health/summary`
- `GET /api/v1/admin/release-health/releases`
- `GET /api/v1/admin/release-health/issues`
- `GET /api/v1/admin/release-health/issues/:issueId`
- `POST /api/v1/admin/release-health/issues/:issueId/preview`
- `POST /api/v1/admin/release-health/issues/:issueId/actions`
- `GET /api/v1/admin/release-health/ingestion-health`

Admin envelope: `source/window/asOf/dataThrough/lastSuccessfulAt`, `freshness/completeness/confidence/warnings`, `release/comparison/thresholdRevision/groupingVersion`, `permissions/revision/errorCode`. Liste/detail stable pagination taşır; C-ADMIN-001 auth/RBAC/CSRF/re-auth/audit atlanmaz.

## 11. Sıralı uygulama paketleri

### Paket 0 — Aktivasyon ve snapshot

1. Wave 15 QA kapanışı ve açık başlangıç talimatını doğrula.
2. Git, runtime ve environment snapshotı al.
3. Unrelated değişiklikleri ownership dışına çıkar.
4. Production/provider işlemlerini kapalı tut.

### Paket 1 — Karar ve release manifest

1. Provider karar kaydını tamamla.
2. Web/Android/backend manifest ve build-time doğrulamayı kur.
3. `0.0.0/unknown` production blocker ekle.
4. Health ve source-map/symbol artifact bağını test et.

### Paket 2 — Collector ve recovery

1. Taxonomy, sanitizer ve event ID kur.
2. ErrorBoundary/global/rejection/chunk/bootstrap collector ekle.
3. API/WS expected-vs-critical ayrımını bağla.
4. Android fatal/startup/plugin ve uygunsa ANR'yi doğrula.
5. Offline queue/throttle/sample/circuit breaker uygula.
6. Recovery UI'yi tema/a11y/i18n ile kanıtla.

### Paket 3 — B-OBS-002 ingestion

1. Endpoint, limits, project/origin ve schema gate kur.
2. İkinci redaction, release validation ve idempotency ekle.
3. Provider adapter veya persistence uygula.
4. Fingerprint/grouping ve rollup worker kur.
5. Ingestion health, dead-letter, kill switch ve retention bağla.

### Paket 4 — C-REL-001 admin

1. Denominator/baseline/confidence motorunu uygula.
2. Sağlık durumlarını versioned config ile üret.
3. Summary/releases/issues/detail read-model kur.
4. Dashboard slotunu gerçek veri ve dürüst fallback'e bağla.
5. Detail/lifecycle/grouping override UI'sini kur.
6. Alert dry-run dedupe/cooldown state kur; destination kapalı kalsın.

### Paket 5 — Kanıt ve kapanış

1. Unit/schema/redaction/idempotency/grouping/rollup testlerini tamamla.
2. Focused/full lint/test/build/encoding/Android doğrulamayı çalıştır.
3. Controlled staging Web/Android hatalarını uygula.
4. Source map/symbol yetki ve doğru release çözümünü kanıtla.
5. Admin desktop/mobile/a11y ve outage QA'ini tamamla.
6. Canonical checkbox'ları yalnız kanıtla senkronize et.
7. Kullanıcı onayını al ve Wave 17'yi başlatmadan dur.

## 12. Dosya ve servis etki alanı

| Alan | Muhtemel değişiklik | Kanıt |
|---|---|---|
| Frontend root | ErrorBoundary, collector, recovery | Render/global tests |
| Frontend API/WS/native | Taxonomy/breadcrumb | Expected-critical tests |
| Frontend build | Release manifest/source map | Artifact inspection |
| Android | Crash SDK/plugin/symbol/release | Controlled device crash |
| Backend | Ingestion/redaction/dedupe/adapter | Schema/security/integration |
| DB | Release/event/issue/rollup/lifecycle | Fresh/existing/rollback |
| Admin | Summary/list/detail/lifecycle | RBAC/state/a11y |
| Config/runbook | Provider/retention/threshold/kill switch | Redacted evidence |

Yeni dependency ancak provider kararı, security/privacy/lisans/maliyet ve lockfile etkisiyle eklenir. Mevcut Crashlytics satırları otomatik seçim sayılmaz.

## 13. Otomatik kanıt kapıları

### 13.1 Release/build

- Production frontend `0.0.0/unknown` ile build olamaz.
- Web/Android/backend manifest aynı release'e bağlanır.
- Yanlış/missing source map/symbol fail eder.
- Staging event production manifestine kabul edilmez.

### 13.2 Schema/gizlilik

- Unknown/oversized field, stack ve breadcrumb reddedilir.
- Mesaj/token/username/IP/form/query/body provider/log/DB/admin'e ulaşmaz.
- Duplicate tek occurrence; conflicting duplicate overwrite değildir.
- Rate/origin/project/auth abuse, quota ve kill switch testlidir.

### 13.3 Collector/delivery

- Render/global/rejection/chunk/bootstrap/native sınıfları doğru taxonomy üretir.
- Expected validation/offline/cancel crash olmaz.
- Queue cap/TTL/eviction/backoff/reconnect/idempotency deterministiktir.
- Hata fırtınası kesilir; telemetry kendi döngüsünü üretmez.
- Recovery retry duplicate mesaj/command oluşturmaz.

### 13.4 Grouping/rollup/karar

- Dinamik UUID/zaman içeren aynı kök birleşir; farklı stable code/frame birleşmez.
- Merge/split/override reversible ve auditlidir.
- Unique user/session/occurrence ve first/last fixture ile reconcile edilir.
- Sampling kesin count gibi sunulmaz.
- Low sample/no denominator/gap/stale/zero ayrıdır.
- Fixed issue regression ve yeterli traffic sonrası resolution doğrudur.

### 13.5 Admin/kalite

- RBAC/unauthorized/partial/error section bazında testlidir.
- Dashboard detail/stack taşımaz.
- Filter race/pagination/tie-breaker testlidir.
- Lifecycle/idempotency/revision conflict/audit testlidir.
- Frontend lint/build, backend syntax/unit/integration, Android ve encoding geçer.

## 14. Roadmap'te korunan eski full-scope manuel QA matrisi — Sale Release'te yürütülmez

1. React render crash ve screen/app ErrorBoundary.
2. Window error ve unhandled rejection.
3. Chunk ve bootstrap/config hatası.
4. Validation ile kritik API hatası ayrımı.
5. Normal WS kopması ile reconnect-exhausted ayrımı.
6. Android fatal/startup/plugin crash ve sonraki açılış teslimi.
7. Destekleniyorsa ANR ve doğru release/build.
8. Offline queue cap/TTL/reconnect/duplicate ID.
9. Hata fırtınasında throttle/sample/circuit breaker.
10. Dinamik UUID/zamana rağmen grouping.
11. Collision ve reversible override.
12. Web deploy, Android versionName/versionCode, staging/production.
13. Source map/symbol çözümü ve unauthorized engeli.
14. Mesaj/token/username/IP/form/query/body redaction.
15. 0/az/yeterli örnek, real zero, new/regression/resolved/outage.
16. Release comparison, crash-free denominator ve unique etki.
17. Dashboard kartından maskeli kanıta traceability.
18. Provider/section partial failure ve targeted retry.
19. Lifecycle owner/note/fixed release/conflict/audit.
20. Alert dedupe/cooldown dry-run; gerçek gönderim yok.
21. Recovery retry/home/reopen, no duplicate ve no loop.
22. Desktop, 320 px mobile, keyboard, screen reader, zoom, TR/EN ve reduced motion.

Her test environment, release/build, expected/actual, screenshot/log/record ID, redaction ve pass/fail taşır. Production kullanıcı hatası fixture yapılmaz.

## 15. Canonical kabul kriteri izleme

### 15.1 B-OBS-002

- [ ] Master QA-016 backend/ingestion kriterleri tamam.
- [ ] Mesaj/token/form/IP eventte yok.
- [ ] Source map doğru release'e bağlı.
- [ ] Duplicate `event_id` tek occurrence politikasıyla.
- [ ] Telemetry kesintisi `0 hata` değil.
- [ ] C-REL-001 aynı rollup'ı tüketiyor.

### 15.2 C-REL-001

- [ ] Master QA-016 kriterleri tamam.
- [ ] Chat/token/form/IP eventte yok.
- [ ] Source map public değil ve doğru release'le.
- [ ] Düşük örnek kırmızı alarm değil.
- [ ] Telemetry kesintisi `0 hata` değil.
- [ ] Grouping override/audit mümkün.
- [ ] Fixed release ve regresyon izleniyor.
- [ ] Dashboard yalnız kısa kart; araştırma detay sayfasında.
- [ ] Kullanıcı recovery teknik stack göstermiyor.

### 15.3 Master QA-016

- [ ] Web ErrorBoundary, window error, unhandled rejection ve kritik chunk/açılış hataları kontrollü yakalanıyor.
- [ ] Android native fatal crash ve destekleniyorsa ANR doğru release/build ile ilişkilendiriliyor.
- [ ] Gerçek frontend/Android release kimliği ve production/staging ayrımı var.
- [ ] Event schema allowlist tabanlı; sohbet, token, username, tam IP ve form değeri taşımıyor.
- [ ] Offline queue, retry, event ID dedupe, throttling, sampling ve ingestion rate limit çalışıyor.
- [ ] Source map/symbol dosyaları release ile güvenli eşleşiyor ve açık servis edilmiyor.
- [ ] Issue grouping aynı kök nedeni birleştiriyor; yanlış grouping geri alınabilir/audit edilebilir.
- [ ] Tekil kullanıcı, session, occurrence, first/last seen, ekran, platform ve release etkisi doğru hesaplanıyor.
- [ ] Önceki release karşılaştırması aynı trafik/örnek sınırlarını dikkate alıyor.
- [ ] Sağlıklı/İzleniyor/Bozuldu/Kritik/Veri yok eşikleri görünür ve deterministik.
- [ ] Dashboard kısa özet, Release Health etki sıralı sorunlar ve maskeli kanıt sunuyor.
- [ ] Düşük örnek ve telemetry kesintisi "hata yok" gibi görünmüyor.
- [ ] Issue yaşam döngüsü, owner/not, fixed release ve regresyon takibi auditli.
- [ ] Alarm dedupe/cooldown gürültüyü önlüyor.
- [ ] Kullanıcı recovery teknik detay göstermiyor ve güvenli retry sağlıyor.
- [ ] Ham event/rollup retention, hesap silme ve sağlayıcı veri politikası tanımlı.
- [ ] Kontrollü staging Web/Android hataları admin özetine doğru sürüm, ekran ve etkiyle yansıyor.

Plan hazırlandığı için kriter işaretlenmez. Yalnız uygulama, otomatik kanıt, manuel QA ve kullanıcı onayıyla `[x]` olur.

## 16. Giriş ve çıkış kapıları

### 16.1 Giriş

- [ ] Wave 15 **AUTO-VERIFIED / COMMITTED**.
- [ ] Kullanıcı Wave 16'yı açıkça başlattı.
- [ ] Repo/unrelated değişiklik snapshotı alındı.
- [ ] Provider kararı veya blokajı kayıtlı.
- [ ] Production/provider/live destination kapalı.
- [ ] Migration/dependency/artifact etkisi raporlandı.

### 16.2 Yerel tamam

- [ ] B-OBS-002 ingestion ve güvenlik kanıtları tamam.
- [ ] C-REL-001 admin/read-model/recovery tamam.
- [ ] Release/source-map/symbol bağı doğrulandı.
- [ ] Focused/full kapılar exit code ve sayıyla kayıtlı.
- [ ] Migration fresh/existing/rollback kayıtlı.
- [ ] Secret/PII evidence bundle'a girmedi.

### 16.3 Deferred / Roadmap kapanışı

- [ ] QA-016 manuel matrisi staging'de tamam.
- [ ] Web ve gerçek Android cihaz/emülatör kanıtı var.
- [ ] Admin desktop/mobile/a11y/TR/EN doğrulandı.
- [ ] Low sample/no-data/outage/zero ayrımı kanıtlandı.
- [ ] Provider privacy/retention/cost/runbook tamam.
- [ ] Wave 16 PAS/roadmap sonucu kaydedildi; manuel QA gerekmiyor.
- [ ] Canonical belgeler ve sonuç senkronize edildi.
- [ ] Wave 17 başlatılmadan duruldu.

## 17. Kapsam dışı ve successor guard

Wave 16'ya dahil değildir:

- Wave 17 ortak client/backend/CI kalite zincirinin tamamı
- Wave 18 Android signing/store zinciri ve Wave 19 son QA
- AI/LLM issue summary veya root-cause iddiası
- Session replay, ekran/video kaydı, keylogging veya serbest breadcrumb
- Davranış analitiğini crash kaydı altında yeniden kurmak
- Otomatik rollback/deploy/publish veya harici alert destination aktivasyonu
- Production kullanıcı verisini test fixture'ı yapmak
- Live retention cleanup, provider export/delete veya public source map

Wave 16 kapanışında Wave 17 için kod, test, refactor veya uygulama hazırlığı yapılmaz. Ayrı Wave 17 planı hazırdır; yine de yalnız açık kullanıcı talimatı ve Wave 16 QA kapanışıyla aktive edilebilir.

## 18. Risk ve rollback

| Risk | Erken sinyal | Koruma | Rollback/forward-fix |
|---|---|---|---|
| PII sızar | Fixture provider/log'da | Çift redaction + fail closed | Ingestion off, purge runbook, incident |
| Release yanlış bağlanır | Mixed manifest | Build gate/server validation | Quarantine, mapping fix |
| Public source map | Static URL erişir | Private artifact/RBAC | Remove + rotate |
| Duplicate şişirir | Aynı ID artar | Unique receipt | Rollup recompute |
| Group collision | Farklı frame birleşir | Versioned fingerprint | Split + rebuild + audit |
| Error storm | Queue/quota dolar | Throttle/sample/circuit | Kill switch |
| Outage yeşil | Last success stale | Ingestion health first | `Veri yok` |
| Low sample kırmızı | 1–2 session critical | Minimum sample | `İzleniyor` |
| Denominator yanlış | Oran >100/NaN | Eligible contract | Unavailable |
| Çift otorite | Counts ayrışır | Tek adapter | Secondary off |
| Recovery loop | Tekrar reload | Attempt cap | Safe home |
| Duplicate mesaj | Outbox yeniden yollar | Idempotency | Auto retry off |
| Alert storm | Aynı issue tekrar | Dedupe/cooldown | Destination off |
| Dirty repo örter | Unrelated diff | Ownership snapshot | Yalnız Wave 16 farkı |

Additive schema tercih edilir; compatibility ve rollup rebuild olmadan destructive rollback yapılmaz. Production purge/migration/provider/deploy ayrıca açık yetki ister.

## 19. Canlı ve destructive sınır

Ayrı kullanıcı yetkisi ister:

- provider hesabı/projesi, DPA/plan/ödeme
- SDK/dependency ve lockfile
- production telemetry veya gerçek alert destination
- secret/DSN/project key/config
- production migration/index/backfill/rollup/retention
- source map/symbol upload/silme
- gerçek kullanıcı/session/event inceleme/export/delete
- Render/Neon/Firebase config, restart, deploy veya Android release build

Önce exact environment/service/project/database, veri sınıfı, volume/quota, cost, region/retention, effect/reversibility, secret, backup/rollback, monitoring ve stop condition raporlanır. Plan bunları yetkilendirmez.

## 20. Sonuç/evidence alanı

Wave 16 yürütüldüğünde en az:

- başlangıç/final Git ve exact changed files
- provider kararı ve tek adapter kanıtı
- Web/Android/backend manifest karşılaştırması
- `0.0.0/unknown` blocker ve environment izolasyonu
- source map/symbol çözümü ve unauthorized sonucu
- schema/size/rate/origin/project güvenlik sonuçları
- PII fixture negatif kanıtı
- queue/retry/dedupe/throttle/sample/circuit sonucu
- grouping collision/override/audit ve rollup reconciliation
- low sample/no-data/gap/zero kararları
- previous release/new/regression/resolved karşılaştırması
- Dashboard-detail traceability
- lifecycle/fixed release/conflict/audit
- alert dry-run; gerçek gönderim yapılmadı kaydı
- recovery no-duplicate/no-loop
- migration fresh/existing/rollback ve retention
- focused/full lint/test/build/Android/encoding sonuçları
- Web/Android/admin responsive/a11y/TR/EN screenshots
- canonical checkbox ve kullanıcı onayı
- Wave 17'nin başlatılmadığı durma kaydı

Kriter yalnız kanıtla `[x]` olur. Dependency, console, tek screenshot veya yalnız kod incelemesi uçtan uca QA değildir.

## 21. Durma kuralı

Wave 15 QA kapanışı ve kullanıcının açık Wave 16 başlatma talimatı birlikte gelene kadar:

- Kod, test, dependency, migration, provider, production telemetry, source map/symbol, alert, flag veya deploy değişikliği yapılmaz.
- Wave 16 `Aktif` işaretlenmez; belge yalnız `Hazır — aktif değil` kalır.
- Canonical `[ ]` maddeler kanıtsız kapatılmaz.
- Crashlytics dependency gerçek collection, `0 event` sağlık ve stale telemetry çözülmüş sayılmaz.
- Hassas veri tek client redaction katmanıyla korunmaz.
- Wave 17 planı ayrı dosyada hazırdır; Wave 17 aktive edilmez veya uygulanmaz.
