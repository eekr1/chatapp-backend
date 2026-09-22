# TalkX Wave 17 Plan — Client/Backend Kalite Kapıları ve Ortak CI Zinciri

> Bu belge yalnız Wave 17 için hazırlanmış uygulama planıdır.
> Canonical sıra Plan A `A-QA-001` → Plan B `B-QA-001` → Plan C `C-CI-001` şeklindedir.
> Ana ilke: yeşil işaret ancak yeniden üretilebilir komut, izole test ortamı, saklanan kanıt ve açık blocker politikasıyla anlamlıdır; flaky veya çalışmayan kapı başarı sayılmaz.
> Plan hazırdır. Wave 17 aktif değildir, Wave 01–16 kapanmamıştır ve uygulama başlamamıştır. Wave 18 ayrı belgede planlanmıştır; burada uygulanmaz veya başlatılmaz.

## 1. Durum ve yürütme sınırı

- **Wave:** 17
- **Wave adı:** Client/backend kalite kapıları ve ortak CI zinciri
- **Plan katılımı:** Plan A + Plan B + Plan C
- **Canonical sıra:** `A-QA-001` → `B-QA-001` → `C-CI-001`
- **Plan durumu:** Hazır
- **Wave durumu:** Bekliyor
- **Uygulama durumu:** Başlamadı
- **Uygulama yetkisi:** Verilmedi
- **Giriş kapısı:** Wave 16 **DEFERRED / ROADMAP / COMMITTED** ve kullanıcıdan açık "Wave 17'yi başlat" talimatı
- **Mevcut blokaj:** Wave 16 PAS/roadmap kaydı henüz committed değil; Wave 17 uygulanamaz
- **Önceki wave:** Wave 16 — planı hazır, aktif değil
- **Sonraki wave:** Wave 18 — ayrı planı hazır; aktif değil ve başlatılmadı

Bu dosyanın hazırlanması Wave 17 aktivasyonu, dependency/lockfile değişikliği, test çalıştırma, fixture/seed yazma, CI workflow veya branch protection oluşturma, repository setting/deploy trigger değiştirme, canlı DB/provider kullanma, secret erişimi, Android release uygulaması ya da Wave 18 aktivasyonu için yetki değildir.

## 1.1 Sale Release override — KÜÇÜLTÜLMÜŞ AMA UYGULANIR

- **Satış öncesi uygulanır:** Frontend lint/build, backend syntax/core tests, kritik matchmaking two-client testleri, birkaç auth/session testi, duplicate/reconnect regresyonu ve basit GitHub CI.
- **Post-acquisition Roadmap / Deferred:** Enterprise component/E2E/integration matrisi, geniş PostgreSQL kombinasyonları, artifact platformu ve kapsamlı audit/test cathedral.
- **Kapanış:** Tanımlı minimum CI kapıları yeşil olur, tek Wave 17 commit'i alınır ve **DUR**. Cihaz/browser manuel matrisi Checkpoint C/Wave 19'a gider.
- Başarısız zorunlu CI kapısı Wave 18'e geçişi bloke eder; ekstra enterprise coverage eksikliği bloke etmez.

## 2. Canonical referanslar ve otorite

1. `A-QA-001` — lint, production build, component, kritik E2E, iki-client, accessibility, TR/EN, stale/reconnect/duplicate ve gerektiğinde Android asset/version kanıtı
2. `B-QA-001` — syntax, unit, PostgreSQL integration, iki-client WS/match, migration, schema, abuse, idempotency, reconnect, PII, health ve dependency audit
3. `C-CI-001` — ortak blocker politikası, test ortamı, deploy sırası, flaky sahipliği, release artifact, secret/log kapısı, 0.0.0 engeli ve audit sınıflaması
4. Master §11 — test/kalite envanteri ve QA-014/015/016/017 matrisleri
5. Master §12 — repo, sürüm, tag, deploy SHA, environment ve secret/release operasyon sınırı
6. Master §13–15 — frontend, admin ve Android manuel inceleme listeleri
7. Wave 02 — API schema, auth, logging, abuse, WebSocket ve admin erişim temeli
8. Wave 03 — test edilebilir client kabuğu, tema/state, a11y ve auth UX
9. Wave 04 — health/readiness, migration, DB runtime, performance ve operasyon
10. Wave 05–13 — realtime, matchmaking, mesaj, medya, legal, locale ve Sistem iletişimi dikey dilimleri
11. Wave 14–16 — analytics/admin/release-health kanıt, confidence, redaction ve progressive disclosure sözleşmeleri
12. Wave 18 `C-MOB-001/A-MOB-001` — Android signing/store/device release zinciri; Wave 17'ye çekilmez
13. Wave 19 `C-QA-001` — bütünleşik son admin/operasyon/release manuel kapanış; Wave 17'ye çekilmez

Çelişki çözümü:

- Wave 17 önceki ürün maddelerini yeniden tasarlamaz; onları test edilebilir ve CI tarafından zorlanabilir hâle getirir.
- Test altyapısı kurmak geçmiş wave kabul kriterlerini otomatik kapatmaz.
- Unit/integration/E2E/manual QA birbirinin yerine geçmez; her katman kendi riskini kanıtlar.
- Canlı DB'ye yazan test hızlı veya başarılı olsa bile kabul edilmez.
- Tek retry ile yeşile dönen flaky test sessizce başarı sayılmaz.
- Dependency audit bulgusu yalnız sayı/severity ile değil reachable runtime, internet yüzeyi, fix ve risk kabulüyle sınıflanır.
- Main branch/deploy engeli repository gerçeğiyle doğrulanmadan "CI var" denmez.
- Wave 18 Android release zinciri bu wave'de uygulanmaz; yalnız ortak kapı için handoff contract'ı tanımlanır.
- Yerel makineye özel absolute path, credential veya cache CI otoritesi olamaz.

## 3. Wave sonucu

Wave 17 sonunda:

- Root, frontend ve backend için tek anlamlı komut matrisi ve exit-code sözleşmesi bulunacak.
- Frontend lint/build yanında component, kritik E2E, accessibility, i18n ve stale/reconnect/duplicate testleri çalışacak.
- Backend syntax yanında unit, PostgreSQL integration, migration, schema/security/idempotency ve two-client testleri çalışacak.
- Testler production/canlı DB'ye yazamayacak; izole, ephemeral ve doğrulanmış test ortamı kullanacak.
- Fixture/seed/cleanup deterministik, paralel çalışmaya uygun ve veri sızıntısına kapalı olacak.
- QA-014/015/016/017 gibi kritik matrislerin otomatik sınırları ayrı suite/tag olarak izlenebilir olacak.
- Ortak CI pipeline değişen alana göre hızlı geri bildirim verirken zorunlu tam kapıları atlamayacak.
- Main deploy kırmızı, missing, cancelled veya neutral zorunlu kapıyla ilerlemeyecek.
- Flaky test quarantine değil sahiplik, süre, issue ve izole tekrar kanıtı taşıyacak.
- Dependency, secret, encoding, artifact/version ve log-hassas-veri kontrolleri blocker politikasına bağlanacak.
- Release artifact'ları commit/release kimliği, checksum ve retention ile ilişkilendirilecek.
- PR/check sonuçları komut, runtime, test sayısı, süre, artifact ve failure özetiyle kanıtlanabilir olacak.
- Wave 18 için yalnız doğrulanmış Android handoff girdisi tanımlanacak; Wave 18 başlamayacak.

## 4. Doğrulanmış başlangıç fotoğrafı

### 4.1 Komutlar ve test altyapısı

- Root `npm test` yalnız "no test specified" ile hata veriyor; gerçek orchestrator değil.
- Root'ta encoding, web build ve Android prepare/verify/release scriptleri bulunuyor.
- Frontend package yalnız `dev`, `build`, `lint`, `preview` scriptlerine sahip.
- Frontend component/E2E test runner, test scripti ve doğrulanmış test dosyası yok.
- Backend package yalnız `start` ve `dev`; unit/integration test scripti yok.
- `chatapp-backend/test_auth_flow.js` tek bağımsız script; güncel legal/test-environment güvencesi canonical Master'da açık eksik.
- Repo taramasında yalnız frontend ESLint config'i ve bu auth scripti test/quality yüzeyi olarak bulundu.

### 4.2 CI ve deploy enforcement

- `.github/workflows` bulunmuyor; repository içinde doğrulanmış CI pipeline yok.
- Branch protection, required checks ve deploy trigger ayarları repo dosyasından kanıtlanamıyor.
- Local scriptlerin varlığı remote main/deploy engeli anlamına gelmiyor.
- Frontend sürümü hâlâ `0.0.0`; C-CI-001 bunu release blocker sayıyor.
- Android asset doğrulama Gradle ve PowerShell scriptlerinde var; ortak CI içinde çalıştığı kanıtlanmadı.

### 4.3 Repo ve güvenlik sınırı

- Root çalışma ağacı geniş silinmiş/untracked kullanıcı değişiklikleri taşıyor; Wave 17 bunları temizlemez veya sahiplenmez.
- Root metadata GitHub backend repository'sine işaret ediyor; frontend/backend/root/Android sahipliği aktivasyonda yeniden doğrulanır.
- Production database, Render/Neon/Firebase/Brevo, signing key ve repository settings plan aşamasında sorgulanmaz/değiştirilmez.
- Yeni test dependency'si, workflow, container/service, cache veya artifact storage ayrıca etki ve güvenlik incelemesi ister.

## 5. Kalite modeli ve blocker sözleşmesi

### 5.1 Kapı sınıfları

| Sınıf | Amaç | Örnek | Main/deploy sonucu |
|---|---|---|---|
| `required-blocking` | Birleştirme/yayın güvenliği | lint, build, unit, integration, critical E2E | Başarısız/missing/cancelled ise durur |
| `required-contextual` | Yalnız ilgili değişimde zorunlu | migration, Android asset, locale | Etki alanı eşleşirse durur |
| `scheduled-blocking` | Ağır tam suite ve audit | full E2E, DB matrix, dependency policy | Release öncesi zorunlu |
| `informational` | Trend/teşhis | coverage delta, süre trendi | Tek başına deploy açmaz/kapatmaz |
| `manual-approval` | İnsan/cihaz/canlı sınır | design QA, Android cihaz, prod smoke | Açık kayıt/onay ister |

Her kapı stable name, owner, trigger, command, timeout, retry policy, environment, artifact, failure sonucu ve bypass yetkisi taşır. Required kapı `continue-on-error`, koşulsuz skip veya boş-success ile etkisizleştirilemez.

### 5.2 Sonuç durumları

- `passed`: temiz koşuda tüm assertions tamam
- `failed`: assertion, build, audit veya policy kırmızı
- `infrastructure_error`: runner/service/cache/tool problemi; yeşil değildir
- `cancelled`: yeni commit/manuel iptal; yeşil değildir
- `skipped_not_applicable`: yalnız açık path/policy nedeni ve evidence ile
- `quarantined`: süreli, sahipli ve takip kaydı olan bilinen flaky; required kapsam sessiz azalmaz

Test sayısı `0` ise komut exit 0 verse bile ilgili required kapı başarısızdır. Beklenen suite/file/tag discovery sayısı manifestte doğrulanır.

### 5.3 Risk tabanlı katmanlama

- **Static:** syntax, lint, type/schema, encoding, secret ve dependency policy
- **Unit:** saf domain/state/sanitizer/fingerprint/formatter davranışı
- **Component:** kullanıcı state, a11y, locale ve interaction
- **Integration:** PostgreSQL, migration, route, provider adapter ve persistence
- **Contract:** frontend/admin/backend event-response şeması
- **Two-client:** WebSocket, match, message, reconnect ve duplicate race
- **E2E:** kritik kullanıcı ve admin yolculukları
- **Build/artifact:** production frontend, backend package, Android asset handoff, release manifest
- **Manual:** görsel, cihaz, accessibility yardımcı teknoloji ve yetkili canlı smoke

Bir riski daha ucuz alt katmanda güvenilir test etmek üst katmanı gereksiz çoğaltmaz; ancak kritik dikey yolculuk en az bir E2E/contract kanıtı taşır.

## 6. İzole test ortamı ve veri güvenliği

### 6.1 Fail-closed environment gate

Test process başlamadan:

1. `NODE_ENV/testMode` ve explicit test config doğrulanır.
2. DB host/name/SSL fingerprint allowlist test hedefiyle eşleşir.
3. Production/known live host, database, Render/Neon endpoint veya eksik config görülürse process başlamadan durur.
4. Migration/test user minimum privilege kullanır; production credential kabul edilmez.
5. External push/email/telemetry/media provider fake/local adapter'dır; gerçek recipient/destination yoktur.

Connection string veya secret loglanmaz. CI secret yalnız gerekli job/environment'e scoped, masked ve fork/untrusted PR politikasına uygun olur.

### 6.2 Database lifecycle

- Ephemeral database/schema worker'a özgü isim ve run ID taşır.
- Fresh DB migration ve mevcut-version upgrade ayrı fixture'dır.
- Transaction rollback tek başına yeterli değilse deterministic teardown uygulanır.
- Test başlangıcı/sonu schema version, expected table count ve cleanup sonucu kaydeder; row içeriği loglamaz.
- Paralel worker aynı user/session/match/event ID namespace'ini paylaşmaz.
- Crash/timeout sonrası orphan cleanup bounded ve exact prefix ile çalışır.
- Backup/restore testi sentetik fixture kullanır; canlı dump test datası değildir.

### 6.3 Fixture/seed standardı

- Factory stable minimum alanlar ve açık varyant üretir.
- Zaman/UUID/randomness inject/freeze edilebilir; locale/timezone açık olur.
- PII fixture'ı gerçek kişiye ait değildir; token/secret sentinel değerdir.
- Her fixture owner, lifecycle, expected assertions ve cleanup taşır.
- Snapshot yalnız anlamlı sözleşme içindir; geniş, kolay onaylanan UI/JSON dump'ı değildir.
- Golden evidence güncellemesi review ve neden ister.

## 7. A-QA-001 — Client kalite kapıları

### 7.1 Static, build ve i18n

- ESLint warning/error bütçesi belgeli; yeni warning sessiz baseline olmaz.
- Production build gerçek release env ile, debug/development fallback'siz üretilir.
- Bundle'da secret, localhost/debug endpoint, source map public link ve `0.0.0/unknown` kontrol edilir.
- TR/EN key set parity, interpolation/plural/placeholders ve invalid/null locale fallback testlidir.
- Encoding/mojibake kontrolü kaynak, generated asset ve kullanıcıya görünen kritik metinleri kapsar.

### 7.2 Component ve state testleri

Öncelik davranış sözleşmesidir:

- loading/empty/success/stale/partial/error/unauthorized state'leri
- focus trap/return, keyboard, aria name/role/state ve reduced motion
- 320 px, zoom/large-text için kritik layout invariant'ları
- server-authoritative search/offer/chat phase
- reconnect/stale response ve out-of-order event reddi
- optimistic/outbox idempotency, unknown-result ve duplicate prevention
- locale switch ile state/veri kaybı olmaması
- recovery ErrorBoundary ve güvenli retry/no-loop

Test implementation detail'e değil kullanıcı çıktısı ve erişilebilir role dayanır. Timer, network ve visibility/background deterministik kontrol edilir; gerçek bekleme kullanılmaz.

### 7.3 Kritik E2E yolculukları

Minimum Web E2E seti:

1. register/login/legal gate ve invalid/rate/offline sonuçları
2. Home → Global/Country scope → search → offer → accept → anonymous chat
3. pass/timeout/cancel/requeue/reconnect ve late-event izolasyonu
4. friend transition → persistent message/outbox/read
5. media permission/send/open/expire güvenli akışı
6. report/block/friend-remove ve beklenen erişim sonucu
7. locale/TR-EN, notification/system inbox temel akışı
8. support/account deletion request temel akışı
9. admin login ve yetkiye uygun kritik read/mutation preview akışı
10. Release Health controlled recovery/no-data temel akışı

E2E yalnız UI'nin açıldığını değil backend contract ve final state'i kanıtlar. Her yolculuk bağımsız data namespace ve cleanup kullanır.

### 7.4 Accessibility kanıtı

- Otomatik axe benzeri tarama kritik view/state'lerde çalışır; "0 violation" tek başına yeterli değildir.
- Keyboard-only akış, visible focus, dialog/drawer semantics, live region ve error association component/E2E ile doğrulanır.
- Screen reader manuel smoke, zoom/büyük yazı, reflow ve contrast manuel kapıda kalır.
- Suppression selector + rule + reason + owner + expiry taşır; global devre dışı bırakma kabul edilmez.

## 8. B-QA-001 — Backend kalite kapıları

### 8.1 Syntax ve unit

- Canonical backend kaynak listesi için `node --check` veya eşdeğer syntax gate otomatik keşif yapar.
- Auth/session/legal, matching state machine, message idempotency, locale, sanitizer/redaction, fingerprint, threshold ve formatter saf unit test alır.
- Time, UUID, random, crypto/provider ve network injectable/fake olur.
- Beklenen error code ve public message contract test edilir; stack/body sızıntısı negatif fixture'dır.

### 8.2 PostgreSQL integration ve migration

Her migration için:

1. blank DB latest'e kurulur
2. supported previous schema'dan upgrade edilir
3. mevcut fixture verisi korunur/dönüşür
4. constraint/index/default/nullability doğrulanır
5. reader/writer compatibility penceresi test edilir
6. rollback varsa çalışır; yoksa forward-fix/restore prosedürü kanıtlanır
7. ikinci çalıştırma güvenli/idempotent davranır

Integration testleri transaction, unique/idempotency, concurrency, pagination/tie-breaker, retention/anonymization ve partial provider durumlarını kapsar. Query plan/performance blocker eşikleri ayrı kayıttır; yalnız test hızlılığı gerçek plan kanıtı değildir.

### 8.3 API/schema/security

- Request/response/event schema valid, boundary, unknown field ve oversized payload fixture'ları
- auth/role/ownership, CSRF/origin/CORS ve native no-origin politikası
- rate limit kullanıcı/IP/origin/project sınırları ve reset davranışı
- token/password/message/media/form/IP/log redaction negatif kanıtı
- idempotency duplicate/conflicting duplicate ve retry receipt
- error status/code/header/body consistency
- health/readiness/dependency/release kimliği
- upload MIME/size/nosniff/auth ve malformed body
- admin preview/confirm/re-auth/revision/audit sözleşmesi

Security testi gerçek saldırı trafiği veya production endpoint kullanmaz.

### 8.4 İki-client WebSocket/match/chat harness

Harness iki veya daha fazla authenticated logical client'i ayrı connection/session/device kimliğiyle yönetir. Deterministik senaryolar:

- connect/auth/heartbeat/disconnect/reconnect
- duplicate connection ve stale socket ownership
- Global/Country queue izolasyonu ve atomik scope değişimi
- match offer iki taraf/countdown/accept/pass/timeout
- late offer/accept/cancel ve previous-search event reddi
- rematch cooldown ve duplicate room engeli
- message client ID/ack/retry/order/duplicate
- peer leave/next/report/block ve room cleanup
- backend restart/recovery contract'ı
- varsa multi-instance concurrency adapter'ı

Assertion yalnız client UI eventine değil server state/DB sonucu ve iki tarafın tutarlı outcome'una bakar. Timer'lar fake/controlled clock kullanır.

### 8.5 Dependency audit

Audit policy:

- lockfile bazlı ve reproducible install
- severity tek başına değil runtime/dev, reachable path, exploit şartı ve internet yüzeyi
- fix available/no-fix, breaking-change ve compensating control
- suppress/risk accept için advisory ID, package/path, owner, reason, expiry ve approver
- yeni critical/high reachable internet-yüzeyi bulgusu blocker
- baseline yeni bulguyu gizlemez; expiry geçmiş kabul kırmızı olur
- audit output secret/path sızdırmadan artifact olarak saklanır

## 9. Master kritik matris yönlendirmesi

Wave 17 her eski wave planını kopyalamaz; ilgili QA suite canonical wave/ID'ye link verir. Zorunlu suite aileleri:

| Suite | Birincil risk | Canonical kaynak |
|---|---|---|
| Auth/legal | Güncel acceptance/session ve canlı DB güvenliği | Waves 02/12 |
| Search QA-014 | phase, timer, reconnect, reduced motion | Wave 07 |
| Scope QA-017 | country isolation, fallback consent, late event | Wave 08 |
| Offer QA-003 | pending/countdown/accept/pass/timeout | Wave 09 |
| Message/media | idempotency, outbox, read, expire | Waves 10/11 |
| Locale/System QA-015 | TR/EN recipient, inbox, push, duplicate | Wave 13 |
| Analytics/admin | truth, low sample, partial/stale, traceability | Waves 14/15 |
| Release Health QA-016 | redaction, release, grouping, no-data | Wave 16 |

Test dosya/tag isimleri stable manifestte bulunur. Bir suite geçici yoksa CI yeşil çalışmak yerine missing-suite blocker verir.

## 10. C-CI-001 — Ortak pipeline

### 10.1 Trigger ve güvenlik

- Pull request, protected branch push ve manual release candidate trigger'ları ayrıdır.
- Untrusted fork PR secret alamaz ve privileged deploy job çalıştıramaz.
- Workflow/job permission minimum ve açık yazılır; third-party actions immutable commit SHA ile pinlenir.
- Concurrency aynı ref'in eski run'ını iptal edebilir; cancelled required check yeni run tamamlanmadan yeşil olmaz.
- Path filtering yalnız kanıtlı dependency graph ile job azaltır; docs/config/shared değişiklikleri yanlışlıkla kapı atlamaz.

### 10.2 Önerilen job DAG

`change-scope` → paralel `static-client | static-backend | secret-dependency` → paralel `client-tests | backend-unit | db-migration-integration` → `two-client-contract` → `critical-e2e` → `production-build-artifacts` → `quality-summary`

- Her job explicit timeout ve fail-fast politikası taşır.
- Service readiness healthcheck ile beklenir; sabit uzun sleep kullanılmaz.
- Cache key lockfile + runtime + config hash içerir; cache miss başarıyı etkilemez.
- Build artifact test edilen aynı commit'ten gelir; sonraki job yeniden farklı build üretmez.
- Final summary upstream failure'ı yutmaz; required check sonucu fail-closed'dur.

### 10.3 Branch protection ve deploy gate

- Required check adları workflow içindeki stable job/check adlarıyla birebir eşleşir.
- Stale branch approval/review ve force-push policy repository sahipliğiyle belgelenir.
- Admin bypass kim, neden, süre, incident/risk kabul ve sonradan tam run ister.
- Deploy yalnız protected commit SHA + başarılı required checks + doğru environment approval ile tetiklenir.
- Deploy workflow artifact checksum ve release manifesti doğrular; source'tan sessiz yeniden build etmez.
- Rollback hedef commit/artifact ayrıca bilinir; Wave 17 rollback'i çalıştırmaz.

### 10.4 Artifact ve kanıt retention

Her run için:

- commit/ref/run ID, runtime/tool versions ve dependency lock hashes
- test command, discovered/executed/passed/failed/skipped/quarantined sayıları
- JUnit veya eşdeğer machine-readable sonuç
- coverage summary; tek başına kalite hedefi değil
- screenshots/traces yalnız başarısız veya seçili kritik E2E için
- build manifest/checksum ve gerekiyorsa source-map/symbol referansı
- audit/secret/encoding policy özeti
- migration schema/cleanup sonucu

Artifact hassas DB dump, token, `.env`, full request/response, mesaj/media veya gerçek kullanıcı verisi taşımaz. Retention süre ve erişim rolü veri sınıfına göre belirlenir.

### 10.5 Secret ve log kapısı

- Pre-commit/CI secret scan kaynak, history etkisi, build output ve artifact'ı kapsar.
- Test logger token/header/cookie/connection string/PII sanitizer kullanır.
- Secret scan false positive suppression exact pattern/path, owner, reason ve expiry ister.
- Bulgu logda tekrar yazdırılmaz; fingerprint ve güvenli dosya/satır bağlamı kullanılır.
- Gerçek secret şüphesinde job durur; rotation/incident ayrı yetki ve prosedürdür.

## 11. Flaky test politikası

Bir test ilk koşuda fail edip aynı commit/env'de tekrar geçerse otomatik başarı olmaz:

1. Orijinal failure artifact'ı korunur.
2. Yalnız aynı shard/test izole ve sınırlı sayıda yeniden çalıştırılır.
3. Sonuç `confirmed_failure`, `infrastructure_error` veya `flaky_suspected` olarak sınıflanır.
4. Flaky kaydı owner, issue, ilk/son görülme, oran, environment, geçici koruma ve expiry taşır.
5. Quarantine yalnız açık onayla, dar test bazında ve süreli olur.
6. Quarantine kritik yolu tamamen testsiz bırakamaz; yedek smoke/contract gerekir.
7. Expiry geldiğinde unresolved quarantine blocker olur.
8. Başarı metriği retry sonrası final green değil first-pass ve flaky oranını da gösterir.

Global "retry 3" ile kırmızıyı gizlemek ve timeout'u sınırsız büyütmek yasaktır.

## 12. Jarvis kalite özeti

PR/run özeti ilk bakışta şunları cevaplar:

1. **Durum:** merge/release için geçti mi, kaldı mı, altyapı mı bozuk?
2. **Etki:** hangi alan/suite ve kaç test etkilendi?
3. **Aksiyon:** düzelt, izole tekrar, artifact incele veya yetkili risk kabulü mü?
4. **Kanıt:** exact job/test, commit, komut, süre ve artifact nerede?

Ham binlerce log ilk görünüm değildir. Summary failure'ı stable kategoriye ayırır; kök neden kanıtlanmadıysa uydurmaz. Partial/missing/cancelled/zero-test yeşil olarak gösterilmez.

## 13. Sıralı uygulama paketleri

### Paket 0 — Aktivasyon ve inventory

1. Wave 16 QA kapanışı ve açık Wave 17 başlangıç talimatını doğrula.
2. Repo/root/frontend/backend/Android ownership, branch, remote ve dirty snapshot al.
3. Runtime, package manager, lockfile ve mevcut komut/test envanterini kaydet.
4. Live DB/provider/deploy/repository-setting işlemlerini kapalı tut.

### Paket 1 — Test environment ve orchestrator

1. Fail-closed test environment guard kur.
2. Ephemeral PostgreSQL lifecycle, fixture/seed/cleanup standardını uygula.
3. External provider fakes ve sentetik kimlikleri oluştur.
4. Root'ta stable quality komut matrisi ve zero-test discovery guard kur.
5. Local/CI parity ve runtime version pinlerini doğrula.

### Paket 2 — A-QA-001 client zinciri

1. Component test runner/environment ve helpers kur.
2. State/a11y/i18n/reconnect/duplicate suite'lerini ekle.
3. Kritik E2E harness ve sentetik data lifecycle kur.
4. Screenshot/trace/artifact politikasını uygula.
5. Lint/build/encoding/release checks ile tek client quality command üret.

### Paket 3 — B-QA-001 backend zinciri

1. Syntax discovery ve unit runner kur.
2. PostgreSQL integration/migration matrix kur.
3. API/schema/security/idempotency/redaction suite ekle.
4. Deterministik two-client WS/match/chat harness kur.
5. Dependency audit sınıflama ve evidence üretimini ekle.
6. Tek backend quality command ve cleanup doğrulaması üret.

### Paket 4 — C-CI-001 pipeline/enforcement

1. Least-privilege trigger/job DAG, cache ve service healthcheck kur.
2. Stable required checks ve artifact zincirini uygula.
3. Secret/log/encoding/dependency/version kapılarını bağla.
4. Flaky classification, bounded isolated rerun ve quarantine registry kur.
5. Branch protection/deploy gate için exact settings planı çıkar; external mutation için ayrıca onay al.
6. Quality summary failure propagation'ı doğrula.

### Paket 5 — Kanıt ve kapanış

1. Her gate'i success/failure/zero-test/infra-error fixture'ıyla doğrula.
2. Local ve CI aynı commit/lockfile ile sonuç parity'sini kanıtla.
3. Production DB/provider/recipient/deploy kullanılmadığını doğrula.
4. Required-check/branch-protection sonucu açık yetki verilirse read-back ile kanıtla.
5. Canonical checkbox ve evidence alanını yalnız gerçek sonuçla senkronize et.
6. Manuel QA matrisini Checkpoint C/Wave 19 havuzuna aktar, tek commit'i al ve Wave 18'i başlatmadan dur.

## 14. Komut ve job isim sözleşmesi

Aktivasyonda exact package manager/repo sahipliğine göre kesinleşecek öneri:

- `quality:static`
- `quality:client`
- `quality:backend`
- `quality:db`
- `quality:two-client`
- `quality:e2e:critical`
- `quality:a11y`
- `quality:i18n`
- `quality:security`
- `quality:artifacts`
- `quality:all`

Komut isimleri local ve CI'da aynıdır; CI inline olarak farklı gizli komut üretmez. Her komut child exit code'u korur, zero-test guard taşır ve hangi suite'i çalıştırdığını listeler. Platform-specific wrapper sonucu ortak manifest formatına çevirir.

## 15. Dosya ve servis etki alanı

| Alan | Muhtemel değişiklik | Kanıt |
|---|---|---|
| Root package/scripts | Orchestrator ve stable commands | Local/CI parity |
| Frontend package/config | Component/E2E/a11y runner | Focused + full suite |
| Frontend tests | State, i18n, critical journeys | Assertion/test count |
| Backend package/config | Unit/integration runner | Syntax/unit/integration |
| Backend tests | DB/API/WS/security harness | Cleanup/two-client |
| Migration/test helpers | Fresh/existing/rollback | Schema evidence |
| CI workflows | Job DAG, checks, artifacts | PR/push dry run |
| Policy/runbook | Blocker, flaky, audit, retention | Review/read-back |
| Git hosting settings | Required checks/protection | Ayrı onay + read-back |

Wave 18'e ait signing, store upload, production AAB rollout veya cihaz release matrisi bu tabloda yoktur. Android asset/version ortak handoff kontrolü yalnız build önkoşulu olarak tanımlanır.

## 16. Otomatik kanıt kapıları

### 16.1 Test altyapısının testi

- Production/live DB config fail-closed reddedilir.
- Missing service, wrong migration, cleanup failure ve orphan fixture job'ı kırmızı yapar.
- Zero discovered test ve unknown suite success olamaz.
- Fake provider hiçbir gerçek push/email/telemetry/media destination'a çıkmaz.
- Parallel worker ID/schema/data isolation kanıtlanır.

### 16.2 Client

- Lint warning/error policy ve production build geçer.
- Component/state/a11y/i18n suite sayıları beklenen manifestle eşleşir.
- Critical E2E her yolculuk için final server/client state assert eder.
- Stale/reconnect/out-of-order/duplicate fixture'ları deterministiktir.
- 320 px/reduced-motion/focus gibi otomatiklenebilir invariant'lar geçer.

### 16.3 Backend

- Canonical source syntax discovery eksiksizdir.
- Unit, DB integration, migration, schema/security ve two-client suite geçer.
- Rate/idempotency/redaction/health boundary testlidir.
- Fresh/existing migration ve teardown sonucu kayıtlıdır.
- Dependency audit policy expected allow/block fixture'ları doğru sınıflar.

### 16.4 CI/enforcement

- Her required job bilerek kırıldığında final check ve deploy gate kırmızı olur.
- Missing/cancelled/skipped/infra-error upstream final summary tarafından yutulmaz.
- Cache hit/miss aynı test sonucunu verir.
- Untrusted PR secret/deploy izni alamaz.
- Artifact commit/checksum/release manifesti kaynak run ile eşleşir.
- Secret/PII sentinel build/log/artifact'ta bulunursa kapı kırılır.
- Flaky isolated rerun ilk failure'ı korur ve final sonucu doğru sınıflar.

## 17. Manuel QA ve operasyon havuzu — Checkpoint C / Wave 19 (commit kapısı değil)

1. Temiz checkout ile documented setup ve `quality:all` çalıştırma.
2. Windows/local ile CI Linux runtime farkı ve path/case/newline davranışı.
3. Bilerek lint, unit, DB, E2E, build, audit ve secret failure oluşturma.
4. Zero-test ve yanlış test globunun kırmızı olması.
5. Test DB guard'ın production-benzeri host/name'i reddetmesi.
6. Ephemeral DB fresh/upgrade/cleanup ve interrupted run orphan sonucu.
7. İki-client match/chat/reconnect senaryosunun tekrarlanabilirliği.
8. Browser E2E failure screenshot/trace; başarılı run'da gereksiz hassas artifact olmaması.
9. Keyboard/a11y manuel smoke ve otomatik bulgu bağlantısı.
10. TR/EN key/fallback ve mojibake sonucu.
11. Flaky şüpheli testin izole rerun, owner, expiry ve summary görünümü.
12. Dependency advisory allow/block/risk-accept expiry fixture'ı.
13. Secret sentinel kaynak/log/build/artifact negatif testi.
14. Required check missing/failed/cancelled ve protected main sonucu.
15. Bypass yetkisi ve audit; gerçek bypass uygulanmadan dry-run/read-only doğrulama.
16. Deploy trigger'ın yalnız test edilmiş artifact SHA/checksum'u tüketmesi.
17. Artifact retention/permission ve silinmiş run fallback'i.
18. Doküman-only değişim ile shared config değişiminin doğru job scope'u.
19. Wave 18 Android handoff girdisi; signing/upload/rollout yapılmaması.

Her manuel sonuç tarih, commit, environment, runner/browser, command, exit code, test sayısı, artifact/run linki, expected/actual ve pass/fail taşır. Credential veya canlı veri evidence'e kopyalanmaz.

## 18. Canonical kabul kriteri izleme

### 18.1 A-QA-001

- [ ] Plan ID kabul kriterleri kanıtla işaretli.
- [ ] Bağlı Plan B/C sözleşmeleri tamam veya açıkça kapsam dışı.
- [ ] Test sonucu tarih/komut/sayı ile kayıtlı.
- [ ] Manuel QA sonucu ve cihaz/browser kaydı Checkpoint C/Wave 19 havuzuna aktarıldı.
- [ ] Bilinen hata saklanmıyor.
- [ ] Sonraki wave başlatılmıyor.

### 18.2 B-QA-001

- [ ] Plan ID kabul kriterleri kanıtlı.
- [ ] Migration/rollback sonucu kayıtlı.
- [ ] Test komutu ve sayısı kayıtlı.
- [ ] Client/admin consumer ile contract doğrulanmış.
- [ ] Canlı yazma testi açık onay olmadan yapılmamış.
- [ ] Sonraki wave başlatılmamış.

### 18.3 C-CI-001

- [ ] Hangi bulgunun blocker olduğu belgeli.
- [ ] Testler canlı DB'ye yazmıyor.
- [ ] Main deploy tüm zorunlu kapılardan sonra.
- [ ] Flaky test otomatik yeşil sayılmıyor; izole tekrar ve sahiplik var.
- [ ] Artifact release kimliğiyle.
- [ ] Secret/log hassas veri kapısı var.
- [ ] Frontend 0.0.0 release olamıyor.
- [ ] Mevcut audit bulguları sınıflanmış ve risk kabulü gerekçeli.

Kriterler plan hazırlandığı için işaretlenmez. Önceki Plan ID'lerin checkbox'ları Wave 17 test altyapısı yazıldığı için kendiliğinden kapanmaz; kendi uygulama ve QA kanıtları gerekir.

## 19. Giriş ve çıkış kapıları

### 19.1 Giriş

- [ ] Wave 16 **DEFERRED / ROADMAP / COMMITTED**.
- [ ] Kullanıcı açıkça Wave 17'yi başlattı.
- [ ] Repo sahipliği/branch/remote/dirty snapshot kayıtlı.
- [ ] Runtime/lockfile/test/CI inventory yeniden doğrulandı.
- [ ] Test DB ve fake-provider modeli onaylı.
- [ ] Production/deploy/repository-settings kapalı.

### 19.2 Yerel tamam

- [ ] A-QA-001 client kapıları çalışıyor ve zero-test guard var.
- [ ] B-QA-001 backend/DB/two-client kapıları çalışıyor.
- [ ] C-CI-001 workflow ve policy local/CI parity ile kanıtlı.
- [ ] Testler canlı DB/provider/recipient kullanmıyor.
- [ ] Success/failure/infra/cancel/skip/flaky sonuçları doğru sınıflı.
- [ ] Artifact, secret/redaction ve cleanup kanıtları mevcut.

### 19.3 Sale Release otomatik kapanışı

- [ ] Required checks bilerek failure ile fail-closed kanıtlandı.
- [ ] Branch protection/deploy gate açık onay varsa read-back ile doğrulandı; yoksa açık manual external gate kaldı.
- [ ] Full command/test count/runtime/artifact evidence kayıtlı.
- [ ] Flaky registry boş veya her kayıt owner/issue/expiry ve onaylı koruma taşıyor.
- [ ] Master §11 ilgili maddeleri gerçek kanıtla senkronize edildi.
- [ ] Manuel QA maddeleri Checkpoint C/Wave 19 havuzuna aktarıldı.
- [ ] Canonical Plan A/B/C, Wave Map ve sonuç alanı senkronize edildi.
- [ ] Wave 18 başlatılmadan duruldu.

## 20. Kapsam dışı ve successor guard

Wave 17'ye dahil değildir:

- Wave 18 `C-MOB-001/A-MOB-001` Android signing, keystore, cihaz parity, store upload, rollout ve rollback
- Wave 19 `C-QA-001` bütünleşik admin/operasyon/release son QA
- Önceki wave ürün davranışlarını yeniden tasarlamak veya yeni özellik eklemek
- Coverage yüzdesini tek kalite ölçüsü yapmak
- Test snapshotlarını gerçek UX/DB doğruluğu yerine geçirmek
- Production DB dump'ını fixture yapmak
- Gerçek push/email/telemetry alıcısına test göndermek
- Açık onaysız branch protection, deploy, secret rotation veya provider mutation
- CI vendor migrasyonu ya da monorepo/repository birleşimi kararı

Wave 17 kapanışında Wave 18 için kod, test, refactor veya uygulama hazırlığı yapılmaz. Ayrı Wave 18 planı hazırdır; yine de yalnız açık kullanıcı talimatı ve Wave 17 QA kapanışıyla aktive edilebilir.

## 21. Risk ve rollback

| Risk | Erken sinyal | Koruma | Rollback/forward-fix |
|---|---|---|---|
| Test canlı DB'ye yazar | Known host/name görülür | Fail-closed guard | Job stop, incident/data cleanup planı |
| CI yeşil ama 0 test | Discovered=0 | Suite manifest | Required gate fail |
| Flaky gizlenir | Retry sonrası green | First-failure artifact | Quarantine/owner/expiry |
| Branch protection etkisiz | Check adı eşleşmez | Exact read-back | Deploy kapalı, setting fix |
| Path filter kapıyı atlar | Shared değişimde skip | Dependency map tests | Full required fallback |
| Secret sızar | Log/artifact sentinel | Scan + masker | Job stop, rotate prosedürü |
| Artifact yanlış commit | SHA/checksum farklı | Provenance manifest | Deploy refuse/rebuild |
| Migration cleanup eksik | Orphan schema | Run-ID lifecycle | Exact cleanup/worker stop |
| Paralel test çakışır | Duplicate fixture IDs | Worker namespace | Concurrency düşür/factory fix |
| Snapshot yanlış onay | Büyük diff kolay kabul | Semantic assertions | Snapshot reject/review |
| Audit gürültülü/blind | Baseline her şeyi örter | Reachability + expiry | Policy tighten/upgrade |
| Cache stale sonuç | Lock/config hash eksik | Complete cache key | Cache bypass |
| Dirty repo işi örter | Unrelated diff | Exact ownership snapshot | Yalnız Wave 17 farkını geri al |

Workflow/policy değişiklikleri additive ve küçük adımlı olur. Required-check adı silinmeden önce replacement aktif/read-back yapılır. External settings rollback'i ayrıca repo admin yetkisi ve açık onay ister.

## 22. Canlı ve external mutation sınırı

Ayrı kullanıcı yetkisi isteyen işlemler:

- dependency install/update ve lockfile değişimi
- CI vendor/repository workflow çalıştırma maliyeti veya external service açma
- GitHub/Git provider branch protection, required checks, environment approval ve deploy trigger değişikliği
- repository/organization secret oluşturma, okuma, döndürme veya silme
- production/staging DB migration/yazma veya live endpoint smoke
- Render/Neon/Firebase/Brevo config, restart veya deploy
- Android signing/keystore/AAB/store işlemleri

Yetki öncesi exact repository/environment/service, hedef setting/job/check, mevcut ve önerilen değer, impact, bypass/rollback, secret/data erişimi, maliyet ve durma koşulu raporlanır. Plan hazırlığı bunları yetkilendirmez.

## 23. Sonuç/evidence alanı

Wave 17 yürütüldüğünde en az:

- başlangıç/final Git snapshotı ve exact changed files
- repo/branch/remote/ownership ve runtime/lockfile inventory
- stable komut/job/check matrisi
- production DB guard negatif testi
- ephemeral DB fresh/upgrade/cleanup/orphan kanıtı
- fixture/seed/fake-provider veri sınırı
- frontend lint/build/component/a11y/i18n test sayıları
- kritik E2E yolculukları ve final state assertions
- backend syntax/unit/integration/migration/security sonuçları
- two-client WS/match/chat/reconnect/duplicate kanıtı
- dependency audit reachability/risk-accept/expiry özeti
- secret/PII sentinel source/log/build/artifact negatif kanıtı
- zero-test/missing/cancelled/infra-error fail-closed sonucu
- flaky isolated rerun, owner/quarantine/expiry sonucu
- CI DAG, cache hit/miss ve upstream failure propagation
- artifact commit/checksum/release identity ve retention
- required checks/branch protection/deploy read-back veya açık external manual gate
- local/CI parity ve süre/test-count sonucu
- production/live mutation yapılmadığı kayıt
- canonical checkbox için mevcut otomatik kanıt; manuel QA Checkpoint C / Wave 19 havuzunda
- Wave 18'in başlatılmadığı açık durma kaydı

Kriter yalnız kanıtla `[x]` olur. Bir scriptin varlığı, tek başarılı yerel run, otomatik retry sonrası yeşil veya workflow dosyasının commit edilmesi main/deploy enforcement kanıtı değildir.

## 24. Durma kuralı

Wave 16 QA kapanışı ve kullanıcının açık Wave 17 başlatma talimatı birlikte gelene kadar:

- Wave 17 için kod, test, dependency, lockfile, fixture, migration, workflow, branch protection, secret, deploy veya external setting değişikliği yapılmaz.
- Wave 17 `Aktif` işaretlenmez; belge yalnız `Hazır — aktif değil` kalır.
- Canonical `[ ]` maddeler kanıtsız kapatılmaz.
- Mevcut `npm test`, lint/build scripti veya Crashlytics/Android asset satırı çalışır CI kanıtı sayılmaz.
- Flaky retry, skipped/missing job, zero test ve infrastructure error yeşil sayılmaz.
- Wave 18 planı ayrı dosyada hazırdır; Wave 18 aktive edilmez veya uygulanmaz.
