# TalkX Wave 19 Plan — Sale Acceptance QA ve Release Freeze

> Bu belge yalnız Wave 19 için hazırlanmış uygulama planıdır.
> Canonical kapsam Plan C `C-QA-001` maddesidir.
> Ana ilke: önceki wavelerin kanıtlarını tek release adayı üzerinde birleştir; admin, operasyon, Web, backend ve Android gerçeğini kaynak/veri/zaman/yetki zinciriyle doğrula; kullanıcı onayı olmadan canlı veya geri döndürülemez işlem yapma.
> Plan hazırdır. Wave 19 aktif değildir, Wave 01–18 kapanmamıştır ve uygulama başlamamıştır. Wave 19 canonical haritadaki son wave'dir; Wave 20 veya yeni ürün dönemi burada planlanmaz, hazırlanmaz ya da başlatılmaz.

## 1. Durum ve yürütme sınırı

- **Wave:** 19
- **Wave adı:** Bütünleşik admin, operasyon ve release QA kapanışı
- **Plan katılımı:** Plan C
- **Canonical kapsam:** `C-QA-001`
- **Plan durumu:** Hazır
- **Wave durumu:** Bekliyor
- **Uygulama durumu:** Başlamadı
- **Uygulama yetkisi:** Verilmedi
- **Giriş kapısı:** Wave 18 **AUTO-VERIFIED / COMMITTED** ve kullanıcıdan açık "Wave 19'u başlat" talimatı
- **Mevcut blokaj:** Wave 01–18'in Sale Release sonuçları committed değil; Wave 19 uygulanamaz
- **Önceki wave:** Wave 18 — planı hazır, aktif değil
- **Sonraki wave:** Yok — Wave 19 mevcut canonical haritanın terminal wave'idir
- **Terminal sınır:** Fikir Parkı, yeni özellik veya yeni ürün dönemi ayrı karar ve ayrı planlama ister

Bu dosyanın hazırlanması Wave 19 aktivasyonu; test, build, sync, deploy, migration, notification send, legal publish, admin mutation, backup/restore, Play Console işlemi, production smoke veya yeni ürün dönemi için yetki değildir.

## 1.1 Sale Release override — SALE ACCEPTANCE / TERMINAL QA

- **Yeni feature geliştirme yoktur.** Wave 19'un işi Wave 01–18'den taşınan manuel QA'yı toplamak, hataları triage etmek, ilgili sahip wave kapsamında fix commit'i çıkarmak, regresyonu yeniden çalıştırmak ve release'i dondurmaktır.
- **Zorunlu uçtan uca rota:** register/login → home → Global/Kendi Ülkem → search → offer → accept/pass → anonymous chat → media → report/block → friend → persistent DM → presence → reconnect → account → admin/moderation → Android.
- **Acceptance:** Checkpoint A/B/C açıkları, legal/store/Play Console insan kontrolleri ve gerçek cihaz matrisi burada kapanır. Bulgu varsa freeze verilmez.
- **Freeze:** Kritik/major blocker kalmadığında otomatik regresyon yeniden yeşil, final kullanıcı onayı kayıtlı ve Sale Release artifact'leri izlenebilir olur; ardından **SALE RELEASE FREEZE** ilan edilir.
- **Roadmap koruması:** Wave 03/12/13/14/16/17'den ertelenen kapsam release bug'ı sayılmaz; **Post-acquisition Roadmap / Deferred** olarak satış paketinde kalır.

## 2. Canonical referanslar ve otorite

1. Plan C `C-QA-001` — on bir otomatik kapı, manuel kapılar ve altı kapanış kuralı
2. Master §11 — test stratejisi, QA matrisi, environment ve kanıt ilkeleri
3. Master §12 — repo, release ve operasyon sahipliği
4. Master §13 — Web/frontend manuel QA
5. Master §14 — admin manuel inceleme ve QA-004–013, QA-015–017
6. Master §15 — Android kurulum, lifecycle, ağ, push, izin, sürüm ve deep-link
7. Plan A/B/C içindeki 67 stable ID — davranış ve kabul kriteri otoritesi
8. Wave 01–18 — uygulama sınırları, kapanış kapıları ve evidence manifestleri
9. Wave 17 `A-QA-001/B-QA-001/C-CI-001` — test, CI, artifact ve secret disiplini
10. Wave 18 `C-MOB-001/A-MOB-001` — Android release kimliği, provenance ve WebView eşliği

Çelişkide Master'ın kilitli kararları korunur; ayrıntıda ilgili stable ID otoritedir. Wave 19 yeni davranış tasarlamaz. Kanıt stable ID ile çelişirse örtülü düzeltme yapılmaz; bulgu sahibi wave'e döner. Kanıtlanamayan kriter `geçti` sayılmaz; `başarısız`, `blokeli` veya gerekçeli `uygulanamaz` kaydedilir.

## 3. Tek nihai sonuç

Wave 19 sonunda tek bir release adayı için:

- Wave 01–18 Sale Release sonuçları **AUTO-VERIFIED / COMMITTED** durumundadır; ertelenmiş manuel maddeler bu wave'in acceptance havuzundadır.
- 67 stable ID kanıt veya açık onaylı istisna ile izlenebilir.
- Admin sayı/durum/aksiyonları gerçek kaynağa ve zaman penceresine bağlıdır.
- Web, backend, admin ve Android release kimlikleri uyumludur.
- Test, CI, build/sync ve operasyon kanıtları aynı immutable candidate'a aittir.
- Desktop/mobile admin ve Android manuel matrisleri tamamdır.
- Canlı destructive işlem yapılmamış ya da exact onay/sonuç/audit kaydı vardır.
- Kritik açık bulgu, kısmi başarısızlık veya doğrulanmamış release iddiası yoktur.
- Kullanıcı final manuel QA sonucunu açıkça onaylamıştır.
- Wave 20/yeni ürün dönemi başlatılmadan terminal durma kaydı vardır.

Çıktı yeni özellik değil; denetlenebilir **final QA sonucu, release manifesti, defect/istisna kaydı ve kullanıcı onayıdır**.

## 4. Başlangıç gerçekliği ve giriş kapısı

- Wave 01–18 planları hazırdır fakat hiçbiri aktif değildir; bugün tamamlanmış sayılmaz.
- Script/test varlığı Wave 17/18 kapılarının uygulanmış olduğu anlamına gelmez.
- Kullanıcıya ait mevcut worktree değişiklikleri sahiplenilmez, temizlenmez veya geri alınmaz.
- Deployment, DB, provider, legal ve Android artifact durumu aktivasyonda yeniden okunur.
- Checklist'ler kanıtsız işaretlenmez.

Wave 19 yalnız Wave 01–18 canonical sırada uygulanıp QA-kapalı ve kullanıcı onaylıysa; result'lar exact commit/ortam/artifact'a bağlıysa; Wave 18 Android/release handoff'u geldiyse; canonical belgelerde çelişki kalmadıysa ve kullanıcı açıkça Wave 19'u başlattıysa aktive edilir. Eksik predecessor kanıtı Wave 19 içinde varsayılmaz; ilgili wave'e dönen blokajdır.

Başlangıç snapshot'ı repo/branch/SHA/dirty özetini; Web/backend/admin/Android sürümlerini; environment, URL, DB/schema/migration head'i; CI/artifact/signing referanslarını; legal/provider/analytics sürümlerini; predecessor onaylarını ve canlı yetki sınırını kaydeder.

## 5. Release candidate kimliği ve freeze

| Alan | Zorunlu kayıt |
|---|---|
| Source | Repository, branch, full SHA, dirty/clean durumu |
| Web | Package/build ID, asset manifest/hash, deploy SHA/URL |
| Backend | Runtime/package, deploy ID/SHA, base URL, config fingerprint |
| Database | Provider/project/database, `current_schema()`, migration head |
| Admin | Bundle/build ID, API base URL, role/policy version |
| Android | versionName/versionCode, AAB/APK SHA-256, certificate fingerprint |
| Legal | Active document/version/locale set |
| Notification | Provider/project, template catalog, dry-run mode |
| Analytics | Event schema/rollup, timezone ve freshness policy |
| CI | Workflow revision, run ID, required checks ve artifact retention |

Candidate SHA değişirse etkilenen sonuçlar; backend config/deploy değişirse API/auth/realtime/admin; DB değişirse schema/source/audit/analytics; bundle değişirse build/smoke/a11y; Android artifact değişirse signing/install/cihaz; legal/template değişirse yayın/delivery kanıtı yenilenir. Tarih değiştirmek eski kanıtı güncellemez.

## 6. Evidence registry ve yeniden kullanım

Her kayıt `evidence_id`, Wave/Plan/QA ID, kriter, exact komut/adım, source/config/data snapshot, ortam/cihaz/tarayıcı/rol, UTC zaman ve pencere, expected/actual, pass/fail/blocked/N/A, test/kayıt sayısı, artifact yolu, owner/reviewer, redaction, freshness ve defect/onay bağlantısı taşır.

Önceki kanıt yalnız aynı source/config/schema/artifact'a aitse, davranış değişmediyse, freshness geçmediyse, ham artifact erişilebilirse ve reviewer/kullanıcı onayı varsa yeniden kullanılır. Candidate değişimi, flaky sonuç, ortam farkı, kayıp provenance veya güvenlik/yetki belirsizliği ilgili kapıyı yeniden çalıştırır. `Skipped`, `blocked`, flaky retry ve gerekçesiz `N/A`, `passed` değildir.

## 7. Stable ID ve QA coverage

| Kaynak | Beklenen durum | Wave 19 doğrulaması |
|---|---|---|
| Plan A | Kriterler kanıtlı | Akış, a11y, locale, responsive, Android istemci |
| Plan B | Kriterler kanıtlı | API, realtime, data, security, observability, recovery |
| Plan C | Kriterler kanıtlı | Admin, trust, moderation, compliance, release, operation |
| QA-001–003/014 | Sahip wave'de kapalı | Admin/release regresyon referansı |
| QA-004–013 | C-QA birincil | Admin ve operasyon doğruluğu |
| QA-015–017 | C-QA birincil/bağlı | Campaign, Release Health, analytics/privacy |
| Wave 01–18 result | QA-kapalı/onaylı | Provenance, freshness, invalidation |

Checkbox ile evidence çelişirse kanıt kazanır; canonical durum düzeltilmeden final kapanış yapılmaz.

## 8. Otomatik kapılar

### 8.1 Admin endpoint auth/rate-limit

- Yetkisiz, expired, yanlış rol ve normal kullanıcı erişimi reddedilir.
- Reveal/export/mutation yetkisi server-side uygulanır.
- Rate key/window/status/retry ve proxy/header davranışı kanıtlanır.
- Session revoke/re-auth ve başarısız denemelerin audit sonucu test edilir.
- Credential/PII loglanmaz.

### 8.2 API/schema

- Request/response/status/error ile null/missing/empty/unknown ayrımı test edilir.
- Pagination/filter/sort/cursor/timezone deterministiktir.
- Migration head, runtime query ve client compatibility uyumludur.
- Doğru DB ve `current_schema()=public` doğrulanır.
- Breaking veya sessiz alan kaybı kapıyı düşürür.

### 8.3 Admin frontend smoke

- Login/session/role guard ve tüm ana admin route'ları açılır.
- Loading/empty/error/stale/partial/forbidden doğru bilgi hiyerarşisini korur.
- Deep-link, refresh, back/forward ve mobile viewport çalışır.
- Console/unhandled/network/a11y kritik hataları raporlanır.
- Mask/reveal/copy ve destructive aksiyonlar yetki/audit ile korunur.

### 8.4 Data summary vs source

- Her kritik sayı için metric tanımı, birim, timezone, pencere, freshness, source tablo/event/rollup ve filtre kaydedilir.
- Fixture veya salt-okunur sorguyla UI/API/source karşılaştırılır.
- Duplicate, late event, anonymized/deleted user ve partial ingestion kapsanır.
- `0`, `no data`, `unknown`, `stale` ve `partial` ayrı doğrulanır.

### 8.5 Permission/audit

- Rol × kaynak × aksiyon matrisi view/reveal/copy/export/mutate/publish/send/restore/deploy için doğrulanır.
- UI gizleme server authorization yerine geçmez.
- Audit actor, target, action, reason, before/after özeti, time ve result taşır.
- Audit payload secret/token/gereksiz PII içermez.

### 8.6 Notification dry-run/test

- Provider environment, locale/template/fallback ve recipient preview kanıtlanır.
- Dry-run gerçek teslimat üretmez; test recipient allowlist ile sınırlıdır.
- Idempotency, retry, expiry ve failure reason test edilir.
- Push/inbox/deep-link sonucu Wave 13/18'e bağlanır.
- Production toplu gönderim varsayılan kapsam değildir.

### 8.7 Legal draft/publish staging

- Draft/review/staged publish/active ayrımı; type/version/locale/hash/effective date kaydedilir.
- Eksik locale/fallback, client fetch ve acceptance sonucu test edilir.
- Rollback/withdraw staging'de doğrulanır; production publish ayrı açık onay ister.

### 8.8 Analytics fixture/rollup

- Event schema/version ve consent/privacy filtresi doğrulanır.
- Fixture ingestion → storage → rollup → API → UI zincirinden geçer.
- User/session/event birimi, timezone, late/duplicate/backfill ayrıdır.
- Low/no/stale/partial ve retention/deletion/anonymization sonucu kanıtlanır.

### 8.9 Release Health controlled event

- PII içermeyen event doğru environment/release'e gider.
- Ingestion → grouping → context/symbolication → admin zinciri doğrulanır.
- Release SHA/versionName/versionCode ve recovery/read-back kanıtlanır.
- Production event ayrıca açık onay ister.

### 8.10 CI pipeline

- Wave 17 required checks exact candidate SHA üzerinde fail-closed çalışır.
- Skipped/cancelled/neutral/allowed-failure kritik pass değildir.
- Cache riski, checksum/retention/source SHA ve toolchain kaydedilir.
- Secret redaction ve untrusted-run sınırı doğrulanır.

### 8.11 Android build/sync

- Wave 18 canonical version/environment manifesti kullanılır.
- Clean Web build, Capacitor sync ve full asset-tree hash doğrulanır.
- Merged manifest, permission/export/deep-link, signing ve checksum eşleşir.
- Install/update/smoke aynı signed candidate'a aittir; debug artifact release kanıtı değildir.
- Upload/rollout ayrıca açık onay ister.

## 9. Manuel admin matrisi

| QA | Yüzey | Final inceleme |
|---|---|---|
| QA-004 | Dashboard | KPI source/freshness, health, empty/error, aksiyon |
| QA-005 | Activity | Event/actor/target, filtre, zaman ve ham kanıt |
| QA-006 | Navigation | Route, deep-link, back/forward, rol görünürlüğü |
| QA-007 | Profiles | Geo/data source, mask, low/no data, durum özeti |
| QA-008 | User detail | Session/data, reveal/copy audit, ilişkili olay |
| QA-009 | Reports | Queue/detail/evidence/moderation/confirmation/result |
| QA-010 | Notifications | Locale/template/preview/dry-run/test/error |
| QA-011 | Performance | Metric/pencere/percentile/partial data/bottleneck |
| QA-012 | Analytics | Funnel/cohort/unit/rollup/source/privacy |
| QA-013 | Legal | Version/locale/draft/publish/acceptance/audit |
| QA-015 | Campaign | Target preview, schedule, delivery, client sonucu |
| QA-016 | Release Health | Release filtre, controlled event, recovery |
| QA-017 | Scope analytics | Enum, fallback reason, consent, privacy |

Her satır desktop/mobile; normal, low/no, stale, partial, denied ve failure durumlarıyla değerlendirilir.

## 10. Bütünleşik yolculuklar

1. Onboarding/legal → auth/session → ana yüzey → admin/legal read-back
2. Global/My Country → arama → teklif → kabul/ret → sohbet → analytics/admin
3. Reconnect/offline/resume → recovery → duplicate önleme → health/metric
4. Mesaj/outbox/media → delivery/read → hata/retry → support/admin evidence
5. Report/block/moderation → admin queue → yetkili aksiyon → kullanıcı sonucu → audit
6. Friend/inbox → unread/read → push/System → deep-link
7. Privacy/delete → session revoke → retention/anonymization → admin/source
8. Deploy/install/update → health event → rollback/forward-fix → user smoke

Her zincir correlation ID veya eşdeğeriyle PII üretmeden izlenir.

## 11. Desktop/mobile admin, mask ve destructive UX

- Navigation, table/card ve progressive disclosure dar/geniş viewport'ta çalışır.
- Klavye/focus/dialog/Escape/zoom/reduced motion/uzun metin doğrulanır.
- Renk/ikon tek başına durum taşımaz.
- Screenshot'lar before/after, viewport ve redaction bilgisi taşır.
- Hassas değer maskeli; reveal/copy ayrı permission/purpose/audit gerektirir.
- Yetki düşünce açık değer cache/UI'da kalmaz.
- Destructive confirmation hedef, kapsam, etki, geri dönüş ve reason gösterir.
- Re-auth/two-person policy uygulanır; double submit ve stale target engellenir.
- Varsayılan QA destructive production aksiyonunu yalnız inceler/dry-run eder.

## 12. Android manuel release matrisi

- Temiz kurulum ve desteklenen sürümden update
- Splash/status/navigation bar, safe-area, keyboard, 100dvh
- Android back: modal, route, search, offer, chat, exit
- Notification fg/bg/killed ve deep-link
- Camera/gallery allow/deny/permanent deny/cancel/process death
- Background/foreground socket/timer/offer/outbox recovery
- Wi-Fi/mobile, airplane, weak network ve reconnect
- Force-stop/process death sonrası revalidation
- Release/version/asset/backend/signing eşliği
- Legal/delete/support deep-link
- Minimum/orta/güncel API ve WebView

Sonuç cihaz, API, WebView, artifact checksum ve exact senaryoyla kaydedilir.

## 13. Ortam, production ve operasyon sınırı

Sıra: local fixture → CI/ephemeral → staging → production salt-okunur → yalnız gerekliyse açık onaylı dar production smoke.

- Exact servis/project/database/release tanımlanır.
- Read-only soru mutation'a çevrilmez; test hesap/recipient allowlist kullanılır.
- Notification, legal, moderation, delete, restore, deploy ve rollout ayrı yetkilendirilir.
- Onay exact aksiyon, etki, süre, maliyet, rollback ve stop condition içerir.
- Önce/sonra read-back yapılır; onay yoksa `yapılmadı — onay gerekli` kaydı tutulur.
- Backup okunabilirlik/checksum/encryption/access/retention ile doğrulanır.
- Restore yalnız izole boş hedefte; kritik count, referential integrity, schema ve migration head ile test edilir.
- Cutover runbook restart/redeploy/smoke ve RPO/RTO içerir.
- Canlı restore/failover/DB URL değişimi ayrı açık onay ister.

## 14. Defect, flaky ve istisna yönetimi

- **P0:** Veri kaybı, auth bypass, secret/PII sızıntısı, yanlış production mutation — koşu durur.
- **P1:** Çekirdek/release blocker, yanlış admin gerçeği, kırık rollback — final blokeli.
- **P2:** Önemli regresyon/operatör riski — sahip ve karar olmadan kabul edilmez.
- **P3:** Düşük etkili fark — gerekçeli kullanıcı risk kabulüyle izlenebilir.

Her defect Plan/QA/wave sahibi, repro, expected/actual, ortam ve evidence taşır. Düzeltme candidate'ı değiştirirse invalidation matrisi çalışır. Flaky test tek yeşil retry ile kapanmaz; izole tekrar, neden, quarantine ve risk kararı gerekir.

## 15. Uygulama paketleri

1. **Preflight/freeze:** Wave 01–18 kapanışı, Git/environment/release kimliği, registry, invalidation ve canlı sınır.
2. **Otomatik kapılar:** Auth/API/admin/source/audit/notification/legal/analytics/health/CI/Android.
3. **Sale Acceptance manuel QA:** Checkpoint A/B/C havuzu, QA-004–013/015–017, desktop/mobile/a11y/failure states ve Android matrisi.
4. **Operasyon rehearsal:** İzole backup/restore, deploy/rollback/forward-fix dry-run ve gerekiyorsa ayrı onaylı smoke.
5. **Final reconciliation:** Stable ID/QA coverage, defect/istisna kararı, manifest, kullanıcı onayı, canonical senkron ve terminal durma.

Sıra atlanmaz; bir paket kapanmadan sonraki final iddiası kurulmaz.

## 16. Dosya, komut ve manuel kanıt envanteri

Aktivasyonda exact yollar yeniden keşfedilir: Master, Plan A/B/C, Wave Map, Wave 01–19; frontend/admin test/build; backend auth/rate/data/audit/notification/legal/analytics/health; migration/backup; CI/scripts/artifacts; Android/Capacitor/Gradle/manifest/release; provider/deploy read-back. Liste mutation yetkisi değildir; ürün düzeltmesi predecessor scope'una döner.

Gerçek package script/workflow keşfedilir; komut uydurulmaz. Exact komut, exit code, test sayısı, süre, SHA ve artifact kaydedilir. Manuel kayıtta scenario/QA/Plan ID, önkoşul, rol, ortam, adımlar, expected/actual, screenshot/video, cihaz/browser, correlation, redaction, durum, defect, tester/reviewer ve UTC zaman bulunur. Kullanıcıya yalnız `kontrol et` denmez; exact adım ve beklenen sonuç verilir.

## 17. C-QA-001 canonical kapanış checklist'i

- [ ] Plan ID kabul kriterleri kanıtlı.
- [ ] Source/time window doğruluğu testli.
- [ ] Yetki/audit sonucu kayıtlı.
- [ ] Canlı destructive işlem yapılmadı veya açık onay/sonuç var.
- [ ] Web/backend/Android release kimliği kayıtlı.
- [ ] Sonraki wave başlatılmadı.

Son madde terminal bağlamda: Wave 20 yoktur; Fikir Parkı, yeni özellik veya yeni ürün dönemi açık kullanıcı talimatı olmadan başlatılmamıştır.

## 18. Wave 19 kapanış kapıları

### 18.1 Giriş hazır

- [ ] Wave 01–18 QA-kapalı ve kullanıcı onaylı.
- [ ] Candidate source/config/schema/artifact kimliği frozen.
- [ ] Evidence registry ve invalidation matrisi hazır.
- [ ] Canlı erişim/mutation sınırı kayıtlı.
- [ ] Açık Wave 19 başlatma talimatı var.

### 18.2 Otomatik kapılar kapalı

- [ ] Admin auth/rate-limit ve API/schema geçti.
- [ ] Admin frontend smoke geçti.
- [ ] Data summary/source reconciliation geçti.
- [ ] Permission/audit matrisi geçti.
- [ ] Notification dry-run ve legal staging geçti.
- [ ] Analytics rollup ve Release Health controlled event geçti.
- [ ] CI required checks exact candidate'ta geçti.
- [ ] Android build/sync/artifact provenance geçti.
- [ ] Secret/PII scan temiz.

### 18.3 Manuel/operasyon kapıları kapalı

- [ ] Master §14 admin matrisi tamam.
- [ ] QA-004–013 ve QA-015–017 kayıtlı.
- [ ] Desktop/mobile admin ve a11y tamam.
- [ ] Mask/reveal/copy/destructive confirmation kanıtlı.
- [ ] Low/no/stale/partial/failure durumları kanıtlı.
- [ ] Master §15 Android matrisi tamam.
- [ ] Backup/restore ve rollback/forward-fix prova sonucu kayıtlı.
- [ ] Production smoke yapılmadı veya exact onay/read-back var.

### 18.4 Final QA kapalı

- [ ] 67 stable ID ve QA coverage boşluksuz.
- [ ] Kritik defect, flaky belirsizlik veya stale evidence yok.
- [ ] İstisnalar gerekçe, sahip, süre ve kullanıcı risk kabulü taşıyor.
- [ ] Final release manifesti Web/backend/admin/Android için tutarlı.
- [ ] C-QA-001 altı canonical kriteri kanıtla kapalı.
- [ ] Kullanıcı final manuel QA sonucunu açıkça onayladı.
- [ ] Master, Plan A/B/C, Wave Map, README ve Wave 19 result senkronize edildi.
- [ ] Planlama envanteri 19/19 tamam; hiçbir wave otomatik başlamadı.
- [ ] Wave 20/yeni ürün dönemi başlatılmadan duruldu.

## 19. Kapsam dışı ve terminal guard

- Yeni özellik, UI redesign veya stable ID
- Fikir Parkı'nı otomatik backlog'a almak
- Predecessor ürün kodunu Wave 19 içinde sessizce düzeltmek
- Wave 20 oluşturmak
- Kullanıcı onaysız deploy/restart/restore/publish/send/rollout
- Gerçek kullanıcı üzerinde destructive test
- Yeni vendor, store policy veya hukuk tasarımı
- QA için security/audit/privacy/permission gevşetmek

Ürün düzeltmesi gerekirse Wave 19 `blokeli` kalır; ilgili stable ID/wave kontrollü yeniden açılır ve yeni candidate üzerinde etkilenen kanıt yenilenir.

## 20. Risk ve koruma matrisi

| Risk | Sinyal | Koruma | Sonuç |
|---|---|---|---|
| Eski kanıt | SHA/config farkı | Freeze/invalidation | Kapıyı yenile |
| Ham kanıt yok | Yalnız yeşil özet | Evidence registry | Finali blokla |
| Yanlış admin sayı | UI/API/source farkı | Reconciliation | Sahip ID'ye defect |
| `0`/no-data karışır | Yanlış health | Durum matrisi | Kapıyı düşür |
| UI-only yetki | Direct API başarılı | Server negatif test | Security blocker |
| Audit PII | Token/PII payload | Redaction | Koşuyu durdur |
| Dry-run send | Delivery oluşur | Test allowlist | Incident/stop |
| Staging prod sayılır | Environment farkı | Manifest etiketi | İddiayı reddet |
| Android stale | Asset hash farkı | Full-tree manifest | Rebuild/resync |
| CI skipped | Neutral/cancelled | Fail-closed | Finali blokla |
| Flaky retry | Fail sonra pass | İzole rerun | Risk kararı |
| Production scope | Belirsiz onay | Exact action gate | İşlemi yapma |
| Dirty worktree | Unrelated diff | Ownership snapshot | Yalnız Wave 19 |
| Scope drift | Wave 20 hazırlığı | Terminal guard | Talimat bekle |

## 21. Canlı ve external mutation sınırı

Ayrı, eylem-bazlı açık kullanıcı onayı ister: production deploy/restart/config; live DB write/migration/restore/failover/cutover; campaign send; legal publish; moderation/ban/reveal/export/delete; production controlled event; Play upload/promote/rollout/halt; signing/secret erişimi; CI/repository setting mutation'ı.

Onaydan önce exact target, mevcut durum, değişiklik, etki, maliyet, veri/güvenlik riski, rollback/forward-fix ve stop condition raporlanır. Bir eylemin onayı diğerine yayılmaz.

## 22. Sonuç/evidence alanı

Wave 19 yürütüldüğünde en az:

- başlangıç/final Git ve exact changed files
- Wave 01–18 closure/onay registry
- 67 stable ID ve QA coverage
- frozen candidate/release manifesti
- evidence freshness/invalidation sonucu
- on bir otomatik kapı raporu
- QA-004–013/015–017 ve desktop/mobile admin evidence'i
- Android cihaz/release matrisi
- low/no/stale/partial/failure ve mask/reveal/copy/destructive sonuçları
- backup/restore/rollback prova sonucu
- production için yapılmadı veya exact onay/read-back
- defect/flaky/istisna/risk kabul listesi
- kullanıcı final manuel QA onayı
- C-QA checklist ve canonical senkron
- Wave 20/yeni dönem başlatılmadan terminal durma kaydı

Kriter yalnız kanıtla `[x]` olur. Genel yeşil CI, toplam test sayısı, tek screenshot veya tek cihaz smoke'u kendi başına release-ready kanıtı değildir.

## 23. Terminal durma kuralı

Wave 18 QA kapanışı ve kullanıcının açık Wave 19 başlatma talimatı birlikte gelene kadar:

- Wave 19 için test, build, sync, deploy, migration, provider, canlı ortam veya ürün kodu değişikliği yapılmaz.
- Wave 19 `Aktif` işaretlenmez; yalnız `Hazır — aktif değil` kalır.
- Canonical `[ ]` maddeler kanıtsız kapatılmaz.
- Predecessor kanıtı source/config/artifact eşliği olmadan geçerli sayılmaz.
- Production/destructive işlem genel QA talimatından yetki türetmez.
- Wave 20, Fikir Parkı veya yeni ürün dönemi planlanmaz, hazırlanmaz ya da uygulanmaz.

Wave 19 QA kapanışı ve kullanıcı onayından sonra yürütme terminal durumda durur. Bundan sonraki her çalışma yeni ve açık bir kullanıcı kararı ister.
