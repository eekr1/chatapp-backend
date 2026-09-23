# TalkX Wave Map

> Plan A/B/C içindeki 67 stable uygulama maddesini bağımlılık sırasına göre wave'lere yönlendiren canonical yürütme haritası.
> Bu belge plan ayrıntısını tekrar etmez; ayrıntının otoritesi ilgili Plan A/B/C maddesidir.
> Harita ile Wave 01–19 planları hazırdır. Wave 01 ve Wave 02 Sale Release kapsamları 2026-09-23 tarihinde auto-verified/committed/manual-QA-deferred kapanışına ulaştı; Wave 03–19 başlatılmadı.

> **Sale Release override:** Bu harita, Master Backlog ile Plan A/B/C'deki uzun vadeli kararları değiştirmez. Satış öncesinde hangi parçanın uygulanacağını, hangi parçanın küçültüldüğünü ve hangisinin **Post-acquisition Roadmap / Deferred** olarak korunacağını belirler. Bir wave dosyasındaki eski kapanış veya manuel QA dili bu override ile çelişirse bu harita geçerlidir.

## 1. Belge rolü ve otorite

TalkX yürütme belgelerinin otorite sırası:

1. `TALKX_MASTER_BACKLOG.md` — kilitli kararlar, kaynak kanıtı, QA-001–017 ve Fikir Parkı
2. `TALKX_PLAN_A_PRODUCT_CLIENT.md` — ürün, client ve kullanıcı deneyimi kabul kriterleri
3. `TALKX_PLAN_B_PLATFORM_REALTIME_DATA.md` — backend, realtime ve veri kabul kriterleri
4. `TALKX_PLAN_C_ADMIN_TRUST_RELEASE.md` — admin, trust, release ve operasyon kabul kriterleri
5. Bu `TALKX_WAVE_MAP.md` — uygulama sırası, wave sınırı ve durum
6. Kullanıcının açık planlama talimatıyla hazırlanacak `waves/TALKX_WAVE_NN.md` — tek wave kapsamı, kanıt ve sonuç; planın varlığı aktivasyon değildir
7. Kod, test, migration, build ve açık onaylı canlı doğrulama kanıtı

Wave yeni ürün kararı veya mimari üretmez. Çelişkide uygulama durur; önce Master Backlog veya ilgili plan düzeltilir.

## 2. Güncel durum

- **Wave Map durumu:** Hazır
- **Aktif wave:** Yok
- **Hazırlanmış Wave Planları:** `waves/TALKX_WAVE_01.md`, `waves/TALKX_WAVE_02.md`, `waves/TALKX_WAVE_03.md`, `waves/TALKX_WAVE_04.md`, `waves/TALKX_WAVE_05.md`, `waves/TALKX_WAVE_06.md`, `waves/TALKX_WAVE_07.md`, `waves/TALKX_WAVE_08.md`, `waves/TALKX_WAVE_09.md`, `waves/TALKX_WAVE_10.md`, `waves/TALKX_WAVE_11.md`, `waves/TALKX_WAVE_12.md`, `waves/TALKX_WAVE_13.md`, `waves/TALKX_WAVE_14.md`, `waves/TALKX_WAVE_15.md`, `waves/TALKX_WAVE_16.md`, `waves/TALKX_WAVE_17.md`, `waves/TALKX_WAVE_18.md` ve `waves/TALKX_WAVE_19.md` — on dokuz plan da aktif değil
- **Uygulama durumu:** Wave 01 ve Wave 02 auto-verified; ayrı backend/frontend commitleri ve ertelenmiş manuel QA ile kapalı
- **İlk yürütme adayı:** Wave 03 — yalnız ayrı açık kullanıcı talimatıyla
- **Wave 01 yetkisi:** 2026-09-23 tarihinde verildi ve yalnız Sale Release kapsamı yürütüldü
- **Wave 02 yetkisi:** 2026-09-23 tarihinde verildi ve yalnız Sale Release kapsamı yürütüldü
- **Sonraki işlem:** Dur; Wave 03 için ayrı açık başlangıç talimatını bekle

Wave 03 ve sonrası yalnız hazırlanmış plandır; aktivasyon veya uygulama anlamına gelmez.

## 3. Değişmez yürütme kuralları

1. Aynı anda yalnız bir aktif wave bulunur.
2. Açık kullanıcı talimatı olmadan hiçbir wave başlatılmaz.
3. Aktif wave dışındaki ID için kod, test hazırlığı, refactor, migration veya gelecek-wave altyapısı yapılmaz.
4. Wave içindeki `Plan refs` sıralıdır; gerekli önceki sözleşme kurulmadan bağımlı ID uygulanmaz.
5. Wave Plan, plan metnini kopyalamaz; yalnız ID, kabul kriteri aralığı, kapsam, dışarıda bırakılanlar ve kanıt kapısını taşır.
6. Aynı wave'deki A/B/C maddeleri tek dikey teslimat olabilir; canonical sahiplik ilgili planda kalır.
7. Plan ön koşulu ile çapraz-plan sağlayıcı/tüketici sözleşmesi birbirine karıştırılmaz.
8. Güvenlik, canlı DB, migration, deploy, bildirim, legal yayın, toplu moderasyon ve mağaza işlemi ayrıca açık yetki ister.
9. Her wave yalnız kullanıcı mobilde veya bu görevde wave numarasını açıkça başlattığında yürütülür.
10. Wave akışı: **implement → otomatik doğrula → tek wave commit'i → DUR**. Sonraki wave kendiliğinden başlamaz.
11. Başarısız otomatik kapı, çözülmemiş contract/decision blocker'ı veya ayrıca yetki isteyen canlı/geri döndürülemez işlem wave'i durdurur.
12. Manuel QA, Wave 01–18'in tekil ilerleme kapısı değildir. İlgili adımlar silinmez; checkpoint/final havuzuna aktarılır ve en geç Wave 19 Sale Acceptance QA'da çalıştırılır.
13. Commit sonrası wave **AUTO-VERIFIED / COMMITTED / MANUAL-QA-DEFERRED** durumuna gelir. Bu durum bir sonraki wave için yeterli teknik ön koşuldur; kullanıcı yine açıkça başlatmalıdır.
14. Plan A/B/C checkbox'ları yalnız gerçekten elde edilen kanıt kadar güncellenir. Ertelenen manuel veya roadmap kriterleri yanlış biçimde tamamlanmış gösterilmez.
15. Kapanışta Wave Map ile aktif Wave Plan sonucu senkronize edilir; sonraki wave **Bekliyor** kalır.
16. Fikir Parkı maddeleri bu haritaya otomatik girmez.

## 4. Durum modeli

| Durum | Anlam |
|---|---|
| Bekliyor | Haritada; uygulama veya hazırlık başlamadı |
| Aktif | Kullanıcı açıkça başlattı ve hazırlanmış plan tek aktif Wave Plan olarak yürütülüyor |
| Auto-verified | Sale Release scope'u uygulandı ve zorunlu otomatik kapılar geçti |
| Committed / QA deferred | Tek wave commit'i alındı; manuel QA checkpoint/Wave 19 havuzunda |
| Checkpoint QA | Birden çok committed wave toplu manuel smoke/regression altında |
| QA kapalı | Wave 19 Sale Acceptance kanıtı ve gerekli kullanıcı onayı tamam |
| Deferred / Roadmap | Satış öncesi uygulanmayacak kapsam, canonical plan referanslarıyla korunuyor |
| Bloke | Somut dış bağımlılık veya kullanıcı kararı gerekiyor |
| Kapsam dışı | Yalnız açık gerekçe ve kullanıcı kabulüyle uygulanmaz |

Başlangıçta bütün wave'ler `Bekliyor` durumundadır. Sıradaki wave kendiliğinden `Aktif` yapılmaz.

## 5. Faz mimarisi

| Faz | Wave'ler | Amaç |
|---|---:|---|
| Faz I — Temel ve sözleşmeler | 01–04 | Ürün sınırı, güvenlik, platform/client temeli, health, DB ve operasyon |
| Faz II — Realtime ve eşleşme | 05–09 | Reconnect/presence, veri sahipliği, QA-014, QA-017 ve QA-003 |
| Faz III — Mesaj, güven ve hesap | 10–13 | Kalıcı mesaj, medya/moderasyon, legal/hesap ve Sistem iletişimi |
| Faz IV — Yönetim ve görünürlük | 14–16 | Analitik, admin görev ekranları ve Release Health |
| Faz V — Kalite ve dağıtım | 17–19 | Ortak kalite kapıları, Android zinciri ve bütünleşik son QA |

Faz bir uygulama yetkisi değildir; yürütme birimi wave'dir.

## 5.1 Wave dosya mimarisi

- Ayrıntılı wave planlarının canonical klasörü `docs/waves/` ve klasör sözleşmesi `waves/README.md` dosyasıdır.
- Toplam **19 wave** vardır; dosya adları `TALKX_WAVE_01.md`–`TALKX_WAVE_19.md` kalıbını izler.
- Wave dosyaları topluca veya boş placeholder olarak oluşturulmaz. Kullanıcı hangi wave'in yazılmasını açıkça isterse yalnız o dosya hazırlanır ve ardından durulur.
- Hazırlanmış bir dosya wave'i aktif etmez. Aktivasyon açık kullanıcı talimatı, önceki wave'in **Committed / QA deferred** veya **QA kapalı** olması ve güncel repo doğrulaması ister.
- Bu harita sıra, Plan A/B/C katılımı ve durum otoritesidir; wave dosyası yalnız ilgili stable ID'lerin uygulama ayrıntısını ve kanıtını taşır.
- Mevcut envanter: `waves/TALKX_WAVE_01.md`, `waves/TALKX_WAVE_02.md`, `waves/TALKX_WAVE_03.md`, `waves/TALKX_WAVE_04.md`, `waves/TALKX_WAVE_05.md`, `waves/TALKX_WAVE_06.md`, `waves/TALKX_WAVE_07.md`, `waves/TALKX_WAVE_08.md`, `waves/TALKX_WAVE_09.md`, `waves/TALKX_WAVE_10.md`, `waves/TALKX_WAVE_11.md`, `waves/TALKX_WAVE_12.md`, `waves/TALKX_WAVE_13.md`, `waves/TALKX_WAVE_14.md`, `waves/TALKX_WAVE_15.md`, `waves/TALKX_WAVE_16.md`, `waves/TALKX_WAVE_17.md`, `waves/TALKX_WAVE_18.md` ve `waves/TALKX_WAVE_19.md` hazır fakat aktif değil; 19/19 planlama envanteri tamamdır.

## 5.2 Sale Release scope matrisi

| Wave | Sale sınıfı | Satış öncesi çekirdek | Post-acquisition Roadmap / Deferred |
|---:|---|---|---|
| 01 | TAM / ÇEKİRDEK | Ürün dili; HTTP/WS input, payload, origin ve guest fallback güvenliği | Play Console, store ve insan legal incelemesi Wave 19 manuel checklist'inde |
| 02 | TAM / ÇEKİRDEK | API/error standardı; session; socket identity; abuse/rate-limit; redaction; admin erişim sertleştirmesi | Büyük backend framework/refactor ve enterprise capability katmanı |
| 03 | KÜÇÜLTÜLMÜŞ | Riskli state/domain ayrımı; auth UX; kritik responsive/a11y | Komple App.jsx parçalama, design-system ve geniş token migration |
| 04 | TAM / ÇEKİRDEK | Liveness/readiness; release identity; migration disiplini; DB sınırları; backup/restore; deploy/rollback runbook | Gelişmiş SLO/performance gözlem platformu |
| 05 | TAM / ÇEKİRDEK | Deterministik reconnect/recovery; ghost state temizliği; presence/last seen; state izolasyonu | Redis veya distributed realtime mimarisi |
| 06 | TAM / ÇEKİRDEK | Canonical country; veri sahipliği; deletion; retention/anonymization; privacy eşliği | Geniş privacy automation/platform yatırımı |
| 07 | TAM / ÇEKİRDEK | Server-otoriteli join/search/cancel/requeue ve stale/double queue temizliği | Yeni matchmaking ürün kapsamı |
| 08 | TAM / ÇEKİRDEK | Ayrı Global/Kendi Ülkem queue-scope; kesin country filtresi; açık fallback; temel telemetry | Gelişmiş segment/deney altyapısı |
| 09 | TAM / ÇEKİRDEK | Pending offer; server countdown; accept/pass/timeout; duplicate karar; requeue | Yeni eşleşme varyantları |
| 10 | TAM / ÇEKİRDEK | Kalıcı DM; clientMsgId; idempotency; outbox/retry; offline/reconnect; unread/read | Mesajlaşma platformu genişletmeleri |
| 11 | TAM / ÇEKİRDEK | Mevcut tek kullanımlık medya; report/block; ban/shadowban; evidence zinciri; admin bağlantısı | Yeni medya özellikleri |
| 12 | KÜÇÜLTÜLMÜŞ | Session-expired/recovery UX; account settings; deletion/support; gerekli legal acceptance/version | Gelişmiş legal publishing sistemi |
| 13 | ÇOK KÜÇÜLTÜLMÜŞ | TR/EN fallback; mevcut push; notification deep-link güvenilirliği | TalkX System inbox, campaign ve çok dilli iletişim platformu |
| 14 | MİNİMAL | Users, active/online, searches/matches, reports ve mümkünse basic activity; no-data/0 ayrımı | Davranış rollup, confidence window ve gelişmiş analytics |
| 15 | TAM / ÇEKİRDEK | User list/detail; reports; ban/block/moderation; state'ler; makul maskeleme | Enterprise admin console genişletmeleri |
| 16 | PAS / ROADMAP | Wave 04 health/version/deploy identity yeterlilik doğrulaması ve PAS kaydı | B-OBS-002/C-REL-001 gelişmiş Release Health ingestion/UI bütünü |
| 17 | KÜÇÜLTÜLMÜŞ | Frontend lint/build; backend syntax/core tests; kritik two-client/auth/reconnect/duplicate regresyonu; basit CI | Enterprise test matrisi, geniş artifact/audit sistemi |
| 18 | TAM / ÇEKİRDEK | Version hizası; prod build; Capacitor sync; stale asset; signed AAB/RC; temel Android davranışı | Mağaza yayını ve production rollout ayrıca açık yetki ister |
| 19 | SALE ACCEPTANCE | Toplu manuel QA; bug triage/fix-regression; release freeze | Yeni özellik, yeni ürün dönemi veya roadmap implementasyonu |

Roadmap'e taşınan stable ID ve kabul kriterleri silinmez. Canonical Plan A/B/C'de açık kalır; ilgili wave dosyasındaki Sale Release override bölümünde yönlendirilir ve satış paketinde **Post-acquisition Roadmap / Deferred** olarak korunur.

## 6. Canonical Wave Map

| Wave | Sonuç | Plan refs — uygulama sırası | Birincil çıkış kapısı | Durum |
|---:|---|---|---|---|
| 01 | Ürün sınırı, internet yüzeyi güvenliği ve global uyum başlangıcı | A-PRD-001 → B-SEC-001 → C-COMP-001 | Ürün vaadi ile güvenlik/uyum kararları çelişmiyor | Auto-verified / commit & QA deferred |
| 02 | Core API, auth, logging, abuse, socket ve admin erişim temeli | B-API-001 → B-AUTH-001 → B-OBS-001 → B-SEC-002 → B-WS-001 → C-ADMIN-001 | Sürümlü platform erişim sözleşmesi kanıtlı | Auto-verified / commit & QA deferred |
| 03 | Test edilebilir client kabuğu, tema/state temeli ve dürüst auth UX | A-FND-001 → A-FND-002 → A-A11Y-001 → A-AUTH-001 | Client temeli TalkX temasını ve erişilebilirliği koruyor | Bekliyor |
| 04 | Health, performans verisi, DB runtime ve operasyon güvenliği | B-API-002 → B-ANL-002 → B-DB-001 → C-PERF-001 → C-OPS-001 → C-OPS-002 | Readiness, migration ve kurtarma zemini kanıtlı | Bekliyor |
| 05 | Reconnect, active state ve gerçek presence | B-WS-002 → B-PRES-001 → A-MATCH-004 → A-FRIEND-001 → A-PRD-002 | İki-client recovery/presence deterministik | Bekliyor |
| 06 | Veri sahipliği, canonical ülke, privacy ve hesap silme | B-DATA-001 → B-DATA-002 → C-COMP-002 → B-DATA-003 → C-TRUST-002 | Veri yaşam döngüsü ve ülke otoritesi geri izlenebilir | Bekliyor |
| 07 | QA-014 gerçek arama yaşam döngüsü | B-MM-001 → A-MATCH-001 | Arama ekranı yalnız server-otoriteli phase gösteriyor | Bekliyor |
| 08 | QA-017 Global / Kendi Ülkem dikey dilimi | B-MM-002 → A-MATCH-003 → C-ANL-002 → A-HOME-001 | Scope izolasyonu, açık fallback ve telemetry doğrulandı | Bekliyor |
| 09 | QA-003 pending match teklif protokolü | B-MM-003 → A-MATCH-002 | Offer/countdown/accept/pass/requeue regresyonsuz | Bekliyor |
| 10 | Kalıcı mesaj idempotency ve outbox deneyimi | B-MSG-001 → A-FRIEND-003 | Retry/duplicate/offline davranışı güvenilir | Bekliyor |
| 11 | Tek kullanımlık medya, moderasyon ve sohbet güven aksiyonları | B-MSG-002 → C-TRUST-001 → A-FRIEND-002 → A-FRIEND-003 (medya kapanışı) | Medya ve rapor/engel kanıt zinciri tutarlı | Bekliyor |
| 12 | Legal reaccept, session recovery ve hesap yüzeyleri | C-LEGAL-001 → B-AUTH-002 → A-AUTH-002 → A-HOME-002 | Legal sürümden client sonucuna uçtan uca kanıt | Bekliyor |
| 13 | Locale, bildirim ve TalkX Sistem iletişimi | B-I18N-001 → A-I18N-001 → C-NOTIFY-001 → B-SYS-001 → C-SYS-001 → A-SYS-001 | TR/EN fallback, recipient ve kalıcı inbox teslimi doğrulandı | Bekliyor |
| 14 | Davranış analitiği, dashboard ve aktivite özeti | B-ANL-001 → C-ANL-001 → C-ADMIN-002 → C-ADMIN-003 | Admin özetleri kaynak/zaman penceresine geri izlenebilir | Bekliyor |
| 15 | Profil ve uygulama raporu operasyon ekranları | C-ADMIN-004 → C-ADMIN-005 → C-ADMIN-006 | Liste/detay/rapor yetki ve veri durumlarıyla doğrulandı | Bekliyor |
| 16 | QA-016 Release Health | B-OBS-002 → C-REL-001 | Release kimliği, ingestion, redaction ve karar özeti kanıtlı | Bekliyor |
| 17 | Client/backend test kapıları ve ortak CI zinciri | A-QA-001 → B-QA-001 → C-CI-001 | Lint/test/build/audit kapıları tekrar üretilebilir | Bekliyor |
| 18 | Android release zinciri ve WebView davranış eşliği | C-MOB-001 → A-MOB-001 | Version/build/signing/sync ve cihaz davranışı kanıtlı | Bekliyor |
| 19 | Bütünleşik admin, operasyon ve release QA kapanışı | C-QA-001 | QA matrisi, manuel kanıt ve kullanıcı onayı tamam | Bekliyor |

## 6.1 Plan katılım ve sahiplik matrisi

Bu matris her wave'in hangi kalıcı planlardan iş aldığını görünür kılar. Bir wave birden fazla planı birleştirebilir; stable ID'nin ayrıntı ve kabul kriteri sahipliği her zaman kendi canonical planında kalır.

| Wave | Plan A — Product & Client | Plan B — Platform, Realtime & Data | Plan C — Admin, Trust & Release | Birincil teslimat ekseni |
|---:|---|---|---|---|
| 01 | A-PRD-001 | B-SEC-001 | C-COMP-001 | Çapraz-plan ürün/güvenlik/uyum temeli |
| 02 | — | B-API-001, B-AUTH-001, B-OBS-001, B-SEC-002, B-WS-001 | C-ADMIN-001 | Platform ve erişim temeli |
| 03 | A-FND-001, A-FND-002, A-A11Y-001, A-AUTH-001 | — | — | Client temeli |
| 04 | — | B-API-002, B-ANL-002, B-DB-001 | C-PERF-001, C-OPS-001, C-OPS-002 | Platform ve operasyon |
| 05 | A-MATCH-004, A-FRIEND-001, A-PRD-002 | B-WS-002, B-PRES-001 | — | Realtime ve client recovery |
| 06 | — | B-DATA-001, B-DATA-002, B-DATA-003 | C-COMP-002, C-TRUST-002 | Veri yaşam döngüsü ve uyum |
| 07 | A-MATCH-001 | B-MM-001 | — | QA-014 arama yaşam döngüsü |
| 08 | A-MATCH-003, A-HOME-001 | B-MM-002 | C-ANL-002 | QA-017 Global / Kendi Ülkem |
| 09 | A-MATCH-002 | B-MM-003 | — | QA-003 eşleşme teklifi |
| 10 | A-FRIEND-003 | B-MSG-001 | — | Kalıcı mesaj güvenilirliği |
| 11 | A-FRIEND-002, A-FRIEND-003 (medya kapanışı) | B-MSG-002 | C-TRUST-001 | Medya ve sohbet güveni |
| 12 | A-AUTH-002, A-HOME-002 | B-AUTH-002 | C-LEGAL-001 | Legal ve hesap yüzeyleri |
| 13 | A-I18N-001, A-SYS-001 | B-I18N-001, B-SYS-001 | C-NOTIFY-001, C-SYS-001 | Sistem iletişimi |
| 14 | — | B-ANL-001 | C-ANL-001, C-ADMIN-002, C-ADMIN-003 | Analitik ve admin özetleri |
| 15 | — | — | C-ADMIN-004, C-ADMIN-005, C-ADMIN-006 | Admin operasyon ekranları |
| 16 | — | B-OBS-002 | C-REL-001 | Release Health |
| 17 | A-QA-001 | B-QA-001 | C-CI-001 | Ortak kalite ve CI kapıları |
| 18 | A-MOB-001 | — | C-MOB-001 | Android release zinciri |
| 19 | — | — | C-QA-001 | Bütünleşik son QA |

| Plan | Stable ID | Katıldığı wave sayısı | Wave'ler |
|---|---:|---:|---|
| Plan A | 20 | 12 | 01, 03, 05, 07–13, 17–18 |
| Plan B | 25 | 15 | 01–02, 04–14, 16–17 |
| Plan C | 22 | 14 | 01–02, 04, 06, 08, 11–19 |
| **Toplam** | **67** | **19 wave** | Her stable ID tek wave'de |

## 7. Wave sınırları

| Wave | Giriş kapısı | Özellikle dâhil değil |
|---:|---|---|
| 01 | Açık Wave 01 yetkisi ve aktif Wave Plan | API/auth uygulaması, UI refactor, deploy |
| 02 | Wave 01 committed + açık Wave 02 yetkisi | Reconnect, matchmaking, migration, admin görev ekranları |
| 03 | Wave 02 committed + açık Wave 03 yetkisi | Match/search işlevi, geniş design-system ve Android release |
| 04 | Wave 03 committed + açık Wave 04 yetkisi | Açık yetkisiz canlı DB, cutover, restart veya deploy |
| 05 | Wave 04 committed + açık Wave 05 yetkisi | Match scope, offer protokolü ve distributed mimari |
| 06 | Wave 05 committed + açık Wave 06 yetkisi | Partition queue ve Global/Country selector UI |
| 07 | Wave 06 committed + açık Wave 07 yetkisi | Country scope, fallback ve QA-003 offer |
| 08 | Wave 07 committed + açık Wave 08 yetkisi | Manuel ülke, canlı havuz sayısı ve yeni match filtresi |
| 09 | Wave 08 committed + açık Wave 09 yetkisi | QA-003 içine scope kontrolü veya peer konumu |
| 10 | Wave 09 committed + açık Wave 10 yetkisi | Tek kullanımlık medya ve moderasyon |
| 11 | Wave 10 committed + açık Wave 11 yetkisi | Yeni medya özelliği, toplu moderasyon ve yetkisiz destructive işlem |
| 12 | Wave 11 committed + açık Wave 12 yetkisi | Gelişmiş legal publishing, yetkisiz production publish veya gerçek hesap silme |
| 13 | Wave 12 committed + açık Wave 13 yetkisi | System campaign/inbox platformu ve yetkisiz canlı bildirim |
| 14 | Wave 13 committed + açık Wave 14 yetkisi | Gelişmiş behavior analytics, tahmine dayalı AI özeti ve kaynaksız metrik |
| 15 | Wave 14 committed + açık Wave 15 yetkisi | Yetkisiz hassas veri açma, enterprise console veya toplu canlı aksiyon |
| 16 | Wave 15 committed + açık Wave 16 PAS kaydı yetkisi | Release Health implementasyonu; kapsam roadmap'e kaydedilir |
| 17 | Wave 16 deferred kaydı committed + açık Wave 17 yetkisi | Enterprise test matrisi ve otomatik Wave 18 geçişi |
| 18 | Wave 17 committed + açık Wave 18 yetkisi | Yetkisiz mağaza yayını veya production rollout |
| 19 | Wave 18 committed + açık Wave 19 yetkisi | Fikir Parkı, yeni özellik veya yeni ürün dönemi |

Bir wave'in ayrıntılı otomatik ve manuel kanıt listesi hazırlanmış `waves/TALKX_WAVE_NN.md` içinde ilgili Plan refs kabul kriterlerine bağlanır; liste ancak açık başlangıç talimatıyla uygulanır.

## 8. Stable ID kapsama özeti

| Plan | ID sayısı | Wave dağılımı |
|---|---:|---|
| Plan A | 20 | 01, 03, 05, 07–13, 17–18 |
| Plan B | 25 | 01–02, 04–14, 16–17 |
| Plan C | 22 | 01–02, 04, 06, 08, 11–19 |
| **Toplam** | **67** | Her ID tam bir kez |

Her stable ID'nin canonical planda tek tanımı, bu haritada tek wave sahibi ve önceki ya da aynı wave içinde daha önce sıralanmış bağımlılığı bulunmalıdır.

## 9. Wave Plan hazırlık ve aktivasyon sözleşmesi

Kullanıcı belirli bir wave için planlama aşamasına geçilmesini açıkça istediğinde ilgili `waves/TALKX_WAVE_NN.md` yalnız o wave için hazırlanır veya güncellenir:

1. Wave numarası, adı ve durum
2. Sıralı Plan refs ve kabul kriteri aralıkları
3. Repo/dosya etki alanı
4. Açıkça dâhil olmayanlar
5. Başlangıç ve bağımlılık doğrulaması
6. Uygulama adımları
7. Otomatik test kapıları
8. Checkpoint/Wave 19 havuzuna taşınacak manuel QA adımları
9. Risk, rollback ve canlı işlem yetkileri
10. Sonuç/evidence
11. Otomatik kapanış, commit ve ertelenmiş manuel QA kaydı
12. “Sonraki wave başlatılmadı” koruması

Wave Planın hazırlanması tek başına uygulama yetkisi değildir. Wave ancak kullanıcı ayrıca açıkça başlattığında `Aktif` olur.

## 10. Açılış ve kapanış protokolü

### Açılış

- Önceki wave **AUTO-VERIFIED / COMMITTED / MANUAL-QA-DEFERRED** veya **QA kapalı** değilse yeni wave açılmaz.
- Kullanıcı açıkça wave numarasını başlatır.
- Canonical Plan refs ve mevcut repo gerçeği yeniden doğrulanır.
- Hazırlanmış `waves/TALKX_WAVE_NN.md`, canonical Plan refs ve güncel repo gerçeğiyle yeniden doğrulanır.
- Kapsam ve dâhil olmayanlar uygulamadan önce kilitlenir.

### Uygulama

- Yalnız aktif wave dosyaları ve kabul kriterleri ele alınır.
- Beklenmeyen karar ihtiyacında uygulama durur.
- Canlı veya geri döndürülemez işlem ayrıca açıkça yetkilendirilir.
- Sonraki wave için uygulama veya kod/test hazırlığı yapılmaz; ayrı plan belgesi yalnız açık planlama talimatıyla hazırlanabilir.

### Kapanış

- Zorunlu otomatik kanıt kaydedilir; başarısız kapı varsa commit alınmaz ve wave bloke edilir.
- Sale Release scope'u tek wave commit'iyle kapatılır; commit kimliği sonuç alanına yazılır.
- Manuel QA maddeleri checkpoint/Wave 19 havuzuna aktarılır; Wave 01–18'de kullanıcı manuel QA onayı aranmaz.
- Plan A/B/C checkbox'ları yalnız kanıt kadar güncellenir.
- Wave Map ve aktif Wave Plan sonucu senkronize edilir.
- Canonical planlar roadmap/deferred kapsamını korur; kanıtlanmayan kriterler açık kalır.
- Sonraki wave yalnız `Bekliyor` kalır.

## 10.1 Toplu manuel QA checkpoint modeli

- **Checkpoint A — Core (Wave 01–06):** auth/security, reconnect/presence, account/data lifecycle, DB/deploy smoke.
- **Checkpoint B — Product (Wave 07–15):** Global/Country, search, offer, chat, friend DM, media, report/block ve admin operasyonları.
- **Checkpoint C — Release (Wave 17–19):** CI, Android gerçek cihaz, production-readiness ve tam regression.
- Checkpoint'ler kullanıcı uygun olduğunda toplu çalıştırılır. Yapılmamış checkpoint, otomatik kapıları geçmiş tekil wave'in commit edilmesini engellemez.
- Wave 19 tüm açık manuel QA maddelerinin terminal **Sale Acceptance QA + freeze** kapısıdır.

## 11. Harita değişiklik kuralı

Yeni kanıt bir bağımlılığın yanlış olduğunu gösterirse wave durur; ilgili canonical plan, bu harita ve kapsama doğrulaması güncellenir. Etki kullanıcıya açıklanmadan ve ayrı devam talimatı alınmadan uygulama sürdürülmez.

## 12. Hazırlık tanımı

Bu harita ancak 67 stable ID tam ve benzersiz dağıtılmış, bütün bağımlılıklar ileri/aynı-wave sırasıyla uyumlu, QA-001–017 sahiplikleri korunmuş, QA-017 sırası Master ile uyumlu ve riskli işlem sınırları görünür olduğunda hazırdır.

**Mevcut sonuç:** Wave Map hazırdır. Wave 01 Sale Release kapsamı auto-verified olup ayrı backend/frontend commitleriyle kapanışa hazırdır; manuel QA Checkpoint A / Wave 19'a ertelenmiştir. Aktif wave yoktur ve Wave 02 başlatılmamıştır.
