# TalkX Wave 14 Plan — Davranış Analitiği, Dashboard ve Aktivite Özeti

> Bu belge yalnız Wave 14 için hazırlanmış uygulama planıdır.
> Canonical uygulama sırası Plan B `B-ANL-001` → Plan C `C-ANL-001` → Plan C `C-ADMIN-002` → Plan C `C-ADMIN-003` şeklindedir.
> Ana ilke: yönetici ham event hacmini değil, tanımlı ölçüm birimleriyle hesaplanmış kullanıcı sonucunu görür; her özet aynı filtre ve tanım sürümüyle ham kanıta geri izlenir.
> Plan hazırdır. Wave 14 aktif değildir, Wave 01–13 kapanmamıştır ve uygulama başlamamıştır. Wave 15 planı ayrı talimatla hazırlanmıştır; aktif değildir ve burada uygulanmaz.

## 1. Durum ve yürütme sınırı

- **Wave:** 14
- **Wave adı:** Davranış analitiği, dashboard ve aktivite özeti
- **Plan katılımı:** Plan B + Plan C
- **Canonical sıra:** `B-ANL-001 → C-ANL-001 → C-ADMIN-002 → C-ADMIN-003`
- **Plan durumu:** Hazır
- **Wave durumu:** Bekliyor
- **Uygulama durumu:** Başlamadı
- **Uygulama yetkisi:** Verilmedi
- **Giriş kapısı:** Wave 13 `QA kapalı` ve kullanıcıdan açık "Wave 14'ü başlat" talimatı
- **Mevcut blokaj:** Wave 01–13 uygulanıp kapanmadı; Wave 14 uygulanamaz
- **Önceki wave:** Wave 13 — planı hazır, aktif değil
- **Sonraki wave:** Wave 15 — planı ayrı talimatla hazırlandı; aktif değil ve başlatılmadı

Bu dosyanın hazırlanması Wave 14 aktivasyonu, kod/test/dependency değişikliği, migration, canlı DB sorgusu, production analytics export'u, hassas kullanıcı izi açma, feature flag, deploy veya Wave 15 aktivasyonu/uygulaması için yetki değildir.

## 2. Canonical referanslar ve otorite

1. `B-ANL-001` — stable event envelope, ölçüm birimleri, ordered funnel, dedupe, pencere ve event story veri sözleşmesi
2. `C-ANL-001` — Master QA-012 karar odaklı Davranış Analitiği bilgi mimarisi
3. `C-ADMIN-002` — Master QA-004 Dashboard genel bakış ve sistem sağlığı
4. `C-ADMIN-003` — Master QA-005 Dashboard aktivite özeti
5. Master `QA-012`, `QA-004` ve `QA-005` kabul kriterleri
6. Wave 02 `B-API-001/B-AUTH-001/B-OBS-001/C-ADMIN-001` — API, güvenli log ve admin erişim temeli
7. Wave 04 `B-API-002/B-ANL-002/C-PERF-001` — health/performance sözleşmesi ve karar özeti
8. Wave 05–13 — journey kimliklerinin üretildiği reconnect, match, message, trust, legal ve Sistem iletişimi sözleşmeleri
9. Wave 06 `B-DATA-001/B-DATA-003/C-COMP-002` — retention, hesap silme, privacy ve admin veri amacı
10. Wave 08 `B-MM-002/C-ANL-002` — requested/effective scope, country ve fallback telemetry anlamı
11. Wave 16 `B-OBS-002/C-REL-001` — gelecekteki Release Health sağlayıcısı; Wave 14 bu veriyi üretmez
12. `A-A11Y-001/A-I18N-001/C-CI-001` — erişilebilirlik, TR/EN etiket ve kalite kapıları

Çelişki çözümü:

- Bağımsız event toplamları ordered funnel sayılmaz.
- İki `match_offer_received` tek `matchId` için bir match; iki `chat_started` tek `conversationId` için bir conversation'dır.
- Kabul/red/auto-accept katılımcı kararıdır; match'in nihai sonucu değildir.
- Dashboard, Analytics araştırma ayrıntısını kopyalamaz; source/time/confidence taşıyan kısa sonuç ve detay aksiyonu sunar.
- Wave 04 performance özeti tüketilir; yeni SLO tanımı icat edilmez.
- Wave 16 verisi yokken Release Health kartı `not_available/provider_pending` gösterir; yeşil veya `0 hata` uydurmaz.
- Deterministik Jarvis cümlesi yalnız sözleşmedeki sayıları özetler; AI tahmini ve kaynaksız kök neden üretmez.
- Ham mesaj, prompt, fotoğraf, token, tam IP veya gereksiz PII analitiğe taşınmaz.

## 3. Wave sonucu

Wave 14 sonunda:

- `person`, `session`, `searchAttempt`, `match`, `conversation` ve `event` birimleri ayrılacak.
- Event envelope schema version, stable identity, server zamanı, ilişki kimlikleri, platform/locale/release ve sanitize metadata taşıyacak.
- Retry/reconnect/çift callback duplicate'leri belgelenmiş idempotency kuralıyla tekilleştirilecek.
- Ordered user funnel ve match funnel ayrı hesaplanacak; diagnostic totals açık etiketlenecek.
- Cohort başlangıcı, takip süresi, pencere sınırı, late arrival ve eksik telemetry davranışı açık olacak.
- Tek match ve conversation katılımcı event sayısından bağımsız bir kez sayılacak.
- Önceki dönem eşit süre ve aynı filtre/tanım sürümüyle karşılaştırılacak; baseline yoksa sahte yüzde olmayacak.
- Low sample, partial, stale, telemetry gap ve no-data ayrı güven durumları taşıyacak.
- Analytics `Özet`, `Yolculuklar` ve bilinçli aksiyonla `Ham Kanıt` katmanlarını sunacak.
- Yönetici beş saniyede ana dönüşümü, en büyük kaybı, dönem farkını, güveni ve inceleme aksiyonunu bulacak.
- Match/conversation araması kararları, nihai sonucu, süreyi, bitiş nedenini ve eksik eventleri tek hikâyede gösterecek.
- Bölümler bağımsız yüklenecek; tek endpoint hatası sağlam bölümleri kapatmayacak.
- Dashboard `Genel Bakış`, `Sistem Sağlığı` ve `Push Teslimatı` katmanlarına ayrılacak.
- Dashboard aktivitesi az KPI, okunabilir grafik ve kısa olay önizlemesi olacak; ham detay bilinçli eylem isteyecek.
- Desktop, tablet, 320 px mobil, klavye, ekran okuyucu, partial endpoint ve hassas veri QA'i kanıtlanacak.
- Wave 15 başlamayacak.

## 4. Doğrulanmış başlangıç fotoğrafı

### 4.1 Event storage ve ingestion

- `behavior_events` bugün event/user/client/device/platform/match/conversation/metadata/created_at taşıyor.
- Event ID DB insert sırasında oluşuyor; producer idempotency key veya semantic unique constraint görünmüyor.
- Schema version, search/session/release, client occurred time, received time ve dedupe sonucu ayrı sözleşme değil.
- Metadata sanitizer uzunluk sınırı uyguluyor fakat event-bazlı allowlist ve hassas alan sınıfı sunmuyor.
- `trackBehaviorEvent` fire-and-forget insert yapıyor; başarısızlık coverage/telemetry health özeti üretmiyor.
- Plan aşamasında tabloya migration veya production sorgusu yapılmadı.

### 4.2 Sayım riski

- `match_offer_received` ve `chat_started` her katılımcı için ayrı kaydediliyor.
- Mevcut overview bu alanlarda `COUNT(*)` kullanıyor; ürün sonucu gibi gösterilirse ikiye katlama riski var.
- Accept/reject/auto-accept participant kararı; match-level final outcome belirgin değil.
- `match_search_attempt` stable search/attempt ID taşımıyor; tekrarlar güvenilir ayrılmayabilir.
- Event story bütünlüğü, tek final sonuç ve eksik-event işareti endpointte birleştirilmiyor.

### 4.3 Analytics API ve UI

- `/analytics/overview` kişi ve event birimlerini aynı metrics nesnesinde karıştırıyor.
- `/analytics/funnel` bağımsız distinct user eventlerini sayıyor; sıralı/cohort funnel değil.
- `/analytics/timeseries` boş bucketları sıfırla dolduruyor, match/chat için raw event sayıyor.
- `/analytics/recent` sabit limitte raw event/metadata döndürüyor; cursor yok.
- `renderAnalyticsView` filtre, sekiz KPI, funnel, saatlik tablo, dağılımlar, user tablosu ve raw akışı tek sayfaya yığıyor.
- `loadAnalyticsTab` beş endpointi `Promise.all` ile bağlıyor; biri hata verince bütün ekran düşüyor.
- Missing data `0/0%` gibi görünebiliyor; match/conversation story lookup yok.

### 4.4 Dashboard ve repo sınırı

- Stats, push health, push diagnostics ve performance ayrı isteklerle yükleniyor; ortak freshness/partial contract yok.
- Bazı hatalar `-` veya `-%` oluyor; koşulsuz renk health semantiği riski var.
- QA-005 aktivite alanı ham saatlik tablo ve iç scroll ile özet ekranını uzatıyor.
- Release Health Wave 16 sağlayıcısı henüz yok; Wave 14 sağlıklı release sonucu uyduramaz.
- Root repo geniş silinmiş/untracked kullanıcı içeriği taşıyor; korunur ve legacy `backend/`/`frontend/` durumuna dokunulmaz.
- Plan aşamasında production event/user/device/match/conversation verisi sorgulanmaz veya export edilmez.

## 5. Ölçüm sözlüğü — B-ANL-001

### 5.1 Değişmez ölçüm birimleri

| Birim | Stable anahtar | Ne sayılır | Ne sayılmaz |
|---|---|---|---|
| Person | pseudonymous `userId` | Cohort içindeki tekil hesap | Event veya connection toplamı |
| Session | `sessionId` | Authenticated uygulama oturumu | Reconnect başına yeni kullanıcı |
| Search attempt | `searchId/attemptId` | Server'ın kabul ettiği tek arama yaşam döngüsü | Retry join komutları |
| Match | `matchId` | İki tarafı ve tek final sonucu olan teklif | İki participant offer eventi |
| Conversation | `conversationId` | Oluşturulan tek anonim sohbet | İki participant start eventi |
| Event | `eventId` | Tek telemetry kaydı | Ürün sonucu veya kullanıcı |

Her API alanı `unit`, `definitionKey` ve `definitionVersion` taşır; farklı birimler sessizce aynı dönüşümde kullanılmaz.

### 5.2 Stable event envelope

Her yeni veya normalize event en az şunları taşır:

- `eventId`, `eventName`, `schemaVersion`
- `serverOccurredAt`, uygun olduğunda `clientOccurredAt`, ayrıca `receivedAt/persistedAt`
- `userId/sessionId/clientId/deviceId`
- `searchId/matchId/conversationId`
- `participantRole/actorType`
- `platform/locale/releaseId/environment`
- sürümlü `result/reasonCode/trigger`
- event-bazlı allowlist `metadata`
- `dedupeKey/producer/definitionVersion`

Unknown enum yeni cardinality üretmez; kontrollü `unknown` ve tanısal neden kullanır. Client yalnız görüntüleme/etkileşim sinyali üretir; queue, match ve conversation sonucu server otoritelidir.

### 5.3 Event kataloğu ve sahiplik

- Her event için producer, authoritative moment, zorunlu ID, unit, reason allowlist, retention sınıfı ve consumer tek katalogda bulunur.
- Aynı karar hem client hem server eventinden sayılmaz; primary ve diagnostic source ayrılır.
- Wave 07-09 search/match, Wave 10-11 conversation/message, Wave 13 campaign/recipient kimliğini sağlar.
- Eski event yeni anlama sessizce çevrilmez; `legacy/insufficient_identity` olarak coverage'a girer.
- Event rename definition version eşlemesi olmadan uygulanmaz.

### 5.4 Dedupe ve idempotency

1. **Exact duplicate:** Aynı `eventId/dedupeKey` yalnız bir kez persist edilir.
2. **Semantic duplicate:** Aynı authoritative command/result ve relation ID ürün metriğine bir kez katılır.

- Retry/reconnect yeni relation yaratmadıysa yeni ürün sonucu sayılmaz.
- İki participant kararı duplicate değildir; ikisi korunur, match aggregate tek sonuç verir.
- Aynı participant karar tekrarı stable identity ile tekilleştirilir.
- Çelişkili duplicate `telemetry_conflict` olur; sessiz son-yazan-kazan yoktur.
- Dedupe süresi yerine relation identity ve authoritative state tercih edilir.
- Dedupe/çatışma sayıları coverage diagnostics içinde izlenir.

### 5.5 Zaman, pencere ve timezone

- Canonical zaman `serverOccurredAt`; legacy fallback confidence düşürür.
- Pencereler yarı açık `[from,to)`; response timezone'u açık yazar.
- Previous period tam eşit süre ve aynı filtreleri kullanır.
- Client clock skew ölçülür; client zamanı tek otorite değildir.
- Late arrival, takip süresi ve rollup revision policy sürümlüdür.
- Takip süresi dolmayan journey `in_progress`; dolmuş eksik journey `incomplete` olur.
- Definition revision sonrası değişen rollup `recalculatedAt` taşır.

### 5.6 Ordered cohort funnel

User funnel örneği:

`connected → search_started → queue_confirmed/offer_created → participant_decision → match_finalized → conversation_created/chat_started`

Match funnel örneği:

`offer_created → participant_outcomes → final_outcome → conversation_created → chat_started → chat_ended`

- Funnel pencere içinde başlayan cohort'a anchor edilir.
- Her transition izinli predecessor, maksimum takip süresi ve terminal sonuç taşır.
- Missing predecessor veya out-of-order event adıma eklenmez; coverage warning'e gider.
- Her adım previous-step conversion, loss ve eligible denominator gösterir.
- Bağımsız distinct totals yalnız diagnostic alandadır.
- Bir kullanıcı birden çok attempt yapabilir; user ve attempt funnel ayrıdır.
- Follow-up süresini aşan sonuç cohort'u sessizce değiştirmez.
- Definition version değişirse geçmiş/yeni seri tek funnel gibi sunulmaz.

### 5.7 Match ve conversation aggregate

Match `matchId` ile offer time, iki participant kararı, final result ve finalization time taşır. Final result server otoriteli `accepted/rejected/timeout/cancelled/peer_left/server_error/incomplete` enumudur. Auto-accept sonuç değil karar yöntemidir.

Conversation `conversationId` ile bağlı match, created/started/ended time, duration, end reason ve telemetry completeness taşır. Participant eventleri tek conversation sonucuna katlanır; mesaj içeriği tutulmaz. Eksik veya çelişkili relation normal başarı gibi sayılmaz.

### 5.8 Previous period ve confidence

Her özet current, previous ve delta'yı aynı definition/filter üzerinden verir. Baseline yoksa `baseline_unavailable`; `0%` veya sonsuz artış uydurmaz. Count, denominator ve coverage birlikte taşınır.

Confidence: `sufficient|low_sample|partial|stale|telemetry_gap|not_available`. Reason ve owner-configured threshold revision response'tadır. Eşik belirlenmemişse `unknown/not_configured`; plan keyfi örnek eşiği kilitlemez.

### 5.9 Reconciliation ve provenance

Her response source, window, filters, definitionVersion, calculatedAt, dataThrough, freshness, sampleSize, coverage, confidence ve evidenceRef taşır. Overview, funnel, trend, journey ve evidence aynı relation tanımlarını tüketir. Fark varsa `reconciliationStatus` ve insan tarafından okunur neden görünürdür.

### 5.10 Retention ve privacy

- Event amacı, saklama süresi ve erişim rolü catalog'da tanımlıdır.
- Tam mesaj/prompt/support içeriği/fotoğraf/token/password/IP analitiğe girmez.
- User/device/client kimlikleri yetkili ham kanıtta maskeli ve audit kontrollüdür.
- Export varsayılan kapalı; permission, re-auth, kolon/satır limiti, expiry ve audit ister.
- Account deletion/retention Wave 06 politikasını uygular.
- Analytics hata logu payload/metadata'yı düz metin dökmez.

## 6. Analytics API sözleşmesi — B-ANL-001 → C-ANL-001

### 6.1 Logical endpoint katmanları

- `GET /admin/analytics/summary` — dört ana sonuç, deterministic insight, biggest loss, previous period ve confidence
- `GET /admin/analytics/funnels` — seçilen unit/definition için ordered steps
- `GET /admin/analytics/trends` — aynı tanımlı serilerin bucketları
- `GET /admin/analytics/journeys` — cursor ve sonuç filtresiyle story listesi
- `GET /admin/analytics/journeys/:journeyKey` — tek match/conversation hikâyesi
- `GET /admin/analytics/evidence` — yetkili, maskeli, cursor'lı teknik kanıt
- `GET /admin/analytics/definitions` — unit/event/reason/threshold/label sürümleri

Mevcut `overview/funnel/timeseries/users/recent` route'ları bir anda silinmez; adapter veya sürümlü deprecation takvimi kullanılır.

### 6.2 Ortak query ve response

Query allowlist'i from/to veya preset, timezone, platform, locale, release, unit, definitionVersion, result/reason, exact match/conversation/user ref ve cursor/limit alanlarını kapsar. Geçersiz filtre stable `400` code; time range ve limit hard cap taşır.

Response data, window, filters, definitionVersion, source/dataThrough, freshness, confidence/sample/reason, reconciliation/evidenceRef ve warnings taşır. Alan yokluğu ile sayısal sıfır ayrıdır; gerçek sıfır yalnız başarılı ve yeterli kapsamlı sorguda `0` olur.

### 6.3 Deterministic insight contract

- Ana unit ve denominator açık olur.
- Biggest loss yalnız eligible ordered transitionlar arasından seçilir.
- Delta yalnız comparable baseline varsa yazılır.
- Low sample/partial/stale cümleyi yumuşatır.
- Kök neden yalnız reason distribution kanıtlıysa söylenir.
- Telemetry eksikse `Ölçülmüyor/Kanıt yetersiz` denir.
- Action stable key/deep-link'tir.

LLM, serbest prompt veya olasılıksal yorum Wave 14'e girmez.

### 6.4 Partial failure, pagination ve maliyet

- Summary/funnel/trend/journeys/evidence bağımsız request/state taşır.
- Bir `5xx` diğer başarılı bölümleri kapatmaz; retry yalnız sorunlu bölümü çağırır.
- Refresh eski sonucu `refreshing/stale` etiketiyle korur.
- Filter revision değişirse eski response render edilmez.
- Aborted request hata toast'ına dönüşmez.
- Journey/evidence cursor stable `(serverOccurredAt,eventId)` sırası kullanır.
- Query cap/index/EXPLAIN ile doğrulanır; rollup raw reconciliation olmadan otorite olmaz.
- Cache key filtre, timezone ve definition version'ı içerir.

## 7. Davranış Analitiği bilgi mimarisi — C-ANL-001

### 7.1 Üç katman

1. **Özet:** varsayılan; sonuç, biggest loss, ordered funnel ve sade trend
2. **Yolculuklar:** match/conversation bazlı story ve sonuç filtreleri
3. **Ham Kanıt:** yetkili teknik detay, diagnostic totals ve cursor'lı eventler

Filtre context'i katmanlar arasında korunur; Ham Kanıt varsayılan sekme değildir.

### 7.2 Özet yerleşimi

İlk viewport sırası:

- Başlık, son başarılı yenileme, freshness ve confidence
- Basit zaman penceresi ve platform filtresi
- İnsan dilinde aktif filter summary ve temizleme
- Tek deterministic Jarvis cümlesi
- En fazla dört unit-labeled KPI: aktif kişi, attempt, gerçek match, benzersiz conversation
- Biggest loss ve `Yolculukları incele` aksiyonu
- Ordered funnel
- Sade trend

Özel tarih, timezone, locale, release, unit ve ID araması Gelişmiş filtrelerdedir. Her KPI değer veya `Veri yok/Ölçülmüyor`, unit, window, delta/baseline reason, confidence, source/freshness ve evidence action taşır.

### 7.3 Funnel ve trend

- Funnel tek unit'i, cohort/follow-up kuralını ve previous-step conversion/loss'u açıklar.
- Missing/out-of-order toplamı normal adımlara eklenmez.
- Biggest loss tek vurgudur; bilgi yalnız renkle taşınmaz.
- Trend varsayılan tek seri ve açık metric selector kullanır.
- Farklı unit aynı axis'te sessiz birleşmez.
- No-data boşluğu çizgiyle doldurulmaz; true zero ayrıdır.
- Tooltip exact time/timezone/value/unit/sample/confidence taşır.
- Önceki dönem yalnız comparable ise gösterilir.
- Sinyal seçimi aynı filtreyle journeys görünümünü açar.

### 7.4 Journey listesi ve hikâye

Her journey önce ne oldu, hangi relation, ne zaman, participant kararları, final outcome/reason, platform/scope/locale/release ve telemetry completeness sorularını cevaplar. Exact match/conversation search tek story açar.

Story omurgası:

1. Search attempt oluşturuldu
2. Queue server tarafından onaylandı
3. Offer/match oluşturuldu
4. Participant kararları geldi
5. Match final sonucu kesinleşti
6. Conversation oluşturuldu/başladı
7. Conversation bitti ve reason kaydedildi

Eksik/sıra dışı adım warning'dir; başarı gibi tamamlanmaz. `Teknik kanıtı aç` yalnız ilgili maskeli eventleri gösterir.

### 7.5 Ham Kanıt

- Event/platform/user diagnostic tabloları bu katmandadır.
- Teknik ad yanında central TR/EN insan etiketi bulunur.
- Metadata önce allowlist özeti; JSON yalnız kontrollü advanced detail.
- Server cursor, limit ve filtre görünür.
- `Gösterilen N kayıt; daha fazlası var/yok` dürüstçe yazılır.
- Export yalnız izin/policy varsa auditli ve kolon allowlist ile açılır.
- Masked ID ile full ID yetkisi ayrılır.

### 7.6 Durum ve filtre state'i

`No events`, `no baseline`, `low sample`, `partial`, `stale`, `telemetry gap`, `unauthorized` ve `error` ayrıdır. URL yalnız allowlist filtre taşır; hassas full ID paylaşılmaz. Draft/apply tek atomik filter revision üretir. Back/forward görünümü geri kurar. Mobile filter sheet focus trap, escape/back ve focus return sağlar.

## 8. Dashboard genel bakış — C-ADMIN-002

### 8.1 Bilgi mimarisi

Dashboard üç ana bölümdür:

1. **Genel Bakış:** toplam kullanıcı, online, aktif sohbet, kullanıcı raporları 24s; uygulama raporu görünürlüğü korunur.
2. **Sistem Sağlığı:** backend/API, DB/readiness, performance, push ve Release Health kısa durumları.
3. **Push Teslimatı — Son 24 saat:** Firebase, project/credential source, device freshness, sent/failure/invalid ve top error.

Davranış araştırması Dashboard'a yığılmaz; `Davranış Analitiğine git` aksiyonuyla C-ANL-001'e bağlanır.

### 8.2 Dashboard veri manifesti

Her kart central manifestte şunları taşır:

- `cardKey`, label ve semantic icon
- source endpoint/provider
- metric field ve unit
- time window ve freshness policy
- normal/warning/critical/unknown evaluator
- permission ve detail route
- no-data/partial copy key
- last successful refresh

Korunacak bağlar:

- `/admin/stats`
- `/admin/push/health?minutes=60`
- `/admin/push/diagnostics?hours=24`
- `/admin/performance/overview?hours=1`
- QA-005 için `/admin/analytics/timeseries`
- QA-005 için `/admin/analytics/recent`

Route değişecekse compatibility adapter ve response comparison testi gerekir; silent metric removal kabul edilmez.

### 8.3 Health durum modeli

Durumlar: `normal`, `warning`, `critical`, `unknown`, `not_available`.

- Health yalnız documented threshold ve yeterli/taze sample ile değerlendirilir.
- P95/error threshold Wave 04 `B-ANL-002/C-PERF-001` sözleşmesinden gelir.
- DB/readiness, API performance, push config ve push delivery ayrı kart/state'tir.
- Bir servis critical olduğunda bütün sistemin her kartı kırmızı olmaz.
- Bilinmeyen veya stale sonuç yeşil gösterilmez.
- Renk yanında icon, label ve kısa neden bulunur.
- Threshold revision ve pencere detail'de görünür.

### 8.4 Refresh ve partial state

Dashboard refresh state'i:

`idle → refreshing → success | partial | failed`

- İlk load skeleton, refresh mevcut veriyi koruyan progress kullanır.
- Her provider kendi request/error/freshness state'ini taşır.
- Partial üst özette hangi bölümün eski/eksik olduğunu söyler.
- Retry yalnız başarısız provider'ı çağırabilir.
- Son başarılı yenileme ile son deneme zamanı ayrıdır.
- Eski veri stale etiketi olmadan canlı gibi bırakılmaz.
- Tek response gelince toplu `Canlı veriler` yazısı güncellenmez; gerekli provider state'leri değerlendirilir.

### 8.5 Release Health sağlayıcı sınırı

Wave 14 içinde:

- Dashboard manifestinde `release_health` provider slotu tanımlanır.
- Wave 16 `C-REL-001` uygulanana kadar kart `provider_pending/not_available` gösterir.
- `Release Health henüz bağlı değil` açıklaması insan dilindedir.
- `0 hata`, `sağlıklı`, yeşil badge veya previous-release farkı uydurulmaz.
- Gelecek provider `status/releaseId/window/dataThrough/confidence/topIssue/detailRoute` sağlar.
- Wave 16 bu slotu gerçek veriye bağlayıp C-ADMIN-002 entegrasyonunu final QA'da yeniden doğrular.

Bu sınır Wave 16 ingestion/rollup işini erken uygulamayı ve Dashboard'u sahte veriyle kapatmayı engeller.

### 8.6 Push teşhisi

- Firebase enabled/disabled, project ID ve credential source korunur.
- Aktif cihaz ile gönderim denemesi/başarısı/hatası aynı sayı değildir.
- Success rate sample count ve pencereyle görünür.
- Error yoksa sakin `Hata yok`; varsa code, count, severity ve detail.
- Uzun code wrap/truncate + accessible detail ile taşmaz.
- Init error ve delivery error ayrıdır.
- Hassas credential/token UI'a taşınmaz.

### 8.7 Responsive ve accessibility

- Desktop grid tam/yarım satır bırakmadan bilgi önceliğiyle akar.
- Tablet iki kolon; 320 px mobil tek kolon olur.
- Kart içeriği yatay taşmaz; alt bilgi okunabilir kalır.
- Anlamsız harf ikonları semantic iconlarla değiştirilir.
- Refresh/detail en az 44x44 px, visible focus ve accessible name taşır.
- Status yalnız renk değildir; reduced motion animasyonu sadeleştirir.

## 9. Dashboard aktivite özeti — C-ADMIN-003

### 9.1 Yerleşim

Dashboard alt alanı:

- başlık + aktif pencere
- en fazla 3-4 kısa aktivite KPI'sı
- tek ana trend grafiği ve metric selector
- sınırlı anlamlı recent activity satırı
- `Saatlik detayı gör` ve `Tüm aktiviteleri gör` aksiyonları

Ham saatlik tablo ve uzun event listesi varsayılan Dashboard'dan çıkar; Analytics Ham Kanıt veya kontrollü detail içinde açılır.

### 9.2 KPI ve grafik anlamı

- Kabul oranı denominator ve auto-accept dahil/ayrı kuralını definition'dan alır.
- Match/chat adetleri corrected units kullanır; participant event sayısını ürün sonucu diye göstermez.
- Grafik ve kartlar aynı from/to/timezone/platform/definition revision'ı kullanır.
- Selector unit değiştirince axis/tooltip/label birlikte güncellenir.
- Tek nokta, no-data, spike ve partial bucket yanıltıcı ölçek üretmez.
- Previous period yalnız comparable ve yeterli confidence ile gösterilir.

### 9.3 Recent activity

Her satır:

1. insan dilinde ne oldu
2. maskeli kullanıcı/journey bağlamı
3. göreli zaman + exact timestamp detail
4. platform
5. gerekiyorsa severity/telemetry warning

- Event label central TR/EN sözlükten gelir.
- Unknown event kontrollü teknik fallback kullanır.
- UUID ve raw metadata varsayılan satırda görünmez.
- Aynı journey'nin ardışık normal eventleri story/group olabilir.
- Telemetry gap/server error normal aktiviteden anlamla ayrılır.
- Uzun username/display name erişilebilir tam değerle güvenli kısalır.

### 9.4 Tek scroll ve detay

- Dashboard recent preview kendi dikey scrollbar'ını üretmez.
- Sayfa ana scroll ile akar; preview hard limit ve `Tümünü gör` kullanır.
- Drawer/modal focus trap, escape, back, focus return ve body scroll restore sağlar.
- Alternatif Analytics deep-link'i aynı filter penceresini korur.
- Raw table kontrollü yatay scroll kullanabilir; Dashboard içinde iç içe dikey scroll olmaz.

### 9.5 Veri bağının korunması

- Timeseries/recent compatibility veya adapter üzerinden korunur.
- Grafik toplamları source response ile uzlaşır.
- Recent preview limit'i bütün evren gibi sunulmaz.
- Endpointlerden biri hata verdiğinde diğeri görünür kalır.
- Loading/empty/partial/error/long name/missing name/bad metadata fixture'larla test edilir.

## 10. State mimarisi

### 10.1 Analytics page state

```text
filtersDraft → apply → filtersRevision
  ├─ summary
  ├─ funnel
  ├─ trend
  ├─ journeys
  └─ evidence
       each: idle/loading/refreshing/success/empty/stale/partial/error
```

- Response yalnız kendi filter revision'ına uygulanır.
- Tab değişimi başarılı section cache'ini gereksiz silmez.
- Journey detail'dan dönünce list cursor/scroll/filters korunur.
- Global error yalnız auth/shell gibi tüm ekranı geçersiz yapan durumda kullanılır.

### 10.2 Dashboard ve story state

Dashboard manifesti stats, readiness/performance, push health, push diagnostics, activity ve Wave 16'ya kadar pending Release Health state'lerini bağımsız birleştirir. Aggregate state provider sonucunu ezmez.

Story state'leri `complete|in_progress|incomplete|out_of_order|conflict|legacy_limited` olur; eksik hikâye başarıya çevrilmez.

## 11. Migration ve compatibility

### 11.1 Additive şema

Aktivasyonda gerekirse:

- behavior_events için schema/dedupe/session/search/release/time alanları additive migration ile eklenir
- event catalog/definition revision tablosu veya kod manifesti kurulur
- aggregate view/rollup yalnız ölçülmüş query ihtiyacında eklenir
- indexler gerçek `EXPLAIN` kanıtıyla seçilir
- migration down/forward-fix ve backfill dry-run hazırlanır

Plan dosyası migration çalıştırmaz.

### 11.2 Legacy event ve endpoint

- Stable ID'si olmayan eventler tahminle journey'ye bağlanmaz.
- Güvenle ilişkilendirilen backfill explicit version/source taşır.
- Diğerleri raw evidence/diagnostic totals içinde kalır ve confidence'ı etkiler.
- Backfill re-run idempotent ve count-reconciled olur.
- Eski admin route/field bir anda silinmez; adapter/deprecation kullanılır.
- Dashboard QA-005 geçişi karşılaştırma fixture'ı taşır.

### 11.3 Deploy sırası

1. Additive migration/index dry-run ve backup kararı
2. Producer compatibility ve shadow validation
3. New query contract admin-only flag arkasında
4. Old/new count reconciliation
5. Analytics Özet/Yolculuklar/Ham Kanıt UI
6. Dashboard genel bakış ve aktivite özeti
7. Canary admin doğrulaması
8. Eski path deprecation, yalnız kanıt ve açık onayla

Production migration, backfill, flag veya deploy ayrıca açık kullanıcı yetkisi ister.

## 12. Güvenlik, yetki ve audit

- Bütün endpointler Wave 02 admin auth/RBAC/CSRF standardını kullanır.
- Summary ile raw evidence aynı permission olmak zorunda değildir.
- Full user/device/client ID erişimi ayrı yetki ve audit gerektirir.
- Search exact/validated ve rate/cost cap'li olur.
- Export ayrı permission, re-auth, satır/kolon sınırı, expiry ve audit ister.
- Error SQL, stack, connection string veya raw metadata dökmez.
- Query loglarında hassas filtre redacted/hashed olur.
- Dashboard source/threshold/config detayı secret içermez.
- Deep-link URL'sine raw message/token/PII yazılmaz.

## 13. Dosya ve servis etki haritası

| Alan | Muhtemel hedef | Wave 14 işi | Sınır |
|---|---|---|---|
| DB şema | `chatapp-backend/db.js` veya migration alanı | Event identity/index additive değişimi | Canlı migration ayrı yetki |
| Event ingestion | `chatapp-backend/index.js` ve domain modülü | Catalog, IDs, dedupe, authoritative outcome | Match UX yeniden tasarımı yok |
| Analytics API | `chatapp-backend/admin.js` veya analytics modülü | Summary/funnel/trend/journey/evidence | Profil/rapor operasyonu yok |
| Admin UI | `chatapp-backend/admin.html` veya testli modüller | Analytics ve Dashboard IA/state | Yeni navigation ürünü yok |
| i18n | Admin TR/EN source | Event/status sözlüğü | Wave 13 locale motorunu kurma yok |
| Tests | Backend/admin focused fixture/test | Unit/integration/UI/a11y/reconciliation | Wave 17 ortak CI yok |
| Docs/assets | Contract/runbook/manual QA | Definition ve before/after evidence | Wave 15 uygulaması yok |

Exact file listesi aktivasyonda güncel repo incelemesiyle daraltılır; tablo dosya değiştirme yetkisi değildir.

## 14. Uygulama sırası

1. Giriş kapısı, kullanıcı yetkisi ve üç Git bağlamını doğrula.
2. Master QA-004/005/012 ve dört stable ID kriterini checklist'e sabitle.
3. Event catalog, unit, time/cohort/dedupe/retention kararlarını sürümlü contract yap.
4. Mevcut producer coverage ve relation ID boşluklarını fixture/test ile görünür kıl.
5. Gerekli additive migration/index/backfill planını dry-run/rollback ile hazırla; canlıya uygulama.
6. Exact/semantic dedupe ve authoritative match/conversation aggregate'lerini kur.
7. Ordered user/match funnel ve previous-period/confidence hesaplarını backendte kur.
8. Summary/trend/journey/evidence envelope ve reconciliation katmanını kur.
9. Existing endpoint adapter/compatibility testlerini tamamla.
10. Analytics UI'ı üç katmana böl; per-section state'i kur.
11. Journey search/story ve controlled raw evidence/pagination yüzeyini tamamla.
12. Dashboard manifest, source/time/freshness ve health state'lerini kur.
13. Release Health slotunu dürüst pending state ile sınırla.
14. Activity KPI/grafik/recent preview ve tek-scroll yapısını tamamla.
15. Security/privacy/audit, query cost ve export kapılarını test et.
16. Focused/full test, syntax/lint/build/encoding kapılarını çalıştır.
17. Desktop/mobile/a11y, endpoint comparison ve reconciliation kanıtını topla.
18. Checkbox'ları yalnız kanıt/onayla kapat; Wave 15'i başlatmadan dur.

## 15. Otomatik test planı

### 15.1 Event envelope ve privacy

- Zorunlu schema/version/ID/time alanları
- Event/reason/platform/locale/release allowlist
- Oversize/unknown/malformed metadata
- Message/prompt/token/IP/secret redaction
- Server/client time ve clock skew
- Producer retry ile stable eventId
- Insert failure telemetry davranışı

### 15.2 Dedupe ve ölçüm birimleri

- Aynı eventId iki kez → bir metric event
- Aynı search command retry → bir attempt
- İki participant offer event → bir match
- İki participant chat_started → bir conversation
- İki farklı participant kararı → iki decision, bir final match
- Reconnect aynı journey → yeni person/match değil
- Çelişkili duplicate → conflict warning

### 15.3 Ordered funnel

- Tam sıralı user journey
- Missing predecessor
- Out-of-order timestamps
- Window öncesinde başlayan journey
- Pencere içinde başlayıp follow-up'ta biten journey
- Takip süresi sonrası late event
- Aynı user çok attempt
- Reject/timeout/auto-accept/cancel/server error
- Definition version mismatch

### 15.4 Previous period ve confidence

- Eşit duration ve aynı filters
- Baseline missing → null/reason; sahte 0% yok
- Current true zero ile no-data ayrımı
- Low-sample threshold revision
- Partial source ve stale data
- Telemetry coverage gap
- Summary/funnel/trend/journey/evidence reconciliation

### 15.5 API, pagination ve security

- Query allowlist/time range/limit cap
- Cursor stable order; duplicate/skip yok
- Invalid/expired cursor stable error
- Exact matchId/conversationId lookup
- One endpoint failure independent response
- Retry only failed section
- Summary/evidence/export permission farkı
- Query timeout/cancel ve sanitize error

### 15.6 Analytics UI

- Default Özet; Ham Kanıt varsayılan değil
- En fazla dört KPI ve unit label
- Deterministic sentence low-sample/no-data variants
- Previous-step funnel conversion/loss
- Trend no-data gaps/tooltip/timezone
- Advanced filters apply/clear/back-forward
- One section error preserves others
- Complete/incomplete/out-of-order/conflict story
- Long username, missing name, malformed metadata
- Keyboard tabs, focus return, screen reader, contrast, reduced motion

### 15.7 Dashboard ve regresyon

- Stats/push/performance endpoint-to-card mapping fixtures
- Source/time/freshness on every number
- Normal/warning/critical/unknown/not_available states
- Partial provider ve stale prior data
- Release Health pending never green/zero-error
- Firebase disabled/init/delivery distinctions
- Push no-error ve long-code overflow
- Activity graph/recent independent errors
- No nested vertical scroll
- 320 px/tablet/desktop
- Backend syntax, focused/full tests, lint/build ve encoding
- Old/new route response comparison
- Match/search product UX regresyonu yok
- Wave 15 uygulama hazırlığı yok

## 16. Manuel QA matrisi

| Senaryo | Kurulum | Beklenen kanıt |
|---|---|---|
| Beş saniye özeti | Normal 24s pencere | Dönüşüm, biggest loss, delta, confidence ve action ilk viewport'ta |
| Tek match | Aynı matchId için iki offer | Match 1; participant events yalnız kanıtta 2 |
| Tek conversation | Aynı conversationId için iki start | Conversation 1 |
| Sıralı funnel | Doğru sıralı fixture | Previous-step conversion/loss doğru |
| Out-of-order | Offer search'ten önce | Funnel'a eklenmez; warning görünür |
| Window boundary | Başlangıç içeride, sonuç follow-up'ta | Belgeli cohort kuralı |
| Duplicate/reconnect | Retry ve reconnect | Sonuç ikiye katlanmaz |
| Low sample | Çok küçük örnek | Kesin başarı/başarısızlık yok |
| Missing baseline | Önceki pencere boş | Karşılaştırma yok; 0% değil |
| Partial endpoint | Funnel hata | Summary/trend görünür; local retry |
| Journey lookup | Exact match/conversation | Tek story; karar/final/end reason |
| Multi-event story | Uzun/eksik journey | Group, pagination, gaps okunur |
| Raw evidence | Yetkili admin | Maskeli, cursor'lı, sanitize |
| Evidence denial | Yetkisiz rol | Server engeli |
| Dashboard fresh | Tüm provider başarılı | Source/window/refresh ve doğru health |
| Dashboard partial | Push diagnostics hata | Diğer kartlar korunur; toplu yeşil yok |
| Release pending | Wave 16 provider yok | Henüz bağlı değil; sağlıklı/0 hata yok |
| Push no-error | Error summary boş | Sakin Hata yok |
| Push long error | Uzun code | Taşmaz; detail erişilebilir |
| Activity summary | 24s veri | Az KPI + grafik + kısa recent |
| Hourly detail | Bilinçli eylem | Ham tablo default değil |
| Single scroll | Uzun recent | İkinci dikey scroll yok |
| Mobile | 320 px | Tek kolon, no overflow, okunur grafik |
| Keyboard/SR | Filter/tab/detail/refresh | Focus/name/return doğru |
| TR/EN | Event/status labels | Karışık teknik copy yok |
| Sensitive data | Message/token/device fixture | UI/log/export sızıntısı yok |
| Reconciliation | Aynı filtre DB fixture | Tüm katmanlar uzlaşıyor |

Production verisiyle QA yalnız açık izin, minimizasyon ve exact query kapsamıyla yapılır; normal doğrulama sentetik/local fixture kullanır.

## 17. Canonical kabul eşlemesi

### 17.1 B-ANL-001 — 6 kriter

| # | Canonical kabul | Wave 14 kanıtı |
|---:|---|---|
| 1 | Ham event sayısı kullanıcı sayısı diye gösterilmiyor | Unit dictionary, API ve label testleri |
| 2 | Sıra dışı event funnel'ı bozduğu hâlde gizlenmiyor | Ordered fixture ve coverage warning |
| 3 | Aynı match iki participant yüzünden iki match sayılmıyor | matchId aggregate testi |
| 4 | Duplicate/retry tek olaya indirgeniyor | Exact/semantic dedupe testleri |
| 5 | Düşük örnek güven etiketi taşıyor | Confidence variants |
| 6 | C-ANL-001 özetleri ham kayda geri izleniyor | Evidence ref ve reconciliation |

### 17.2 C-ANL-001 — 7 kriter

| # | Canonical kabul | Wave 14 kanıtı |
|---:|---|---|
| 1 | Master QA-012 kriterleri tamam | §18 matrisi ve kullanıcı onayı |
| 2 | Person/attempt/match/conversation ayrık | Unit/API/UI contract |
| 3 | Sırasız event funnel'a sessiz eklenmiyor | Missing/out-of-order fixtures |
| 4 | İki participant bir match'i iki match yapmıyor | Match aggregate fixture |
| 5 | Düşük örnek güven işareti taşıyor | Summary/funnel/trend QA |
| 6 | Ham event varsayılan tablo değil | Default Özet screenshot/DOM |
| 7 | Tam mesaj/prompt/PII analitikte yok | Redaction/security test |

### 17.3 C-ADMIN-002 — 6 kriter

| # | Canonical kabul | Wave 14 kanıtı |
|---:|---|---|
| 1 | Master QA-004 tamam | §19 matrisi ve manuel QA |
| 2 | Dashboard araştırma detayını kopyalamıyor | İlk viewport/IA screenshot |
| 3 | Her sayı source/time window taşıyor | Manifest ve mapping tests |
| 4 | DB ve push sorunları tek kırmızı kutuda değil | Independent health fixtures |
| 5 | Release Health C-REL-001 kısa kart olarak bağlanıyor | Provider slotu dürüst pending; gerçek veri Wave 16'da yeniden kanıt |
| 6 | Low sample/partial başarı gibi görünmüyor | State matrix ve visual QA |

C-ADMIN-002/5 Wave 14'te provider slotu, güvenli fallback ve sahte başarı üretmeme olarak kapanır. Gerçek C-REL-001 verisi Wave 16'nın işidir; Wave 16 kapanışında tüketici entegrasyonu yeniden doğrulanır. Bu stable ID'yi ikinci kez sahiplenmez.

### 17.4 C-ADMIN-003 — 6 kriter

| # | Canonical kabul | Wave 14 kanıtı |
|---:|---|---|
| 1 | Master QA-005 tamam | §20 matrisi ve manuel QA |
| 2 | Ham saatlik tablo default değil | Dashboard DOM/screenshot |
| 3 | Grafik/metrik aynı pencere | Filter/window contract |
| 4 | İç içe scroll yok | Layout QA |
| 5 | Eventler anlaşılır sonuç | Central TR/EN labels |
| 6 | Ham kayda geri izleme | Detail/evidence ref |

### 17.5 Stable ID kapanış checklist'i — 25 kriter

B-ANL-001:

- [ ] Ham event sayısı kullanıcı sayısı diye gösterilmiyor.
- [ ] Sıra dışı event funnel'ı bozduğu hâlde gizlenmiyor.
- [ ] Aynı match iki katılımcı yüzünden iki match sayılmıyor.
- [ ] Duplicate/retry tek olaya indirgeniyor.
- [ ] Düşük örnek güven etiketi taşıyor.
- [ ] C-ANL-001 özetleri ham kayda geri izlenebiliyor.

C-ANL-001:

- [ ] Master QA-012 kriterleri tamam.
- [ ] Person/attempt/match/conversation ayrık.
- [ ] Sırasız event funnel'a sessizce eklenmiyor.
- [ ] İki participant bir match'i iki match yapmıyor.
- [ ] Düşük örnek güven işareti taşıyor.
- [ ] Ham event varsayılan tablo değil.
- [ ] Tam mesaj/prompt/PII analitikte yok.

C-ADMIN-002:

- [ ] Master QA-004 kabul kriterleri tamam.
- [ ] Dashboard araştırma detayını kopyalamıyor.
- [ ] Her sayı source/time window taşıyor.
- [ ] DB ve push sorunları aynı genel kırmızı kutuya gömülmüyor.
- [ ] Release Health C-REL-001 kısa kart provider kontratına bağlanıyor; Wave 16 öncesi dürüst pending state, Wave 16 kapanışında gerçek provider regresyon kanıtı var.
- [ ] Düşük örnek/partial data başarı gibi görünmüyor.

C-ADMIN-003:

- [ ] Master QA-005 kriterleri tamam.
- [ ] Ham saatlik tablo varsayılan görünüm değil.
- [ ] Grafik ile metrik aynı pencereyi kullanıyor.
- [ ] İç içe scroll yok.
- [ ] Eventler teknik isim değil anlaşılır sonuç.
- [ ] Ham kayda geri izleme mümkün.

Bu 25 madde yalnız ilgili otomatik kanıt, Master QA matrisi ve kullanıcı manuel QA onayı birlikte bulunduğunda `[x]` yapılır.
## 18. Master QA-012 kabul matrisi — 9 kriter

| # | Master kabul | Wave 14 kanıtı |
|---:|---|---|
| 1 | Beş saniyede dönüşüm, kayıp, delta, güven ve action | First-viewport kullanıcı QA'i |
| 2 | İki offer'a rağmen match 1; iki start'a rağmen conversation 1 | Aggregate + UI fixture |
| 3 | Funnel sıra/süre uygular; independent totals funnel değildir | Cohort/order tests |
| 4 | Boundary/reconnect/retry/missing event belgelenmiş kurala göre | Edge-case matrix |
| 5 | Match/conversation search raw taramadan story açar | Lookup QA |
| 6 | Summary/funnel/trend/journey/evidence uzlaşır | Reconciliation report |
| 7 | Low sample kesin değil; missing baseline sahte 0% değil | State/copy tests |
| 8 | Tek endpoint hatası sağlam bölümleri korur | Network failure test |
| 9 | Desktop/mobile/a11y/long/multi/pagination/privacy QA | Evidence pack |

## 19. Master QA-004 kabul matrisi — 12 kriter

| # | Master kabul | Wave 14 kanıtı |
|---:|---|---|
| 1 | Dört Dashboard veri bağı korunur | Endpoint-to-card comparison |
| 2 | Canlı veri freshness/last success; refresh açık feedback | Refresh test |
| 3 | Health eşikten türetilir; koşulsuz yeşil yok | State fixtures |
| 4 | P95/error eşikleri belgeli; renk tek anlam değil | Wave 04 contract + a11y |
| 5 | Mini trend yalnız gerçek seriyle | No/real-series tests |
| 6 | Firebase/device/project/credential/sent/error/invalid korunur | Mapping test |
| 7 | Push error boş/dolu/uzun code güvenli | UI fixtures |
| 8 | Zero/no-data/loading/stale/auth/error/partial ayrık | State matrix |
| 9 | Ortak token/icon; anlamsız harf ikon yok | Visual review |
| 10 | 320 px/tablet/desktop taşmasız | Responsive QA |
| 11 | Keyboard/focus/SR/contrast/44 px | Accessibility QA |
| 12 | Before/after screenshot ve endpoint regression | Evidence + onay |

Release Health kaynaksız değerlendirilmez; Wave 14 pending state'iyle sınırlar, Wave 16 gerçek bağlantıyı yeniden doğrular.

## 20. Master QA-005 kabul matrisi — 8 kriter

| # | Master kabul | Wave 14 kanıtı |
|---:|---|---|
| 1 | Timeseries/recent kayıpsız ve doğru toplamayla korunur | Old/new comparison |
| 2 | Kabul oranı, auto-accept, saatlik anlam/pencere korunur | Definition fixtures |
| 3 | Alt bölüm grafikle taranır; raw table detail ister | Desktop QA |
| 4 | Selector/detail keyboard/focus/SR/contrast/44 px | A11y QA |
| 5 | Recent labels central TR/EN; unknown controlled | Dictionary test |
| 6 | Loading/empty/error/partial/long/missing/bad metadata | Fixture matrix |
| 7 | Mobil tek kolon, grafik okunur, nested scroll yok | Mobile QA |
| 8 | Before/after ve endpoint count regression | Evidence + onay |

## 21. Başlangıç kapısı checklist'i

Wave 14 ancak bütün maddeler sağlandığında aktive edilir:

- [ ] Kullanıcı açıkça "Wave 14'ü başlat" dedi.
- [ ] Wave 13 `QA kapalı` ve kullanıcı onaylı.
- [ ] Wave 01–13 kapanış belgeleri canonical dosyalarla senkron.
- [ ] Root, backend ve frontend Git snapshot'ları kaydedildi.
- [ ] Mevcut kullanıcı değişiklikleri ve exact Wave 14 kapsamı ayrıldı.
- [ ] Master QA-004/005/012 güncel satırları yeniden okundu.
- [ ] Mevcut analytics/dashboard code snapshot'ı ve route envanteri kaydedildi.
- [ ] Focused/full test, lint, build ve syntax komut envanteri doğrulandı.
- [ ] QA-004/005/012 mevcut ve onaylı görsel/brief kanıt yolları doğrulandı.
- [ ] Wave 04 performance provider contract'ı QA kapalı.
- [ ] Wave 05–13 journey IDs/event coverage gerçek kodda yeniden doğrulandı.
- [ ] Event unit/catalog/time/cohort/dedupe kararları owner tarafından kabul edildi.
- [ ] Privacy/retention/export/RBAC sınırları doğrulandı.
- [ ] Migration/backfill exact target/impact/dry-run/rollback planı hazır.
- [ ] Production DB/migration/backfill/deploy gerekiyorsa ayrıca açık yetki alındı.
- [ ] Release Health yokluğu pending olarak kabul edildi; sahte metrik yasak.
- [ ] Wave 15 kapsamına taşma olmadığı doğrulandı.

Eksik bir giriş maddesi Wave'i `Aktif` yapmaz; blokaj sonuç alanına yazılır.

## 22. Kapsam dışı ve successor guard

Wave 14'e dâhil değildir:

- Tahmine dayalı veya LLM tabanlı AI insight/kök neden
- Kaynaksız metrik, dekoratif fake chart veya no-data'yı sıfır/sağlıklı gösterme
- Wave 15 profil listesi, profil detayı ve uygulama raporu operasyon ekranları
- Wave 16 error ingestion, fingerprint grouping ve gerçek Release Health rollup/UI
- Wave 17 ortak CI zinciri
- Wave 18 Android release/signing/store işlemi
- Yeni analytics vendor, tracking SDK veya cookie/consent ürünü kararı
- Yeni kullanıcı-facing özellik veya matchmaking davranış değişikliği
- Yetkisiz raw PII export'u veya geniş production sorgusu
- Canlı migration/backfill/cleanup/deploy/restart

Wave 14 kapanışında Wave 15 için dosya, kod, test, refactor veya hazırlık yapılmaz. Wave 15 planı ayrı açık talimatla hazırlanmıştır; yine de ayrıca açık aktivasyon ister.

## 23. Risk ve rollback

| Risk | Erken sinyal | Koruma | Rollback/forward-fix |
|---|---|---|---|
| Match/chat double count | Event count ürün sonucuyla uyuşmuyor | Relation aggregate fixture | New summary flag off; legacy açık etiketli |
| Funnel yanlış cohort | Step artıyor veya %100'ü aşıyor | Ordered property tests | Funnel unavailable; totals funnel diye gösterilmez |
| Legacy event yanlış bağlanır | Coverage/conflict artar | No-guess backfill | Backfill revision iptal; legacy_limited |
| Dedupe gerçek event siler | Participant kararı kaybolur | Exact/semantic ayrımı | Definition rollback + raw reconciliation |
| Query DB'yi zorlar | Timeout/P95 artışı | Caps/index/EXPLAIN | Route flag off; forward-fix |
| Partial data yeşil | Provider hata ama normal badge | Independent states | Aggregate unknown/partial |
| Release Health uydurulur | Provider yokken 0 hata | Pending fixture | Kart not_available |
| Raw evidence PII sızdırır | Full ID/message/token | Redaction/RBAC | Endpoint off ve audit review |
| Metric kaybolur | Old/new mismatch | Contract comparison | Old adapter restore |
| Tek hata ekranı kapatır | Bir request rejection | Per-section state | New analytics flag off |
| Mobile/nested scroll | 320 px overflow | Layout tests | Component CSS rollback |
| Dirty repo işi örter | Unrelated diff | Exact path snapshot | Yalnız Wave 14 farkını geri al |

Rollback veri kaybı üretmemelidir. Additive sütunları acele drop etmek yerine compatibility/forward-fix tercih edilir. Production rollback/deploy ayrıca açık yetki ister.

## 24. Rollout ve canlı işlem sınırı

Ayrı kullanıcı yetkisi isteyenler:

- production behavior event veya user-linked analytics sorgusu
- schema migration/index/backfill/retention cleanup
- materialized view refresh veya ağır reconciliation
- analytics export
- feature flag/canary
- Render/Neon config, restart veya deploy
- gerçek kullanıcı verili production screenshot

Yetki öncesi exact environment/database/service, query/migration/route/flag, tahmini satır/lock/süre/performance etkisi, privacy kapsamı, backup/rollback, gözlem penceresi ve durma koşulu raporlanır. Plan hazırlığı bunları yetkilendirmez.

## 25. Sonuç/evidence alanı

Wave 14 yürütüldüğünde en az:

- başlangıç/final root/backend/frontend Git snapshot
- değişen exact dosyalar ve stable ID sahipliği
- event catalog/unit/definition version kararı
- migration/index/backfill dry-run ve varsa açık canlı onay
- double-count, dedupe, ordered funnel ve boundary testleri
- bütün katmanlar için reconciliation report
- old/new endpoint compatibility comparison
- Dashboard source/window/freshness/partial kanıtı
- Release Health pending fallback kanıtı
- privacy/redaction/RBAC/export audit kanıtı
- focused/full test, syntax/lint/build/encoding exit code'ları
- QA-004 before/after desktop/mobile ve endpoint comparison
- QA-005 desktop/mobile/single-scroll/recent label kanıtı
- QA-012 journey/pagination/a11y/sensitive-data kanıtı
- canonical checkbox ve kullanıcı manuel QA onayı
- destructive işlemlerin yapılmadığı veya exact onayla yapıldığı kayıt
- Wave 15'in başlatılmadığı açık durma kaydı

Kriter yalnız kanıtla `[x]` olur. "Kısmen", "görünüşe göre" veya yalnız kod incelemesi manuel QA'nın yerine geçmez.

## 26. Durma kuralı

Wave 13 QA kapanışı ve kullanıcının açık Wave 14 başlatma talimatı birlikte gelene kadar:

- Wave 14 için kod, test, dependency, migration, backfill, production query/export, feature flag veya deploy değişikliği yapılmaz.
- Wave 14 `Aktif` işaretlenmez; belge yalnız `Hazır — aktif değil` kalır.
- Canonical `[ ]` maddeler kanıtsız kapatılmaz.
- Event count, person, attempt, match ve conversation birimleri birbirine çevrilmez.
- Partial/stale/no-data/low-sample sağlıklı veya kesin yorum olarak gösterilmez.
- Release Health provider verisi Wave 16'dan önce uydurulmaz.
- Wave 15 planı hazırlanmış olsa da aktive edilmez veya uygulanmaz.
