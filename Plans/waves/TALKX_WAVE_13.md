# TalkX Wave 13 Plan — Locale, Bildirim ve TalkX Sistem İletişimi

> Bu belge yalnız Wave 13 için hazırlanmış uygulama planıdır.
> Canonical uygulama sırası Plan B `B-I18N-001` → Plan A `A-I18N-001` → Plan C `C-NOTIFY-001` → Plan B `B-SYS-001` → Plan C `C-SYS-001` → Plan A `A-SYS-001` şeklindedir.
> QA-010 çok dilli bildirim teslimi ile QA-015 kalıcı TalkX Sistem sohbeti tek locale ve delivery sözleşmesini kullanır; push kalıcı mesajın yerine geçmez.
> Plan hazırdır. Wave 13 aktif değildir, Wave 01–12 kapanmamıştır ve uygulama başlamamıştır. Wave 14 planı ayrı talimatla hazırlanmıştır; aktif değildir ve burada uygulanmaz.

## 1. Durum ve yürütme sınırı

- **Wave:** 13
- **Wave adı:** Locale, bildirim ve TalkX Sistem iletişimi
- **Plan katılımı:** Plan B + Plan A + Plan C
- **Canonical sıra:** `B-I18N-001 → A-I18N-001 → C-NOTIFY-001 → B-SYS-001 → C-SYS-001 → A-SYS-001`
- **Plan durumu:** Hazır
- **Wave durumu:** Bekliyor
- **Uygulama durumu:** Başlamadı
- **Uygulama yetkisi:** Verilmedi
- **Giriş kapısı:** Wave 12 `QA kapalı` ve kullanıcıdan açık “Wave 13'ü başlat” talimatı
- **Mevcut blokaj:** Wave 01–12 uygulanıp kapanmadı; Wave 13 uygulanamaz
- **Önceki wave:** Wave 12 — planı hazır, aktif değil
- **Sonraki wave:** Wave 14 — planı ayrı talimatla hazırlandı; aktif değil ve başlatılmadı

Bu dosyanın hazırlanması Wave 13 aktivasyonu, kod/test/dependency değişikliği, migration, production recipient sorgusu, canlı global/segment/test bildirimi, push gönderimi, campaign çalıştırma, schedule `run-now`, feature flag, deploy veya Wave 14 aktivasyonu/uygulaması için yetki değildir.

## 2. Canonical referanslar ve otorite

1. `B-I18N-001` — authenticated locale kaynağı, TR/EN içerik haritası, English fallback ve kanal eşliği
2. `A-I18N-001` — user-facing TR/EN, stable message ID, tek dilli fallback ve responsive metin
3. `C-NOTIFY-001` — QA-010 anlık/planlı/run-now çok dilli bildirim merkezi
4. `B-SYS-001` — QA-015 kalıcı Sistem inbox, recipient, delivery, read ve CTA backend sözleşmesi
5. `C-SYS-001` — QA-015 güvenli hedefleme, preview/test/onay, batch ve Jarvis sonuç özeti
6. `A-SYS-001` — Arkadaşlar ekranında doğrulanmış, kalıcı ve tek yönlü TalkX Sistem sohbeti
7. Master `QA-010` — TR/EN bildirim dağıtımı ve locale-aware WS/push
8. Master `QA-015` — kalıcı Sistem mesajı ürün ve veri sözleşmesinin ana otoritesi
9. Wave 02 `B-API-001/B-AUTH-001/B-OBS-001/B-SEC-002/B-WS-001/C-ADMIN-001` — auth, abuse, socket, audit ve admin yetki temeli
10. Wave 04 `B-DB-001` — migration, scheduler/worker ve DB runtime kapısı
11. Wave 06 `B-DATA-001/B-DATA-002/B-DATA-003/C-COMP-002` — locale/geo/retention/deletion veri amacı
12. Wave 10 `B-MSG-001` — stable message ID, idempotency ve outbox ilkeleri; Sistem mesajı friend message tablosunu taklit etmez
13. `A-A11Y-001/A-MOB-001/C-CI-001` — accessibility, Web/Android ve ortak kalite kapıları

Çelişki çözümü:

- Ana otorite push veya toast değil, veritabanındaki kalıcı Sistem campaign/recipient kaydıdır.
- TalkX Sistem normal kullanıcı değildir; sahte `users`, `profiles`, `friendships` veya direct conversation oluşturulmaz.
- `profile.locale`, authenticated client/device locale ve fallback ayrı kaynaklardır; locale client'ın hedef segmentini veya country otoritesini keyfi değiştirmesine izin vermez.
- QA-010'daki anlık/planlı admin bildirimi, kalıcı Sistem mesaj altyapısı devreye girdiğinde aynı campaign motorunu kullanır; scheduler doğrudan tek metin broadcast etmez.
- QA-015 ilk sürümde ayrı pazarlama/operasyon sınıfı, kategori susturma veya Bildirim Tercih Merkezi istemez. Plan C iç etiketi kullanıcı tercih semantiği üretmez.
- Master QA-015 yalnız allowlist uygulama içi CTA'ya izin verir. `A-SYS-001` içindeki “CTA dış URL güvenli açılıyor” kriteri serbest URL yetkisi değildir; izin verilmeyen dış URL reddedilir/gizlenir. Gelecekte policy-approved dış hedef istenirse ayrı ürün kararı gerekir.
- Country targeting Wave 08 canonical ülke gerçeğini kullanır; acceptance IP/geo snapshot'ı veya serbest metin “anlık konum” değildir.
- Wave 14 analytics/dashboard, gelişmiş automation/template/A-B test ve yeni notification preference ürünü bu Wave'e çekilmez.

## 3. Wave sonucu

Wave 13 sonunda:

- Locale resolution backend, WebSocket, push, scheduler, system inbox ve client için tek sürümlü sözleşme olacak.
- TR/EN aynı feature release'inde teslim edilecek; unknown/null/unsupported locale belgelenmiş English fallback kullanacak.
- Account targeting locale, device/session render locale ve fallback nedeni birbirinden ayrılacak; ölçülebilir olacak.
- Anlık, planlı, scheduler ve `run-now` aynı `contentByLocale`, validation, recipient snapshot ve idempotency yolunu kullanacak.
- Mevcut tek dilli schedule kayıtları sessizce TR veya EN sayılmayacak; `translation_required` durumunda global çalıştırılmayacak.
- Admin, göndermeden önce hedef, TR/EN/fallback, app inbox, online WS ve push-capable sayısını source/time ile görecek.
- Preview ve kendime test production recipient veya global delivery üretmeyecek.
- `system_message_campaigns` ve `system_message_recipients` kalıcı, idempotent, auditli ve retention-aware ana kaynak olacak.
- Campaign recipient snapshot gönderimden önce güvenle oluşturulacak; retry, çift tıklama ve worker restart duplicate recipient/message üretmeyecek.
- Online kullanıcı live event, offline kullanıcı sonraki açılışta aynı kalıcı message identity ile Sistem inbox'ı görecek.
- Push başarısızlığı kalıcı message state'ini silmeyecek; push yalnız attention layer olarak raporlanacak.
- TalkX Sistem Arkadaşlar ekranında logo, ad ve doğrulanmış badge ile normal arkadaştan ayrılacak.
- Sistem sohbeti tek yönlü olacak; composer cevap vaat etmeyen kanal açıklamasına dönüşecek.
- History cursor pagination, unread/read ve multi-device sync server otoriteli olacak.
- CTA yalnız allowlist internal action/route kullanacak; unsupported old client'ta mesaj kalacak, CTA gizlenecek.
- Admin sonuç ekranı hedeflenen, kalıcı kaydedilen, canlı teslim, push, locale/fallback, okunan ve hatalı sayıları birbirine karıştırmayacak.
- Hesap silme/retention Wave 06 politikasını uygulayacak; hassas target/token/content normal log veya varsayılan özete dökülmeyecek.
- Wave 14 başlamayacak.

## 4. Doğrulanmış başlangıç fotoğrafı

### 4.1 Locale kaynakları

- `profiles.locale` yalnız `tr/en` kabul ediyor; register/login/profile update bu alanı yazabiliyor.
- WebSocket client kaydı `client.lang` taşıyor ve connection sırasında normalize ediliyor.
- HTTP request locale'i `x-talkx-lang`/Accept-Language üzerinden çözülebiliyor.
- `push_devices` user/device/platform/token taşıyor fakat locale snapshot'ı taşımıyor.
- Push ve aktif WS için aynı kullanıcıda locale kaynağı/önceliği tek domain sözleşmesinde görünmüyor.
- Client locale local storage, query override, navigator ve profile sync yollarından gelebiliyor; source/revision/stale davranışı ayrıca kanıtlanmalı.

### 4.2 Notification ve scheduler

- `POST /admin/notify` tek `title/body`, duration ve `all|online|mobile` hedefi alıyor.
- `sendSystemNotice` aynı tek metni bütün aktif WebSocket client'larına `admin_notice` olarak broadcast ediyor.
- Push query aktif tokenları locale join/segment olmadan tek payload ile gönderiyor.
- `notification_schedules` tek `title/body`, local time/timezone, active ve last-sent alanları taşıyor.
- Create/update/list/toggle/run-now ve scheduler aynı çok dilli şema/idempotency kanıtına sahip değil.
- Current `last_sent_local_date` günlük duplicate'i azaltabilir; çoklu instance lease/atomic claim ile birlikte kanıtlanmalı.
- Push delivery log token/sent/failure toplamlarını taşıyor; locale/fallback ve kalıcı inbox sonucu yok.

### 4.3 Sistem inbox

- Current DB'de `system_message_campaigns` ve `system_message_recipients` görünmüyor.
- Arkadaş listesi yalnız gerçek friends/request/blocked modelini kullanıyor; TalkX Sistem satırı yok.
- Client `admin_notice` olayını toast/local notification olarak gösterebiliyor; kalıcı history/read/pagination kaynağı değil.
- Push payload attention/deep-link taşıyabiliyor; client push içeriğini kalıcı DB history yerine koymamalı.
- Normal direct message conversation/friendship yapısı Sistem kimliğini modellemek için uygun değil.

### 4.4 Admin ve hedefleme

- Bildirim Ayarları anlık ve schedule formları tek dilli; TR/EN completeness, preview, recipient estimate ve fallback özeti yok.
- Admin Sistem Mesajları için tek/seçili/segment/herkes hedef snapshot yüzeyi bulunmuyor.
- Kullanıcı/profil listeleri, country/locale/platform/last-active sinyalleri farklı veri kaynaklarında; source/recency/eligibility tek hedef sözleşmesine bağlanmalı.
- Mevcut global notice gönderimi kalıcı recipient snapshot oluşturmuyor; gönderim anındaki tam hedef sonradan kanıtlanamıyor.
- Yetki, CSRF, re-auth, rate, large audience confirmation ve audit Wave 02/C-ADMIN-001 temelinden yeniden doğrulanmalı.

### 4.5 Repo ve canlı sınır

- Root/backend/frontend geniş kullanıcı değişiklikleri taşıyabilir; uygulama başında üç Git bağlamı ayrı snapshot edilir.
- Plan aşamasında production user/locale/country/push token/schedule/recipient verisi sorgulanmaz veya export edilmez.
- Migration, scheduler, target estimate, test delivery, live campaign, push ve feature flag ayrıca exact-target/impact/onay ister.

## 5. Locale domain sözleşmesi — B-I18N-001

### 5.1 Ayrık locale kavramları

- `profileLocale`: hesabın canonical uygulama dili; server doğrular ve version/time taşır
- `sessionLocale`: authenticated WebSocket/HTTP client'ın bu oturumdaki desteklenen dili
- `deviceLocale`: push cihazının kayıt anındaki desteklenen dil snapshot'ı; güncelleme zamanı taşır
- `targetLocale`: campaign segmentine dahil edilme kuralında kullanılan locale ve source
- `renderLocale`: belirli inbox/WS/push tesliminde seçilen varyant
- `fallbackLocale`: ilk sürümde `en`
- `fallbackReason`: missing/null/unsupported/stale/not_available

Locale, timezone, country ve content language aynı şey değildir. Her sayım hangi locale alanını kullandığını belirtir.

### 5.2 Çözüm önceliği

Owner tarafından uygulama başında kesinleştirilecek önerilen politika:

1. Authenticated active client için validated `sessionLocale`.
2. Push delivery için güncel validated `deviceLocale`; yoksa `profileLocale`.
3. Kalıcı inbox API için authenticated request/session locale; yoksa `profileLocale`.
4. Hiçbiri desteklenmiyorsa English fallback.

Campaign immutable TR/EN varyantlarını birlikte tuttuğu için aynı message identity farklı cihazlarda o cihazın desteklenen render locale'iyle sunulabilir. Recipient hedef snapshot'ı değişmez; locale değişikliği hedefi geçmişe dönük değiştirmez. Read state hesap bazında ortak kalır.

Bu öneri QA-010/015 ve `B-I18N-001` çoklu cihaz kriteriyle test edilir. Owner account-level tek dil seçerse bu karar, değişim zamanı ve tüm kanal eşliği açıkça belgelenmeden uygulanmaz.

### 5.3 Locale güven sınırı

- Client yalnız kendi UI/session locale'ini desteklenen allowlist içinde bildirebilir.
- Client hedef `targetLocale`, segment, recipient user veya country seçemez.
- Profile locale mutation authenticated self endpointi, validation ve audit/updatedAt taşır.
- Push token register device/platform/locale bağını current user'a kurar; başka user hedeflenemez.
- Unknown locale raw string olarak segment veya metrics label oluşturmaz.
- Country display name client locale kataloğundan gelir; ISO country code ile karıştırılmaz.

### 5.4 Content envelope

Tüm anlık/schedule/system teslimleri:

- stable content/campaign version
- `contentByLocale.tr.title/body`
- `contentByLocale.en.title/body`
- explicit `fallbackLocale: en`
- optional CTA labelByLocale + allowlist action
- limits/şema version/content hash

Global/herkes hedefinde TR ve EN zorunludur. Locale-specific açık hedef policy izin veriyorsa kullanılmayan varyant kararı admin onayında görünür; tek dilli içeriğin globale genişlemesi yoktur.

### 5.5 Locale değişikliği ve çoklu cihaz

- Profile locale update response canonical locale/revision/updatedAt döndürür.
- Active WS session kendi authenticated locale update/rehydration olayını alır.
- Push device locale register/refresh ile güncellenir; stale snapshot fallback reason üretir.
- Campaign target snapshot send anında sabittir; user locale değişimi queued-unsent recipient için policy'ye göre çözülür ve revision kanıtı taşır.
- Inbox read response current device render locale'ini kullanabilir; audited campaign varyantları immutable kalır.
- Aynı ekranda title TR/body EN gibi mixed variant oluşmaz.

## 6. Client i18n sözleşmesi — A-I18N-001

### 6.1 Stable message kimliği

- Client backend `code/eventType/contentKey` değerini user-facing raw text olarak göstermez.
- UI copy stable translation key üzerinden TR/EN çözülür.
- Campaign content server-authored varyanttır; UI chrome translation kataloğuyla karıştırılmaz.
- Prompt/event analytics full user text değil stable ID taşır.
- Missing key tek deterministic fallback diline düşer; aynı component içinde karışık dil üretmez.

### 6.2 Parity ve quality gate

- Yeni system/notification key'i TR ve EN aynı PR/release içinde eklenir.
- Placeholder isimleri ve çoğul/zaman parametreleri iki dilde eşleşir.
- Unicode/emoji/grapheme length admin/backend/client/push katmanlarında tutarlıdır.
- Pseudo-long/long TR/EN metinleri 320 px ve Android WebView düzenini bozmaz.
- Screen reader accessible name görünür dille aynı locale'dedir.
- English fallback metni insan review'ı olmadan global production içeriğine dönüşmez.

### 6.3 Client kaynak senkronu

Boot sırasında local preference hızlı UI sağlar; authenticated `profileLocale/sessionLocale` response canonical reconciliation yapar. Network hatası locale'i sessizce farklı hesaba taşımaz. Logout/account switch user-bound locale/cache ayrımını korur. Query override yalnız açık debug/preview policy altında profile target alanını değiştirmeden çalışır.

## 7. QA-010 bildirim merkezi — C-NOTIFY-001

### 7.1 Birleşik akış

`instant`, `scheduled`, scheduler tick ve `run-now` aynı pipeline'ı kullanır:

1. Draft/content envelope validation
2. Target/locale/channel estimate
3. Preview veya test mode ayrımı
4. Admin permission/re-auth ve confirmation
5. Idempotent campaign/dispatch creation
6. Recipient snapshot
7. Persistent inbox creation
8. WS attention delivery
9. Push attention delivery
10. Locale/channel result summary ve audit

Legacy direct broadcast bu pipeline'ı bypass edemez. `run-now`, schedule'ın normal execution command'ini kullanır ve aynı occurrence'ı ikinci kez çalıştırmaz.

### 7.2 TR/EN formu ve preview

- TR ve EN tabs/side-by-side; missing language badge
- Title/body character count ve canonical limits
- Whitespace, unsupported link/CTA ve truncation risk validation
- Web Sistem row, chat bubble ve Android/Web push preview
- Target mode, locale, fallback, channel ve schedule time summary
- Loading, validation error, stale estimate, partial preview ve unauthorized state
- Keyboard/SR tabs, field-error association ve responsive stacking

### 7.3 Recipient estimate

Estimate en az:

- eligible user count
- TR target/render count
- EN target/render count
- English fallback count ve reason buckets
- online authenticated WS client count
- active push device count ve unique user count
- persistent inbox-only user count
- excluded/inactive/deletion-pending/uncertain count
- source query revision/filters/calculatedAt

Estimate send snapshot değildir. Confirmation sonrası target revision değişirse send yeniden estimate veya açık stale confirmation ister.

### 7.4 Schedule/timezone/DST

- Schedule local time, IANA timezone, recurrence/occurrence identity ve nextRunAt taşır.
- Locale timezone'dan türetilmez.
- DST skipped/ambiguous local time policy'si görünür ve testlidir.
- Multi-instance worker atomic lease/claim kullanır.
- Her occurrence unique idempotency key taşır.
- `run-now` ayrı manual occurrence'dır; normal schedule occurrence'ını tüketip tekrar tetiklemez.
- Pause/update/delete in-flight recipientler ve already-created message'lar için açık sonuç taşır.

### 7.5 Legacy schedule migration

Current single title/body records:

- otomatik TR veya EN sayılmaz
- raw legacy title/body yalnız migration evidence olarak korunabilir
- `translation_required` + inactive/blocked global execution durumuna alınır
- admin TR/EN varyantlarını tamamlayıp preview/onay vermeden çalışmaz
- migration forward/rollback, scheduler mixed-version guard ve cleanup zamanı belgelenir

## 8. Sistem campaign ve recipient modeli — B-SYS-001

### 8.1 Campaign

`system_message_campaigns` en az:

- stable campaignId, schemaVersion ve idempotencyKey
- source: instant/schedule/run-now/test
- status: draft/validating/ready/queued/sending/completed/partial_failed/cancelled/failed
- immutable TR/EN content map ve contentHash
- allowlist CTA action + TR/EN label
- target type/filter summary/snapshot revision
- fallback locale/policy
- schedule/occurrence identity varsa
- created/confirmed/sent actor ve timestamps
- batch/worker revision
- aggregate result refs, retention ve audit link

Sent campaign content silently edited olmaz. Düzeltme yeni campaign/version ve açık ilişki üretir.

### 8.2 Recipient

`system_message_recipients` en az:

- campaignId + userId unique
- eligibility/target snapshot source
- targetLocale ve source
- current render/fallback result summary
- in-app status/timestamp
- latest WS delivery status/timestamp
- push aggregate/device result refs
- readAt/readRevision
- CTA usedAt/action
- createdAt/retention/deletion state

Tek kişi bir recipient'lı campaign'dir. Ortak içerik campaign'de, kullanıcıya ait delivery/read recipient'ta kalır. Recipient oluşturulması friendship veya normal message yaratmaz.

### 8.3 Delivery attempt ledger

Per-device/attempt ayrıntısı gerektiğinde recipient aggregate'ini ezmek yerine bounded delivery ledger/push logs kullanılır:

- campaignId/recipientId/deviceId hash
- channel, renderLocale/fallback reason
- attemptNo/idempotency key
- queued/sent/failed/invalid/skipped
- provider message identity ve safe error bucket
- occurredAt

Push token veya full content normal ledger/audit'e yazılmaz.

### 8.4 Transaction ve idempotency

- Campaign confirm transaction'ı immutable content, target snapshot identity ve command result oluşturur.
- Recipient snapshot bounded batch veya staging table ile deterministik oluşturulur.
- Unique `(campaign_id,user_id)` duplicate recipient'i engeller.
- Worker recipient/channel attempt'i lease/CAS ile claim eder.
- Retry yalnız failed/retryable channel attempt'i yineler; persistent inbox kaydını çoğaltmaz.
- Response loss same idempotency key ile existing campaign/result replay eder.
- Worker restart queued/sending stale lease'i reclaim eder; completed recipient'i yeniden yaratmaz.

### 8.5 Kalıcı inbox ve pagination

- Authenticated user yalnız kendi recipients'ını okuyabilir.
- Cursor `(createdAt,campaignId)` gibi stable total order taşır; offset drift yok.
- First page summary last message + unread count döndürür.
- History immutable message identity, selected locale content ve CTA capability taşır.
- Push payload history item oluşturmaz; API/DB canonical item kazanır.
- Offline/reinstall/second device aynı hesap geçmişini serverdan yükler.

### 8.6 Read ve çoklu cihaz

- Read yalnız Sistem conversation görünür ve belirli message/throughCursor gerçekten render edildiğinde gönderilir.
- Sadece route open tüm geçmişi körlemesine read yapmaz.
- `markReadThrough(messageId/revision)` idempotent ve monoton olur.
- Eski device daha düşük cursor ile readAt'ı geriye alamaz.
- WS `system_message_read_sync` veya next inbox refresh diğer cihazları toparlar.
- Read “kullanıcı anladı/onayladı” anlamına gelmez.

### 8.7 Push ve WebSocket

- Recipient/in-app kaydı push/WS'den önce vardır.
- Online event campaignId/messageId/recipient identity/content locale/revision ve CTA taşır.
- Stale/duplicate event client reducer'da aynı item'i çoğaltmaz.
- Push aynı stable messageId ile Sistem conversation deep-link'i taşır.
- Push failure persistent inbox state'ini değiştirmez.
- Sistem sohbeti foreground'da açıksa gereksiz toast/local push policy ile bastırılabilir; mesaj listesi yine server item'dır.
- Çoklu cihaz push delivery bir recipient'ı birden çok inbox message'a dönüştürmez.

### 8.8 Retention ve hesap silme

Campaign/recipient/delivery/audit için purpose, owner, retention, deletion/anonymization ve backup davranışı Wave 06 registry'ye eklenir. Account deletion recipient user linkini policy'ye göre siler/pseudonymize eder; campaign aggregate tek kullanıcıyı açığa çıkarmadan korunabilir. Silinmiş kullanıcı worker/push targetı olarak tekrar canlanmaz.
## 9. Admin Sistem Mesajları — C-SYS-001

### 9.1 Bilgi mimarisi

Sade adımlı yüzey:

1. Hedef
2. İçerik TR/EN
3. CTA ve preview
4. Estimate ve güvenlik özeti
5. Test
6. Confirmation/send
7. Result/history

Aynı ekranda bütün user listesi, raw token, campaign JSON ve delivery log yığılmaz. Admin önce kimi, hangi dille, hangi kanallarla etkileyeceğini anlar; recipient ve provider kanıtı gerektiğinde açılır.

### 9.2 Hedef türleri

- Tek kullanıcı: username/display name/UUID arama; ambiguity çözümü
- Seçili kullanıcılar: explicit IDs + valid/invalid/excluded count
- Ülke/bölge: Wave 08 canonical ISO country + source/confidence/updatedAt
- Dil: canonical profile/target locale
- Platform: tanımlı active/recent device eligibility window
- Son aktiflik ve kayıt tarihi: server time, timezone ve inclusive boundary
- Herkes: uygun aktif accounts; pending deletion/banned/policy-excluded ayrımı

Filter allowlist ve parameterized query kullanır. Client/admin raw SQL/filter expression göndermez. Segment tanımı snapshot anında version/hash taşır.

### 9.3 Coğrafi dürüstlük

- `Kayıt ülkesi`, `canonical profil ülkesi`, `son bilinen ülke` ve `IP tahmini` aynı etiket değildir.
- QA-015 hedeflemede tercih edilen source Wave 08 canonical country'dir.
- Belirsiz/unknown kullanıcı ayrı sayılır; sessizce ülkeye eklenmez.
- Tam IP, city/GPS veya adres recipient snapshot'a kopyalanmaz.
- VPN/seyahat sinyali anlık kesin konum veya gizli targeting değildir.
- Small cohort privacy threshold owner policy'si uygulanır.

### 9.4 Preview ve kendime test

Preview:

- Friends row
- System conversation bubble/history
- Web online notice behavior
- Android/Web push appearance
- CTA supported/unsupported client sonucu
- TR, EN ve fallback varyantı

Kendime test:

- yalnız authenticated authorized admin'in bağlı test user/device hedefi
- explicit `test=true`, test campaign/recipient/metrics/audit etiketi
- production estimate/schedule occurrence/global recipient üretmez
- aynı gerçek pipeline validation/render/deep-link davranışını kullanır
- test sonucu production success rate'e karışmaz

### 9.5 Send confirmation ve cancellation

Confirmation:

- exact target snapshot revision ve total
- TR/EN/fallback split
- in-app/online/push-capable/inbox-only split
- excluded/uncertain
- content hash/preview identity
- CTA action/capability
- irreversible delivered-message warning
- admin re-auth, reason ve idempotency commandId

Cancellation yalnız unclaimed/unqueued recipients için etkili olabilir. Zaten persistent inbox'a yazılmış veya push edilmiş message geri alınmış gibi gösterilmez. Düzeltme yeni Sistem message'ıdır.

### 9.6 Campaign history ve Jarvis özeti

Özet katmanı:

- Targeted
- Persistent inbox created
- Live WS delivered
- Push attempted/sent/failed/invalid
- Inbox-only
- TR/EN/fallback
- Read
- CTA used
- Queued/in progress/partial failed/cancelled
- lastUpdatedAt ve data freshness

Push sent, user read veya campaign success aynı metrik değildir. Summary raw counts/recipient state ile uzlaşır. Provider error samples maskeli ve yalnız kanıt katmanında bulunur.

## 10. TalkX Sistem client deneyimi — A-SYS-001

### 10.1 Friends list entry

İlk gerçek message ile görünür:

- TalkX resmi logo/avatar asset'i
- `TalkX Sistem` localized adı
- doğrulanmış badge + accessible label
- last message preview
- server timestamp
- unread badge
- normal friends'ten sakin ama net ayırt edilen system styling
- listede görünür ve deterministic section/order

Boş fake system row gösterilmez. Baştan görünmesi ürünce istenirse backend gerçek welcome campaign oluşturur.

### 10.2 Normal hesaptan farkı

TalkX Sistem:

- normal profile route açmaz
- block/unblock/remove friend aksiyonu göstermez
- friend request veya presence üretmez
- online/offline/last seen iddiası taşımaz
- typing, media send ve reply composer kullanmaz
- normal conversationId/friendId varsayımı yapmaz

Client discriminated entity type (`friend | system`) kullanır; magic UUID veya name string karşılaştırmasıyla karar vermez.

### 10.3 Tek yönlü conversation

Header doğrulanmış kimlik ve “TalkX bilgilendirmeleri” açıklamasını taşır. Composer yerine tek yönlü kanal bilgisi bulunur. Mesajlar chronological, paginated ve accessible list olarak render edilir. System message text server-authored safe renderer'dan geçer; raw HTML çalışmaz.

Loading, empty, offline-cached, error, retry, history end ve new message indicator ayrı state'lerdir. Error friend chat outbox/composer açmaz.

### 10.4 Unread ve read UX

- Friends row badge backend unread count'tan gelir.
- Conversation görünür viewport'ta render edilen items için read-through gönderir.
- Background tab veya hidden app otomatik read üretmez.
- New live message scroll konumuna göre unread/new-message indicator kullanır; kullanıcıyı zorla alta atmaz.
- Read ack timeout duplicate UI item üretmez; next status reconcile eder.
- Başka cihaz read sync badge/history state'ini monoton günceller.

### 10.5 CTA davranışı

- Tek optional CTA; message body'den ayrı semantic button/link
- Server allowlist actionId ve validated params
- TR/EN label server content varyantıyla aynı locale
- Client capability registry action'ı destekliyorsa route açar
- Unsupported/old client'ta CTA güvenle gizlenir veya localized unavailable sonucu gösterir
- Arbitrary URL, HTML, JavaScript veya unknown deep-link çalışmaz
- Action target auth/legal/permission gate'ini bypass etmez
- Tap telemetry stable campaign/message/action ID taşır; full content yoktur

Canonical A-SYS-001 kriterindeki dış URL güvenliği, ilk sürümde dış URL'yi açmak değil serbest dış URL'nin reddedilmesiyle sağlanır.

### 10.6 Push deep-link ve dedupe

- Push `systemMessageId/campaignId` ile Sistem route'una gider.
- Client push title/body'yi DB history item'i olarak insert etmez.
- App cold/background/foreground state'inde route auth/legal boot sonrasında bir kez açılır.
- Inbox fetch aynı message ID'yi getirir; WS/push/history üç kopya üretmez.
- Sistem sohbeti açıksa foreground push noise policy ile bastırılır, message listesi güncellenir.
- Push permission kapalıysa message sonraki inbox fetch'te unread kalır.

### 10.7 Locale değişimi ve cache

Campaign iki immutable varyant taşıyorsa locale değişiminden sonra history server-selected render locale ile yeniden çözülebilir. Cached page locale/revision etiketi taşır; yeni locale'de mixed title/body oluşturmaz. Offline cache policy ve retention Wave 06 kararına uyar; account switch/logout önceki system items'ı sızdırmaz.

### 10.8 Web/Android ve accessibility

- 320 px, safe-area, dynamic viewport ve large text
- Friends row ve verified badge screen-reader name
- Message list heading/landmark/time semantics
- Focus return, keyboard pagination/retry/CTA
- Android back önce System conversation'dan Friends'e döner
- Push action cold start aynı route'u açar
- Reinstall/second device server history'yi yükler
- Reduced motion; unread animation anlamın tek kaynağı değildir

## 11. Notification ve Sistem iletişimi state akışı

### 11.1 Campaign state

- `draft → validating → ready`
- `ready → estimating → confirmation_required`
- `confirmation_required → queued`
- `queued → snapshotting → sending`
- `sending → completed | partial_failed | failed | cancelled`

Validation/estimate stale ise confirmation tekrar gerekir. Completed bütün pushların başarılı olduğu anlamına gelmez; persistent recipient creation policy'ye göre tamamdır ve channel sonuçları ayrı kalır.

### 11.2 Recipient state

- `eligible → persisted`
- `persisted → live_pending/push_pending`
- channel states bağımsız `skipped | queued | sent | failed | invalid`
- in-app item persistent kalır
- `unread → read`
- deletion policy ile `deleted | pseudonymized`

Bir channel failure recipient'i silmez. Read state delivery state'i değiştirmez.

### 11.3 Admin state

- `idle | editing | validating | previewing | estimating | stale_estimate`
- `test_sending | test_result`
- `confirming | submitting | submitted | partial_failed | failed`
- `history_loading | result_stale | unauthorized`

Toast tek sonuç değildir. Page-level durable status line ve retry/read-back bulunur.

### 11.4 Client state

- list: `loading | ready | empty | offline_cached | failed`
- system summary: `absent | present_unread | present_read`
- conversation: `loading | ready | loading_more | end | offline | failed`
- live item: `received | deduped | reconciled`
- CTA: `available | unsupported | opening | failed`

Friend ve system reducers ayrı entity namespace/type kullanır.

## 12. API, WebSocket ve worker sözleşmesi

### 12.1 Admin API yüzeyleri

Beklenen capability'ler:

- target şeması/capabilities
- recipient estimate
- content validate/preview
- self-test send/status
- campaign create/confirm/status/cancel/history/detail
- schedule CRUD/preview/run-now/occurrence history
- masked recipient/channel evidence

Exact route isimleri current API convention keşfiyle seçilir. Her write stable commandId, auth/role, CSRF/re-auth gereksinimi, validation ve audit taşır.

### 12.2 User API yüzeyleri

- System summary/unread
- cursor-paginated System history
- read-through
- CTA capability/resolve gerekiyorsa

Her response account-owned scope, locale/revision, stable IDs, pagination cursor ve safe errors taşır. Kullanıcı başka recipientId/userId ile veri alamaz.

### 12.3 WebSocket events

- `system_message`
- `system_message_summary_changed`
- `system_message_read_sync`
- gerekiyorsa campaign-independent locale/profile sync

Eventler version, eventId, campaignId/messageId/recipientId, createdAt, renderLocale/fallback, safe content/CTA ve revision taşır. Unknown/new version controlled ignore+refresh üretir; disconnect yok.

### 12.4 Worker ve batch

- DB-backed queue/claim; yalnız memory timer otorite değildir
- multi-instance-safe lease + heartbeat/expiry
- bounded recipient snapshot ve delivery batch
- per-channel/provider rate limit
- retryable vs terminal error classification
- exponential backoff + max attempt owner policy
- poison item isolation
- cancellation check
- circuit breaker ve error-rate stop threshold
- restart/redeploy reconciliation
- progress/lag metrics

Scheduler tick campaign occurrence oluşturur; doğrudan push/WS broadcast etmez.

## 13. Hata ve sonuç sözleşmesi

### 13.1 Admin/campaign kodları

- `CONTENT_VARIANT_REQUIRED`
- `CONTENT_VALIDATION_FAILED`
- `TARGET_INVALID`
- `TARGET_ESTIMATE_STALE`
- `TARGET_COHORT_TOO_SMALL`
- `CAMPAIGN_REAUTH_REQUIRED`
- `CAMPAIGN_IDEMPOTENCY_CONFLICT`
- `CAMPAIGN_ALREADY_SUBMITTED`
- `CAMPAIGN_PARTIAL_FAILED`
- `CAMPAIGN_CANCEL_PARTIAL`
- `SCHEDULE_TRANSLATION_REQUIRED`
- `SCHEDULE_OCCURRENCE_ALREADY_CLAIMED`

### 13.2 User/delivery kodları

- `SYSTEM_MESSAGE_NOT_FOUND`
- `SYSTEM_MESSAGE_CURSOR_INVALID`
- `SYSTEM_MESSAGE_READ_CONFLICT`
- `SYSTEM_CTA_UNSUPPORTED`
- `SYSTEM_CTA_FORBIDDEN`
- `LOCALE_UNSUPPORTED`
- `DELIVERY_RETRYABLE`
- `PUSH_UNAVAILABLE`

İsimler uygulamadaki stable error registry ile kesinleştirilir. User-safe response raw Firebase/DB error, token, target list veya content dump taşımaz.

### 13.3 HTTP/retry semantiği

- 400/422 validation; otomatik retry yok
- 401/403 auth/permission; campaign submit yapılmaz
- 409 stale estimate/idempotency/state; read-back/review
- 413 content/target payload limit
- 429 bounded retry-after
- 5xx/network unknown write result; command status/read-back

Push provider 2xx/failed sonucu HTTP campaign success ile bir tutulmaz.

## 14. Güvenlik ve privacy

### 14.1 Targeting güvenliği

- Filter key/operator/value allowlist
- Parameterized queries ve bounded result
- Exact audience preview/confirm revision
- Small cohort privacy threshold
- Unauthorized cross-user target engeli
- Admin list/detail permission ayrımı
- Large/global send re-auth ve ikinci confirmation
- Target snapshot erişimi ve retention sınırlı

### 14.2 Content ve CTA güvenliği

- Plain text veya mevcut approved safe renderer
- No arbitrary HTML/script
- URL/action allowlist
- Unicode normalization ve control-character policy
- Backend/client/push consistent length limits
- Content hash ve immutable sent version
- Push payload secret veya sensitive full context taşımaz

### 14.3 Log/audit redaction

Yasak normal log/audit alanları:

- push token ve provider credential
- tam target user listesi
- full IP/GPS/location detail
- full message body/title gereksiz kopyası
- raw Firebase response/stack
- client auth/session token

Audit campaign/content hash, target filter summary, aggregate counts, actor/reason/time/idempotency ve result ref taşır. Yetkili recipient evidence açılışı ayrıca audit edilir.

### 14.4 Abuse ve operasyon

- Admin send/test/estimate/preview rate limitleri
- Global send concurrency limiti
- Per-user campaign flood/cooldown policy
- Batch error-rate stop
- Disabled Firebase/WS partial availability
- Test/prod environment isolation
- Kill switch campaign creation/delivery/read-only ayrımı

Limit değerleri owner/SLO/traffic kanıtıyla config olur; agent sayı uydurmaz.

## 15. Telemetry ve Jarvis sonuç modeli

### 15.1 Ölçüm birimleri

- campaign
- unique recipient user
- device delivery attempt
- active WS client
- persistent inbox item
- read recipient
- CTA use

Bu birimler birbirine karıştırılmaz. Örneğin iki cihaz push sent = iki recipient değildir.

### 15.2 Zorunlu breakdown

- source: instant/schedule/run-now/test
- target type
- TR/EN/fallback reason
- in-app persisted
- WS sent/delivered tanımı
- push attempted/sent/failed/invalid/skipped
- unread/read
- queued/in-progress/final
- sample/source/updatedAt

No data ve zero ayrılır. Partial failure completed gibi yeşil gösterilmez.

### 15.3 Content privacy

Analytics full title/body, target UUID list, token veya exact low-volume geo içermez. Stable campaign/message/action IDs ve coarse safe buckets kullanılır. Recipient drill-down analytics değil, yetkili operational evidence'tır.

## 16. Migration ve compatibility

### 16.1 Additive şema

- `system_message_campaigns`
- `system_message_recipients`
- gerekirse bounded delivery attempts/worker leases
- notification schedule locale content/status/occurrence identity
- push device locale/source/updatedAt gerekiyorsa
- indexes/unique constraints/retention metadata

Wave 04 migration runbook, Neon direct endpoint ve `search_path=public` doğrulaması kullanılır.

### 16.2 Legacy paths

- Current `admin_notice` event yalnız compatibility adapter olarak kalabilir; persistent campaign/message ID olmadan yeni send kabul etmez.
- Old single-language schedules `translation_required` olur; auto-run kapalı.
- Old push logs historical evidence olarak korunur; yeni campaign sonuçlarıyla sahte merge edilmez.
- Friend messages/conversations tablolarına fake system records backfill edilmez.
- Client feature capability yoksa message inbox'ta kalır; unsupported CTA gizlenir.

### 16.3 Deploy sırası

1. Additive migration ve read model
2. Locale/content resolver
3. Campaign/recipient write + worker capability-off
4. User inbox/read API
5. Admin preview/test/estimate
6. Client System UI
7. Internal/test cohort delivery
8. Schedule migration ve new pipeline
9. Legacy direct broadcast disable/deprecation

Destructive legacy cleanup yalnız usage zero, retention ve rollback kanıtından sonra ayrı onayla yapılır.

## 17. Dosya ve servis etki haritası

Uygulama başlangıcında güncel keşifle daraltılacak beklenen yüzey:

- `chatapp-backend/db.js` — campaign/recipient/delivery/schedule/device-locale migration'ı
- `chatapp-backend/index.js` — locale resolution, WS delivery, scheduler/worker wiring ve legacy notice adapter
- `chatapp-backend/admin.js` — notification/system target, preview, test, campaign, schedule ve result API
- `chatapp-backend/admin.html` veya ayrıştırılmış admin componentleri — QA-010/015 UI
- `chatapp-backend/utils/i18n.js` — locale normalization/source/fallback
- `chatapp-backend/utils/push.js` — localized per-device payload ve safe provider result
- `chatapp-backend/routes/push.js` — device locale snapshot/register refresh
- Yeni/ayrıştırılmış system inbox repository/service/routes
- Backend migration, locale, recipient, worker, pagination, read ve security testleri
- `chatapp-frontend/src/App.jsx` — system events, push deep-link, locale/dedupe/read sync
- `chatapp-frontend/src/api.js` — system summary/history/read/CTA API
- `chatapp-frontend/src/screens/FriendsScreen.jsx` — verified System row/unread
- `chatapp-frontend/src/screens/ChatScreen.jsx` veya ayrı `SystemChatScreen` — tek yönlü system history
- `chatapp-frontend/src/i18n/index.js`, `messages.tr.js`, `messages.en.js`
- `chatapp-frontend/src/utils/nativeBridge.js` — notification locale/deep-link/foreground behavior
- `chatapp-frontend/src/index.css`/`App.css` — mevcut temada system/admin responsive/a11y yüzeyleri
- Web/Android push, offline, multi-device ve accessibility E2E fixtures

Genel Friends/Chat redesign, Bildirim Tercih Merkezi veya analytics dashboard Wave 13 kapsamına girmez.

## 18. Uygulama sırası

1. Wave 12 kapanışını, üç Git bağlamını ve current locale/notification/push/friends flow'unu doğrula.
2. Wave 02 auth/security/admin, Wave 04 migration/worker ve Wave 06 geo/retention/deletion sözleşmelerini kanıtla.
3. Locale source priority, account/device/session/render/target ayrımı ve English fallback politikasını kilitle.
4. Ortak `contentByLocale` şema/limits/validation ve client translation parity gate'ini kur.
5. Notification schedule additive migration ve legacy `translation_required` guard'ını test-first tamamla.
6. QA-010 instant/schedule/run-now preview/estimate/test/confirmation akışını aynı pipeline'a taşı.
7. Campaign/recipient/delivery/lease şeması ve idempotency transaction'ını tamamla.
8. Target filter/source/estimate/snapshot ve privacy/re-auth güvenliğini tamamla.
9. System inbox summary/history/cursor/read API'lerini ve retention/deletion davranışını tamamla.
10. Multi-instance worker, batch/backoff/restart/cancel ve locale-aware WS/push attention layer'ını tamamla.
11. C-SYS-001 admin target/content/CTA/test/send/history/Jarvis result UI'sini tamamla.
12. A-SYS-001 verified Friends row, one-way conversation, unread/read, pagination, CTA ve deep-link UX'ini tamamla.
13. Old client/admin_notice/schedule compatibility ve capability rollout'unu doğrula.
14. Automatic, admin manual, Web/Android, multi-device, offline ve push-failure QA'yı tamamla.
15. Stable ID/QA evidence'ı kaydet ve Wave 14'ü başlatmadan dur.

## 19. Otomatik test planı

### 19.1 Locale ve içerik

- TR/EN/unknown/null/unsupported normalization ve English fallback.
- Profile/session/device/target/render locale source priority.
- Client başka user target locale/segment seçemiyor.
- Çoklu cihaz farklı locale ve aynı stable message/read identity.
- Locale değişimi WS, next push ve inbox render zamanlaması.
- Mixed-language title/body engeli.
- Missing variant global send block.
- Unicode/emoji/grapheme/limits ve content hash.
- Translation key parity, placeholder mismatch ve raw error code scan.
- Country ISO/display name ayrımı.

### 19.2 QA-010 notification/schedule

- Instant/scheduled/tick/run-now aynı content resolver ve pipeline.
- Global TR/EN completeness ve whitespace validation.
- Preview/test production recipient oluşturmuyor.
- Estimate user/device/WS/inbox/fallback counts source/time taşıyor.
- Stale estimate confirmation conflict.
- Single-language legacy schedule translation_required ve auto-run block.
- Timezone/DST skipped/ambiguous occurrence.
- Two scheduler workers tek occurrence claim ediyor.
- Run-now normal occurrence'ı duplicate tetiklemiyor.
- Retry same occurrence/campaign/delivery duplicate üretmiyor.

### 19.3 Campaign/recipient transaction

- Single/selected/locale/country/platform/activity/registration/all target fixtures.
- Invalid/excluded/uncertain/deletion-pending user counts.
- Geo source label ve unknown isolation.
- Filter allowlist/SQL injection/large target bounds.
- Double submit same idempotency key same campaign result.
- Same key different content/target conflict.
- Unique campaign+user recipient.
- Transaction failure partial recipient kümesini current send'e açmıyor.
- Worker restart/lease expiry/reclaim/poison item/circuit breaker.
- Cancellation yalnız eligible unclaimed items.

### 19.4 Inbox/read/pagination

- User yalnız own recipients/history görüyor.
- No fake user/profile/friendship/conversation rows.
- Stable cursor no gap/duplicate under concurrent insert.
- Offline/reinstall/second device persistent history.
- WS/push/history same ID dedupe.
- Read-through visible item; route open blind-read yok.
- Read idempotent/monotonic/multi-device sync.
- Push disabled/failed still inbox unread.
- Retention/deletion/pseudonymization ve deleted user worker exclusion.

### 19.5 CTA ve security

- Allowed internal actions and validated params.
- Unknown/arbitrary external/javascript/deep-link reject.
- Unsupported old client message visible, CTA safe hidden.
- CTA auth/legal/permission gate bypass etmiyor.
- Admin role/CSRF/re-auth/rate/global confirmation.
- Target/content/token/IP/geo/log redaction.
- Test/prod environment isolation.

### 19.6 Client ve accessibility

- System row absent before first real message, appears after delivery.
- Verified identity/logo/name/badge and SR label.
- No profile/block/remove/add/reply/typing controls.
- Loading/empty/offline/error/retry/pagination/end/new-message states.
- Unread badge, scroll behavior and background no-auto-read.
- Push cold/background/foreground deep-link once.
- Account switch/logout no cached data leak.
- TR/EN/long content/320 px/large text/keyboard/SR/reduced motion.
- Android back/reinstall/process recreation/multi-device.
## 20. Manuel QA matrisi

| Alan | Senaryo | Beklenen sonuç |
|---|---|---|
| Locale | TR profile/client/device | Inbox, WS ve push policy'ye göre doğru TR varyantı |
| Locale | EN profile/client/device | Bütün kanallarda doğru EN varyantı |
| Fallback | Null/invalid/unsupported | English ve ölçülen fallback reason |
| Multi-device | Aynı hesap TR ve EN cihaz | Policy'ye uygun varyant; tek message/read identity |
| Locale change | Açık WS + push device | Etki zamanı açık; mixed language yok |
| Instant | Global iki varyant | Preview/estimate/confirm sonrası tek campaign |
| Schedule | TR/EN daily + timezone | Correct occurrence; locale timezone'dan türemez |
| DST | Skipped/ambiguous local time | Belgelenmiş tek sonuç; duplicate yok |
| Run-now | Schedule çalıştır | Manual occurrence; normal tick'i iki kez üretmez |
| Legacy | Single-language schedule | Translation required; global auto-send yok |
| Estimate | User/device/WS/fallback | Source/time ve stale state görünür |
| Test | Kendime TR/EN | Yalnız test hedefi; production metrics yok |
| Target | Tek user | Ambiguous search çözülür; tek recipient |
| Target | Seçili users | Valid/invalid/excluded sayıları doğru |
| Target | Country+locale | Canonical country source; unknown ayrı |
| Target | Platform/activity/date | Boundary/timezone/eligibility doğru |
| Target | Everyone | Large audience re-auth/second confirm |
| Submit | Double click/response loss | Aynı campaign sonucu; duplicate yok |
| Worker | Restart/two instance | Lease ile tek recipient/delivery attempt |
| Partial | Firebase disabled/failure | Persistent inbox mevcut; push ayrı failed |
| Online | System conversation kapalı | Live item/attention policy; DB item aynı |
| Foreground | System conversation açık | Duplicate toast yok; listede tek message |
| Offline | Sonraki app açılışı | Persistent unread System item görünür |
| Friends | İlk gerçek system message | Verified TalkX Sistem row görünür |
| Identity | Profile/block/remove girişimi | Bu aksiyonlar yok/engelli; friend gibi davranmaz |
| One-way | System conversation | Composer yok; açık channel explanation |
| History | Çok sayfa + concurrent new | Cursor ile gap/duplicate yok |
| Read | Visible/read-through | Unread azalır; diğer cihaz sync olur |
| Push | Tap cold/background/foreground | Auth/legal sonrası doğru System route bir kez |
| CTA | Allowed internal action | Doğru localized label ve route |
| CTA | Unknown/external/old client | Mesaj kalır; CTA güvenle reddedilir/gizlenir |
| Deletion | Recipient user deleted | Policy uygulanır; yeniden push/worker target olmaz |
| Accessibility | Admin + Friends + conversation | Keyboard/SR/focus/large text/320 px çalışır |
| Security | Unauthorized admin/user | Target/history/evidence erişimi reddedilir |
| Summary | Completed/partial/queued | Inbox/WS/push/locale/read ayrı ve sayımla uyumlu |

## 21. Canonical kabul eşlemesi

### 21.1 B-I18N-001 — 6 kriter

- [ ] WS ve push aynı kullanıcıda yanlış dil üretmiyor.
- [ ] Çoklu cihaz kendi locale'iyle doğru içerik alıyor.
- [ ] Eksik varyant global gönderimde policy'ye göre engelleniyor.
- [ ] Fallback sayısı ölçülüyor.
- [ ] Locale client'ın yetkisiz hedef segmenti seçmesini sağlamıyor.
- [ ] Schedule/run-now/anlık aynı içerik sözleşmesini kullanıyor.

### 21.2 A-I18N-001 — 6 kriter

- [ ] TR/EN aynı feature sürümünde teslim.
- [ ] Teknik error code son kullanıcıya dökülmüyor.
- [ ] Eksik locale güvenli ve tek dilli fallback kullanıyor.
- [ ] Country code ile display name karıştırılmıyor.
- [ ] Uzun metin responsive düzeni bozmuyor.
- [ ] Prompt ID analitikte tam kullanıcı metni taşımıyor.

### 21.3 C-NOTIFY-001 — 9 kriter

- [ ] Master QA-010 kriterleri tamam.
- [ ] Global iki dil tamamlanmadan gönderilemiyor.
- [ ] Test production globale sızmıyor.
- [ ] Recipient estimate source/time taşıyor.
- [ ] WS/push aynı kullanıcı double success gibi sayılmıyor.
- [ ] Schedule timezone/DST açık.
- [ ] Run-now aynı schedule'ı tekrar tetiklemiyor.
- [ ] Retry duplicate delivery üretmiyor.
- [ ] User locale fallback sayısı görünür.

### 21.4 B-SYS-001 — 8 kriter

- [ ] Master QA-015 backend kriterleri tamam.
- [ ] Sahte user/friendship yok.
- [ ] Campaign retry recipient duplicate üretmiyor.
- [ ] Offline kullanıcı sonra inbox'ta görüyor.
- [ ] Read receipt çoklu cihazda toparlanıyor.
- [ ] Push başarısızlığı kalıcı mesajı kaybetmiyor.
- [ ] CTA allowlist ve locale fallback server'da doğrulanıyor.
- [ ] Hesap silme/retention politikası uygulanıyor.

### 21.5 C-SYS-001 — 9 kriter

- [ ] Master QA-015 admin kriterleri tamam.
- [ ] Kayıt ülkesi/son bilinen/IP tahmini source etiketi açık.
- [ ] Belirsiz geo kesin hedef gibi kullanılmıyor.
- [ ] Preview/test production recipient üretmiyor.
- [ ] Onay öncesi hedef/dil/kanal etkisi görünür.
- [ ] Campaign retry duplicate recipient değil.
- [ ] Kalıcı inbox sonucu push sonucundan ayrı.
- [ ] CTA allowlist ve permission açık.
- [ ] Gönderim sonrası temiz Jarvis özeti ve audit var.

### 21.6 A-SYS-001 — 7 kriter

- [ ] Master QA-015 kullanıcı-client kriterleri tamam.
- [ ] Sistem mesajı normal arkadaş hesabı gibi davranmıyor.
- [ ] Reply alanı yanlış vaat üretmiyor.
- [ ] Push yalnız dikkat katmanı; mesaj inbox'ta kalıcı.
- [ ] CTA dış URL güvenli açılıyor.
- [ ] Duplicate campaign recipient client'ta çift mesaj olmuyor.
- [ ] Read state cihazlar arasında toparlanıyor.

`CTA dış URL güvenli açılıyor` kriteri Master QA-015'in daha dar allowlist kuralıyla uygulanır: ilk sürüm serbest dış URL açmaz; unknown/dış URL güvenle reddedilir. Bu yorum canonical kriteri silmez ve yeni link yetkisi üretmez.

## 22. Master QA-010 kabul matrisi — 10 kriter

| # | Canonical kabul | Wave 13 kanıtı |
|---:|---|---|
| 1 | TR kullanıcı bütün kanallarda TR; EN kullanıcı EN varyantı alır | Locale resolver + WS/push/inbox integration |
| 2 | Null/geçersiz locale English fallback ve metriğe dahil | Fallback fixtures/summary reconciliation |
| 3 | Global send iki varyant ve confirmation olmadan çalışmaz; test globale sızmaz | Admin/API permission tests |
| 4 | Instant/schedule/run-now aynı locale/fallback fonksiyonunu kullanır | Shared pipeline contract tests |
| 5 | Locale değişiminin WS ve next push etki zamanı tanımlı | Multi-device/profile/device tests |
| 6 | Title/body limitleri tüm katmanlarda aynı; Unicode/emoji bozulmaz | Boundary/grapheme matrix |
| 7 | Android foreground/background/closed ve web online dili; tap/deep-link korunur | Web/Android E2E |
| 8 | DB/API/WS/push locale counts uzlaşır; duplicate/missing segment yok | Delivery ledger reconciliation |
| 9 | English fallback insan review'ı olmadan global değildir | Content approval/audit gate |
| 10 | Admin desktop/mobile variant, preview, estimate, loading/partial/stale/a11y QA | Visual/manual QA evidence |

## 23. Master QA-015 kabul matrisi — 18 kriter

| # | Canonical kabul | Wave 13 kanıtı |
|---:|---|---|
| 1 | Sahte user/friendship olmadan verified TalkX Sistem kaydı | DB invariant + Friends entity UI |
| 2 | Persistent history, unread, pagination ve multi-device read sync | Inbox/read/cursor integration |
| 3 | İlk sürüm tek yönlü; composer yerine kanal açıklaması | System conversation component QA |
| 4 | Tek/seçili/country/locale/platform/date/activity/everyone targets | Target filter/estimate/snapshot matrix |
| 5 | Geo source dürüst; unknown ayrı | Wave 08 country/source contract |
| 6 | TR/EN ve English fallback doğru locale'e gider | Resolver/channel E2E |
| 7 | Target/locale/push/inbox/unknown sayıları send öncesi görünür | Estimate UI/API reconciliation |
| 8 | Self-test, Web/Android preview ve final confirmation | Test isolation + visual QA |
| 9 | Campaign/recipient send öncesi güvenli oluşturulur | Transaction/worker evidence |
| 10 | Online anında, offline reopen'da aynı persistent message | WS/offline same-ID E2E |
| 11 | Push failure message'i kaybetmez ve ayrı raporlanır | Provider failure fixture |
| 12 | Reconnect/retry/double click/worker restart duplicate üretmez | Idempotency/concurrency suite |
| 13 | CTA yalnız allowed app target açar | Action registry/security tests |
| 14 | Sistem block/remove/profile gibi davranmaz | Client capability negative tests |
| 15 | Permission/audit/rate/batch/backoff/redaction var | Security/worker/audit suite |
| 16 | Result target/persisted/live/push/locale/read ayrımı taşır | Jarvis summary count parity |
| 17 | Retention/deletion tanımlı; ayrı preferences olmadan normal push izni ve persistent inbox | Wave 06 lifecycle + permission tests |
| 18 | Web/Android single/multi/segment/all/offline/multi-device/reconnect/push-error E2E | Cross-platform matrix |

Stable ID checkbox'ları yalnız kendi canonical kriterlerinin tamamı kanıtlandığında kapanır. QA-010 ve QA-015 master kayıtları ilgili tabloda tek açık satır varken tamam sayılmaz.

## 24. Kapsam dışı ve successor guard

- Wave 14 behavior analytics, dashboard, activity summary ve metric presentation
- Ayrı marketing/operations/critical notification categories
- Bildirim Tercih Merkezi, category mute veya unsubscribe ürünü
- Sistem hesabına reply veya “Destek ile konuş” ürünü
- Serbest dış URL, arbitrary deep-link, rich HTML veya script
- Advanced automation, template library, A/B test, multi-step journey
- Tahmine dayalı AI targeting/copy/summary
- Normal friend message/conversation tablolarına fake Sistem user/friendship
- Exact user location veya sensitive micro-targeting
- Production global/segment/test campaign veya schedule run-now
- Live recipient/token/content export
- Wave 14 uygulaması veya aktivasyonu

## 25. Risk ve rollback

| Risk | Koruma | Rollback/durma |
|---|---|---|
| Yanlış locale toplu gider | Content map + resolver + preview | Campaign delivery kill switch |
| Mixed TR/EN payload | Atomic variant selection | Affected channel disable |
| Unknown locale sessiz TR olur | Explicit English fallback/reason | Resolver fallback-only mode |
| Client locale segment yetkisi olur | Server target authority | Segment endpoint kapat |
| Legacy schedule tek dili globale yollar | translation_required block | Scheduler legacy pause |
| DST/run-now duplicate occurrence | Unique occurrence + lease | Schedule worker pause |
| Estimate yanlış audience gösterir | Revision/source/time + stale gate | Send confirmation kapat |
| Self-test production'a sızar | Environment/target isolation | Test delivery disable |
| Double click iki campaign üretir | Idempotency key | Create endpoint read-only |
| Worker restart duplicate recipient | Unique recipient + lease/CAS | Worker stop/reconcile |
| Push failure message'i kaybettirir | Persist before attention | Push channel disable |
| WS/push/history triple message | Stable ID client dedupe | Live event compatibility off |
| Read route open ile her şeyi okur | Visible read-through cursor | Read mutation disable |
| Fake system user friend akışını bozar | Discriminated system entity | System UI capability off |
| CTA arbitrary route açar | Server+client allowlist | CTA globally hide |
| Target list/token/IP log'a sızar | Redaction + access/audit | Evidence/detail access close |
| Deleted user tekrar hedeflenir | Eligibility + deletion policy | Worker stop/reconcile |
| Large campaign provider'ı boğar | Batch/rate/backoff/circuit breaker | Delivery pause |
| Old client unread/CTA loop yaşar | Capability/version fallback | Old-client live push off |
| Dirty repo işi örter | Üç Git snapshot'ı | Yalnız Wave 13 farkını geri al |

Persistent inbox'a yazılmış veya push edilmiş mesaj rollback ile yok olmuş gibi gösterilmez. Hatalı içerik owner kararıyla yeni düzeltme campaign'i ve açık audit oluşturur. Migration additive; rollback yeni tabloları destructive drop etmeye dayanmaz.

## 26. Rollout ve canlı destructive sınır

1. Product/Trust owner ilk sürüm tek message class ve no-preference sınırını imzalar.
2. Locale source priority, device/account davranışı, English fallback ve content limits onaylanır.
3. Additive şema/migration/restore isolated DB'de doğrulanır.
4. Locale resolver/content validation/schedule migration capability-off tamamlanır.
5. Campaign/recipient/inbox/read API synthetic users ile doğrulanır.
6. Worker WS/push providerları kapalı fake adapters ile idempotency/load testinden geçer.
7. Admin preview/estimate/self-test yalnız staging test account/cohort'a açılır.
8. Client verified System row/conversation Web/Android internal build'de açılır.
9. Push/deep-link multi-device ve offline E2E tamamlanır.
10. Small authorized staging cohort ile inbox, sonra WS, sonra push ayrı flaglerle açılır.
11. Schedule tick/run-now locale pipeline staging'de açılır.
12. Recipient lag, duplicate constraint, fallback, push failure, unread/read ve worker lease metrics izlenir.
13. QA-010/015 ve altı stable ID kullanıcı onayıyla değerlendirilir.

Production migration, target estimate query, test/campaign send, push, schedule run-now, feature flag, Firebase config veya deploy ayrıca exact target/impact/onay ister. “Kendime test” bile canlı hesaba dış etki olduğundan plan hazırlığı sırasında çalıştırılmaz.

## 27. Başlangıç kapısı

- [ ] Wave 01–12 QA kapanışları ve kullanıcı onayı doğrulandı.
- [ ] Kullanıcı açıkça “Wave 13'ü başlat” dedi.
- [ ] Root/backend/frontend Git snapshot'ı alındı.
- [ ] Wave 02 auth/security/admin/WS foundation gerçek kodda doğrulandı.
- [ ] Wave 04 migration/scheduler/multi-instance/backup runbook doğrulandı.
- [ ] Wave 06 country/geo/retention/deletion sözleşmeleri QA kapalı.
- [ ] Wave 10 stable identity/idempotency ilkeleri doğrulandı.
- [ ] Current locale/profile/client/device/push/schedule/admin notice flow yeniden envanterlendi.
- [ ] Profile/session/device/target/render locale source priority owner tarafından onaylandı.
- [ ] English fallback ve TR/EN content quality/approval policy'si onaylandı.
- [ ] Notification/System content limits ve safe renderer/CTA allowlist kilitlendi.
- [ ] İlk sürümde ayrı preference/category/reply olmayacağı doğrulandı.
- [ ] Campaign/recipient/delivery/read/worker şeması ve idempotency gözden geçirildi.
- [ ] Legacy single-language schedule migration/translation_required/rollback yolu kanıtlandı.
- [ ] Target filter/source/eligibility/small-cohort privacy matrisi onaylandı.
- [ ] Admin send/test/global permission, re-auth ve audit matrisi onaylandı.
- [ ] Synthetic TR/EN/fallback/geo/recipient/push/worker fixtures hazırlandı.
- [ ] Web/Android offline/push/deep-link/multi-device/a11y matrisi hazırlandı.
- [ ] Production recipient sorgusu veya herhangi bir gönderim yapılmayacağı doğrulandı.
- [ ] Wave 14 kapsamına taşma olmadığı doğrulandı.

## 28. Sonuç alanı

- Başlangıç/bitiş, refs ve gerçek değişen dosyalar
- Üç Git bağlamının önce/sonra farkı
- Final profile/session/device/target/render locale sözleşmesi
- TR/EN content envelope, limits, fallback ve translation parity kanıtı
- Schedule migration/translation_required/DST/occurrence idempotency sonucu
- Campaign/recipient/delivery/read/lease şeması ve migration/restore kanıtı
- Target filter/source/estimate/snapshot/confirmation sonucu
- Self-test isolation ve production recipient üretmeme kanıtı
- Worker batch/backoff/restart/cancel/circuit-breaker sonucu
- Persistent inbox/history/cursor/unread/read/multi-device sonucu
- WS/push/history same-ID delivery ve dedupe sonucu
- Push disabled/failure ile kalıcı message ayrımı
- CTA allowlist/unsupported old-client/deep-link güvenlik sonucu
- C-SYS-001 admin desktop/mobile/Jarvis result evidence paketi
- A-SYS-001 verified Friends row/one-way conversation/a11y paketi
- QA-010 locale/channel count reconciliation
- QA-015 target/persisted/live/push/read reconciliation
- Retention/deletion/redaction/audit kanıtı
- Syntax/lint/build/encoding/focused/full test exit code'ları
- Stable ID checkbox ve kullanıcı manuel QA onayı
- Production delivery/destructive işlemlerin yapılmadığı kayıt
- Wave 14'ün başlatılmadığı açık durma kaydı

## 29. Durma kuralı

Wave 12 QA kapanışı ve kullanıcının açık Wave 13 başlatma talimatı birlikte gelene kadar:

- Wave 13 için kod, test, dependency, migration, recipient/locale/token query, campaign, schedule, WS/push delivery, feature flag veya deploy değişikliği yapılmaz.
- Wave 13 `Aktif` işaretlenmez; belge yalnız `Hazır — aktif değil` kalır.
- Canonical `[ ]` maddeler kanıtsız kapatılmaz.
- QA-010 locale delivery ile QA-015 persistent Sistem message sonuçları birbirine karıştırılmaz.
- Production test/global/segment/user gönderimi ayrıca açık yetki olmadan yapılmaz.
- Wave 14 planı hazırlanmış olsa da aktive edilmez veya uygulanmaz.