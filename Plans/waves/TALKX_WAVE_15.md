# TalkX Wave 15 Plan — Profil ve Uygulama Raporu Operasyon Ekranları

> Bu belge yalnız Wave 15 için hazırlanmış uygulama planıdır.
> Canonical uygulama sırası Plan C `C-ADMIN-004 → C-ADMIN-005 → C-ADMIN-006` şeklindedir.
> Ana ilke: yönetici önce kimlik/durum, problem/etki, güvenilir kaynak ve güvenli sonraki aksiyonu görür; hassas ve teknik kanıt yalnız yetkili, bilinçli ve auditli ayrıntıda açılır.
> Plan hazırdır. Wave 15 aktif değildir, Wave 01–14 kapanmamıştır ve uygulama başlamamıştır. Wave 16 Release Health ayrı belgede planlanmıştır; burada uygulanmaz veya başlatılmaz.

## 1. Durum ve yürütme sınırı

- **Wave:** 15
- **Wave adı:** Profil ve uygulama raporu operasyon ekranları
- **Plan katılımı:** Plan C
- **Canonical sıra:** `C-ADMIN-004 → C-ADMIN-005 → C-ADMIN-006`
- **Plan durumu:** Hazır
- **Wave durumu:** Bekliyor
- **Uygulama durumu:** Başlamadı
- **Uygulama yetkisi:** Verilmedi
- **Giriş kapısı:** Wave 14 `QA kapalı` ve kullanıcıdan açık "Wave 15'i başlat" talimatı
- **Mevcut blokaj:** Wave 01–14 uygulanıp kapanmadı; Wave 15 uygulanamaz
- **Önceki wave:** Wave 14 — planı hazır, aktif değil
- **Sonraki wave:** Wave 16 — ayrı planı hazır; aktif değil ve başlatılmadı

Bu dosyanın hazırlanması Wave 15 aktivasyonu, kod/test/dependency değişikliği, migration, canlı DB/profile/report sorgusu, tam IP/device reveal, medya açma, ban/unban/friend/block/report mutation, archive/delete, feature flag, deploy veya Wave 16 aktivasyonu için yetki değildir.

## 2. Canonical referanslar ve otorite

1. `C-ADMIN-004` — Master QA-007 okunabilir, güvenli ve operasyonel profil listesi
2. `C-ADMIN-005` — Master QA-008 katmanlı profil detayı ve doğru veri anlamları
3. `C-ADMIN-006` — Master QA-009 problem/etki/kanıt/aksiyon odaklı Uygulama Raporları
4. Master `QA-007`, `QA-008` ve `QA-009` kabul kriterleri
5. Wave 02 `C-ADMIN-001/B-AUTH-001/B-OBS-001/B-SEC-002` — admin auth, RBAC, rate, CSRF/re-auth ve immutable audit temeli
6. Wave 04 `B-DB-001/C-OPS-001` — migration, DB runtime ve rollback kapısı
7. Wave 05 `B-PRES-001` — online/last seen gerçeği
8. Wave 06 `B-DATA-001/B-DATA-002/B-DATA-003/C-COMP-002/C-TRUST-002` — veri kaynağı, geo, retention, deletion ve compliance
9. Wave 10–11 `B-MSG-001/B-MSG-002/C-TRUST-001` — relationship, media ve moderasyon kanıtı
10. Wave 12 `B-AUTH-002/C-LEGAL-001` — session recovery, legal version/acceptance ve hesap sonucu
11. Wave 14 `B-ANL-001/C-ANL-001/C-ADMIN-002/C-ADMIN-003` — ortak admin state, source/time/freshness ve kanıta geri izleme
12. Wave 16 `B-OBS-002/C-REL-001` — sonraki Release Health kapsamı; Wave 15'e çekilmez
13. `A-A11Y-001/A-I18N-001/C-CI-001` — accessibility, TR/EN ve kalite kapıları

Çelişki çözümü:

- Liste response'u tam IP'yi varsayılan olarak taşımaz; CSS maskelemesi güvenlik değildir.
- Geo country/city yalnız canonical resolved source ve freshness ile gösterilir. Unresolved, stale ve provider error gerçek ülke değildir.
- Session `expires_at` gerçek logout/revocation/son kullanım değildir; "sona erme tarihi" diye etiketlenir.
- Friendship zamanı arkadaş kullanıcının `users.created_at` değeri değil, relation'ın `friendships.created_at/updated_at` alanıdır.
- "Bu kullanıcının engelledikleri" ile "bu kullanıcıyı engelleyenler" ayrı yönlerdir.
- `brevo_status` rapor çözüm durumu değildir; yalnız e-posta teslimidir.
- Rapor gruplaması deterministik, sürümlü, açıklanabilir ve geri alınabilir olur; benzer görünen kayıtlar zorla birleşmez.
- Kalıcı silme ana liste aksiyonu değildir; lifecycle, çözüm, archive ve retention önce gelir.
- Profil/moderasyon/report mutationları ortak hedef-etki-gerekçe-onay/re-auth/idempotency/audit sözleşmesini kullanır.
- Wave 15 toplu canlı işlem çalıştırmaz, gerçek hassas veri açmaz ve production migration/deploy yapmaz.

## 3. Wave sonucu

Wave 15 sonunda:

- Profil listesi kimlik, durum, konum ve aktiviteyi sakin bir hiyerarşiyle okutacak.
- Search/filter/sort/pagination server otoriteli, stable ve paylaşılabilir state taşıyacak.
- Selection sayfa/sorgu kapsamını açık gösterecek; bulk toolbar yalnız seçim olduğunda açılacak.
- Tam IP veya teknik kaynak liste payload/DOM'unda bulunmayacak; reveal/copy ayrı yetki, gerekçe ve audit isteyecek.
- Resolved/unresolved/stale/unknown geo durumları yanlış ülke üretmeden ayrılacak.
- Profil detayı özet, moderasyon, oturum-cihaz, legal-konum ve ilişkiler katmanlarına ayrılacak.
- Tarih, status, session, push device, friendship ve block yönleri kaynak alanına uygun etiketlenecek.
- Bir section endpointi hata verdiğinde diğer profil bölümleri korunacak ve yalnız sorunlu bölüm retry edilecek.
- Ban/unban/friend add-remove/unblock/delete gibi riskli aksiyonlar preview-confirm-result ve audit zinciri taşıyacak.
- Uygulama Raporları lifecycle durumu ile Brevo teslim durumu ayrılacak.
- Problem grupları deterministic fingerprint/version ile gerçek raporlara geri izlenecek; merge/split geri alınabilir olacak.
- Rapor listesi priority/status/impact/repeat/owner/action odaklı, server-side paginationlı olacak.
- Rapor detayı kullanıcı bildirimi, ortam, medya, teknik kanıt ve işlem geçmişini kademeli sunacak.
- Archive default reversible sonuç; hard delete yalnız retention/policy ve özel yetkiyle olacak.
- Desktop/mobile/a11y, uzun veri, partial endpoint, concurrency, XSS, media ve audit QA'i tamamlanacak.
- Wave 16 başlamayacak.

## 4. Doğrulanmış başlangıç fotoğrafı

### 4.1 Profil listesi

- `type=profiles` query'si username/display name araması, created/last_seen/username sort ve page/pageSize sağlıyor.
- Stable tie-breaker `u.id ASC` var; filtreler henüz yalnız metin aramasıyla sınırlı.
- Response registration IP, city/country/label/source/resolvedAt ve last platform taşıyor.
- UI `registration_ip + location_source` değerini `IP/Kaynak` kolonunda varsayılan gösteriyor.
- Sekiz kolon, fixed tablo/word-break ve satırdaki baskın Yasakla aksiyonu okunabilirlik/güvenlik riski.
- Bulk toolbar reports/bans/profiles için ortak; seçim yokken riskli eylemlerin görünmesi QA-007 ile çelişiyor.

### 4.2 Profil detayı

- Profil, registration, ilk/sessionlar ve push cihazları tek endpointten; blocks/friends ayrı endpointlerden geliyor.
- UI üç isteği `Promise.all` ile bağlıyor; biri hata verirse tüm modal hata oluyor.
- `sessions.expires_at` "Bitiş" diye etiketleniyor.
- Friends endpoint'i relation tarihleri yerine friend kullanıcının `users.created_at` değerini döndürüyor.
- Blocks endpoint'i yalnız blocker yönünü veriyor; başlık yönü belirsiz.
- Reports endpointi alınan/gönderilen rapor ve sayıları sağlıyor fakat mevcut detay UI tüketmiyor.
- Session ve push cihazı pipe listeleri; IP/device ID varsayılan açık.
- Add friend auditli transaction kullanıyor; remove friend ve unblock yollarında aynı audit/confirmation güvencesi görünmüyor.
- Modal focus trap, focus return, section state ve sticky identity contract'ı belirgin değil.

### 4.3 Uygulama Raporları

- `support_reports` subject/description/contact/user snapshot/environment/error/IP/user-agent/Brevo alanlarını taşıyor.
- Operasyon lifecycle status, priority, owner, note, resolution, archive veya revision alanları yok.
- Liste search ile en son 100 kaydı döndürüyor; total/pagination/grouping yok.
- Listedeki Durum yalnız `brevo_status`; çözüm/inceleme durumu değil.
- Detay bütün teknik alanları eş ağırlıklı gösteriyor; full IP/user-agent/Brevo ID/error varsayılan açık.
- `DELETE /support-report/:id` kalıcı silme yapıyor; görünür archive/retention/audit zinciri yok.
- Media content endpointi ve image/video preview var; permission, MIME, oversized/corrupt ve safe response header davranışı uygulamada yeniden kanıtlanmalı.
- Kullanıcı description ve teknik alanları escape ediliyor; yeni render yollarında XSS regresyonu engellenmeli.

### 4.4 Repo ve canlı sınır

- Root repo geniş silinmiş/untracked kullanıcı değişiklikleri taşıyor; bunlar korunur.
- Canonical uygulama yüzeyleri `chatapp-backend/`, `chatapp-frontend/` ve `docs/`; legacy dizinler değiştirilmez.
- Önceki geo cache notuna göre failed/unresolved lookup final ülke gerçeği olarak cache'lenmez; IP/source görünürlüğü yalnız yetkili admin ayrıntısında korunur.
- Plan aşamasında production profile, IP, device, session, relationship, report veya media verisi sorgulanmaz.
- Migration/backfill/index/retention, media erişimi, bulk mutation ve deploy ayrıca exact-target/impact/onay ister.

## 5. Ortak admin veri ve aksiyon sözleşmesi

### 5.1 Kaynak, zaman ve veri durumu

Her section/list response en az şunları taşır:

- `source`: logical table/view/provider
- `window/asOf`: sorgu zamanı ve timezone
- `dataThrough/lastSuccessfulAt`
- `freshness: fresh|stale|unknown`
- `completeness: complete|partial|not_available`
- `warnings` ve stable error code
- `revision`: optimistic concurrency ve stale-write koruması

Gerçek sıfır, boş, bilinmiyor, unresolved, stale, unauthorized ve endpoint error aynı `-` olarak sunulmaz.

### 5.2 Kimlik ve hassas veri sınıfları

- Public admin summary: username, display name, semantic account state, masked identity
- Operational: stable user/report/case ID, relation/status, timestamps ve source
- Sensitive: full IP, device ID, contact email, user-agent, Brevo message ID/error
- Content evidence: support description/media; yalnız iş amacı ve role uygun
- Secret: session token/hash, push token, credential/password; hiçbir admin response'unda gösterilmez

Liste endpointi sensitive değeri CSS ile saklamak yerine hiç döndürmez. Reveal endpointi field allowlist, permission, re-auth/policy, gerekçe, target, expiry ve immutable audit kullanır. Reveal sonucu DOM/cache/URL/log'da gereksiz kalmaz.

### 5.3 Ortak mutation envelope

Riskli eylem akışı:

`inspect → preview → confirm/re-auth → idempotent command → audit → result → targeted refresh`

Preview target identity, current state/revision, action, scope, direction, effect, reversibility, reason requirement ve conflict gösterir. Command `actionId/idempotencyKey/expectedRevision/reason` taşır. Double click/retry duplicate mutation üretmez.

Sonuç `success|no_op|conflict|partial|failed`, changed entities ve auditRef taşır. Audit başarısızsa güvenli policy belirlenmeden mutation sessiz başarılı sayılmaz. Bulk action her target için sonuç verir; yalnız toplam yeşil badge yeterli değildir.

### 5.4 Section dayanıklılığı

Liste, detail ve report sectionları bağımsız `idle/loading/refreshing/success/empty/stale/partial/error/unauthorized` state taşır. Refresh eski veriyi stale etiketiyle korur; filter revision değişince eski response yeni sorguya uygulanmaz. Retry yalnız başarısız section/provider'ı çağırır.

## 6. Profil listesi — C-ADMIN-004

### 6.1 Bilgi mimarisi

Desktop ana kolonları:

1. **Kullanıcı:** username, display name, platform ve kısa ID
2. **Durum:** active/banned/shadow/deletion pending gibi semantic badge
3. **Konum:** city + country; source/freshness ikincil
4. **Aktivite:** last seen ana, created ikincil
5. **İşlemler:** Detay ana eylemi, üç nokta menüsünde yetkili riskli işlemler

Tam IP, raw source string, bio/tags ve uzun teknik alan varsayılan tabloda bulunmaz. İnce row separator, kontrollü zebra/hover/focus ve ortak admin table tokenları kullanılır; ağır spreadsheet grid zorunlu değildir.

### 6.2 Profil liste API read model

Önerilen sürümlü response:

- identity: `userId/displayId/username/displayName`
- account: `status/banState/deletionState`
- activity: `lastSeenAt/lastPlatform/onlineState/source/asOf`
- location: `state/city/countryCode/countryLabel/source/resolvedAt/freshness`
- createdAt
- permissions: `canViewDetail/canRevealSensitive/canModerate`
- row revision
- pagination/filter/sort meta

`registrationIp` liste response'unda yoktur. Geo source ve network identity farklı alanlardır; display country client/admin TR/EN catalog'undan canonical countryCode ile gelir.

### 6.3 Geo dürüstlüğü

Location state:

- `resolved`: canonical country code ve source var
- `unresolved`: lookup tamamlandı fakat güvenilir sonuç yok
- `pending`: çözüm sürüyor
- `stale`: resolvedAt freshness politikasını aştı
- `provider_error`: geçici hata, final gerçek değil
- `not_available`: kaynak alan yok

Unresolved/provider error tekrar denenebilir; final resolved ülke diye cache'lenmez. City/country source ve resolvedAt kanıta geri izlenir. IP normalization/proxy source, geo country'nin içine metin olarak birleştirilmez.

### 6.4 Arama, filtre, sıralama ve pagination

Basit arama username/display name içindir. Advanced filtre adayları yalnız gerçek veri ve operasyon ihtiyacı varsa platform, country, account/ban state, online/last-seen range ve geo state'tir.

- Filter allowlist/server validation
- Active filter chips + tek tık temizleme
- URL/share state hassas veri içermez
- Sort allowlist; `aria-sort`, semantic icon ve insan etiketi
- Stable order: seçilen kolon + user ID tie-breaker
- Server-side total, shown range, page size, previous/next
- Out-of-range page empty sayfa yerine canonical son/geçerli state
- Refresh arama/filtre/sort/page'i makul biçimde korur
- Deleted/changed row pagination drift'i revision veya cursor policy ile açıkça ele alınır

### 6.5 Selection ve bulk toolbar

- Seçim varsayılan current page scope'udur.
- Checkbox accessible name kullanıcıyı tanımlar.
- Header select yalnız görünür/seçilebilir current page satırlarını seçer.
- "Tüm sonuçları seç" ilk sürümde yoksa vaat edilmez; varsa ayrı explicit query-snapshot sözleşmesi ister.
- Pagination sonrası selection korunacaksa seçili IDs ve stale/permission revalidation görünürdür; aksi durumda açıkça temizlenir.
- Bulk toolbar yalnız seçim olduğunda görünür.
- Selected count, page/query scope ve clear action görünür.
- 24s ban, permanent ban, shadow ban ve unban ayrı ad/etki/reversibility taşır.
- Bulk preview invalid/already-state/unauthorized targetları ayırır.
- Toplu canlı action production'da ayrıca açık yetki ister.

### 6.6 Satır aksiyonları

Detay satırın birincil eylemidir. Ban/shadow/unban gibi eylemler sürekli alarm rengiyle görünmez; overflow menüde semantic isim ve current state ile açılır. Riskli action preview hedef username + kısa ID, mevcut ban, süre/tür, reason, expected result ve audit koşulunu gösterir.

Row click ile checkbox/action çakışmaz. Klavye Enter/Space, menu arrow/Escape, focus return ve touch 44 px standardı uygulanır.

### 6.7 Responsive ve state

Geniş desktop tablo; dar desktop kontrollü yatay scroll ve kritik identity/action korunumu; mobilde sıkışmış sekiz kolon yerine summary card/row + expandable details kullanılır.

Fixture'lar: loading skeleton, no results, endpoint error, partial geo, unknown platform, invalid timestamp, deleted row, very long username/display/city/source ve permission denied. Truncation yalnız hover'a bağlı değildir; keyboard/touch accessible detail verir.

## 7. Profil detayı — C-ADMIN-005

### 7.1 Yüzey seçimi ve header

Nihai pattern güncel admin shell ile doğrulanacak responsive full-height drawer veya page detail'dir. Küçük, uzun ham modal kullanılmaz.

Sticky header:

- username + display name + masked/stable ID
- semantic account/ban/shadow/deletion badges
- last seen/platform
- close/back
- yetkiye göre `İşlemler` menüsü

Açılışta focus heading/close'a alınır; Escape ve visible close çalışır; dış click destructive form açıkken sessiz kapatmaz. Kapanınca focus aynı Detay düğmesine döner ve background scroll restore edilir.

### 7.2 Bölümler

1. **Profil Özeti:** kimlik, account state, created, last seen/platform
2. **Moderasyon:** received/sent reports, active/history bans/shadow, audit
3. **Oturumlar:** session kayıtları ve gerçek state semantics
4. **Push Cihazları:** session'dan ayrı device/delivery capability
5. **Yasal Kabul ve Konum:** document/version/acceptedAt, canonical geo source/freshness
6. **İlişkiler:** friends ve blocks iki yönlü
7. **Hassas/Teknik Kanıt:** yalnız yetkili reveal
8. **İşlem Geçmişi:** kim/ne zaman/niçin/sonuç

İlk ekran yalnız karar özeti; uzun listeler pagination veya `daha fazla yükle`; raw JSON varsayılan değildir.

### 7.3 Section API ayrımı

Profile shell/summary ile moderation, sessions, devices, legal/location, relationships ve audit logical providerları bağımsız state taşır. Tek birleşik endpoint kullanılacaksa section-level status/warnings içeren partial response zorunludur.

Mevcut `Promise.all` all-or-nothing davranışı kaldırılır. Bir section hata verince shell ve sağlıklı sectionlar görünür; retry yalnız hatalı section ve aynı user/revision içindir. User değişince önceki response yeni profile render edilmez.

### 7.4 Tarih ve session anlamı

- `users.created_at`: hesap kayıt zamanı
- `last_seen_at`: canonical presence sözleşmesindeki son görülme
- `sessions.created_at`: session oluşturulma zamanı
- `sessions.expires_at`: sona erme/son kullanma tarihi; logout değildir
- revokedAt/lastUsedAt yoksa active/revoked kesinliği uydurulmaz
- `push_devices.last_seen_at/updated_at`: push device tazeliği; session aktivitesi değildir
- `legal_acceptances.accepted_at`: belirli document/version kabul zamanı
- Tüm timestamp exact + timezone; uygun yerde relative; invalid/future açık warning

Session active ancak server authoritative revocation/expiry/last-use kuralı varsa gösterilir. Aksi hâlde `Aktiflik bilinmiyor`.

### 7.5 Friendship ve block yönü

Friends response relation'ın `friendships.created_at/updated_at/status`, counterpart user ve relation direction alanını döndürür; counterpart `users.created_at` friendship tarihi değildir. Duplicate yönlü rows canonical tek relation kuralıyla ele alınır.

Blocks ayrı listeler:

- Bu kullanıcının engelledikleri: blocker = profile user
- Bu kullanıcıyı engelleyenler: blocked = profile user

Her relation pagination, count, createdAt ve source taşır. Admin remove friend/unblock eylemi exact direction/row identity ve no-op/conflict semantiği kullanır.

### 7.6 Moderasyon özeti

- Received/sent report counts ve recent items ayrı
- Active ban/shadow state, type, reason, until, createdBy
- History gerekiyorsa lifecycle/audit kaynağı
- Son ilgili admin audit events
- Veri kaynağı ve count limit/pagination bilgisi
- User report ile support/app report birbirine karıştırılmaz

Farklı kaynak sayıları tek risk skoru gibi sessizce birleştirilmez. Deterministik risk özeti varsa tanımı/source'u görünür; yoksa ham sayılar olgusal sunulur.

### 7.7 Hassas reveal ve copy

Full IP, device ID, email/user-agent gibi alanlar masked özetle başlar. Reveal/copy:

- role permission ve gerekirse re-auth
- field/target allowlist
- zorunlu purpose/reason
- kısa görünürlük süresi ve explicit hide
- clipboard success/failure feedback
- immutable auditRef
- screenshot/print/export'ta otomatik açık kalmama
- URL, client log, analytics ve error report'a sızmama

Session/push token/hash hiçbir koşulda reveal edilmez.

### 7.8 Riskli profil aksiyonları

Ban/unban/shadow, manual friend add, friend remove, unblock ve account delete/request işlemleri okuma yüzeyinden görsel olarak ayrıdır.

Her action current state, exact target/direction, effect, duration, reason, reversibility, expected revision ve confirmation phrase/re-auth policy taşır. Add/remove/unblock audit parity kazanır. Account deletion Wave 06/12 canonical flow'unu bypass etmez; doğrudan tablo silme yoktur.

Başarı sonrası yalnız ilgili section refresh edilir; partial mutation veya notification failure ana DB sonucunu gizlemez. Conflict durumunda yeni state yüklenmeden retry yapılmaz.

### 7.9 Responsive ve accessibility

320 px, zoom, long username/device, çok session/friend/report ve empty state test edilir. Tabs/accordion/drawer keyboard, SR relationship, heading hierarchy, focus-visible, 44 px ve reduced motion sağlar. Teknik listeler pipe metni değil semantic row/definition list olur.

## 8. Uygulama Raporları — C-ADMIN-006

### 8.1 Ayrık durum kavramları

- `workflowStatus`: new, investigating, resolved, duplicate, insufficient_info, archived
- `priority`: explicit rule/manual decision; low, normal, high, critical ve reason
- `deliveryStatus`: Brevo pending/sent/failed; yalnız e-posta teslimi
- `evidenceState`: complete/partial/missing/unsafe
- `groupingState`: standalone/grouped/possible_match/conflict
- `retentionState`: active/archived/eligible_for_delete/legal_hold

UI "Durum" dediğinde workflow'u; "E-posta teslimi" dediğinde Brevo'yu gösterir. Sent e-posta resolved problem anlamına gelmez.

### 8.2 Lifecycle veri modeli

Gerekli additive model aktivasyonda kesinleştirilir:

- report üzerinde workflow status/priority/owner/revision/archive fields veya ayrı `support_report_workflow`
- immutable status/note/owner/priority/action history
- problem/case group identity ve fingerprint version
- group membership history: attach/detach/merge/split actor, reason, time
- resolution summary/code ve resolvedAt/by
- archive reason/at/by
- hard-delete eligibility/legal hold/retention decision
- auditRef

Serbest not ve kullanıcı açıklaması farklı amaçlıdır. Note append/edit policy ve geçmişi kaybetmeme kararı açık olmalıdır. Optimistic revision stale admin write'ını `409 conflict` ile durdurur.

### 8.3 Deterministik problem gruplaması

İlk sürüm AI zorunlu değildir. Fingerprint versioned normalized alanlardan kontrollü biçimde oluşabilir:

- canonical subject/category
- allowlisted normalized `last_error_code`
- platform ve gerektiğinde app release
- kontrollü zaman/cohort penceresi
- yalnız gerçekten ayrıştırıcı environment alanları

Description serbest metnini kör hash veya similarity ile otomatik birleştirmek yoktur. Yeterli kanıt yoksa standalone kalır. Possible matches öneri olabilir; insan confirm olmadan group truth olmaz.

Her grup:
- title ve deterministic rule explanation
- report count ve distinct affected user count
- firstSeen/lastSeen
- platform/release distribution
- evidence coverage
- priority/status/owner
- member report IDs ve filter/window
- last action

taşır. Yanlış grouping detach/split ile geri alınır; merge/split auditlidir. Fingerprint version değişimi geçmiş grupları sessizce yeniden yazmaz.

### 8.4 Priority ve Jarvis özeti

Priority yalnız açık rule veya admin kararıyla oluşur. Kural sinyalleri report rate, distinct users, critical error allowlist, new-release correlation ve evidence/media olabilir. Renk/his tek başına karar değildir.

Deterministik özet:

- **Sorun:** Olgusal, kaynak alanlara geri izlenir
- **Etki:** report/user count, first-last seen, platform/release
- **Tekrar:** group trend veya standalone
- **Durum:** workflow + owner + last action
- **Kanıt:** description/media/error ve coverage
- **Aksiyon:** incele, üyeleri gör, profile git, status/note güncelle, archive

Kanıt yetersizse `Sınıflandırılamadı/Bilgi yetersiz`; kök neden uydurulmaz. AI/LLM summary ayrı gelecekteki güvenlik/PII/cost/prompt-injection/human approval kararı olmadan yoktur.

### 8.5 Liste bilgi mimarisi

Varsayılan group/case listesi:

1. Problem title
2. Workflow status + priority
3. Impact: reports + distinct users
4. First/last seen ve trend
5. Platform/release
6. Owner/last action
7. Detay

Standalone report açıkça tekil kalır. Toggle ile raw reports görünümü olabilir; default ham kayıt değildir.

Filtreler: workflow, priority, owner, date, subject/category, error code, platform, app version, media, delivery status, user ve grouping state. Active filters görünür/temizlenebilir. Server total, shown range, page size, stable sort/tie-breaker ve cursor/page contract bulunur; sessiz 100 limit yoktur.

### 8.6 Rapor/grup detayı

Katmanlar:

- Üst özet: problem, status/priority, impact/repeat, first-last seen, owner/last action
- Kullanıcı bildirimleri: description ana kanıt, reporter/contact preference ve profile link
- Environment: platform, app version, device, network, error; common/outlier ayrımı
- Media evidence: güvenli gallery ve member/report relation
- Teknik kanıt: report ID, client/server time, masked IP/UA, delivery ID/error; default kapalı
- Group members: filters/pagination, attach/detach reason
- İşlem geçmişi: status/note/priority/owner/group/archive/delete audit

Silinmiş/anonim user ve boş email ayrı fallback'tir. Profile deep-link user mevcut ve permission uygunsa açılır.

### 8.7 Status, owner ve note işlemleri

- Allowed transition matrix server'dadır; örneğin archived doğrudan resolved anlamına gelmez.
- Status değişimi expectedRevision, reason/note ve audit taşır.
- Owner assignment known admin identity/role ile doğrulanır.
- Priority override reason ve source `manual` taşır.
- Note boş/oversize/XSS validated ve escaped; history append-only veya revisioned olur.
- Concurrent update `409` ile current state/diff döndürür; admin refresh/resolve eder.
- Success targeted section/list row refresh üretir.

### 8.8 Archive, retention ve hard delete

Archive reversible ve varsayılan listeden kaldıran operasyon state'idir; report/media kaydını silmez. Resolved ile archived ayrı kavramdır.

Hard delete:
- ana satır aksiyonu değildir
- retention/legal hold ve policy eligibility ister
- özel permission + re-auth + exact report/group/media scope
- geri döndürülemezlik ve backup/retention etkisi
- transaction ve audit
- partial media deletion bırakmama
- canlıda ayrıca açık kullanıcı yetkisi

Legacy DELETE route yeni UI'dan kaldırılır/deprecate edilir; compatibility sırasında yetkisiz sessiz kullanım engellenir.

### 8.9 Hassas teknik kanıt

Default summary/list/detail full IP, UA, contact email, Brevo ID/error göstermez. Masked değer ve `Teknik kanıtı aç` ayrı permission/reason/audit kullanır. User description ve Brevo error her render'da escaped kalır.

Client/server timestamp ayrı etiketli ve timezone görünürdür. Invalid/future client time sıralamayı tek başına belirlemez; server createdAt canonical chronology'dir.

### 8.10 Media güvenliği

- Media list metadata ve content permission ayrı doğrulanır.
- Report/group erişimi olmayan media ID doğrudan açılamaz.
- MIME allowlist, magic-byte/declared type kontrolü ve safe `Content-Type`
- `X-Content-Type-Options: nosniff`, güvenli disposition/cache policy
- Oversized/corrupt/unsupported file temiz fallback
- Image/video error ve loading state
- Autoplay yok; controls/caption/accessible name
- SVG/HTML/scriptable payload policy açık
- Download/reveal/copy gerekiyorsa audit
- Media report relation ve filename/size/type kanıtla uyuşur

### 8.11 Partial state ve responsive

Group summary, member reports, media, workflow history ve technical evidence bağımsız state taşır. Tek media veya delivery detail hatası kullanıcı description'ını yok etmez. Retry yalnız sorunlu section'ı çağırır.

Desktop/master-detail veya full drawer, mobil tek kolon. Long description/UA/error code overflow üretmez. Drawer/modal QA-008 focus/Escape/return/background lock standardını aynen tüketir.

## 9. API ve query sözleşmesi

### 9.1 Profil liste/detail

Logical endpointler aktivasyonda existing route compatibility ile kesinleştirilir:

- `GET /admin/profiles`
- `GET /admin/profiles/:userId/summary`
- `GET /admin/profiles/:userId/moderation`
- `GET /admin/profiles/:userId/sessions`
- `GET /admin/profiles/:userId/devices`
- `GET /admin/profiles/:userId/legal-location`
- `GET /admin/profiles/:userId/relationships`
- `GET /admin/profiles/:userId/audit`
- `POST /admin/profiles/:userId/sensitive-reveal`
- action preview/command endpointleri

Mevcut `/admin/data?type=profiles`, `profile-details`, `user-blocks`, `user-friends`, `user-reports` bir anda silinmez; sürümlü adapter/deprecation kullanır.

### 9.2 Rapor yüzeyleri

- `GET /admin/support-cases`
- `GET /admin/support-cases/:caseId`
- `GET /admin/support-cases/:caseId/reports`
- `PATCH /admin/support-cases/:caseId/workflow`
- `POST /admin/support-cases/:caseId/group-preview|merge|split`
- `POST /admin/support-cases/:caseId/archive|restore`
- `GET /admin/support-reports/:reportId/evidence`
- `GET /admin/support-report-media/:mediaId/content` güvenli compatibility
- hard delete yalnız ayrı policy endpoint/permission

Route isimleri ürün kararı değil logical contract'tır; uygulamada mevcut Express yapısına göre sadeleştirilebilir, anlam ve kanıt değişmez.

### 9.3 Query/pagination

Tüm listeler allowlist filter/sort, hard page size, stable tie-breaker, total veya hasMore, query/filter revision, asOf ve permission summary taşır. Geçersiz UUID/filter/cursor stable `400`; unauthorized `401/403`; not found `404`; stale write `409`; dependency unavailable `503`.

Search wildcard/query maliyeti rate/time cap taşır. Query response raw SQL/error/secret dökmez.

## 10. Migration, backfill ve compatibility

### 10.1 Additive değişiklik

Rapor lifecycle/grouping için yeni kolon veya tablolar:
- workflow/priority/owner/revision
- notes/history
- group/fingerprint version/membership history
- archive/retention/legal hold
- gerekli index/constraints

Additive ve forward-compatible olur. DB enum yerine versioned validated text/check kullanımı migration stratejisinde değerlendirilir. Foreign key/on-delete davranışı user anonymization ve report retention ile uyumlu olmalıdır.

### 10.2 Backfill

- Existing reports default `new` olabilir yalnız açık owner kararıyla; Brevo status'tan workflow türetilmez.
- Existing reports otomatik unsafe grouping ile birleştirilmez.
- Deterministic dry-run group candidates, collision/sample review ve count reconciliation üretir.
- Owner/priority bilinmiyorsa unknown/unassigned; uydurulmaz.
- Backfill idempotent, versioned ve rollback/forward-fix planlıdır.
- Production backfill ayrı açık yetki ister.

### 10.3 Compatibility sırası

1. Additive schema/migration dry-run
2. New read models ve sensitive field removal
3. Old/new profile/report response comparison
4. Workflow/grouping shadow calculation
5. New profile list/detail UI
6. New report list/detail/lifecycle UI
7. Legacy destructive control disable/deprecation
8. Canary admin QA
9. Eski route/render kaldırma yalnız kanıt/onayla

Liste response'undan full IP kaldırılması UI ve authorized detail reveal aynı release sırasıyla koordine edilir; güvenlik geri adımı olarak old payload'a dönülmez.

## 11. Güvenlik ve audit matrisi

| İşlem | Minimum koruma | Audit kanıtı |
|---|---|---|
| Profil görüntüle | Admin role | Gerektiğinde access log |
| Sensitive reveal/copy | Ayrı permission, reason, re-auth/policy | field/target/actor/time |
| Ban/shadow/unban | Preview, reason, expected state, confirm | before/after/result |
| Friend add/remove | Exact iki taraf/yön, block check, confirm | relation/result |
| Unblock | Exact blocker/blocked yönü, confirm | deleted/no-op relation |
| Account delete | Canonical deletion flow, re-auth, exact impact | request/result |
| Report status/owner/priority/note | Revision, validation, permission | before/after/reason |
| Group merge/split | Member preview, reason, reversible | membership diff |
| Archive/restore | Lifecycle policy, confirm | before/after |
| Hard delete | Retention/legal hold, special role, re-auth | report+media scope/result |
| Media view/download | Report permission, MIME policy | sensitive access policy |

Admin audit payload'ı secret/full content kopyası tutmaz; gerekli ID, decision, reason, count ve result ile sınırlıdır.

## 12. Dosya ve servis etki haritası

| Alan | Muhtemel hedef | Wave 15 işi | Sınır |
|---|---|---|---|
| DB | `chatapp-backend/db.js` veya migration modülü | Report lifecycle/group schema/index | Canlı migration yok |
| Admin API | `chatapp-backend/admin.js` ve ayrıştırılmış modüller | Profile/report read models/actions | Release Health yok |
| Support route | `chatapp-backend/routes/support.js` | Creation contract/group inputs | Client report UX redesign yok |
| Admin UI | `chatapp-backend/admin.html` veya testli modüller | List/detail/report IA/state | Yeni sidebar ürünü yok |
| Geo | mevcut location helpers/cache | Honest state/source/freshness | Yeni provider kararı yok |
| Media | report media endpoint | Auth/MIME/header/error | İçerik dönüştürme yok |
| Tests | backend/admin fixtures | Query/action/a11y/security | Wave 17 ortak CI yok |
| Docs/assets | API/runbook/manual QA | QA-007/008/009 evidence | Wave 16 uygulaması yok |

## 13. Uygulama sırası

1. Wave 14 QA kapanışı, açık başlangıç yetkisi ve Git snapshotlarını doğrula.
2. Master QA-007/008/009 ile 19 stable kriteri checklist'e sabitle.
3. Ortak data-state, sensitive classification ve mutation envelope kararlarını yaz.
4. Profile list read modelinden full IP'yi çıkar; authorized reveal contract'ını kur.
5. Geo state/source/freshness ile filter/sort/pagination/selection contract'ını tamamla.
6. Profil listesi desktop/mobile IA, contextual bulk ve row action menüsünü uygula.
7. Profil detail section API'lerini ve partial-state orchestration'ı kur.
8. Session/date/legal/location/friendship/block semantic hatalarını düzelt.
9. Moderation/report/audit summary ve sensitive reveal'i detail'e bağla.
10. Add/remove friend, unblock, ban/unban/delete action parity/idempotency/audit'i tamamla.
11. Report workflow/group/history additive schema ve migration dry-run'ını hazırla.
12. Deterministic grouping/priority read model ve reconciliation testlerini kur.
13. Report list/detail, filters/pagination, status/owner/note ve archive UI'ını uygula.
14. Technical evidence/media güvenliği ve hard-delete policy kapısını tamamla.
15. Focused backend/UI/security/a11y testlerini ve old/new comparison'ı çalıştır.
16. Full mevcut test, syntax/lint/build/encoding kapılarını çalıştır.
17. Desktop/mobile/manual endpoint/audit QA kanıtını topla.
18. Stable/QA checkbox'larını yalnız kanıt ve kullanıcı onayıyla kapat.
19. Wave 16'yı başlatmadan dur.

## 14. Otomatik test planı

### 14.1 Profil liste API

- Search normalization, empty/long/Unicode input
- Filter allowlist ve kombinasyonlar
- Sort allowlist, direction ve stable ID tie-breaker
- Page/pageSize bounds, total/range ve out-of-range
- Concurrent insert/delete ile pagination policy
- Resolved/unresolved/pending/stale/provider-error geo
- Unknown platform/status/date
- List payload/DOM'da full IP/device/email/secret yok
- Permissions ve row revision

### 14.2 Selection ve bulk

- No selection toolbar hidden
- Current page select all ve clear
- Disabled/unauthorized row exclusion
- Page/filter change selection policy
- Bulk preview exact target count/scope
- Mixed ban states ve per-target result
- Retry/double click idempotency
- Reason/re-auth/expected revision
- Partial/conflict/no-op
- Audit before/after/result

### 14.3 Profil detail semantics

- Profile not found/invalid ID
- Section independent loading/error/retry
- User switch stale response rejection
- expiresAt labeled expiration, not logout
- Revoked/active unknown without source
- Push device distinct from session
- Legal document/version/acceptedAt
- Geo source/freshness/unresolved
- Friendship true relation dates/direction
- Blocks both directions
- Report counts/recent/audit reconciliation
- Long/empty/invalid timestamps

### 14.4 Sensitive reveal ve aksiyon

- Role denied server-side
- Reason/re-auth/field allowlist
- Secret fields never revealable
- Expiry/hide/cache/URL/log behavior
- Clipboard feedback and audit
- Add/remove friend exact relation/no-op/conflict
- Unblock exact direction
- Ban/shadow/unban current/expected state
- Account deletion canonical flow guard
- Notification side-effect failure vs DB result

### 14.5 Report lifecycle/grouping

- Allowed/forbidden status transitions
- Brevo delivery independent from workflow
- Owner/priority/note validation
- Optimistic revision conflict
- Fingerprint normalization/version
- Same evidence groups; insufficient evidence standalone
- Collision/false-merge fixture
- Manual merge/split reversible and audit
- Member count/distinct user/first-last seen reconciliation
- Deleted/anonymous user fallback
- Server pagination/filter/sort/total
- No silent 100-row cap

### 14.6 Archive, hard delete ve media

- Archive/restore reversible; resolved distinct
- Legal hold/retention blocks delete
- Special permission/re-auth/reason
- Report+media transaction scope
- No partial orphan media
- Media ID access control
- MIME/magic byte/nosniff/disposition/cache headers
- Oversized/corrupt/unsupported/SVG policy
- Image/video error, autoplay off ve accessible name
- Description/error/note XSS escaping
- Masked IP/UA/Brevo technical evidence

### 14.7 UI ve regresyon

- Table header/row association, zebra/hover/focus
- Semantic sort icon + aria-sort
- Truncation keyboard/touch detail
- 320 px card/row, tablet, desktop
- Drawer focus trap/Escape/close/return/background lock
- Partial sections preserve healthy content
- Long username/device/description/error
- Empty/loading/stale/unauthorized/error states
- Backend syntax, focused/full tests
- Admin/frontend lint/build ve text encoding
- Existing auth/analytics/moderation/report submission regression
- No Wave 16 code/test preparation

## 15. Manuel QA matrisi

| Senaryo | Kurulum | Beklenen |
|---|---|---|
| Profil tarama | Normal page | Kimlik/durum/konum/aktivite hızla okunur |
| Long values | Uzun username/display/city | Kelime ortası bozulmaz; detail erişilebilir |
| Sort | Her sortable kolon | Icon/direction/aria-sort ve server order doğru |
| Search/filter | Birleşik filtre | Count/chip/clear/state doğru |
| Pagination | Çok sayfa | Total/range/page size/next-prev doğru |
| No selection | Liste ilk açılış | Bulk danger toolbar baskın değil |
| Bulk mixed | Farklı ban durumları | Target/scope/effect ve per-item sonuç |
| Full IP | Normal liste | Payload/DOM'da yok |
| Reveal | Yetkili/yetkisiz | Reason/re-auth/audit; server denial |
| Geo unresolved | Lookup başarısız | Gerçek ülke gibi görünmez |
| Mobile list | 320 px | Identity/action kaybolmaz; sekiz kolon sıkışmaz |
| Detail open/close | Keyboard/touch | Focus, Escape, return, scroll lock doğru |
| Partial detail | Friends endpoint hata | Diğer sectionlar görünür; local retry |
| Session meaning | Expiry kaydı | Sona erme; logout diye etiketlenmez |
| Friendship date | Bilinen relation | friendships tarihi gösterilir |
| Block direction | İki yönlü fixture | Engelledikleri/engelleyenler ayrık |
| Moderation | Reports/bans/audit | Source/count/current state uzlaşır |
| Friend/unblock | Mutation | Exact yön, confirm, audit, targeted refresh |
| Report workflow | Status/owner/note | Brevo'dan ayrı ve history auditli |
| Grouping | Similar/different reports | Deterministic doğru grup; false merge ayrılır |
| Report impact | Grup listesi | Count/users/first-last/platform/release doğru |
| Report pagination | 100+ kayıt | Eski kayıtlar erişilir; silent limit yok |
| Report detail | Full evidence | Problem/etki/kanıt/aksiyon önce |
| Anonymous user | Deleted user | Güvenli fallback, kırık profile link yok |
| Technical evidence | Default/reveal | Maskeli/kapalı; izinli auditli açılır |
| Media | valid/error/unauthorized | Güvenli preview ve fallback |
| Archive | Archive/restore | Reversible, auditli, delete değil |
| Hard delete | Ineligible/eligible | Policy/re-auth/scope/retention guard |
| XSS | Malicious description/note/error | Text olarak escape; script çalışmaz |
| Concurrency | İki admin revision | Stale update 409 ve refresh |
| Mobile/zoom | Detail/report 320 px | Taşma yok, aksiyonlar erişilebilir |

Production verisi, media, sensitive reveal veya mutation QA'i ayrıca açık exact-scope yetki ister. Normal doğrulama sentetik/local fixture ile yapılır.

## 16. Canonical kabul eşlemesi

### 16.1 C-ADMIN-004 — 6 kriter

| # | Canonical kabul | Wave 15 kanıtı |
|---:|---|---|
| 1 | Master QA-007 tamam | Section 18 matrisi ve manuel onay |
| 2 | Tam IP varsayılan görünmüyor | Payload/DOM/security test |
| 3 | Unresolved geo gerçek ülke değil | Geo state fixture |
| 4 | Pagination/sort backend ile stable | API/order comparison |
| 5 | Bulk ban liste taramasına gizlenmiyor | Contextual toolbar QA |
| 6 | Dar ekranda kritik kolon/aksiyon kaybolmuyor | 320 px QA |

### 16.2 C-ADMIN-005 — 7 kriter

| # | Canonical kabul | Wave 15 kanıtı |
|---:|---|---|
| 1 | Master QA-008 tamam | Section 19 matrisi ve onay |
| 2 | expires_at yanlış session bitişi değil | Semantic fixture/UI label |
| 3 | Friendship tarihi doğru tablodan | Relation API/DB test |
| 4 | Location source/unresolved/stale açık | Detail fixtures |
| 5 | Sensitive reveal auditli | Permission/reveal/audit test |
| 6 | Ban/unban/delete hedef-etki-onaylı | Action envelope tests |
| 7 | Default görünüm raw JSON değil | Detail screenshot/DOM |

### 16.3 C-ADMIN-006 — 6 kriter

| # | Canonical kabul | Wave 15 kanıtı |
|---:|---|---|
| 1 | Master QA-009 tamam | Section 20 matrisi ve onay |
| 2 | Email gönderildi sorun çözüldü değil | Ayrık status contract |
| 3 | Yanlış grouping ayrılabilir | Split/reconciliation/audit |
| 4 | Ham diagnostik isteğe bağlı/maskeli | Technical evidence tests |
| 5 | Destructive delete yerine archive/retention | Lifecycle/policy QA |
| 6 | Problem/etki/tekrar/aksiyon ilk görünümde | First viewport QA |

### 16.4 Stable ID kapanış checklist'i — 19 kriter

C-ADMIN-004:

- [ ] Master QA-007 kriterleri tamam.
- [ ] Tam IP varsayılan görünmüyor.
- [ ] Unresolved geo gerçek ülke gibi gösterilmiyor.
- [ ] Pagination/sort backend ile stable.
- [ ] Toplu ban liste taramasının içine gizlenmiyor.
- [ ] Dar ekranda kritik kolon ve aksiyon kaybolmuyor.

C-ADMIN-005:

- [ ] Master QA-008 kriterleri tamam.
- [ ] `expires_at` yanlış session bitişi olarak etiketlenmiyor.
- [ ] Friendship tarihi doğru tablodan.
- [ ] Location source/unresolved/stale açık.
- [ ] Hassas alan reveal auditli.
- [ ] Ban/unban/delete hedef-etki-onay taşıyor.
- [ ] Varsayılan görünüm ham JSON değil.

C-ADMIN-006:

- [ ] Master QA-009 kriterleri tamam.
- [ ] Email gönderildi ürün sorunu çözüldü demek değil.
- [ ] Yanlış grouping ayrılabilir.
- [ ] Ham diagnostik isteğe bağlı ve maskeli.
- [ ] Destructive delete yerine uygun archive/retention.
- [ ] Problem/etki/tekrar/aksiyon ilk görünümde.

Bu 19 madde yalnız otomatik kanıt, Master QA matrisi ve kullanıcı manuel QA onayı birlikte bulunduğunda `[x]` yapılır.

## 17. Master QA-007 kabul matrisi — 14 kriter

| # | Master kabul | Wave 15 kanıtı |
|---:|---|---|
| 1 | Header/data kolon ilişkisi, hover/focus/zebra/ayırıcı okunur | Visual/a11y QA |
| 2 | Grid/padding/height/font/contrast ortak tokenlarda | Design token review |
| 3 | Uzun değer kelime ortası bozulmaz; full değer keyboard/touch erişilir | Long fixture |
| 4 | Semantic sort icon, direction, aria-sort ve server order | Sort tests |
| 5 | Search clear/count/filters sade ve işlevsel | Filter QA |
| 6 | Bulk toolbar yalnız seçimle, scope ve pagination davranışı açık | Selection QA |
| 7 | Dört bulk ban/unban action hedef/etki/reason/reversibility taşır | Preview/audit |
| 8 | Tekil Yasakla baskın değil; current state/audit doğru | Row action QA |
| 9 | Full IP role/mask/audit kontrollü; geo source ile birleşmez | Security test |
| 10 | Pagination total/range/size/prev-next/loading ve state restore | API/UI test |
| 11 | Loading/empty/error/missing geo/unknown platform/invalid date/long fallback | Fixture matrix |
| 12 | Desktop/dar ekran/mobil priority layout doğru | Responsive QA |
| 13 | Keyboard/checkbox/menu/focus/SR/44 px | Accessibility QA |
| 14 | Before/after screenshot ve search/sort/page/detail/single/bulk regression | Evidence pack |

## 18. Master QA-008 kabul matrisi — 16 kriter

| # | Master kabul | Wave 15 kanıtı |
|---:|---|---|
| 1 | Header identity/display/status semantic | Detail screenshot |
| 2 | Label/value ayrık; empty/unknown/error farklı | State fixtures |
| 3 | Kademeli bölüm; ilk ekran karar özeti | IA QA |
| 4 | expires/created/lastSeen/updated/revocation anlamları doğru | Semantic tests |
| 5 | Friendship gerçek relation tarih/status/direction ve pagination | DB/API test |
| 6 | Session active expiry'den kesin varsayılmıyor | Unknown-state fixture |
| 7 | Push cihazı session'dan ayrı semantic | Device QA |
| 8 | Full IP/device masked; reveal/copy permission/audit | Security test |
| 9 | Moderation reports/ban/audit doğru source/count | Reconciliation |
| 10 | Friend add/remove/unblock okuma akışından ayrık, hedef/yön/reason/audit | Action tests |
| 11 | Ban/shadow/unban current/expected/re-auth korumalı | Action envelope |
| 12 | Bir section hatası tüm detail'i kapatmıyor | Partial test |
| 13 | Focus in/Escape/close/outside/return/background lock | Modal/drawer a11y |
| 14 | 320 px/zoom/long/many/empty taşmasız | Responsive QA |
| 15 | Desktop/mobile screenshots ve endpoint comparison | Evidence pack |
| 16 | Friend/block/moderation mutations audit dahil regresyonsuz | Functional evidence |

## 19. Master QA-009 kabul matrisi — 14 kriter

| # | Master kabul | Wave 15 kanıtı |
|---:|---|---|
| 1 | Workflow backend contract; Brevo yalnız E-posta teslimi | Schema/API/UI test |
| 2 | Summary/group gerçek reports/window/filter'a izlenir | Evidence refs |
| 3 | İlk sürüm deterministic; AI zorunlu/kaynaksız değil | Grouping rules |
| 4 | Priority explicit report/user/error/release/evidence rules | Priority fixtures |
| 5 | Liste/detail aynı localized terimleri kullanır | Dictionary test |
| 6 | Safe profile link ve anonymous/deleted/empty email fallback | Navigation QA |
| 7 | IP/UA masked/reveal auditli; content/error XSS safe | Security test |
| 8 | Hard delete ana action değil; lifecycle/archive/retention önce | UI/policy QA |
| 9 | Media error/size/MIME/unauthorized güvenli | Media tests |
| 10 | Client/server time, timezone ve invalid/future açık | Time fixtures |
| 11 | Loading/empty/partial/stale/retry section bazlı | State matrix |
| 12 | Drawer focus/Escape/return/scroll/mobile/long text standardı | A11y QA |
| 13 | Screenshots, group counts, filters/pages DB/API comparison | Evidence pack |
| 14 | Status/note/archive/delete/media permissions immutable auditli | Functional QA |

## 20. Başlangıç kapısı checklist'i

Wave 15 ancak bütün maddeler sağlandığında aktive edilir:

- [ ] Kullanıcı açıkça "Wave 15'i başlat" dedi.
- [ ] Wave 14 `QA kapalı` ve kullanıcı onaylı.
- [ ] Wave 01–14 kapanış belgeleri canonical dosyalarla senkron.
- [ ] Root, backend ve frontend Git snapshotları kaydedildi.
- [ ] Mevcut kullanıcı değişiklikleri ve exact Wave 15 kapsamı ayrıldı.
- [ ] Master QA-007/008/009 güncel satırları yeniden okundu.
- [ ] Profile/report current route/schema/UI envanteri kaydedildi.
- [ ] Wave 02 admin auth/RBAC/re-auth/audit temeli QA kapalı.
- [ ] Wave 05–12 presence/data/geo/trust/legal dependencies QA kapalı.
- [ ] Wave 14 ortak admin state/source/freshness standardı QA kapalı.
- [ ] Sensitive classification/reveal/copy owner kararı onaylandı.
- [ ] Profile mutation target/effect/reason/idempotency/audit policy onaylandı.
- [ ] Report workflow/status/priority/owner/note transitionları onaylandı.
- [ ] Deterministic grouping/fingerprint/reversible split kararı onaylandı.
- [ ] Archive/retention/hard-delete/legal-hold policy onaylandı.
- [ ] Migration/backfill exact target/impact/dry-run/rollback hazır.
- [ ] Production DB/media/reveal/mutation/deploy için gerekirse ayrı yetki alındı.
- [ ] QA-007/008/009 kanıt asset yolları doğrulandı.
- [ ] Focused/full test, lint/build/syntax/encoding komut envanteri doğrulandı.
- [ ] Wave 16 kapsamına taşma olmadığı doğrulandı.

Eksik kapı Wave'i Aktif yapmaz; somut blokaj sonuç alanına yazılır.

## 21. Kapsam dışı ve successor guard

Wave 15'e dahil değildir:

- Wave 16 Release Health ingestion, fingerprint, source-map/release rollup ve UI
- Wave 17 ortak CI zinciri
- Wave 18 Android release/store zinciri
- Yeni moderation ürünü, risk skoru veya otomatik yaptırım
- AI/LLM report summary/classification
- Yeni geo provider veya country ürün kararı
- Client support form UX redesign
- Serbest toplu tüm-sonuç seçimi ve yetkisiz bulk canlı action
- Session/push token, password/hash veya credential reveal
- Canlı full IP/device/description/media export
- Yetkisiz permanent delete
- Production migration/backfill/retention cleanup/deploy/restart

Wave 15 kapanışında Wave 16 için kod, test, refactor veya uygulama hazırlığı yapılmaz. Ayrı Wave 16 planı hazırdır; yine de yalnız açık kullanıcı talimatı ve Wave 15 QA kapanışıyla aktive edilebilir.

## 22. Risk ve rollback

| Risk | Erken sinyal | Koruma | Rollback/forward-fix |
|---|---|---|---|
| Full IP listede sızar | Payload/DOM içerir | Contract deny test | New list endpoint zorunlu; sensitive field kapalı |
| Geo yanlış ülke olur | unresolved country label | State/source/freshness | unresolved'a dön; retry cache |
| Pagination drift | duplicate/skip row | Stable tie-breaker/revision | Cursor/page contract fix |
| Bulk yanlış kapsam | page dışı hedef | Explicit scope/snapshot | Command stop; per-target audit |
| Session yanlış aktif | expiry gelecekte | Source-aware unknown | Label unknown/expiration |
| Friendship tarihi yanlış | user createdAt eşleşir | Relation field test | Endpoint adapter fix |
| Partial detail kapanır | tek request hata | Independent section | Hatalı provider off/retry |
| Mutation auditsiz | DB değişti audit yok | Transaction/policy gate | Action disable ve incident review |
| Brevo resolved görünür | sent badge workflow'da | Ayrık enums/labels | Workflow unknown/new |
| False report grouping | farklı problem birleşir | Standalone default/split | Detach/split + audit |
| Stale write ezer | iki admin update | Revision/409 | Reload/resolve |
| Hard delete kayıp | report/media geri yok | Archive first/legal hold | Route disable; backup/incident |
| Media exploit | MIME/script payload | Auth/allowlist/nosniff | Preview/download off |
| XSS | description/note executes | Escape/CSP tests | Renderer rollback |
| Dirty repo işi örter | unrelated diff | Exact snapshot | Yalnız Wave 15 farkını geri al |

Additive migration kolonları acele drop edilmez; reader/writer compatibility ve forward-fix tercih edilir. Production rollback ayrıca açık yetki ister.

## 23. Rollout ve canlı destructive sınır

Ayrı kullanıcı yetkisi isteyen işlemler:

- production profile/report/IP/device/session/relation sorgusu
- sensitive reveal veya media açma/download
- ban/unban/shadow/friend/unblock/account action
- bulk action
- report status/owner/note/group/archive mutation
- hard delete veya retention cleanup
- schema migration/index/backfill
- feature flag/canary/Render-Neon config/restart/deploy

Yetki öncesi exact environment/database/service, target IDs/query/filter snapshot, row/media count, effect/reversibility, lock/performance/privacy etkisi, backup/rollback, audit ve durma koşulu raporlanır. Plan hazırlığı bunları yetkilendirmez.

## 24. Sonuç/evidence alanı

Wave 15 yürütüldüğünde en az:

- başlangıç/final Git snapshotları ve exact changed files
- schema/migration/backfill dry-run ve canlı onay kaydı
- old/new profile/report response comparison
- sensitive field payload/DOM/reveal/audit kanıtı
- geo state/source/freshness kanıtı
- sort/filter/pagination/selection/bulk result kanıtı
- session/friendship/block/legal semantic comparison
- section partial failure ve targeted retry kanıtı
- mutation preview/idempotency/conflict/audit kanıtı
- report workflow vs Brevo ayrımı
- grouping collision/merge/split/count reconciliation
- archive/retention/hard-delete guard ve media security
- focused/full test, syntax/lint/build/encoding exit code'ları
- QA-007/008/009 desktop/mobile/a11y screenshots
- canonical checkbox ve kullanıcı manuel QA onayı
- production destructive işlemlerin yapılmadığı veya exact onayla yapıldığı kayıt
- Wave 16'nın başlatılmadığı açık durma kaydı

Kriter yalnız kanıtla `[x]` olur. Kısmen/görünüşe göre veya yalnız kod incelemesi manuel QA yerine geçmez.

## 25. Durma kuralı

Wave 14 QA kapanışı ve kullanıcının açık Wave 15 başlatma talimatı birlikte gelene kadar:

- Wave 15 için kod, test, dependency, migration, backfill, production query, reveal/media, mutation, feature flag veya deploy değişikliği yapılmaz.
- Wave 15 `Aktif` işaretlenmez; belge yalnız `Hazır — aktif değil` kalır.
- Canonical `[ ]` maddeler kanıtsız kapatılmaz.
- Unresolved geo gerçek ülke, expiry logout, Brevo sent resolved olarak sunulmaz.
- Hassas veri veya destructive action yalnız UI gizlemesiyle korunmaz.
- Wave 16 planı ayrı dosyada hazırdır; Wave 16 aktive edilmez veya uygulanmaz.
