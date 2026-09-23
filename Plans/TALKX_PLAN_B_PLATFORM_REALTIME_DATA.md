# TalkX Plan B — Platform, Realtime & Data

> TalkX backend, API, WebSocket, matchmaking ve PostgreSQL veri sözleşmelerinin canonical uygulama planı.
> Kaynak envanter: `docs/TALKX_MASTER_BACKLOG.md`.
> Bu plan hazırdır; hiçbir uygulama wave'i başlamamıştır.

## 1. Belge rolü ve otorite

Bu belge kullanıcı ve admin yüzeylerinin güvendiği platform davranışının ana otoritesidir. Frontend veya admin sonucu tahmin etmez; backend gerçek durum, zaman, kimlik, hata ve veri tazeliğini açık sözleşmeyle taşır.

Master backlog ham bulgu ve QA brieflerini korur. Bu belge backend/data işini stable ID'lere dönüştürür. Wave'ler burada yazılı davranışı yeniden açıklamaz; ilgili ID ve kabul kriterlerine yönlendirir.

Otorite sırası:

1. `TALKX_MASTER_BACKLOG.md` kilitli ürün kararları ve QA kanıtı
2. Bu belgedeki Plan B platform sözleşmeleri
3. Plan A kullanıcı sunumu ve Plan C admin/operasyon tüketici sözleşmeleri
4. `TALKX_WAVE_MAP.md` ve hazırlanmış `waves/TALKX_WAVE_NN.md` dosyaları; plan dosyasının varlığı aktivasyon değildir
5. Kod, migration, otomatik test ve canlı doğrulama kanıtı

Çelişki çıkarsa frontend workaround veya wave içi yeni karar üretilmez; canonical plan düzeltilir.

## 2. Plan durumu ve sınırı

- **Plan durumu:** Hazır
- **Uygulama durumu:** Başlamadı
- **Wave Map durumu:** Hazır
- **Hazırlanmış Wave Planları:** Wave 01 — `waves/TALKX_WAVE_01.md`; Wave 02 — `waves/TALKX_WAVE_02.md`; Wave 03 — `waves/TALKX_WAVE_03.md`; Wave 04 — `waves/TALKX_WAVE_04.md`; Wave 05 — `waves/TALKX_WAVE_05.md`; Wave 06 — `waves/TALKX_WAVE_06.md`; Wave 07 — `waves/TALKX_WAVE_07.md`; Wave 08 — `waves/TALKX_WAVE_08.md`; Wave 09 — `waves/TALKX_WAVE_09.md`; Wave 10 — `waves/TALKX_WAVE_10.md`; Wave 11 — `waves/TALKX_WAVE_11.md`; Wave 12 — `waves/TALKX_WAVE_12.md`; Wave 13 — `waves/TALKX_WAVE_13.md`; Wave 14 — `waves/TALKX_WAVE_14.md`; Wave 15 — `waves/TALKX_WAVE_15.md`; Wave 16 — `waves/TALKX_WAVE_16.md`; Wave 17 — `waves/TALKX_WAVE_17.md`; Wave 18 — `waves/TALKX_WAVE_18.md`; Wave 19 — `waves/TALKX_WAVE_19.md` — on dokuz plan da hazır, aktif değil
- **Uygulama wave'i:** Başlamadı
- **Birincil alan:** Backend / API / WebSocket / Matchmaking / PostgreSQL / veri yaşam döngüsü
- **Ana repo alanı:** `chatapp-backend/`
- **Bağlı planlar:** Plan A — Product & Client Experience; Plan C — Admin, Trust & Release

Bu plan:

- Backend güvenliği,
- Event ve API şemaları,
- Auth/session,
- Realtime bağlantı,
- Matchmaking,
- Mesaj/presence/push teslimi,
- DB migration ve retention,
- Analitik veri sözleşmesi,
- Backend test ve canlılık kapılarını

tanımlar.

Bu plan kullanıcı ekranının kompozisyonunu, admin bilgi hiyerarşisini veya release sırasını sahiplenmez.

## 3. Bağlayıcı platform ilkeleri

- Frontend `queued`, `matched`, teslim, read, presence veya legal sonucu tahmin etmez.
- Her retry/reconnect akışı idempotent veya açıkça reddedilebilir olmalıdır.
- Aynı kullanıcı için çelişkili active search/room/session state'i bırakılmaz.
- Event payloadları schema/allowlist ile doğrulanır.
- Teknik error code kararlı; kullanıcı metni locale katmanında güvenli üretilir.
- Tam IP, token, şifre, mesaj metni ve medya içeriği gereksiz telemetry/log'a girmez.
- Mevcut tek bellek içi queue davranışı çoklu instance güvenilirliği varmış gibi sunulmaz.
- PostgreSQL değişiklikleri sürümlü migration, rollback ve veri doğrulaması olmadan canlıya uygulanmaz.
- Neon için direct endpoint ve `search_path=public` doğrulama/runbook kuralı korunur.
- `ensureTables()` boş DB açabilir fakat migration geçmişi yerine kalıcı çözüm sayılmaz.
- Global varsayılan; COUNTRY kesin ve ayrı queue'dur.
- `legal_acceptances.location_country` tarihsel serbest metin snapshot'tır; canonical matchmaking ülkesi değildir.
- Düşük örnek, veri yok, stale ve partial error gerçek sıfır/başarı gibi raporlanmaz.
- Ayrı talimat olmadan sonraki plan maddesi veya wave uygulanmaz.

## 4. Stable ID ve wave referans kuralı

Plan B kimlik alanları:

- `B-SEC-*`: güvenlik ve abuse sınırları
- `B-API-*`: API/error/health sözleşmeleri
- `B-AUTH-*`: session ve legal backend
- `B-WS-*`: bağlantı ve realtime state
- `B-MM-*`: matchmaking
- `B-PRES-*`: presence
- `B-MSG-*`: mesaj ve medya
- `B-SYS-*`: TalkX Sistem altyapısı
- `B-I18N-*`: locale ve teslimat varyantı
- `B-DB-*`: migration/backup/DB runtime
- `B-DATA-*`: veri yaşam döngüsü
- `B-ANL-*`: davranış/performance veri sözleşmesi
- `B-OBS-*`: log/telemetry/release kimliği
- `B-QA-*`: backend kalite kapıları

Plan haritasındaki `Birincil bağımlılık` sütunu yalnız wave sıralamasında önce kapanması gereken ID'leri gösterir. `Çapraz plan sözleşmeleri` tablosundaki sağlayıcı/tüketici ilişkileri bağımlılık değildir; bağlı ID'ler aynı wave'de veya ardışık wave'lerde birlikte doğrulanabilir.

## 5. Plan haritası

| ID | Sonuç | Master/QA kaynağı | Birincil bağımlılık | Durum |
|---|---|---|---|---|
| B-SEC-001 | WebSocket/API input ve origin güvenliği | Master §8 | — | [ ] |
| B-SEC-002 | Rate limit ve abuse katmanı | Master §8/§9 | B-SEC-001 | [ ] |
| B-API-001 | Sürümlü schema/error sözleşmesi | Master §8 | B-SEC-001 | [ ] |
| B-API-002 | Health/readiness/release kimliği | Master §8/§12 | B-OBS-001 | [ ] |
| B-AUTH-001 | Session ve çoklu cihaz yaşam döngüsü | Master §7/§8 | B-SEC-001 | [ ] |
| B-AUTH-002 | Legal reaccept backend sözleşmesi | Master §7, QA-013 | C-LEGAL-001 | [ ] |
| B-WS-001 | Authenticated socket ve bağlantı sahipliği | Master §8 | B-AUTH-001 | [ ] |
| B-WS-002 | Reconnect ve active-state recovery | QA-001/014/017 | B-WS-001 | [ ] |
| B-MM-001 | QA-014 search lifecycle | QA-014 | B-WS-002 | [ ] |
| B-MM-002 | QA-017 Global/Country matching | QA-017 | B-DATA-002, B-MM-001 | [ ] |
| B-MM-003 | QA-003 pending offer protokolü | QA-003 | B-MM-001 | [ ] |
| B-PRES-001 | QA-001 gerçek presence/last seen | QA-001 | B-WS-001 | [ ] |
| B-MSG-001 | Mesaj idempotency ve outbox | Master §7/§8 | B-API-001 | [ ] |
| B-MSG-002 | Tek kullanımlık medya yaşam döngüsü | Master §7/§8/§10 | B-DATA-001 | [ ] |
| B-SYS-001 | QA-015 Sistem inbox ve teslim altyapısı | QA-015 | B-DB-001, B-I18N-001 | [ ] |
| B-I18N-001 | Locale çözümü ve çok dilli teslimat | QA-010/015 | B-API-001 | [ ] |
| B-DB-001 | Sürümlü migration ve DB runtime | Master §10 | B-API-002 | [ ] |
| B-DATA-001 | Retention ve veri sahipliği matrisi | Master §10 | B-DB-001 | [ ] |
| B-DATA-002 | Canonical matchmaking country | QA-017 | B-DB-001 | [ ] |
| B-DATA-003 | Hesap silme ve anonimleştirme | Master §9/§10 | B-DATA-001 | [ ] |
| B-ANL-001 | Davranış analitiği event/rollup sözleşmesi | QA-012 | B-DB-001 | [ ] |
| B-ANL-002 | Performance/SLO veri sözleşmesi | QA-011 | B-OBS-001 | [ ] |
| B-OBS-001 | Structured logging ve hassas veri maskesi | Master §8 | B-SEC-001 | [ ] |
| B-OBS-002 | Release Health ingestion adaptörü | QA-016 | B-API-002 | [ ] |
| B-QA-001 | Unit/integration/two-client kalite kapıları | Master §11 | B-API-001, B-DB-001, B-WS-001 | [ ] |

## 6. B-SEC-001 — WebSocket ve API input güvenliği

**Amaç:** İnternet yüzeyindeki bütün HTTP ve WebSocket girdilerini doğrulanmış ve sınırlı hâle getirmek.

**Kapsam:**

- Token olmadan guest/legacy fallback kararı
- WebSocket `maxPayload`
- Mesaj ve serbest metin maksimum uzunluğu
- Event type/payload schema
- Origin ve native/no-origin politikası
- Header/CORS güvenliği
- Güvenli JSON parse ve bilinmeyen event
- Dependency riskleri: `ws`, `multer`, `express-rate-limit` ve internet yüzeyi paketleri
- Hassas hata ayrıntısının client'a sızmaması

**Kabul kriterleri:**

- [x] Token gerektiren event guest bağlantıda çalışmıyor.
- [x] Bilinmeyen veya fazla alanlı payload kontrollü reddediliyor.
- [x] Aşırı payload bağlantı/servis belleğini tüketmiyor.
- [x] Anonim ve direkt mesaj uzunluğu server'da uygulanıyor.
- [x] TalkX origin ve izinli native bağlam dışında CORS açık değil.
- [x] Security header ve `x-powered-by` kararı uygulanmış.
- [ ] Dependency güncellemesi davranış testiyle yapılmış.
- [ ] Hata log'u token/mesaj/şifre taşımıyor.

## 7. B-SEC-002 — Rate limit ve abuse sınırları

**Amaç:** Proxy arkasında gerçek kullanıcıyı yanlış ayırmadan HTTP/WS kötüye kullanımını sınırlamak.

**Kapsam:**

- Render proxy/trust proxy doğrulaması
- Origin, IP, kullanıcı, cihaz ve bağlantı boyutları
- Auth denemesi
- Join/leave/scope değişimi spam'i
- Mesaj ve medya gönderimi
- Rapor/destek
- Sistem mesajı ingestion
- Admin brute force Plan C bağlantısı
- Shadow ban ve normal ban semantiği

**Kabul kriterleri:**

- [x] NAT altındaki tüm kullanıcılar tek kişi gibi engellenmiyor.
- [x] IP değiştirmek kullanıcı/device limitini tamamen aşmıyor.
- [x] Limit sonucu kararlı error code ve retry zamanı veriyor.
- [x] Scope tıklama spam'i birden fazla queue entry üretmiyor.
- [x] Rate-limit log'u tam hassas IP'yi gereksiz saklamıyor.
- [x] Admin ve public limitleri ayrı policy.

> **Wave 02 kanıtı (2026-09-23):** Auth/public/support/admin/WS ayrı policy ve pseudonymous key kullanıyor; user/device/session/connection boyutları, event-cost, side-effect öncesi kontrol, TTL/eviction/max-key ve `RATE_LIMITED + retryAfterMs` odaklı testlerle doğrulandı. Render gerçek header zinciri canlı değişiklik yapılmadan Wave 19 staging QA'ya ertelendi.

## 8. B-API-001 — API/event schema ve hata sözleşmesi

**Amaç:** Frontend ve adminin string/error tahmini yapmasını bitirmek.

**Kapsam:**

- HTTP request/response schema
- WebSocket event version
- Kararlı `errorCode` ve güvenli metadata
- Unknown/stale/partial state
- Pagination/cursor
- Idempotency key
- Server time
- Capability/config
- Eski client geriye uyumu
- `index.js` sorumluluklarının test altında ayrılması
- Tekrarlanan auth middleware merkezileştirme

**Kabul kriterleri:**

- [ ] Kritik endpoint/eventler sürümlü schema'ya sahip.
- [x] Client metni backend İngilizce error string'ine bağlı değil.
- [ ] Stale ve not-found ayrılıyor.
- [x] Retry edilebilir hata açık.
- [ ] Pagination stable ordering kullanıyor.
- [x] Eski client capability yokken temel akışını koruyor.
- [x] Büyük modül ayrımı test olmadan yapılmıyor.

> **Wave 02 Sale Release kanıtı (2026-09-23):** HTTP hata envelope'u `schemaVersion/errorCode/message/retryable/requestId/serverTime` ve legacy `code/error` alias'larıyla; WS envelope'u event kimliği ve capability handshake'iyle uygulandı. Client `errorCode` + locale kataloğunu tüketiyor. Enterprise pagination/cursor ve geniş success-schema framework'ü roadmap olarak açık bırakıldı.

## 9. B-API-002 — Health, readiness ve release kimliği

**Amaç:** `process çalışıyor` ile `servis trafik alabilir` durumunu ayırmak.

**Kapsam:**

- Liveness
- PostgreSQL'i kontrol eden readiness
- Deploy commit SHA
- Backend app version
- Ortam/staging-production ayrımı
- Bağımlılık timeout'u
- Hassas config göstermeyen response
- Render restart/deploy doğrulaması

**Kabul kriterleri:**

- [ ] DB ulaşılamıyorsa readiness başarısız.
- [ ] Liveness kısa DB sorunu yüzünden process restart döngüsü yaratmıyor.
- [ ] Commit/version gerçek deploy ile eşleşiyor.
- [ ] Credential veya connection string response'a çıkmıyor.
- [ ] Plan C release kaydı health cevabıyla doğrulanabiliyor.

## 10. B-AUTH-001 — Session ve çoklu cihaz yaşam döngüsü

**Amaç:** Login, logout, password change ve çoklu cihaz etkisini deterministik yapmak.

**Kapsam:**

- Session oluşturma/expire
- Token saklama risk kararına backend desteği
- Tek cihaz/tüm cihazlardan logout
- Şifre değişiminde session iptali
- Çoklu authenticated WebSocket
- Hesap silme sırasında session sonlandırma
- Stale socket ve reconnect

**Kabul kriterleri:**

- [x] Expired/revoked session WebSocket yetkisi taşımıyor.
- [x] Logout policy client ve backend'de aynı.
- [x] Şifre değişimi sonucu belgeli.
- [x] Aynı cihaz retry duplicate session üretmiyor.
- [x] Hesap silme tüm aktif bağlantıları kapatıyor.
- [x] Session tablosu retention planıyla uyumlu.

> **Wave 02 kanıtı (2026-09-23):** Ortak session servisi 30 günlük TTL, current/all-device revoke, password-change/account-deletion revoke hook'u ve aynı user/device için replace semantiği sağlıyor; session'a bağlı tüm socketler kontrollü kapanıyor.

## 11. B-AUTH-002 — Legal reaccept backend sözleşmesi

**Amaç:** Kullanıcının hangi legal sürümü neden kabul etmesi gerektiğini güvenilir veriyle taşımak.

**Kapsam:**

- Required ve accepted version
- Locale/belge ayrımı
- Reaccept gerekli/değil
- Atomik kabul yazımı
- Idempotent retry
- IP/UA/geo snapshot anlamı
- Stale yayın ile yarış
- C-LEGAL-001 yayın sonucu

**Kabul kriterleri:**

- [ ] Eksik belge sürümü kabul edilmiş görünmüyor.
- [ ] Aynı version retry duplicate anlam üretmiyor.
- [ ] Yayımla eşzamanlı kabul doğru version'a bağlanıyor.
- [ ] Client required state'i tahmin etmiyor.
- [ ] Geo snapshot matchmaking country alanı gibi kullanılmıyor.

## 12. B-WS-001 — Authenticated socket ve bağlantı sahipliği

**Amaç:** Socket bağlantısını kullanıcı, cihaz, locale, platform ve release ile güvenli bağlamak.

**Kapsam:**

- Hello/auth handshake
- `clientId`, `dbUserId`, device ve platform
- Locale
- Release/build
- Heartbeat ve stale connection cleanup
- Duplicate socket
- Backpressure
- Disconnect reason
- Active client registry

**Kabul kriterleri:**

- [x] Auth tamamlanmadan protected event işlenmiyor.
- [x] Aynı socket farklı kullanıcıya dönüşmüyor.
- [x] Stale socket queue/room/presence bırakmıyor.
- [x] Platform/locale client'ın keyfi hassas alan yazmasına izin vermiyor.
- [x] Çoklu cihaz policy'si açık.
- [x] Backpressure servisi çökertmiyor.

> **Wave 02 kanıtı (2026-09-23):** Beş fazlı connection registry, immutable tek handshake, session/user/device indeksleri, expiry/revoke kapanışı, allowlist client context ve 512 KiB bufferedAmount kapısı focused iki-socket testleriyle doğrulandı; reconnect recovery Wave 05'te kaldı.

## 13. B-WS-002 — Reconnect ve active-state recovery

**Amaç:** Reconnect sonrası client'ın queue, pending match, room ve unread durumunu tahmin etmesini engellemek.

**Kapsam:**

- Active search snapshot
- Pending match snapshot
- Active room snapshot
- Friend/system unread
- Search korunuyor/yeniden başlıyor ayrımı
- Connection instance ve stale event guard
- App background/foreground
- Server restart
- Idempotent cleanup

**Kabul kriterleri:**

- [ ] Reconnect sonucu açık event/snapshot ile dönüyor.
- [ ] Korunmayan queue `devam ediyor` gibi sunulmuyor.
- [ ] Eski connection eventleri yeni connection'ı bozmuyor.
- [ ] Pending offer countdown server zamanı ile toparlanıyor.
- [ ] Active room yoksa client ghost chat göstermiyor.
- [ ] Recovery duplicate join/message/read üretmiyor.

## 14. B-MM-001 — QA-014 search lifecycle

**Amaç:** Arama hazırlığı, aktif queue, uzun bekleme, reconnect ve offer geçişini kimlikli sözleşmeye dönüştürmek.

**Canonical kaynak:** Master QA-014. Client tüketicisi A-MATCH-001.

**State:**

- `preparing`: istek alındı, queue henüz onaylanmadı
- `queued`: queue entry aktif ve `queuedAt` kesin
- `extended`: merkezi bekleme eşiği
- `reconnecting`: gerçek socket kopması
- `offline`: retry policy tükendi
- `cancelled`: queue güvenli kapandı
- `offer`: gerçek pending match oluştu

**Sözleşme:**

- Her search bir `searchId` taşır.
- `queuedAt` server time'dır.
- Cancel tek aktif search'i idempotent kapatır.
- Reconnect queue korunuyorsa aynı `searchId`; değilse yeni search.
- Eski `queued/match_offer` yeni search'te reddedilir.
- Uzun bekleme connection error değildir.
- Mood/prompt queue filtresi değildir.

**Kabul kriterleri:**

- [ ] Master QA-014 backend maddeleri tamam.
- [ ] Queue onayı olmadan client sayaç başlatmıyor.
- [ ] Cancel sonrası geç offer gösterilmiyor.
- [ ] Reconnect korunma semantiği testli.
- [ ] `match_offer` yalnız geçerli search'ten.
- [ ] Server/client saat farkı sonucu bozmaz.
- [ ] Behavior eventler aynı search yolculuğuna bağlanıyor.

## 15. B-MM-002 — QA-017 Global/Country matchmaking

**Amaç:** Global ve kendi ülkem aramasını kesin, kullanıcı onaylı ve yarış güvenli queue kapsamına dönüştürmek.

**Canonical kaynak:** Master QA-017. Client A-MATCH-003; analytics C-ANL-002.

**Mevcut gerçek:**

- Bugün tek process-memory `waitingQueue` bulunur.
- Queue entry scope veya country taşımaz.
- `joinQueue` client scope/search kimliği kabul etmez.
- `queueClientForRematch` parametresiz yeniden `joinQueue` çağırır.
- `legal_acceptances.location_country` serbest metin tarihsel snapshot'tır.

**Hedef queue anahtarları:**

    match:global
    match:country:TR
    match:country:DE
    match:country:BR

**Kapsam kuralları:**

- `GLOBAL` yalnız `GLOBAL` ile.
- `COUNTRY` yalnız aynı canonical ISO kodlu `COUNTRY` ile.
- Otomatik havuz karışımı yok.
- Bir kullanıcı/hesap aynı anda en fazla bir active search.
- Block, ban, shadow ban ve pair cooldown aynı kalır.
- FIFO/fairness partition içinde korunur.
- Queue entry: client/user/socket routing/searchId/scope/country/queuedAt/trigger.
- Pending match iki kullanıcının scope/search bütünlüğünü taşır.
- İkinci cihaz aynı hesapla farklı scope açamaz.

**Scope değişimi:**

- Tercihen `changeMatchScope` tek atomik event.
- Eski search invalidate edilir.
- Yeni `searchId` ve queue oluşturulur.
- Başarı `queued` ile onaylanır.
- Başarısızlık sıfır veya iki entry bırakmaz.
- Eski offer güvenli kapanır.

**Fallback:**

- Yaklaşık 30 sn ilk varsayım; merkezi config/server time.
- `fallbackEligibleAt` veya `country_fallback_available`.
- Arama devam eder.
- Kullanıcı `Go Global` derse atomik scope change.
- Sessiz Global yok.
- Aynı search'te gürültülü tekrar yok.

**Kabul kriterleri:**

- [ ] Master QA-017 backend/data kabul kriterleri tamam.
- [ ] Farklı country partition'ları eşleşmiyor.
- [ ] GLOBAL ve COUNTRY karışmıyor.
- [ ] Sahte client country code etkisiz/reddedilmiş.
- [ ] Tek active search invariant DB/process/instance sınırında korunuyor.
- [ ] Scope race/stale offer testli.
- [ ] Requeue aynı effective scope'u koruyor.
- [ ] Feature capability eski client'ı bozmuyor.
- [ ] Çoklu instance kullanılacaksa queue shared/atomic otoriteye taşınmış veya deployment tek instance sınırı açıkça korunmuş.

## 16. B-MM-003 — QA-003 pending match protokolü

**Amaç:** İki kullanıcının offer kabul/red/timeout durumunu tek ve idempotent state machine ile yönetmek.

**Kapsam:**

- `matchId` ve kaynak `searchId`
- İki participant decision
- `autoAcceptAt` ve timeout
- Accept/reject idempotency
- Peer accepted hint
- Cancel/peer leave/disconnect
- Pair cooldown
- Conversation creation
- Başarısız conversation sonrası aynı scope requeue

**Kabul kriterleri:**

- [ ] Aynı karar iki kez finalize etmiyor.
- [ ] Stale matchId kararı işlenmiyor.
- [ ] Auto/manual accept yarışı tek room oluşturuyor.
- [ ] Reject iki tarafa doğru reason/state veriyor.
- [ ] Conversation DB hatası ghost room bırakmıyor.
- [ ] Requeue actor/peer policy'si aynı scope'u taşıyor.
- [ ] QA-003 countdown alanları server time ile dönüyor.

## 17. B-PRES-001 — Gerçek presence ve last seen

**Amaç:** QA-001 için friend presence'i authenticated bağlantı yaşam döngüsünden üretmek.

**Kapsam:**

- Online tanımı
- Birden çok cihaz
- Son bağlantı kapanışı
- `last_seen_at`
- Friends list response
- Presence update event
- Stale/unknown
- Privacy/retention

**Kabul kriterleri:**

- [ ] Bir cihaz açıkken diğer cihaz kapanınca kullanıcı offline olmuyor.
- [ ] Son aktif socket kapanınca last seen güvenilir güncelleniyor.
- [ ] Server restart sonrası herkes sonsuza kadar online kalmıyor.
- [ ] Client unknown'u gerçek online/offline gibi sunmuyor.
- [ ] Presence sorgusu liste performansını bozmuyor.

## 18. B-MSG-001 — Mesaj idempotency ve outbox

**Amaç:** Reconnect/retry sırasında duplicate veya kayıp sonucu azaltmak.

**Kapsam:**

- `client_msg_id`
- DB unique/idempotency
- Server ack
- Pending/sent/failed
- Retry
- Ordering
- Friend ve anonymous message farkı
- Multi-device
- Typing event gürültüsü
- Maksimum uzunluk

**Kabul kriterleri:**

- [ ] Aynı `client_msg_id` tek kalıcı mesaj.
- [ ] Ack kaybı retry ile duplicate üretmiyor.
- [ ] Ordering tanımlı.
- [ ] Başarısızlık teslim edilmiş gibi görünmüyor.
- [ ] Typing kalıcı event/analytics yığınına dönüşmüyor.
- [ ] Mesaj body structured log'a girmiyor.

## 19. B-MSG-002 — Tek kullanımlık medya yaşam döngüsü

**Amaç:** Fotoğraf upload, görüntüleme ve expiry davranışını DB/boyut/timeout sınırlarıyla güvenilir kılmak.

**Kapsam:**

- MIME/uzantı ve gerçek içerik kontrolü
- Boyut/pixel limit
- Multer/temp cleanup
- Yetkili alıcı
- Tek görüntüleme
- Expire
- Offline/retry
- Rapor/moderasyon kanıtı
- Hesap silme/retention
- Web/Android farkı

**Kabul kriterleri:**

- [ ] Aşırı dosya belleği/disk'i tüketmiyor.
- [ ] Yetkisiz kullanıcı medyayı alamıyor.
- [ ] Tek görüntüleme yarışı atomik.
- [ ] Expired medya kalıcı açık link değil.
- [ ] Temp/orphan dosya temizliği var.
- [ ] Rapor kanıtı ile privacy/expiry politikası çelişmiyor.

## 20. B-SYS-001 — QA-015 Sistem inbox ve teslimat

**Amaç:** Sahte kullanıcı/friendship kurmadan kalıcı TalkX Sistem mesaj altyapısı kurmak.

**Canonical kaynak:** Master QA-015. Client A-SYS-001; admin C-SYS-001.

**Veri/sözleşme:**

- `system_message_campaigns`
- `system_message_recipients`
- Hedef snapshot
- Locale varyantı/fallback
- Recipient unique/idempotency
- Delivery/read/CTA
- Kalıcı inbox API
- Cursor pagination
- WebSocket canlı teslim
- Push dikkat katmanı
- Retry/backoff/batch
- Yetki/audit/retention

**Kabul kriterleri:**

- [ ] Master QA-015 backend kriterleri tamam.
- [ ] Sahte user/friendship yok.
- [ ] Campaign retry recipient duplicate üretmiyor.
- [ ] Offline kullanıcı sonra inbox'ta görüyor.
- [ ] Read receipt çoklu cihazda toparlanıyor.
- [ ] Push başarısızlığı kalıcı mesajı kaybetmiyor.
- [ ] CTA allowlist ve locale fallback server'da doğrulanıyor.
- [ ] Hesap silme/retention politikası uygulanıyor.

## 21. B-I18N-001 — Locale ve çok dilli teslimat

**Amaç:** Client, push ve kalıcı sistem mesajında dil kaynağını açıklaştırmak.

**Kapsam:**

- Authenticated client locale
- Profile locale
- Push device locale
- Unknown locale → English fallback
- TR/EN içerik map
- Notification schedule migration
- System campaign locale
- Country display name yalnız sunum katmanı
- Dil bazlı delivery sonucu

**Kabul kriterleri:**

- [ ] WS ve push aynı kullanıcıda yanlış dil üretmiyor.
- [ ] Çoklu cihaz kendi locale'iyle doğru içerik alıyor.
- [ ] Eksik varyant global gönderimde policy'ye göre engelleniyor.
- [ ] Fallback sayısı ölçülüyor.
- [ ] Locale client'ın yetkisiz hedef segmenti seçmesini sağlamıyor.
- [ ] Schedule/run-now/anlık aynı içerik sözleşmesini kullanıyor.

## 22. B-DB-001 — Sürümlü migration ve DB runtime

**Amaç:** Tek büyük `ensureTables` yerine izlenebilir PostgreSQL migration yaşam döngüsü kurmak.

**Kapsam:**

- Migration table/version
- İleri/geri dönüş kararı
- Transaction ve lock
- Staging doğrulama
- Backup ön koşulu
- Schema drift
- Neon direct endpoint
- `search_path=public`
- Pool size
- Query/statement timeout
- Slow query/büyüyen tablo
- Çoklu instance migration lock

**Kabul kriterleri:**

- [ ] Boş ve mevcut DB aynı migration zincirinden geçiyor.
- [ ] Aynı migration tekrar çalışınca veri bozmuyor.
- [ ] Partial migration görünür başarısız.
- [ ] Rollback veya forward-fix prosedürü belgeli.
- [ ] Backup/restore sonrası kritik count doğrulanıyor.
- [ ] Pool/timeout Render ve Neon limitleriyle uyumlu.
- [ ] Credential repo/log'a girmiyor.

## 23. B-DATA-001 — Veri sahipliği ve retention matrisi

**Amaç:** Her veri sınıfının amacı, sahibi, saklama süresi ve silme davranışını kesinleştirmek.

**Kapsam:**

- Users/sessions/profiles
- Friendship ve kalıcı mesaj
- Anonymous conversation/message
- Media
- Reports/support
- Push token/log
- Legal acceptance
- IP/geo
- Behavior analytics
- System message
- Release health
- Audit
- Backup

**Kabul kriterleri:**

- [ ] Her tablo/veri sınıfı amaç ve retention sahibi.
- [ ] Anonymous/friend mesaj farkı açık.
- [ ] Moderasyon kanıtı ile kullanıcı gizliliği dengeli.
- [ ] Backup retention canlı silme politikasını boşa çıkarmıyor.
- [ ] Admin maskeleme/erişim Plan C ile uyumlu.
- [ ] Privacy/legal metin gerçek davranışı yansıtıyor.

## 24. B-DATA-002 — Canonical matchmaking country

**Amaç:** QA-017 için eşleşmeye uygun ISO ülke kimliğini tarihsel legal geo snapshot'ından ayırmak.

**Kapsam:**

- `match_country_code` ISO alpha-2
- Kaynak
- Status/uygunluk
- Updated/policy version
- Normalize ve migration
- Null/unavailable/stale
- VPN/seyahat
- Session sırasında kontrollü refresh
- Queue'ya yalnız code
- No GPS/city/full IP
- Hesap silme/retention

**Kilitli yorum:** `doğrulanmış` KYC değildir; tanımlı server policy ile canonical ve matchmaking için uygun kabul edilmiş demektir.

**Kabul kriterleri:**

- [ ] `legal_acceptances.location_country` doğrudan queue key değil.
- [ ] Serbest metin ülke normalize edilmeden taşınmıyor.
- [ ] Client başka ülke seçemiyor.
- [ ] Stale/unavailable açık status.
- [ ] Aktif search ülke refresh'iyle sessiz değişmiyor.
- [ ] ISO/display name ayrımı korunuyor.
- [ ] Tam IP/GPS queue/telemetry'ye kopyalanmıyor.
- [ ] Düşük cohort admin gizliliği C-ANL-002 ile uyumlu.

## 25. B-DATA-003 — Hesap silme ve anonimleştirme

**Amaç:** Hesap silme talebinin bütün bağlı veri ve aktif runtime state'ini kapsamasını sağlamak.

**Kapsam:**

- Session/socket/queue/room
- Profile/friendship/messages
- Media
- Reports/moderation retention istisnası
- Push token
- Legal acceptance
- System recipients/read
- Analytics/release health pseudonymous data
- Backup gecikmesi
- Audit

**Kabul kriterleri:**

- [ ] Silinen hesap yeniden aktif socket/queue bırakmıyor.
- [ ] Hangi veri silindi/anonimleştirildi/tutuldu belirli.
- [ ] FK/orphan kontrolü var.
- [ ] Tutulan kanıt yasal amaç/süreyle sınırlı.
- [ ] Client completion state'i doğru.
- [ ] Silme tekrar çağrısı idempotent.

## 26. B-ANL-001 — Davranış analitiği veri sözleşmesi

**Amaç:** QA-012 için kişi, deneme, eşleşme, conversation ve event birimlerini ayırmak.

**Kapsam:**

- Stable event envelope
- Server/client time
- User/session/device/search/match/conversation ID
- Funnel ordering ve time window
- Duplicate/reconnect
- Platform/locale/cohort
- Match iki participant double count kuralı
- Previous period
- Low sample/confidence
- Event story
- Retention

**Kabul kriterleri:**

- [ ] Ham event sayısı kullanıcı sayısı diye gösterilmiyor.
- [ ] Sıra dışı event funnel'ı bozduğu hâlde gizlenmiyor.
- [ ] Aynı match iki katılımcı yüzünden iki match sayılmıyor.
- [ ] Duplicate/retry tek olaya indirgeniyor.
- [ ] Düşük örnek güven etiketi taşıyor.
- [ ] C-ANL-001 özetleri ham kayda geri izlenebiliyor.

## 27. B-ANL-002 — Performance/SLO veri sözleşmesi

**Amaç:** QA-011 için adminin ham dakikalık kayıtlardan sonuç tahmin etmesini engellemek.

**Kapsam:**

- Route/operation
- Count, error, latency percentile
- SLO/threshold
- Previous period
- Stale/partial/no data
- Platform/release
- Impact ordering
- Confidence/sample
- DB/backend ayrımı

**Kabul kriterleri:**

- [ ] P95 olmayan bucket sıfır gibi gösterilmiyor.
- [ ] Eşik ve pencere açık.
- [ ] Az örnek kırmızı alarm değil.
- [ ] Route etkisi trafik ve hata ile birlikte hesaplanıyor.
- [ ] C-PERF-001 özeti aynı sözleşmeyi tüketiyor.

## 28. B-OBS-001 — Structured logging ve hassas veri maskesi

**Amaç:** Operasyon kanıtı üretirken kullanıcı içeriğini sızdırmamak.

**Kapsam:**

- Request/event ID
- Release/environment
- Error code
- Duration/result
- Pseudonymous actor
- Redaction
- Log level
- Sampling/rate limit
- Retention
- Admin audit'ten ayrım

**Asla varsayılan log'a girmez:**

- Şifre/token/Authorization
- Mesaj metni
- Fotoğraf
- Serbest destek/rapor metni
- Push token
- Tam IP
- Kontrolsüz request/response body

**Kabul kriterleri:**

- [x] Kritik yolculuk search/match/conversation ID ile izlenebilir.
- [x] İçerik loglanmadan sonuç teşhis edilebilir.
- [x] Redaction testleri var.
- [x] Log hacmi sınırlı.
- [x] Staging/production ayrık.

> **Wave 02 kanıtı (2026-09-23):** Allowlist structured logger, pseudonymous actor, fail-closed legacy console redaction, request/connection/event correlation ve bounded/sampled mevcut telemetry birlikte test edildi; environment/release alanları ayrık tutuldu.

## 29. B-OBS-002 — Release Health ingestion/adaptör

**Amaç:** QA-016 client hata olayını seçilen sağlayıcı veya TalkX ingestion modeline güvenli bağlamak.

**Kapsam:**

- Schema/allowlist
- Event idempotency
- Rate limit
- PII redaction
- Release/build/source map bağı
- Fingerprint
- Occurrence/user/session etkisi
- Sampling
- Offline delivery
- Retention
- Sağlayıcı adaptörü

**Kabul kriterleri:**

- [ ] Master QA-016 backend/ingestion kriterleri tamam.
- [ ] Mesaj/token/form/IP eventte yok.
- [ ] Source map doğru release'e.
- [ ] Duplicate event_id tek occurrence politikasıyla.
- [ ] Telemetry kesintisi `0 hata` değil.
- [ ] C-REL-001 aynı rollup'ı tüketiyor.

## 30. B-QA-001 — Backend kalite kapıları

**Otomatik kapılar:**

- JavaScript syntax
- Unit test
- PostgreSQL integration
- İki client WebSocket/match
- Migration fresh/existing DB
- Schema contract
- Rate limit/abuse
- Idempotency/retry
- Reconnect/stale race
- PII redaction
- Health/readiness
- Dependency audit

**Manuel/canlı kapılar:**

- Staging DB
- Render/Neon connection
- Direct endpoint ve `search_path=public`
- Backup/restore kritik count
- Web/Android client uyumu
- Controlled disconnect/restart
- Çoklu instance varsa concurrency

**Kapanış kuralı:**

- [ ] Plan ID kabul kriterleri kanıtlı.
- [ ] Migration/rollback sonucu kayıtlı.
- [ ] Test komutu ve sayısı kayıtlı.
- [ ] Client/admin consumer ile contract doğrulanmış.
- [ ] Canlı yazma testi açık onay olmadan yapılmamış.
- [ ] Sonraki wave başlatılmamış.

## 31. Çapraz plan sözleşmeleri

| Plan B sağlayıcısı | Tüketici | Kural |
|---|---|---|
| B-AUTH-001/002 | A-AUTH-001/002, C-LEGAL-001 | Auth/legal state server otoriteli |
| B-MM-001 | A-MATCH-001 | QA-014 phase/search kimliği |
| B-MM-002 + B-DATA-002 | A-MATCH-003, C-ANL-002 | Scope/country/fallback |
| B-MM-003 | A-MATCH-002 | Pending offer/countdown |
| B-PRES-001 | A-FRIEND-001 | Presence/last seen |
| B-MSG-001/002 | A-FRIEND-003, C-TRUST-001 | Mesaj/medya güvenilirliği |
| B-SYS-001 | A-SYS-001, C-SYS-001 | Inbox/recipient/delivery |
| B-I18N-001 | A-I18N-001, C-NOTIFY-001 | Locale/fallback |
| B-ANL-001/002 | C-ANL-001, C-PERF-001 | Analitik/performance veri |
| B-OBS-002 | A client instrumentation, C-REL-001 | Release Health |

## 32. Master backlog kaynak kapsama indeksi

Plan B'nin birincil aldığı kaynaklar:

- Master §8 — Backend, API ve WebSocket
- Master §10 — Veritabanı ve veri yaşam döngüsü
- Master §11 — backend/unit/integration/DB/WebSocket kalite maddeleri
- QA-001 backend presence dilimi
- QA-003 pending-match dilimi
- QA-010 locale/delivery backend dilimi
- QA-011 performance veri sözleşmesi
- QA-012 behavior veri sözleşmesi
- QA-013 legal backend/version dilimi
- QA-014 search lifecycle
- QA-015 inbox/delivery/data
- QA-016 ingestion/release identity
- QA-017 country/queue/event/data

Referans verip sahiplenmediği kaynaklar:

- Master §5, §7, §13 → Plan A
- Master §6, §9, §12, §14 → Plan C
- Master §15 → kullanıcı davranışı A, release/build C
- Master §17 → master'da kalır

## 33. Plan B tamamlanma tanımı

Plan B bütünü ancak:

- P0 güvenlik ve migration kapıları kapanmış,
- Stable API/WebSocket sözleşmeleri sürümlenmiş,
- Auth/session/reconnect deterministik,
- Matchmaking search/offer/Global-Country state machine iki client testleriyle doğrulanmış,
- Mesaj/media/system inbox idempotency ve retention uygulanmış,
- Canonical country ve veri yaşam döngüsü net,
- Analitik/performance/release eventleri güvenli ve geri izlenebilir,
- Unit/integration/migration/contract testleri geçmiş,
- Plan A/C tüketicileriyle uyum kanıtlanmış

olduğunda tamamlanır.

Planın hazır olması migration, backend değişikliği, canlı DB işlemi veya wave başlangıcı değildir.
