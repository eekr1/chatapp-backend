# TalkX Wave 11 Plan — Tek Kullanımlık Medya, Moderasyon ve Sohbet Güven Aksiyonları

> Bu belge yalnız Wave 11 için hazırlanmış uygulama planıdır.
> Canonical ana sıra Plan B `B-MSG-002` → Plan C `C-TRUST-001` → Plan A `A-FRIEND-002` şeklindedir.
> Wave 10'dan devreden `A-FRIEND-003` medya kriterleri bu Wave'in kanıtıyla kapanabilir; metin/outbox kriterleri yeniden uygulanmaz.
> Plan hazırdır. Wave 11 aktif değildir, Wave 01–10 kapanmamıştır ve uygulama başlamamıştır. Hazırlanmış Wave 12 legal/session/account planı bu belge içinde aktif edilmez veya uygulanmaz.

## 1. Durum ve yürütme sınırı

- **Wave:** 11
- **Wave adı:** Tek kullanımlık medya, moderasyon ve sohbet güven aksiyonları
- **Plan katılımı:** Plan B + Plan C + Plan A
- **Canonical sıra:** `B-MSG-002 → C-TRUST-001 → A-FRIEND-002`
- **Devreden kapanış bağı:** `A-FRIEND-003` yalnız medya/Android-Web eşliği alt kriterleri
- **Plan durumu:** Hazır
- **Wave durumu:** Bekliyor
- **Uygulama durumu:** Başlamadı
- **Uygulama yetkisi:** Verilmedi
- **Giriş kapısı:** Wave 10 `QA kapalı` ve kullanıcıdan açık “Wave 11'i başlat” talimatı
- **Mevcut blokaj:** Wave 01–10 uygulanıp kapanmadı; Wave 11 uygulanamaz
- **Önceki wave:** Wave 10 — planı hazır, aktif değil
- **Sonraki wave:** Wave 12 — planı hazır, aktif değil ve başlatılmadı

Bu dosyanın hazırlanması Wave 11 aktivasyonu, kod/test/dependency değişikliği, migration, medya/PII export'u, moderasyon işlemi, ban/block, retention cleanup, canlı veri, deploy veya Wave 12 uygulaması için yetki değildir.

## 2. Canonical referanslar ve otorite

1. `B-MSG-002` — upload/content validation, limit, authorization, atomik one-view, expiry, cleanup ve report evidence ilişkisi
2. `C-TRUST-001` — report/block/ban kanıt zinciri, minimum disclosure, yetki, audit, retention ve kullanıcı sonucu
3. `A-FRIEND-002` — QA-002 rapor/çıkış header aksiyonları, hiyerarşi, erişilebilirlik ve feedback
4. `A-FRIEND-003` — Wave 10'dan açık kalan expired-media, media telemetry privacy ve Web/Android media semantiği
5. Master §7/§8/§10/§13 — media, WebSocket validation, retention ve friend chat manuel QA
6. Master `QA-002` — tanınabilir report/leave aksiyonları ve responsive header
7. `B-MSG-001` — Wave 10 clientMsgId/outbox/ack/ordering; media send aynı primitive'i tüketir
8. `B-DATA-001/B-DATA-003/C-COMP-002` — Wave 06 retention, deletion, legal hold ve privacy policy
9. `C-ADMIN-001` — admin authorization/re-auth/audit temeli

Çelişki çözümü:

- Kullanıcı açısından tek görüntüleme, moderator açısından sınırsız saklama anlamına gelmez. Evidence retention yalnız açık report/hold ve Wave 06 policy'siyle mümkündür.
- Media content güvenlik için sessizce süresiz tutulmaz; exact süre agent tarafından uydurulmaz.
- Receiver authorization, atomic consume ve expiry gerçeği serverdadır; client “açıldı” durumunu tahmin etmez.
- Report, block ve leave farklı sonuçlardır. UI renk/ünlem işaretiyle değil label, ikon, feedback ve state ile ayırır.
- Wave 10 text outbox yeniden tasarlanmaz; yalnız media idempotency entegrasyonu tüketilir.
- Wave 12 legal/account, Wave 15 admin UI yeniden tasarımı ve yeni AI moderation bu Wave'e çekilmez.

## 3. Wave sonucu

Wave 11 sonunda:

- Media upload yalnız authenticated, kabul edilmiş sohbet katılımcısı için ve aynı `clientMsgId` ile idempotent çalışacak.
- Extension/MIME beyanı tek başına yeterli olmayacak; magic-byte/decoder ve allowlist doğrulaması yapılacak.
- Encoded/decoded byte, pixel/dimension, image bomb, timeout ve per-user/conversation rate limitleri server tarafından uygulanacak.
- SVG/aktif içerik ve desteklenmeyen formatlar reddedilecek; kabul edilen görseller metadata/EXIF privacy politikasından geçecek.
- Temp/disk/memory kullanımının her terminal dalda temizliği olacak; orphan sweep ve gözlemlenebilir stop threshold bulunacak.
- Media + message metadata atomik/idempotent bağlanacak; retry duplicate blob/message üretmeyecek.
- Yalnız intended receiver current authorization ile medyayı bir kez tüketebilecek.
- İki cihaz/eşzamanlı fetch yarışında yalnız tek consume kazanacak; diğerleri `already_consumed/expired` sonucu görecek.
- Expired/consumed medya kalıcı public URL veya tekrar açılabilir button olarak görünmeyecek.
- Offline/reconnect/history aynı media state'i serverdan reconcile edecek.
- Report edilen message/media minimum kanıt, source, actor, reason, timestamps ve retention/hold policy ile moderatora bağlanacak.
- Normal expiry ile report evidence retention çakışmayacak; viewed content yalnız onaylı kısa evidence grace/hold politikasında restricted kalabilecek.
- Moderator varsayılanında full content ve IP açık olmayacak; reveal yetki, gerekçe ve audit isteyecek.
- Report/block/leave kullanıcıya farklı ve dürüst sonuç döndürecek; shadow/auto-ban iç mekanizması ifşa edilmeyecek.
- Friend chat header'ındaki `!` kaldırılacak; tanınabilir report ve leave aksiyonları 44 px, tooltip/aria-label, focus ve responsive overflow davranışı kazanacak.
- A-FRIEND-003'ün Wave 10'da açık kalan medya kriterleri Web/Android kanıtıyla tamamlanabilecek.
- Wave 12 başlamayacak.

## 4. Doğrulanmış başlangıç fotoğrafı

### 4.1 DB ve cleanup

- `ephemeral_media` sender_id, receiver_id, media_data ve created_at temelli bir kayıt taşıyor; explicit expiresAt/status/consumedAt/evidence hold alanları başlangıçta görünmüyor.
- `messages.media_id` media ile kalıcı message satırını ilişkilendirebiliyor.
- Cleanup mevcut created_at + sabit TTL üzerinden DELETE çalıştırıyor; policy registry, bounded batch, lock, sonuç ledger ve report hold farkı görünmüyor.
- Media ve message insertlerinin aynı transaction/atomic idempotency sınırında olduğu ayrıca kanıtlanmalı.

### 4.2 Upload ve fetch

- Current direct image send WebSocket JSON içinde image data alıp DB'ye yazabiliyor.
- Extension/magic-byte/decoded dimension/image bomb doğrulamasının tam zinciri görünmüyor.
- Fetch receiver_id ile SELECT yaptıktan sonra image_data gönderiyor ve ayrı DELETE yapıyor; iki eşzamanlı fetch'in ikisinin de SELECT kazanabileceği yarış riski var.
- Full media payload process memory/WebSocket/base64 maliyeti oluşturabilir.
- Duplicate clientMsgId branch mevcut mediaId'yi ackleyebilir; immutable content/target conflict doğrulaması Wave 10 primitive'iyle birleştirilmeli.
- Image data client'ta Data URL olarak görüntüleniyor; object lifecycle ve memory cleanup doğrulanmalı.

### 4.3 Client medya UX

- Chat bubble mediaId varsa receiver için “Fotoğrafı görüntüle”, sender için gönderildi metni gösteriyor.
- `image_data` alındığında ilgili message `mediaExpired: true` yapılıyor.
- `image_error` farklı error nedenlerini tek expired görünümüne indirebilir.
- Upload outbox `direct_image_send` item'ı kullanıyor; permission/size/upload timeout/retry ve duplicate semantiği tüm platformlarda kanıtlı değil.
- Viewer loading/error/retry durumları var; one-view sonucu, screen capture iddiası ve accessibility copy'si yeniden tasarlanmalı.
- Binary/object URL memory release, background ve Android process recreation davranışı açık değil.

### 4.4 Trust ve header

- Report backend conversation/user bağlantısı ve duplicate/auto-ban hesapları yapabiliyor; media/message evidence kimliği ve restricted reveal zinciri tam değil.
- Existing ChatScreen report aksiyonu küçük `!`; leave ayrı text button fakat ortak hiyerarşi ve dar-screen overflow zayıf.
- Client report reason için browser prompt kullanabiliyor; validation, focus, accessible feedback ve media evidence açıklaması yetersiz.
- Block friend API tarafında bulunuyor; report, block ve leave sonuçlarının kullanıcı state'ine etkisi tek contractta açık değil.
- Auto-ban/ban/shadow kararının actor/owner/reason/evidence/audit zinciri C-TRUST-001 seviyesinde doğrulanmalı.

### 4.5 Repo ve canlı sınır

- Root/backend/frontend geniş kullanıcı değişiklikleri taşıyabilir; üç Git bağlamı ayrı snapshot edilir.
- Production media blob, message, report, IP veya ban verisi plan aşamasında okunmaz/export edilmez.
- Cleanup, migration, report hold veya gerçek moderasyon işlemi ayrı exact-target/onay gerektirir.

## 5. Media domain modeli

### 5.1 Kimlik ve state

Her media:

- `mediaId`
- Wave 10 `clientMsgId` ve canonical `serverMessageId`
- senderId, receiverId, conversationId
- contentType, byteSize, width, height, content fingerprint
- `status: pending | available | consuming | consumed | expired | quarantined | purged`
- createdAt, expiresAt, consumedAt, purgedAt
- storage key/blob ref; public URL değil
- retentionPolicyVersion
- reportHold/evidenceRef yalnız yetkili policy varsa
- revision

User-facing open hakkı ile restricted evidence state ayrı alanlardır. `consumed` kullanıcıya tekrar fetch yok demektir; evidence var demek değildir.

### 5.2 İzinli geçişler

- pending → available: validation + atomic persistence tamam
- pending → purged: validation/persist failure cleanup
- available → consuming → consumed: tek atomic consume
- available → expired: deadline
- consumed/expired → purged: policy deadline ve hold yok
- available/consumed → quarantined: açık report/evidence hold policy
- quarantined → purged: case/retention sonucu
- Terminal purged content yeniden açılamaz

State/revision düşük fetch veya cleanup işlemi current kaydı bozamaz.

### 5.3 Süreler ve policy

Upload timeout, available TTL, post-consume evidence grace, report hold retention ve orphan age değerleri config + Wave 06 registry'den gelir. Bu planda sayı uydurulmaz. Her süre owner, purpose, start trigger, action, legal-hold exception ve backup davranışı taşır.

## 6. Upload transport ve doğrulama

### 6.1 Transport kararı

Tercih edilen hedef, authenticated bounded binary/multipart HTTP upload + WebSocket message metadata eventidir. Gerekçe: base64 amplification, WebSocket maxPayload ve whole-buffer memory riskini azaltmak.

Uygulama başlangıcında iki seçenek kanıtla karşılaştırılır:

- Mevcut WebSocket JSON yolu yalnız küçük, strict decoded-size cap ve memory budget ile güvenliyse compatibility adapter olarak kalabilir.
- Streaming multipart/temp-file yolunda path, permission, cleanup ve auth güvenliği kanıtlanır.
- Client-facing ack/idempotency semantiği transporttan bağımsız aynıdır.
- Yeni dependency seçimi bakım/security/lisans ve bundle/runtime etkisi doğrulanmadan yapılmaz.

### 6.2 Validation zinciri

1. Auth/session ve conversation friendship/participant authorization
2. Request/clientMsgId şeması, rate/concurrency ve declared length
3. Encoded + decoded byte limit; stream sırasında erken kesme
4. Filename/extension güvenilmez
5. Magic-byte + güvenli decoder ile actual type
6. Allowlist raster format; SVG/HTML/aktif payload yok
7. Width/height/total pixel ve decompression-bomb limiti
8. EXIF/GPS/metadata strip veya policy-approved rejection
9. Optional re-encode yalnız deterministik kalite/privacy kararıyla
10. Content fingerprint ve Wave 10 immutable idempotency
11. Media/message atomic commit
12. Temp/buffer cleanup finally bloğu

Exact type/byte/pixel limitleri owner-approved config olur; client hint ve server error aynı sürümlü capability'den gelir.

### 6.3 Idempotency

- Aynı clientMsgId + aynı target/kind/content fingerprint retry aynı mediaId/serverMessageId ack verir.
- Aynı id farklı binary/target/kind ile `MESSAGE_ID_CONFLICT`.
- Media row yazılıp message row yazılamazsa transaction rollback veya orphan ledger/cleanup vardır.
- Ack kaybı retry duplicate blob/push/peer message üretmez.
- Upload sonucu `persisted`, peer viewed/read anlamına gelmez.

## 7. Atomik tek görüntüleme

### 7.1 Tüketim sözleşmesi

Receiver fetch isteği mediaId, conversation context ve commandId taşır. Server:

1. Authenticated user'ın receiver olduğunu ve conversation erişimini doğrular.
2. Current status/deadline/revision kontrol eder.
3. Tek DB transaction/atomic statement ile available hakkını claim eder.
4. Yalnız claim kazanan request'e bytes döndürür.
5. Consumed state/timestamp/revision değerlerini commit eder.
6. Diğer eşzamanlı cihaz/requestlere controlled `MEDIA_ALREADY_CONSUMED` döndürür.

SELECT ardından ayrı DELETE kabul edilmez. PostgreSQL row lock + update/delete returning veya eşdeğer compare-and-set gerekir. Network response yarıda kesilirse “görüldü mü?” politikası açık olmalıdır: security açısından claim commit'i response'tan önceyse tekrar fetch yoktur; UI bunu dürüstçe anlatır. Daha karmaşık two-phase delivery, güvenli tek kullanımı zayıflatmadan kanıtlanırsa seçilebilir.

### 7.2 Fetch response ve cache

- Endpoint authorization olmadan public/stable URL vermez.
- `Cache-Control: no-store`, uygun content headers ve sniffing koruması bulunur.
- Content-Disposition inline/filename saldırısı üretmez.
- Client object URL kullanıyorsa viewer kapanışında revoke eder; Data URL uzun süre store/state/log içinde kalmaz.
- Browser cache, service worker ve Android WebView disk cache davranışı test edilir.
- Screenshot/screen recording teknik olarak bütünüyle engellenemez; ürün “imkânsız” iddiası yapmaz.
- Viewer open, loading, consumed, expired, unavailable, offline ve error durumlarını ayırır.

### 7.3 Multi-device ve yarış

- Receiver'ın iki cihazı aynı anda açarsa yalnız bir consume kazanır.
- Kaybeden cihaz history/live revision ile butonu consumed yapar.
- Sender başka cihazdan yeniden send retry yaparsa aynı media idempotency sonucu döner.
- App background/foreground local “available” görünümünü server snapshot/history ile reconcile eder.
- Stale image_data/error başka active media viewerını değiştiremez.
- Fetch timeout otomatik ikinci consume başlatmaz; server state sorgusu/retry policy gerekir.

## 8. Expiry, cleanup ve storage güvenliği

### 8.1 Expiry

- `expiresAt` server time ve policy version ile response/history'de bulunur.
- Client countdown şart değil; available/expired state server gerçeğinden gelir.
- Expired media fetch atomik biçimde reddedilir ve UI open controlünü kaldırır.
- Expiry sırasında in-flight consume için tek deterministic lock sırası vardır.
- Server/client clock farkı güvenliği etkilemez.

### 8.2 Cleanup worker

- Bounded batch + cursor/limit
- Tek scheduler/advisory lock veya multi-instance-safe lease
- Dry-run/count ve reason bucket
- Hold/quarantine skip
- Retry/backoff ve poison record isolation
- Deleted bytes/rows, failures ve oldest-due ölçümü
- Stop threshold/circuit breaker
- Temp directory ve DB/blob orphan sweep
- Backup/restore sonrası policy reconciliation

Cleanup query içine interpolated interval veya geniş unbounded DELETE gömülmez. Policy value validate edilir. Production execute ayrıca onay ister.

### 8.3 Storage

- DB BYTEA devam edecekse row/DB growth, backup, memory ve query isolation ölçülür.
- Object storage seçilecekse private bucket, short-lived authorized fetch, region, encryption, lifecycle, orphan ve deletion kanıtı gerekir.
- Teknoloji değişimi bu planın otomatik kararı değildir; risk/traffic/limit ölçümüyle owner seçer.
- Media body normal DB/admin list query'sine dahil edilmez.
- Backup media retention ve erasure replay Wave 06 policy'sine bağlanır.

## 9. Moderasyon evidence zinciri — C-TRUST-001

### 9.1 Report subject

Report en az:

- reportId, reporter, reported subject
- conversationId
- optional serverMessageId/mediaId
- controlled reason category + bounded açıklama
- occurrence/report timestamps
- media state at report time
- evidence availability/hold status
- source app/protocol version
- moderation status, owner ve audit trail

Free-form reason body log/analytics'e dökülmez. Duplicate report aynı kullanıcı/conversation/message konusu için idempotent/gruplanabilir olur.

### 9.2 Media evidence ve privacy

- Bütün viewed/expired media “belki raporlanır” diye süresiz tutulmaz.
- Report anında media content hâlâ policy-approved evidence grace içindeyse restricted evidence ref/hold atomik bağlanabilir.
- Content daha önce güvenli purge edildiyse moderator için yeniden üretilemez; metadata/message/context kanıtı açıkça “content unavailable” der.
- Client memory'deki görüntü kullanıcı bilgisi ve açık consent olmadan sessizce tekrar upload edilmez.
- Evidence blob normal media fetch endpointinden erişilemez.
- Reveal yalnız yetkili role, vaka gerekçesi, case scope, expiry ve audit ile olur.
- Varsayılan admin summary full image/text/IP göstermez.
- Account deletion legal/Trust hold'ı policy'ye göre pseudonymize/retain/purge eder; sessiz FK kaybı olmaz.
- Backup restore tamamlanmış purge/erasure kararlarını geri getiremez.

### 9.3 Report, block, leave sonuçları

| Aksiyon | Server etkisi | Kullanıcı sonucu |
|---|---|---|
| Rapor et | Yetkili subject/evidence report kaydı | “Rapor alındı”; ban garantisi yok |
| Engelle | Block ilişkisi, future match/message erişimi kapanır | Etki açık; mevcut chatten güvenli çıkış |
| Sohbetten çık | Yalnız current conversation/runtime ayrılır | Report veya block olmuş gibi gösterilmez |
| Rapor + engelle | İki ayrı idempotent işlem/compound açık seçim | İki sonuç ayrı doğrulanır |

Report otomatik olarak block/leave yapmaz; ürün açık compound aksiyon sunarsa kullanıcı bunu görür. Auto-ban sonucu report submit ack'ini geciktirmez ve moderator/appeal policy'si olmadan kesin suç kararı gibi sunulmaz.

### 9.4 Ban ve audit

- Temp/permanent/shadow ban type, duration, reason, actor/automation owner, evidence refs ve createdAt taşır.
- Auto threshold version, input unit/window, minimum distinct reporters ve result auditlenir.
- Duplicate report score'u şişirmez.
- Shadow-ban user-facing normal ban mesajına çevrilmez; internal erişim role-gated.
- Destructive/bulk moderation C-ADMIN-001 re-auth/impact preview/audit kurallarını kullanır.
- Her reveal, report state, block ve ban mutation actor/reason/time taşır.
- Appeal/review owner ve SLA ürün/policy kararıdır; agent süre uydurmaz.

## 10. Client medya UX ve A-FRIEND-003 kapanışı

### 10.1 Gönderim

- Media picker/camera yalnız kullanıcı aksiyonuyla açılır.
- Web file input ve Android gallery/camera permission akışları ayrı test edilir.
- Permission denied, cancelled picker, unsupported type, too large/dimensions, offline, upload timeout ve server reject farklı feedback alır.
- Client capability'den type/size hint gösterir; server validation otoritedir.
- Media outbox Wave 10 clientMsgId ve pending/sent/failed/retry state'ini kullanır.
- Retry aynı immutable file fingerprint/clientMsgId ile mümkünse güvenli; dosya handle kaybolduysa kullanıcıdan yeniden seçim ve yeni id istenir.
- Preview object URL cleanup edilir; binary localStorage/telemetry/log'a yazılmaz.
- Upload progress yalnız gerçek transmitted bytes varsa gösterilir; fake yüzde yok.

### 10.2 Alıcı balonu

- Available: açık `Fotoğrafı görüntüle` controlü
- Loading/claiming: duplicate tıklama disabled
- Consumed: `Fotoğraf görüntülendi`; tekrar button yok
- Expired: `Fotoğrafın süresi doldu`
- Unavailable/error: teknik olmayan reason + yalnız güvenliyse retry/state-check
- Offline: consume başlatılmaz; bağlantı geri geldiğinde state reconcile edilir
- Quarantined: güvenlik nedeniyle kullanılamıyor; moderation detayı ifşa edilmez

Expired, consumed ve error tek boolean altında aynılaştırılmaz. Server mediaStatus/revision her zaman kazanır.

### 10.3 Viewer

- Focus-trapped accessible dialog/sheet; Escape/back/close
- Loading, ready, error, consumed transition
- Görsel alt açıklaması/semantic name; secret içeriği screen reader'a gereksiz tekrar okutmama
- Safe-area, orientation, zoom policy ve 320 px
- Viewer kapanınca object URL/buffer/state temizliği
- Background/screenshot konusunda yanlış gizlilik vaadi yok
- Android hardware back önce viewerı kapatır; sohbeti yanlışlıkla terk etmez

### 10.4 A-FRIEND-003 kapanış koşulu

Wave 10 text/outbox evidence'i gerçekten QA kapalıysa ve Wave 11 şu sonuçları kanıtlarsa A-FRIEND-003 üst checkbox'ı kapanabilir:

- Expired/consumed media tekrar açılabilir görünmüyor.
- Media content telemetry/log/local outbox persistence'a sızmıyor.
- Web/Android permission, send, open, expiry, retry ve error aynı sonuç semantiğini taşıyor.
- Text/outbox kriterlerinde regresyon yok.

Wave 10 kapanmamışsa Wave 11 bu ID'yi kapatmaz.

## 11. QA-002 header aksiyonları — A-FRIEND-002

### 11.1 Bilgi hiyerarşisi

Header ana odağı peer identity/presence bilgisidir. Sağ eylemler:

- `Rapor et`: tanınabilir outline/shield/flag sınıfı gerçek SVG ikon + label/tooltip
- `Sohbetten çık`: secondary/danger hiyerarşi, açık leave ikonu + label
- Dar ekranda kontrollü accessible overflow menu; aksiyonlar kaybolmaz

`!`, tek harf veya noktalama ikon değildir. Report hata rozeti gibi görünmez. Leave sürekli alarm kırmızısıyla tüm header'ı domine etmez.

### 11.2 Interaction

- Minimum 44×44 px target
- Default, hover, focus-visible, pressed, disabled/loading
- Tooltip mouse + keyboard; accessible name visible anlamla aynı
- Tab/focus sırası heading sonrası report → leave/overflow
- Overflow menu roving/tab davranışı, Escape, outside click, focus return
- Long username/presence ve büyük fontta overlap yok
- 320 px, safe-area ve Android WebView header'ı

### 11.3 Rapor akışı

Browser `window.prompt` yerine mevcut tema içinde accessible dialog/sheet:

1. Kime/neye rapor verildiği kısa ve PII-minimized
2. Controlled reason seçenekleri
3. Gerekirse bounded açıklama
4. Media/message evidence availability açıklaması
5. Submit öncesi etki: report block/leave değildir
6. Sending, success, duplicate, failure/retry feedback
7. İsteğe bağlı açık `Raporla ve engelle` yalnız iki sonucu ayrı gösterirse

Dialog raw media'yı otomatik preview etmez. Report gönderimi client'ta ban sonucu uydurmaz.

### 11.4 Leave akışı

- Friend chatten çıkış yalnız chat yüzeyinden geri dönüyorsa gereksiz destructive confirmation istemeyebilir.
- Aktif upload/consume/pending report gibi kayıp riski varsa hedef/etki açık confirmation veya safe cancel gerekir.
- Anonymous vs friend leave semantics karışmaz.
- Leave report/block state'i üretmez.
- Başarı sonrası focus/navigation doğru Friends yüzeyine döner.

## 12. Backend/client hata sözleşmesi

Media kodları en az:

- `MEDIA_INVALID_TYPE`
- `MEDIA_TOO_LARGE`
- `MEDIA_DIMENSIONS_EXCEEDED`
- `MEDIA_UPLOAD_TIMEOUT`
- `MEDIA_NOT_AUTHORIZED`
- `MEDIA_NOT_FOUND`
- `MEDIA_ALREADY_CONSUMED`
- `MEDIA_EXPIRED`
- `MEDIA_QUARANTINED`
- `MEDIA_RESULT_UNKNOWN`
- `REPORT_INVALID`
- `REPORT_DUPLICATE`
- `REPORT_PERSIST_RETRYABLE`

Her response mediaId/clientMsgId/report command correlation, retryable ve current server state/revision taşır. Client teknik kodu TR/EN eyleme dönük metne çevirir. Not-found ile unauthorized ayrımı enumeration yaratmayacak public semantiğe normalize edilebilir.

## 13. Telemetry ve logging

İçeriksiz eventler:

- media upload started/result
- validation rejected reason bucket
- media available/open attempted/consume result
- media expired/purged/cleanup batch
- report submitted/result/duplicate
- block result
- header action used
- viewer error/performance bucket

Yasak: image bytes/base64, thumbnail, EXIF/GPS, full filename, message/report text, peer IP, raw payload ve unrestricted storage key. Low-volume case/media drill-down analytics değildir. Operational identifiers retention/access policy altında tutulur. Reveal/audit eventleri normal product telemetry'den ayrıdır.

## 14. Dosya ve servis etki haritası

Uygulama başlangıcında güncel keşifle daraltılacak beklenen yüzey:

- `chatapp-backend/db.js` — media state/expiry/evidence/idempotency migration'ı
- `chatapp-backend/index.js` veya ayrıştırılmış media upload/consume/cleanup service
- Authenticated upload/fetch route veya bounded WebSocket compatibility adapter
- Report/block/evidence repository ve audit entegrasyonu
- Cleanup worker/runbook/metrics
- Backend validation/concurrency/authorization/retention tests
- `chatapp-frontend/src/App.jsx` media outbox/viewer/report reducer
- `chatapp-frontend/src/screens/ChatScreen.jsx`
- Ortak HeaderActions, ReportDialog ve MediaViewer componentleri
- TR/EN error/state/reason mesajları
- Web/Android permission/camera/gallery/E2E kanıtı
- A-FRIEND-003 Wave 10+11 birleşik evidence kaydı

Genel admin yeniden tasarımı bu Wave'e girmez; C-TRUST-001 için yalnız mevcut yetkili kanıt erişimi ve audit'in çalışması gerekir.

## 15. Uygulama sırası

1. Wave 10 kapanışını, text/outbox evidence'ini, üç Git bağlamını ve gerçek media/report şemasını doğrula.
2. Retention/evidence süre ownerları, media format/byte/pixel limitleri ve storage/transport kararı kilitlenmeden kodlama başlatma.
3. Media state machine, idempotency, consume/expiry/cleanup lock sırası ve hata sözleşmesini test-first kur.
4. Additive migrationı Wave 04 runbookıyla izole DB'de uygula; legacy rows backfill/dry-run kararını kanıtla.
5. Upload stream/validation/temp cleanup ve atomic media+message persist'i tamamla.
6. Receiver-only atomic consume, cache/no-store ve multi-device revision sync'i tamamla.
7. Cleanup worker, orphan sweep, hold skip ve metrics/runbook'u kur.
8. Report subject/evidence hold/reveal authorization/audit zincirini bağla.
9. Block/leave/report sonuçlarını idempotent ve ayrı contractlar olarak doğrula.
10. Client media outbox, status, viewer, permission ve Web/Android state'lerini tamamla.
11. QA-002 header actions ve accessible report dialog/overflow davranışını uygula.
12. Wave 10 text/outbox ve current friend/anonymous flows regresyonunu çalıştır.
13. A-FRIEND-003 media handoff kriterlerini birleşik evidence ile değerlendir.
14. Otomatik test, Web/Android manuel QA ve gerekli privacy/trust owner review'ı tamamla.
15. Wave 12'yi başlatmadan dur.

## 16. Otomatik test planı

### 16.1 Upload ve validation

- Auth yok/not-friend/wrong conversation/blocked target.
- Empty/truncated/polyglot/spoofed MIME-extension.
- JPEG/PNG/WebP gibi onaylı allowlist positive fixtures.
- SVG/HTML/active content reject.
- Encoded/decoded byte, width/height/pixel ve decompression bomb limitleri.
- EXIF/GPS metadata strip/reject sonucu.
- Slow upload, timeout, abort, connection drop.
- Per-user/conversation concurrency/rate limit.
- Temp file/buffer cleanup her failure branch'inde.
- Same clientMsgId same binary replay; different binary/target conflict.
- Media row + message row atomic rollback.
- Push/peer event duplicate olmaması.

### 16.2 Consume/expiry

- Intended receiver tek başarılı fetch.
- Sender, başka user, friend olmayan ve guessed UUID reddi.
- İki eşzamanlı fetch → yalnız tek bytes sonucu.
- İki receiver cihazı → tek consume, revision sync.
- Consume ile expiry yarışı → tek deterministic sonuç.
- Response drop sonrası state-check; unsafe auto retry yok.
- Consumed/expired/not-found/quarantined public semantiği.
- Cache-control/content-type/sniffing/header testleri.
- Object/data URL cleanup ve stale viewer guard.
- Background/foreground/server clock skew.

### 16.3 Cleanup/storage

- Dry-run ile execute target parity.
- Bounded batch/cursor/advisory lock.
- İki worker yarışında tek delete.
- Hold/quarantine skip.
- Orphan media, message link ve temp artifact senaryoları.
- Failure/retry/poison item/circuit breaker.
- Deleted bytes/rows/failure/oldest-due metrics.
- Backup restore + erasure/hold policy fixture.
- Unbounded delete ve unsafe path regresyonu.

### 16.4 Trust/report/block

- Report message-only, media-available, consumed-grace, purged-content.
- Duplicate report idempotency ve score'un şişmemesi.
- Evidence hold atomik ref; unauthorized reveal reddi.
- Reveal actor/reason/time audit.
- Full content/IP varsayılan summary'de yok.
- Temp/permanent/shadow/auto ban metadata/owner/audit.
- Account deletion pseudonymize/retain/purge policy fixture.
- Report submit block/leave yapmaz.
- Explicit report+block iki sonucu ayrı döndürür.
- Block future message/match erişimini kapatır.

### 16.5 Client/component

- Picker cancel/permission denied/unsupported/oversize/offline/timeout.
- Pending/sent/failed media outbox ve same-id retry.
- Available/loading/consumed/expired/unavailable/quarantined UI.
- Double open disabled; server revision reconciliation.
- Viewer focus trap, Escape/back, orientation, safe-area ve cleanup.
- Report/leave ikon-label-tooltip/aria/focus/pressed/disabled.
- 320 px long username/presence ve overflow menu.
- Report dialog validation/success/duplicate/failure.
- Anonymous/friend mode ve text outbox regresyonu.
- TR/EN, large font, screen reader ve reduced motion.

## 17. Manuel QA matrisi

| Grup | Senaryo | Beklenen |
|---|---|---|
| Send | Valid photo web/Android | Pending→sent; tek media/message |
| Permission | Deny/cancel gallery-camera | Açık sonuç; phantom upload yok |
| Limit | Wrong type/large/pixels | Erken, localized reject; cleanup |
| Offline | Send/fetch offline | Dürüst failed/queued policy; fake success yok |
| Retry | Ack/response kaybı | Aynı id; duplicate blob/message yok |
| Open | Receiver tek cihaz | Bir kez görünür, sonra consumed |
| Race | İki cihaz aynı anda | Yalnız biri bytes alır |
| Expiry | Deadline öncesi/sonrası | Server-authoritative available/expired |
| Viewer | Back/Escape/orientation/background | State ve memory temiz |
| Cache | Browser/WebView tekrar açma | Public/cache üzerinden ikinci görüntü yok |
| Report | Media available/consumed/purged | Evidence availability dürüst |
| Privacy | Default admin/reveal | Maskeli; reveal yetki+gerekçe+audit |
| Block | Report/engelle/çık ayrımı | Her aksiyon doğru ayrı sonuç |
| Header | Desktop/320 px/uzun ad | Tanınabilir, 44 px, taşma yok |
| A11y | Keyboard/SR/focus/large text | Bağımsız tamamlanabilir |
| Cleanup | Staging due/hold/orphan | Yalnız eligible bounded silinir |
| Regression | Friend text + anon chat | Wave 10/room davranışı bozulmaz |
| Platform | Web/Android result parity | Aynı media ve hata semantiği |

## 18. Canonical kabul eşlemesi

### 18.1 B-MSG-002 — 6 kriter

- [ ] Aşırı dosya belleği/disk'i tüketmiyor.
- [ ] Yetkisiz kullanıcı medyayı alamıyor.
- [ ] Tek görüntüleme yarışı atomik.
- [ ] Expired medya kalıcı açık link değil.
- [ ] Temp/orphan dosya temizliği var.
- [ ] Rapor kanıtı ile privacy/expiry politikası çelişmiyor.

### 18.2 C-TRUST-001 — 8 kriter

- [ ] Moderator hangi olay/kullanıcı/mesajı incelediğini anlayabiliyor.
- [ ] Tam içerik ve IP varsayılan açık değil.
- [ ] Ban türü, süre, neden ve owner açık.
- [ ] Shadow ban davranışı normal ban gibi yanlış anlatılmıyor.
- [ ] Toplu/destructive işlem hedef ve etki özeti gösteriyor.
- [ ] Her değişiklik actor/gerekçe/zaman audit'i taşıyor.
- [ ] Hesap silme kanıt retention'ını sessizce bozmuyor.
- [ ] Client A-FRIEND-002 doğru sonucu gösteriyor.

### 18.3 A-FRIEND-002 — 5 kriter

- [ ] İkonlar noktalama veya belirsiz sembol değil.
- [ ] Rapor ve çıkış aynı eylem gibi görünmüyor.
- [ ] Klavye ve ekran okuyucu çalışıyor.
- [ ] Dar telefonda aksiyonlar taşmıyor.
- [ ] Plan C moderasyon sonucu doğru client feedback'e dönüyor.

### 18.4 A-FRIEND-003 — devreden media kapanışı

| Kriter | Wave 10 kanıtı | Wave 11 kapanış kanıtı |
|---|---|---|
| Expired medya tekrar açılabilir görünmüyor | Text/outbox altyapısı, açık bırakıldı | Server expiry/consume state + client UI |
| Fotoğraf içeriği telemetry/log'a sızmıyor | Genel redaction regresyonu | Binary/EXIF/payload/storage/log scan |
| Web/Android aynı sonuç semantiği | Text/outbox kanıtı | Permission/send/open/expire/error matrisi |

A-FRIEND-003 yalnız Wave 10 text kanıtı QA kapalı ve bu üç media sonucu tamam ise `[x]` olabilir.

### 18.5 Master QA-002 — 7 kriter

| # | Canonical kabul | Kanıt |
|---:|---|---|
| 1 | Rapor tanınabilir ikon/etiket, tooltip ve aria-label | Header component/a11y |
| 2 | Çıkış metni ve danger/secondary hiyerarşisi net | Visual/content QA |
| 3 | İki aksiyon 44 px, hizalı ve tutarlı | Layout ölçümü |
| 4 | Default/hover/focus/pressed/disabled tanımlı | Interaction snapshots |
| 5 | Dar ekranda identity/presence ile çakışmıyor | 320 px/long-label QA |
| 6 | Report ve leave feedback mevcut davranışı koruyor | Integration E2E |
| 7 | Desktop/mobile görsel tutarlılık | Before/after screenshots |

## 19. Kapsam dışı ve successor guard

- Wave 12 legal reaccept, session recovery ve hesap yüzeyleri
- Sistem inbox/campaign/push hedefleme
- Genel admin navigation/dashboard/profile yeniden tasarımı
- AI/otomatik görüntü sınıflandırması
- Süresiz bütün medya arşivi
- Public media URL veya tekrar görüntüleme
- Yeni read receipt/screenshot prevention vaadi
- Text outbox mimarisini yeniden yazma
- Wave 12 uygulaması

## 20. Risk ve rollback

| Risk | Koruma | Rollback/durma |
|---|---|---|
| İki fetch aynı içeriği alır | Row lock/CAS consume | Fetch capability kapat |
| Base64 memory taşır | Streaming + hard decoded limit | Upload kapat |
| Polyglot/image bomb kabul edilir | Magic decoder + pixel budget | Type allowlist daralt |
| Temp dosya kalır | Finally cleanup + orphan sweep | Upload durdur |
| Retry duplicate blob üretir | Wave 10 idempotency fingerprint | Reconcile/purge orphan |
| Expiry report kanıtını yok eder | Owner-approved grace/hold | Evidence claim kapat |
| Evidence gizliliği bozar | Restricted ref + reveal audit | Content reveal kapat |
| Viewed içerik süresiz kalır | Policy deadline + cleanup | Hold creation durdur |
| Unauthorized UUID tahmini | Receiver auth + normalized not-found | Incident/route kapat |
| Cache ikinci görünüm verir | no-store + private response | Web fetch kapat |
| Block/report/leave karışır | Ayrı commands/results | Compound UI kapat |
| Auto-ban duplicate score | Report idempotency | Automation kapat/review |
| Header dar ekranda taşar | Accessible overflow | Text-only menu fallback |
| Media refactor texti bozar | Wave 10 regression suite | Media flag kapat |
| A-FRIEND-003 erken kapanır | Birleşik evidence gate | Checkbox açık kalır |
| Dirty repo işi örter | Üç Git snapshot'ı | Yalnız Wave 11 farkını geri al |

Rollback fiziksel olarak purge edilmiş içeriği geri getirmeye veya consumed hakkı yeniden açmaya dayanmaz. Migration/storage rollout additive, capability-gated ve old-client compatible olur.

## 21. Rollout ve canlı destructive sınır

1. Policy owner media limit/retention/evidence kararlarını imzalar.
2. Schema/state/cleanup migration'ı izole DB'de forward/rollback test edilir.
3. Validation ve atomic consume synthetic fixtures ile capability-off tamamlanır.
4. Staging Web/Android iki-device race ve report/hold/cleanup matrisi çalışır.
5. Internal cohort'ta upload, sonra consume, sonra evidence/cleanup ayrı flaglerle açılır.
6. Header/report UI ayrı client flag ile doğrulanır.
7. Memory/disk/DB growth, reject reason, consume conflict, orphan ve cleanup lag izlenir.
8. Active media/hold varken rollback provası yapılır.
9. B-MSG-002/C-TRUST-001/A-FRIEND-002 ve A-FRIEND-003 birleşik evidence kullanıcı onayıyla değerlendirilir.

Production migration, gerçek blob/report/IP erişimi, retention execute, evidence reveal, ban/block, feature flag, storage config veya deploy ayrıca exact target/impact onayı ister.

## 22. Başlangıç kapısı

- [ ] Wave 01–10 QA kapanışları ve kullanıcı onayı doğrulandı.
- [ ] Kullanıcı açıkça “Wave 11'i başlat” dedi.
- [ ] Root/backend/frontend Git snapshot'ı alındı.
- [ ] Wave 04 migration/backup/restore runbook gerçek kodda doğrulandı.
- [ ] Wave 06 retention/deletion/evidence policy registry doğrulandı.
- [ ] Wave 10 clientMsgId/outbox/idempotency ve A-FRIEND-003 handoff kanıtı doğrulandı.
- [ ] Güncel media/message/report/block/ban şeması ve data flow yeniden envanterlendi.
- [ ] Media storage/transport seçimi ve instance topolojisi kanıtlandı.
- [ ] Format/byte/pixel/timeout/rate limitleri owner tarafından onaylandı.
- [ ] Consume/expiry/cleanup/evidence lock sırası kilitlendi.
- [ ] Evidence grace/hold/reveal/retention/account deletion policy'si onaylandı.
- [ ] Auto-ban threshold/owner/review/audit politikası doğrulandı.
- [ ] Staging synthetic images, race ve report fixtures hazırlandı.
- [ ] Web/Android permission/cache/background/a11y matrisi hazırlandı.
- [ ] Wave 12 kapsamına taşma olmadığı doğrulandı.

## 23. Sonuç alanı

- Başlangıç/bitiş, refs ve gerçek değişen dosyalar
- Üç Git bağlamının önce/sonra farkı
- Final media şeması/state/transport/limit sözleşmesi
- Upload validation/memory/temp/idempotency sonuçları
- Atomic consume/multi-device/cache/expiry sonuçları
- Cleanup dry-run/execute/orphan/hold/metrics kanıtı
- Report subject/evidence availability/reveal authorization/audit sonuçları
- Ban/block/leave/report ayrımı ve client feedback
- QA-002 desktop/mobile before-after/a11y kanıtı
- Wave 10 text regression ve A-FRIEND-003 birleşik kapanış tablosu
- Privacy/log/telemetry/EXIF/body scan sonucu
- Web/Android permission/send/open/expire/retry/error sonucu
- Syntax/lint/build/encoding/focused/full test exit code'ları
- Stable ID checkbox ve kullanıcı manuel QA onayı
- Wave 12'nin başlatılmadığı açık durma kaydı

## 24. Durma kuralı

Wave 10 QA kapanışı ve kullanıcının açık Wave 11 başlatma talimatı birlikte gelene kadar:

- Wave 11 için kod, test, dependency, migration, media/data query, cleanup, moderation, feature flag veya deploy yapılmaz.
- Wave 11 `Aktif` işaretlenmez; belge yalnız `Hazır — aktif değil` kalır.
- Canonical `[ ]` maddeler kanıtsız kapatılmaz.
- A-FRIEND-003 yalnız Wave 10 + Wave 11 birleşik evidence ile kapanır.
- Wave 12 uygulanmaz; hazırlanmış plan aktif edilmez.
