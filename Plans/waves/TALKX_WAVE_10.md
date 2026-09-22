# TalkX Wave 10 Plan — Kalıcı Mesaj Idempotency ve Outbox Deneyimi

> Bu belge yalnız Wave 10 için hazırlanmış uygulama planıdır.
> Canonical ayrıntı Plan B `B-MSG-001`, Plan A `A-FRIEND-003` ve Master Backlog §7/§8/§13'tedir.
> Plan hazırdır. Wave 10 aktif değildir, Wave 01–09 kapanmamıştır ve uygulama başlamamıştır. Hazırlanmış Wave 11 medya/moderasyon planı bu belge içinde aktif edilmez veya uygulanmaz.

## 1. Durum ve yürütme sınırı

- **Wave:** 10
- **Wave adı:** Kalıcı mesaj idempotency ve outbox deneyimi
- **Plan katılımı:** Plan B + Plan A
- **Canonical sıra:** `B-MSG-001 → A-FRIEND-003`
- **Plan durumu:** Hazır
- **Wave durumu:** Bekliyor
- **Uygulama durumu:** Başlamadı
- **Uygulama yetkisi:** Verilmedi
- **Giriş kapısı:** Wave 09 `QA kapalı` ve kullanıcıdan açık “Wave 10'u başlat” talimatı
- **Mevcut blokaj:** Wave 01–09 uygulanıp kapanmadı; Wave 10 uygulanamaz
- **Önceki wave:** Wave 09 — planı hazır, aktif değil
- **Sonraki wave:** Wave 11 — planı hazır, aktif değil ve başlatılmadı

Bu dosyanın hazırlanması Wave 10 aktivasyonu, kod/test/dependency değişikliği, migration, production mesaj/veri sorgusu, push gönderimi, deploy veya Wave 11 uygulaması için yetki değildir.

## 2. Canonical referanslar ve kapsam yorumu

1. `B-MSG-001` — client message identity, DB idempotency, ack, ordering, retry, direct/anonymous ayrımı, multi-device, typing ve text limit
2. `A-FRIEND-003` — kalıcı friend mesajının pending/sent/failed/duplicate, reconnect ve outbox kullanıcı deneyimi
3. Master §7 — reconnect/outbox/duplicate, anon/friend state izolasyonu ve frontend sorumluluk ayrımı
4. Master §8 — payload validation, maximum text length, direct-message idempotency ve structured-log redaction
5. Master §13 / Arkadaş sohbeti — history, unread, offline/outbox, reconnect ve duplicate manuel QA
6. `B-WS-002` / `A-MATCH-004` — Wave 05 connection/recovery ve domain state izolasyonu
7. `B-MSG-002` — Wave 11 tek kullanımlık medya backend otoritesi; Wave 10 bunu uygulamaz

### 2.1 A-FRIEND-003 split-closure kuralı

A-FRIEND-003 metin ve medya UX'ini aynı stable ID altında toplar, fakat media dependency'si `B-MSG-002` Wave 11'dedir. Bu nedenle:

- Wave 10 normal/uzun/hızlı/emoji **kalıcı metin mesajı**, outbox, retry, duplicate, typing ve multi-device davranışını uygular.
- Media outbox envelope'u geleceğe uyumlu olabilir; fotoğraf upload/open/expiry, MIME/size/timeout ve media telemetry davranışı değiştirilmez.
- `Expired medya tekrar açılabilir görünmüyor` ve `Fotoğraf içeriği telemetry/log'a sızmıyor` kriterleri Wave 10'da yalnız regresyon olarak korunur; B-MSG-002 kanıtı olmadan kapatılmaz.
- A-FRIEND-003 üst checkbox'ı ancak metin kriterleri ile Wave 11 media kriterleri birlikte kanıtlandığında kapanır.
- Wave 10 kendi çıkış kapısını B-MSG-001'in altı kriteri ve A-FRIEND-003 text/outbox alt kümesiyle kapatabilir; medya için açık handoff bırakır.
- Wave 11 planı hazırlanırken A-FRIEND-003 medya kapanış bağı canonical olarak yeniden doğrulanır; bu dosya Wave 11'i hazırlamaz.

### 2.2 Değişmez ürün sınırları

- Friend/direct mesajlar kalıcıdır; anonim oda mesajları mevcut ürün kararına göre ephemeral kalır.
- Optimistic balon server'a teslim edilmiş gibi gösterilmez; `pending` açık görünür.
- `sent`, server DB commit ack'idir; peer cihazına okunmuş/teslim edilmiş anlamına gelmez.
- Ack kaybı duplicate mesaj üretmez.
- Push sonucu kalıcı mesaj sonucunu değiştirmez.
- Message body structured log, analytics veya error metadata'ya girmez.
- Typing geçici sinyaldir; kalıcı event/analytics yığını olmaz.
- Wave 11 media, Wave 13 Sistem inbox ve Wave 14 analytics kapsamları bu Wave'e çekilmez.

## 3. Wave sonucu

Wave 10 sonunda:

- Her friend text submit client tarafından güçlü bir `clientMsgId` ile bir kez oluşturulacak ve retry boyunca değişmeyecek.
- DB, aynı sender + clientMsgId için en fazla bir kalıcı message satırını atomik koruyacak.
- Aynı id ve aynı immutable payload replay'i canonical message ack döndürecek; aynı id ile farklı conversation/target/body kullanımı conflict olacak.
- Server ack DB commit'ten sonra `serverMessageId`, conversationId, canonical createdAt ve idempotency sonucu taşıyacak.
- Client message görünümü `pending | sent | failed_retryable | failed_terminal` durumlarını dürüstçe ayıracak.
- Ack timeout, socket reconnect ve app restart outbox item'ını kayıp veya duplicate yapmayacak.
- Outbox account-scoped, bounded, TTL'li, logout/account-switch güvenli ve single-flight flush olacak.
- History + outbox + canlı event merge'i serverMessageId/clientMsgId üzerinden duplicate balon üretmeyecek.
- Ordering server `createdAt + serverMessageId` canonical sırasına bağlanacak; transport geliş sırası kalıcı sıra sayılmayacak.
- Receiver ve gönderenin diğer cihazları persisted message'ı idempotent fan-out/recovery ile görebilecek.
- Offline peer için message kalıcı kalacak; push hata/kapalı olsa bile history'de bulunacak.
- Anonymous ve friend message reducer/outbox state'i birbirine karışmayacak.
- Typing throttle/stop/disconnect temizliği bounded olacak ve message delivery sonucu sayılmayacak.
- Maksimum mesaj uzunluğu client ve serverda aynı sürümlü contractla uygulanacak; Unicode/emoji ve byte/code-point sınırı açık olacak.
- Kullanıcı failed mesajı manuel retry edebilecek; retry aynı clientMsgId kullanacak.
- Web/Android, offline/reconnect/background/multi-device ve hızlı gönderim matrisleri kanıtlanacak.
- Media davranışı değiştirilmeden Wave 11'e açık handoff kalacak.
- Wave 11 başlamayacak.

## 4. Doğrulanmış başlangıç fotoğrafı

### 4.1 DB

- `messages` tablosunda `client_msg_id TEXT` bulunuyor.
- Partial unique index `(sender_id, client_msg_id) WHERE client_msg_id IS NOT NULL` mevcut.
- Current uniqueness temel idempotency zemini sağlıyor; aynı id'nin farklı payload/conversation ile reuse conflict semantiği açık değil.
- Insert öncesi SELECT ardından INSERT akışı unique index olsa da race'te exception yoluna düşebilir; atomic upsert/canonical replay sonucu yok.
- History'nin kesin stable ordering/cursor ve canonical ack timestamp sözleşmesi başlangıçta yeniden doğrulanmalı.

### 4.2 Backend

- `direct_message` target, trimmed text ve clientMsgId doğruluyor; friendship ve conversation kontrolü yapıyor.
- Duplicate için sender/clientMsgId sorgulanıyor ve `status: duplicate` ack dönülüyor.
- Yeni message DB'ye yazıldıktan sonra bir target socket seçiliyor, push planlanıyor ve sender'a `status: sent` ack gönderiliyor.
- Aynı kullanıcıya ait birden fazla target/sender cihazına tam fan-out kanıtlı değil.
- Duplicate branch peer delivery/push'u tekrar etmiyor; doğru, ancak ack içeriğinin original immutable request ile aynı olduğu doğrulanmıyor.
- Failure ackleri çoğunlukla tek `failed` status kullanıyor; retryable/terminal ve persisted-but-ack-lost ayrımı yeterince açık değil.
- Anonymous `message` yolu peer'e ephemeral relay yapıyor ve persistence kullanmıyor.
- Typing relay geçici fakat debug log içinde kullanıcı nickname'i bulunabiliyor; logging/privacy sınırı doğrulanmalı.

### 4.3 Client

- Friend send yeni ID üretiyor, local pending balon ekliyor ve outbox'a enqueue ediyor.
- History açılırken sent clientMsgId seti ile outbox pending kayıtları birleştiriliyor.
- `direct_message_ack` handler ve ack timer/in-flight/outbox ref yapısı mevcut.
- Error eventinde clientMsgId varsa outbox item doğrudan düşürülebiliyor ve message failed yapılabiliyor; retryability sınıfı kaybolabilir.
- Chat message listesi array index key kullanıyor; reconciliation/reorder duplicate veya DOM identity sorununa açık.
- UI `sending` ve `sendFailed` gösteriyor; görünen manuel retry eylemi mevcut snippet'te yok.
- Incoming deliveryId dedupe var; serverMessageId temelli canonical dedupe ve sender sibling-device sync ayrıca kanıtlanmalı.
- Outbox persistence içeriği, account namespace, TTL/count/byte sınırı, logout ve başka hesap izolasyonu Wave başlangıcında yeniden denetlenmeli.

### 4.4 Repo ve canlı sınır

- Root/backend/frontend çalışma ağaçları geniş kullanıcı değişiklikleri taşıyabilir; üç Git bağlamı ayrı snapshot edilir.
- Production message body/history/outbox/push verisi plan aşamasında okunmaz.
- Mevcut index.js/App.jsx sorumlulukları büyük; ayrıştırma yalnız test altında ve Wave 10 için gereken en küçük domain sınırında yapılır.

## 5. Message identity ve immutable request

### 5.1 Client ID

- Her kullanıcı submitinde UUID/ULID sınıfı yüksek entropili `clientMsgId` bir kez üretilir.
- Retry, reconnect, reload ve ack reconciliation aynı id'yi kullanır.
- Yeni kullanıcı edit/send intenti yeni id üretir; failed item metni değiştirilirse retry değil yeni message olur.
- ID authenticated sender kapsamındadır; target veya conversation tek başına uniqueness anahtarı değildir.
- Server ID format/uzunluğunu schema ile doğrular.

### 5.2 Immutable idempotency fingerprint

Bir clientMsgId ilk kabulde şu anlamla bağlanır:

- sender user id
- target user id / canonical conversation id
- message kind `direct_text`
- normalized text veya server-side güvenli fingerprint
- protocol version

Aynı id + aynı anlam replay → canonical existing message ack. Aynı id + farklı target/conversation/text/kind → `MESSAGE_ID_CONFLICT`; mevcut mesaj başka sohbete taşınmaz ve yeni satır yazılmaz. Fingerprint structured log'a body koymaz.

### 5.3 Atomic persistence

- SELECT-then-INSERT yerine transaction içinde `INSERT ... ON CONFLICT` veya eşdeğer atomic repository kullanılır.
- Conflict sonrası canonical row okunur ve immutable fingerprint doğrulanır.
- Ack yalnız durable commit sonrası gönderilir.
- DB sonucu kesin değilse server `failed` diye yalan söylemez; safe retryable/unknown sonucu ve aynı-id reconciliation kullanır.
- Unique index schema/type/collation ve legacy null/duplicate durumu migration öncesi izole DB'de doğrulanır.
- Production schema migration/backfill ayrıca açık onay ister.

## 6. Sürümlü mesaj sözleşmesi

### 6.1 Client → server

```json
{
  "type": "direct_message",
  "protocolVersion": 1,
  "clientMsgId": "uuid",
  "targetUserId": "uuid",
  "text": "Merhaba"
}
```

Client conversationId yollasa bile server friendship/participant üzerinden canonical conversationı çözer. Anonymous message bu contractı kullanmaz.

### 6.2 Server ack

```json
{
  "type": "direct_message_ack",
  "protocolVersion": 1,
  "clientMsgId": "uuid",
  "status": "persisted",
  "idempotency": "created",
  "serverMessageId": "uuid",
  "conversationId": "uuid",
  "createdAt": "server-time",
  "retryable": false
}
```

Replay'de `idempotency: replayed` olur; UI ikinci balon eklemez. Status `persisted`, peer-delivered veya read iddiası değildir.

Hata sınıfları:

- `MESSAGE_INVALID` / terminal
- `MESSAGE_TOO_LONG` / terminal
- `NOT_FRIEND` / terminal ve conversation erişimi kapanır
- `MESSAGE_ID_CONFLICT` / terminal, yeni send intenti gerekir
- `MESSAGE_PERSIST_RETRYABLE` / retryable
- `MESSAGE_RESULT_UNKNOWN` / retryable aynı id ile reconcile
- `AUTH_ERROR` / session flow
- `RATE_LIMITED` / retryAfter server time

Error ve ack aynı clientMsgId/command correlation taşır; client çelişkide en yüksek revision/canonical reconciliation sonucunu kullanır.

### 6.3 Recipient/sibling-device event

Persisted message event en az serverMessageId, conversationId, sender public identity/id, clientMsgId, createdAt, message kind ve text taşır. Yetkili conversation participantları dışında yayınlanmaz. Aynı delivery birden fazla transporttan gelse serverMessageId ile dedupe edilir.

## 7. Ordering ve history reconciliation

### 7.1 Canonical sıra

- Kalıcı sıra server `createdAt` ve eşitlik bozucu `serverMessageId` ile tanımlanır.
- WebSocket arrival order, local optimistic time veya array insertion kalıcı sıra değildir.
- History cursor aynı tuple'ı veya eşdeğer monotonic server sequence'i kullanır.
- Aynı conversationda pagination sayfaları gap/duplicate üretmeden merge edilir.
- Client-created time yalnız pending UX içindir; ack sonrası canonical server time'a reconcile edilir.
- Server clock alanı UTC ve sürümlüdür.

### 7.2 Üç kaynak merge

Client aynı conversation görünümünü üç kaynaktan kurabilir:

1. HTTP history
2. Persisted local outbox
3. Live WebSocket delivery/ack

Birleştirme önceliği:

- `serverMessageId` varsa birincil canonical key.
- Kendi gönderisinde serverMessageId öncesi `clientMsgId`.
- `deliveryId` yalnız transport dedupe; kalıcı message identity değildir.
- Array index React key olamaz.
- Ack/history/live event aynı local entity'yi mutate eder; ikinci balon eklemez.
- History'de bulunan clientMsgId outbox item'ını `sent` reconcile eder.
- Başka cihazdan gelen kendi-sender message serverMessageId ile “me” olarak eklenir.
- Pagination merge sort sonrası scroll anchor'ı korunur; yeni mesaj geçmiş yüklerken zıplamaz.

### 7.3 Unread/read sınırı

Wave 10 unread count'ın temel message identity ile duplicate artmamasını korur. Yeni read-receipt ürünü icat etmez. Aktif conversationdaki duplicate delivery unread artırmaz; offline history açılışında server unread gerçeği varsa o kazanır. Wave 13 Sistem inbox read modeli bu kapsama girmez.

## 8. Backend uygulama paketi — B-MSG-001

### 8.1 Tek repository/service

Direct message validation, friendship authorization, conversation resolution, atomic insert/replay, fan-out, ack ve push scheduling tek domain sonucu üzerinden yürür. WebSocket case dalı SQL ve teslim semantiğini ayrı ayrı kopyalamaz.

İşlem sırası:

1. Schema, auth, target, kind ve length doğrula.
2. Accepted friendship ve canonical conversationı çöz.
3. Idempotency key/fingerprint ile atomic persist/replay yap.
4. Sender'a durable ack üret.
5. Yetkili recipient ve sender sibling cihazlarına persisted event fan-out et.
6. Push dikkat katmanını ayrı best-effort işlem olarak planla.
7. Privacy-safe metric/log yaz.

Push failure ack'i failed yapmaz; recipient offline olması persistence failure değildir.

### 8.2 Multi-device

- Bir user'ın bütün authenticated live connectionları user→connections registry'den bulunur.
- Recipient'in bütün uygun cihazları aynı persisted event'i alabilir; client serverMessageId ile dedupe eder.
- Sender'ın diğer cihazları kendi gönderisini history yenilemeden görebilir.
- Submit eden cihaz ack ve live echo birlikte alırsa tek balon kalır.
- Logout/session revoke device registry'yi Wave 05 kurallarıyla temizler.
- Push her live socket başına değil, user/conversation notification policy'sine göre dedupe edilir.
- Device fan-out ordering aynı conversation server sırasını taşır.

### 8.3 Validation ve length

- Text string olmak, normalization sonrası boş olmamak ve allowlisted maksimum code point/byte sınırını geçmemek zorundadır.
- Client karakter sayacı UX sağlar; server her zaman son otoritedir.
- Unicode grapheme/emoji, combining character, CRLF ve çok-byte input test edilir.
- Trim/normalization kararı immutable fingerprint ile aynı fonksiyonu kullanır; replay farklılaşmaz.
- HTML render edilmez; mevcut React text escaping korunur.
- Oversize payload WebSocket maxPayload ve event-schema katmanında bounded reddedilir.
- Error body'yi veya kesilmiş body örneğini loglamaz.

### 8.4 Ack ordering

- Durable ack mümkün olan en erken DB commit sonrasında gönderilir.
- Push, notification, analytics veya peer socket availability ack'i bekletmez.
- Peer event ack'ten önce networkte görülebilse bile canonical serverMessageId aynı olduğundan sonuç çelişmez; tercih edilen emit sırası ack/echo contractında belgelenir.
- Ack gönderimi başarısızsa DB satırı korunur; reconnect retry replayed ack üretir.
- Duplicate retry peer'e/push'a ikinci business delivery üretmez. Sender sibling reconciliation gerekirse replay-safe sync event olabilir.
- DB timeout sonucu bilinmiyorsa aynı id ile lookup/retry yapılmadan yeni id üretilmez.

## 9. Client outbox state machine

### 9.1 Durumlar

- `queued_offline` — local kabul edildi, socket hazır değil
- `sending` — aynı item single-flight gönderildi, ack bekleniyor
- `pending_unknown` — timeout/connection loss; persisted olabilir
- `sent` — canonical persisted/replayed ack veya history reconciliation
- `failed_retryable` — kullanıcı/otomatik policy aynı id ile tekrar deneyebilir
- `failed_terminal` — aynı payload gönderilemez; açık reason/eylem
- `expired_local` — local retention süresi doldu; sessizce sent sayılmaz

UI sade biçimde pending/sent/failed ailesini gösterir; ayrıntılı substate reducer ve retry kararına hizmet eder.

### 9.2 Transitionlar

- submit online → sending
- submit offline → queued_offline
- ack persisted/replayed → sent + outbox removal
- ack timeout/socket loss → pending_unknown, ardından reconcile/retry
- retryable error → failed_retryable
- terminal error → failed_terminal
- history aynı clientMsgId → sent
- logout/account switch → current outbox güvenli clear/quarantine policy
- manual retry → aynı clientMsgId ile sending
- user edit after terminal failure → yeni send intent ve yeni clientMsgId

Bir `error` eventi item'ı retryability bilinmeden körlemesine outbox'tan düşürmez.

### 9.3 Flush ve backoff

- Tek global loop yerine account+conversation aware bounded scheduler.
- Aynı clientMsgId aynı anda yalnız bir in-flight send.
- Reconnectte FIFO local created order ile flush; server rate limit/retryAfter'a uyar.
- Exponential backoff + jitter merkezi config; maksimum attempt sonrası manuel retry.
- Online/offline event fırtınası duplicate flush başlatmaz.
- App backgroundda sonsuz timer çalışmaz; foreground/reconnect tetikler.
- Conversation friendship erişimi kalktıysa terminal failure ve composer/route feedback.
- Outbox toplam item/count/byte ve yaş limiti vardır; overflow kullanıcıya açık sonuç verir.

### 9.4 Local persistence ve gizlilik

Outbox message body taşıdığı için hassas yerel veridir:

- Storage key authenticated account/user scope içerir; başka hesap hydrate edemez.
- Logout, account deletion, session revocation ve explicit clear davranışı testlidir.
- TTL dolan item sessizce gönderilmez; user'a expired/failed sonucu gösterilir.
- Payload yalnız send için gereken alanları taşır; token, peer profile veya full conversation snapshot yoktur.
- Structured console/telemetry'ye body basılmaz.
- Web localStorage/IndexedDB ve Android WebView storage yaşam döngüsü gerçek ortamda doğrulanır.
- Storage teknolojisi değişecekse dependency eklemeden önce risk/kapasite gerekçesi belgelenir.
- XSS/session-token riskinin tüm çözümü bu Wave değildir; outbox exposure etkisi açık threat note olur.

## 10. Client mesaj entity ve UI

Önerilen entity:

- `localKey`
- `clientMsgId`
- `serverMessageId | null`
- `conversationId`, `targetUserId`
- `from: me | peer`
- `kind: direct_text`
- `text`
- localCreatedAt/canonicalCreatedAt
- sendState, retryable, errorCode, attempts

UI kuralları:

- Pending balon normal içerik gibi görünür fakat küçük sakin “Gönderiliyor” durumu taşır.
- Sent için sürekli ağır badge gerekmez; a11y text veya yalnız gerektiğinde teslim durumu.
- Failed balon kaybolmaz ve sent gibi görünmez.
- Retryable failed yanında erişilebilir `Tekrar dene`; aynı id kullanılır.
- Terminal failure reason kullanıcı dilinde ve eyleme dönüktür; teknik code gösterilmez.
- Duplicate/replayed ack ikinci balon veya “iki kez gönderildi” uyarısı üretmez.
- Çok hızlı mesajlarda her balon doğru state ile kendi ID'sine bağlanır.
- Long text/emoji/RTL-like content bubble ve retry controlü taşırmaz.
- Screen reader yeni incoming message'i kontrollü duyurur; pending→sent her saniye spam değildir.
- Composer offline iken ürün kararına göre yazmaya izin verip queued_offline gösterir; bağlantı varmış gibi davranmaz.
- Chat scroll, history prepend ve status label görünümü 320 px/kısa ekran/keyboard inset ile çalışır.

## 11. Anonymous ve friend ayrımı

- Anonymous `message` oda yaşam döngüsüne bağlı ephemeral relay'dir; friend outbox/DB contractına yanlışlıkla girmez.
- Friend `direct_message` canonical conversation ve persistent outbox kullanır.
- Reducer entity namespace `anon:<roomId>` ve `friend:<conversation/user>` olarak ayrılır.
- Old anonymous ack/event friend balonunu mutate edemez; direct ack anon balonuna bağlanamaz.
- Anonymous offline send queue'ya alınmaz; kullanıcı bağlantı olmadığı bilgisini görür.
- Friend history açılırken anonymous messages temizlenir/ayrı store'da kalır.
- App back/navigation/reconnectte active mode ve conversation identity event guardının parçasıdır.

## 12. Typing sinyali

- `typing` ve `stop_typing` yalnız authenticated, authorized conversation participantına gider.
- Client başlangıç throttle ve inactivity stop uygular; her keypress event üretmez.
- Disconnect/route change/blur güvenli stop/expiry üretir.
- Server kısa TTL/coalescing ile stale typing'i temizler.
- Typing DB'ye, behavior events'e veya persistent analytics'e yazılmaz.
- Debug/structured log nickname, text veya her typing eventini spamlamaz.
- Multi-device typing bir conversation/user görünümü olarak birleşir; bir cihaz stop derken diğer aktifse policy açık olur.
- Typing failure message send sonucunu değiştirmez.

## 13. Recovery, history ve conversation yaşam döngüsü

- Reconnect sonrası önce auth/recovery, sonra outbox flush yapılır.
- History fetch ile outbox merge yarışında tek reducer/merge fonksiyonu kullanılır.
- Friend silme/block sırasında pending itemlar server authorization sonucuyla terminal olur; yeni retry gönderilmez.
- Conversation ID değişimi/find-or-create sonucu ack'ten canonical olarak alınır; local hint otorite değildir.
- History fetch error mevcut pending balonları sent yapmaz veya silmez.
- Stale history response başka active friend ekranını overwrite etmez.
- Offline history cache varsa freshness açık olmalıdır; yoksa veri uydurulmaz.
- Push deep-link aynı serverMessageId/clientMsgId ile live/history duplicate üretmez.
- Server restart DB'deki message'ı korur; client retry canonical replay ack alır.

## 14. Media successor guard

Wave 10 media davranışını genişletmez:

- `direct_image_send` mevcutsa text outbox refactorında kırılmaması için regression fixture olabilir.
- MIME, magic-byte, pixel/size, upload timeout, authorization, one-view, expiry, temp/orphan cleanup ve moderation evidence Wave 11 B-MSG-002'dir.
- Text repository ile media repository ortak idempotency primitive tüketebilir; bu Wave media state machine kurmaz.
- Fotoğraf body/base64/binary local log veya telemetry'ye yazılmaz; mevcut privacy regresyonu korunur.
- A-FRIEND-003 media checkboxları açık handoff olarak sonuç kaydına yazılır.

## 15. Telemetry ve logging

Ölçülebilir, içeriksiz eventler:

- outbox item created
- send attempt
- persisted/replayed ack
- ack timeout/result unknown
- retry automatic/manual
- terminal failure reason
- reconciliation by history
- duplicate transport delivery dropped
- queue age/attempt count bounded histogram

Alanlar protocol/app/platform version, message kind, error/reason code, retry count, latency bucket ve connection state olabilir. Message text, public username, token, IP, push body, raw payload ve local storage içeriği yasaktır. Metric “sent” ile “peer delivered/read” ayrımını bozmaz.

Structured logs clientMsgId/serverMessageId'i gerektiğinde kontrollü correlation olarak taşıyabilir; retention/access policy ve hashing kararı Wave 06 registry'sine bağlıdır. Normal production log her message/typing eventini body ile yazmaz.

## 16. Dosya ve servis etki haritası

Uygulama başlangıcında güncel keşifle daraltılacak beklenen yüzey:

- `chatapp-backend/db.js` — existing client_msg_id/index doğrulaması; gerekirse additive fingerprint/order migrationı
- `chatapp-backend/index.js` veya ayrıştırılmış direct-message service/repository
- WebSocket payload schemas, error/ack serializer ve user connection registry
- Backend concurrency/idempotency/history tests
- `chatapp-frontend/src/App.jsx` veya Wave 05 domain/outbox store
- Outbox persistence/scheduler/reconciliation yardımcıları
- `chatapp-frontend/src/screens/ChatScreen.jsx`
- TR/EN status/error/retry locale mesajları
- Friend history API client ve cursor merge
- Web/Android E2E ve manuel QA evidence

B-MSG-002 media lifecycle, Sistem inbox, read receipt ürünü, genel chat redesignı ve production migration varsayılan kapsam dışıdır.

## 17. Uygulama sırası

1. Wave 09 kapanışını, üç Git bağlamını, current schema/index ve gerçek send/ack/history/outbox kodunu doğrula.
2. B-MSG-001 altı kriterini ve A-FRIEND-003 text/media split evidence tablosunu kilitle.
3. Message schema, length/normalization, idempotency fingerprint, ack/error ve ordering contractını belirle.
4. DB concurrency testleriyle atomic persist/replay/conflict repository'sini kur.
5. Backend service'i friendship/conversation authorization, ack, fan-out ve push ayrımıyla bağla.
6. Multi-device registry/dedupe ve typing TTL/throttle davranışını tamamla.
7. Client message entity, account-scoped outbox ve single-flight scheduler'ı test altında ayır.
8. History/live/ack/outbox reconciliation ve canonical ordering'i uygula.
9. Pending/sent/failed/retry UI ile offline/reconnect kullanıcı metinlerini tamamla.
10. Anonymous/friend state isolation ve navigation race testlerini çalıştır.
11. Existing image send/open akışında yalnız regresyon yap; media davranışını değiştirme.
12. Web/Android, multi-device, background ve payload-privacy QA'yı tamamla.
13. B-MSG-001'i kanıtla; A-FRIEND-003 media maddelerini açık handoff bırak.
14. Wave 11'i başlatmadan dur.

## 18. Otomatik test planı

### 18.1 DB/repository

- Eşzamanlı aynı sender/clientMsgId insert → tek row.
- Aynı id/same payload replay → aynı serverMessageId/conversation.
- Aynı id/farklı text, target, kind veya conversation → conflict.
- Null/invalid/oversize clientMsgId reddi.
- Unicode normalization ve fingerprint parity.
- Commit sonrası ack kaybı retry → existing row.
- DB timeout unknown → aynı id reconciliation.
- Ordering tuple ve cursor page boundary gap/duplicate testi.
- Legacy null clientMsgId satırları etkilenmez.
- Migration forward/rollback ve index verification izole DB'de.

### 18.2 Backend contract

- Auth/friendship/conversation authorization.
- Empty/whitespace/emoji/combining/CRLF/max/over-limit text.
- Ack yalnız commit sonrası ve canonical alanlarla.
- Duplicate retry peer/push business delivery'sini çoğaltmaz.
- Recipient offline → persisted ack/history var.
- Push failure → message persisted kalır.
- Recipient multiple devices + sender sibling devices fan-out.
- Reordered/double transport event dedupe.
- Rate limit retryAfter ve terminal/retryable error classification.
- Typing throttle/TTL/stop/disconnect; DB/event/log gürültüsü yok.
- Body structured log/error/analytics redaction.
- Anonymous message kalıcı direct repository'ye girmez.

### 18.3 Client reducer/outbox

- Online send → pending → sent.
- Offline send → queued_offline → reconnect flush → sent.
- Ack timeout → pending_unknown → replayed ack.
- Retryable failure → visible retry, aynı clientMsgId.
- Terminal failure → sent görünmez; edit yeni id üretir.
- Error event retryability bilinmeden item'ı silmez.
- App reload/outbox hydrate doğru account için.
- Logout/account switch/delete outbox isolation/cleanup.
- TTL/count/byte overflow açık sonuç.
- Rapid 20-message FIFO/single-flight ve her item state'i.
- Ack/live/history üçlü merge tek bubble.
- Sender second-device event “me” ve tek bubble.
- Old friend history response active conversationı bozmaz.
- Anonymous/friend state birbirine karışmaz.
- React keys stable message identity kullanır.
- Long/emoji text, retry action, screen reader ve scroll anchor.

### 18.4 Entegrasyon/E2E

- Ack networkte düşürülür, reconnect retry yapılır, DB/UI tek message.
- Server DB commit sonrası restart, client same-id replay.
- İki browser aynı sender hesabı + iki recipient cihazı.
- Recipient offline/push failed/history açılışı.
- Hızlı sohbet + typing fırtınası + reconnect.
- Friend delete/block pending sırasında.
- Pagination yüklenirken live message ve outbox ack.
- Web Chromium ve Android WebView background/foreground.
- Existing direct image happy/error path yalnız regression.
- Anonymous room send ile friend outbox isolation.

## 19. Manuel QA matrisi

| Grup | Senaryo | Beklenen |
|---|---|---|
| Normal | Tek friend text | Pending ardından persisted/sent |
| Offline | Bağlantı yokken gönder | Açık queued state, reconnectte tek mesaj |
| Ack kaybı | DB yazıldı, ack düşürüldü | Retry aynı id; tek balon/DB row |
| Retry | Retryable hata | Görünür Tekrar dene, aynı id |
| Terminal | Not friend/too long/conflict | Sent görünmez, eyleme dönük metin |
| Hız | Çok hızlı mesaj/emoji | Sıra ve her item state'i doğru |
| History | Reload/pagination/live aynı anda | Duplicate yok, scroll korunur |
| Multi-device | Sender/recipient iki cihaz | Yetkili cihazlarda tek canonical mesaj |
| Push | Peer offline/push error | History kalıcı; sender sent sonucu doğru |
| Hesap | Logout/başka hesap | Eski outbox sızmaz/gönderilmez |
| Süre | TTL dolmuş outbox | Sessiz auto-send veya sent yok |
| Block | Pending sırasında friend silme/block | Terminal failure, retry durur |
| Typing | Yaz/blur/disconnect | Bounded indicator, kalıcı gürültü yok |
| Isolation | Anon chat ardından friend chat | State/ack/balon karışmaz |
| Privacy | Log/analytics/storage inspect | Body log/telemetry'de yok |
| Mobil | Android background/reconnect/keyboard | Aynı sonuç semantiği |
| A11y | Retry/status/SR/focus/büyük font | Mesaj sonucu anlaşılır ve kullanılabilir |
| Media | Existing photo smoke regression | Değişmeden çalışır; Wave 11'e devredilir |

## 20. Canonical kabul eşlemesi

### 20.1 B-MSG-001 — 6 kriter

- [ ] Aynı `client_msg_id` tek kalıcı mesaj.
- [ ] Ack kaybı retry ile duplicate üretmiyor.
- [ ] Ordering tanımlı.
- [ ] Başarısızlık teslim edilmiş gibi görünmüyor.
- [ ] Typing kalıcı event/analytics yığınına dönüşmüyor.
- [ ] Mesaj body structured log'a girmiyor.

### 20.2 A-FRIEND-003 — split kanıt

| Canonical kriter | Wave 10 sonucu | Kapanış |
|---|---|---|
| Belirsiz gönderim durumu dürüst | Pending/unknown/failed/sent state ve reconciliation | Wave 10'da kanıtlanır |
| Retry duplicate mesaj üretmiyor | Same clientMsgId + DB replay | Wave 10'da kanıtlanır |
| Anon ve friend mesaj state'i ayrık | Namespace/reducer/E2E isolation | Wave 10'da kanıtlanır |
| Expired medya tekrar açılabilir görünmüyor | Yalnız mevcut regresyon | Wave 11 B-MSG-002 kanıtına kadar açık |
| Fotoğraf içeriği telemetry/log'a sızmıyor | Yalnız mevcut redaction regresyonu | Wave 11 B-MSG-002 kanıtına kadar açık |
| Web/Android aynı sonuç semantiği | Text/outbox Wave 10; media Wave 11 | Üst kriter Wave 11 sonrası tam kapanır |

Wave 10 sonunda A-FRIEND-003 üst checkbox'ı medya kriterleri eksikse `[ ]` kalır. Sonuç alanında text alt kümesi kanıtı ve Wave 11 handoff'u açıkça yazılır; `[x]` ile sahte tam kapanış yapılmaz.

### 20.3 Master izlenebilirlik tablosu

| Master kayıt | Wave 10 kanıtı |
|---|---|
| App.jsx outbox sorumluluğunu test altında ayır | Domain store/scheduler focused tests |
| Reconnect, retry ve duplicate | Ack-loss/restart E2E |
| Anon/friend state karışmaması | Reducer namespace + navigation tests |
| Direct message DB idempotency | Atomic unique/fingerprint tests |
| WebSocket schema ve max text | Contract/Unicode/oversize matrix |
| History ve unread | History/live/outbox merge |
| Offline/outbox manuel kontrol | Web/Android evidence |
| Fotoğraf akışı | Yalnız smoke regression; Wave 11 otoritesi |

## 21. Kapsam dışı ve successor guard

- B-MSG-002 photo upload/open/one-view/expiry/temp cleanup
- Media permission, MIME, pixel/size, binary persistence veya moderation evidence değişikliği
- A-FRIEND-003 media kriterlerini kanıtsız kapatma
- Read receipt/delivered product surface
- Anonymous mesajları kalıcılaştırma veya offline queue'ya alma
- Sistem inbox/push kampanya davranışı
- Genel ChatScreen görsel redesignı
- Admin message content görünümü
- Wave 11 uygulaması

## 22. Risk ve rollback

| Risk | Koruma | Rollback/durma |
|---|---|---|
| Select-insert race hata verir | Atomic upsert + unique index | New repository flag kapat |
| Aynı id farklı sohbeti ackler | Immutable fingerprint conflict | Request terminal reddet |
| Ack kaybı duplicate gönderir | Same-id retry/replayed ack | Flush durdur, reconcile |
| Error outbox'ı erken siler | Retryability state machine | Item pending_unknown tut |
| History/live/ack çift balon | Canonical ID merge | Re-fetch + dedupe |
| Local optimistic sent görünür | Pending until DB ack | Statusu pending'e geri al |
| Multi-device duplicate unread | ServerMessageId dedupe | Unread reconcile |
| Push failure send'i failed yapar | Push post-commit best effort | Push yolunu ayır |
| Outbox başka hesaba sızar | Account namespace + clear | Hydration fail-closed |
| TTL item sessiz gönderilir | Expired_local terminal state | Auto flush bloke |
| Ordering mesajı zıplatır | Server tuple + anchor | Canonical re-sort |
| Typing log/analytics yığını | TTL/throttle/no persistence | Typing telemetry kapat |
| Text refactor media'yı bozar | Media smoke regression | Ortak değişikliği geri al |
| A-FRIEND-003 yanlış kapanır | Split closure tablosu | Checkbox açık kalır |
| Dirty repo işi örter | Üç Git snapshot'ı | Yalnız Wave 10 farkını geri al |

Rollback persisted mesajları silmeye dayanmaz. Client flag kapanırsa DB canonical identity korunur; pending local itemlar aynı id ile reconcile edilir veya açık failed state'e alınır.

## 23. Rollout ve canlı sınır

1. Existing schema/index ve legacy client fixture'ları doğrulanır.
2. Atomic repository/ack contract capability-off test edilir.
3. Staging concurrency, ack-loss, restart ve multi-device matrisi tamamlanır.
4. Yeni server contract legacy client adapter ile küçük cohortta açılır.
5. Client outbox reducer/scheduler ayrı flag ile açılır.
6. Web ardından Android offline/background/long-text/a11y QA yapılır.
7. Duplicate, retry, unknown, conflict, queue age ve send latency içeriksiz metricleri izlenir.
8. Rollback provası pending outbox ve DB-committed/ack-lost mesajlarla yapılır.
9. B-MSG-001 kapatılır; A-FRIEND-003 medya handoff'u açık bırakılır.

Production message/PII query, migration, feature flag, push, deploy/restart veya gerçek user outbox müdahalesi ayrıca exact target/impact onayı ister.

## 24. Başlangıç kapısı

- [ ] Wave 01–09 QA kapanışları ve kullanıcı onayı doğrulandı.
- [ ] Kullanıcı açıkça “Wave 10'u başlat” dedi.
- [ ] Root/backend/frontend Git snapshot'ı alındı.
- [ ] Wave 05 recovery/domain isolation gerçek kodda doğrulandı.
- [ ] Wave 09 room/conversation sonucu gerçek kodda doğrulandı.
- [ ] Current message schema/index ve legacy duplicate durumu izole/read-only doğrulandı.
- [ ] Direct send/ack/history/outbox/typing/push yolları yeniden envanterlendi.
- [ ] Max length/normalization/idempotency fingerprint kararı kilitlendi.
- [ ] Ack status, retryability, ordering ve cursor contractı kilitlendi.
- [ ] Local outbox TTL/count/byte/account/logout politikası onaylandı.
- [ ] Multi-device fan-out, push dedupe ve unread sınırı onaylandı.
- [ ] A-FRIEND-003 split-closure ve Wave 11 media handoff'u doğrulandı.
- [ ] Web/Android/offline/reconnect/a11y test matrisi hazırlandı.
- [ ] Wave 11 kapsamına taşma olmadığı doğrulandı.

## 25. Sonuç alanı

- Başlangıç/bitiş, refs ve gerçek değişen dosyalar
- Üç Git bağlamının önce/sonra farkı
- Final message schema, idempotency fingerprint ve ack/error contractı
- DB atomic concurrency/replay/conflict kanıtı
- Ordering/cursor/history/live/outbox merge sonuçları
- Client outbox transition, persistence, retry/backoff ve account isolation kanıtı
- Multi-device fan-out/unread/push ayrımı
- Typing throttle/TTL/log sonuçları
- Anonymous/friend isolation
- Web/Android offline/reconnect/background/a11y kanıtı
- Message-body log/telemetry redaction sonucu
- Existing media smoke regresyonu ve açık Wave 11 handoff'u
- Syntax/lint/build/encoding/focused/full test exit code'ları
- B-MSG-001 kapanışı ve A-FRIEND-003 açık/kapalı alt kriter tablosu
- Kullanıcı manuel QA onayı
- Wave 11'in başlatılmadığı açık durma kaydı

## 26. Durma kuralı

Wave 09 QA kapanışı ve kullanıcının açık Wave 10 başlatma talimatı birlikte gelene kadar:

- Wave 10 için kod, test, dependency, migration, config, production data, push, feature flag veya deploy değişikliği yapılmaz.
- Wave 10 `Aktif` işaretlenmez; belge yalnız `Hazır — aktif değil` kalır.
- Canonical `[ ]` maddeler kanıtsız kapatılmaz.
- A-FRIEND-003 media kriterleri Wave 11 kanıtı olmadan kapatılmaz.
- Wave 11 uygulanmaz; hazırlanmış plan aktif edilmez.
