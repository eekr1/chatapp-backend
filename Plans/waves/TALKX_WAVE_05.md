# TalkX Wave 05 Plan — Reconnect, Active State ve Gerçek Presence

> Bu belge yalnız Wave 05 için hazırlanmış uygulama planıdır.
> Canonical ayrıntı Plan B ve Plan A stable ID maddelerindedir; burada Wave 06 ülke/veri sahipliği veya Wave 07–09 matchmaking protokolü üretilmez.
> Plan hazırdır. Wave 05 aktif değildir, Wave 01–04 kapanmamıştır ve uygulama başlamamıştır.

## 1. Durum ve yürütme sınırı

- **Wave:** 05
- **Wave adı:** Reconnect, active state ve gerçek presence
- **Plan katılımı:** Plan B + Plan A
- **Plan durumu:** Hazır
- **Wave durumu:** Bekliyor
- **Uygulama durumu:** Başlamadı
- **Uygulama yetkisi:** Verilmedi
- **Giriş kapısı:** Wave 04 `QA kapalı` ve kullanıcıdan açık “Wave 05'i başlat” talimatı
- **Mevcut blokaj:** Wave 01–04 uygulanıp kapanmadı; Wave 05 uygulanamaz
- **Önceki wave:** Wave 04 — planı hazır, aktif değil
- **Sonraki wave:** Wave 06 — planı ayrı talimatla hazırlandı; aktif değil ve uygulanmadı

Bu dosyanın hazırlanması Wave 05 aktivasyonu, kod/test/dependency değişikliği, DB migrationı, Android sync, canlı servis işlemi, deploy veya Wave 06 aktivasyonu/uygulaması için yetki değildir.

## 2. Canonical referanslar

Uygulama sırası değişmez: `B-WS-002 → B-PRES-001 → A-MATCH-004 → A-FRIEND-001 → A-PRD-002`.

1. `B-WS-002` — Plan B / reconnect ve active-state recovery / bütün kabul kriterleri
2. `B-PRES-001` — Plan B / gerçek presence ve last seen / bütün kabul kriterleri
3. `A-MATCH-004` — Plan A / client state izolasyonu ve recovery / bütün kabul kriterleri
4. `A-FRIEND-001` — Plan A / QA-001 gerçek presence / bütün kabul kriterleri
5. `A-PRD-002` — Plan A / anonimden arkadaşlığa tutarlı ürün hikâyesi / bütün kabul kriterleri

Yürütme kaynağı: `../TALKX_WAVE_MAP.md` / Wave 05.
Canonical ayrıntı kaynakları: `../TALKX_PLAN_B_PLATFORM_REALTIME_DATA.md` ve `../TALKX_PLAN_A_PRODUCT_CLIENT.md`.
Kilitli karar ve başlangıç kanıtı: `../TALKX_MASTER_BACKLOG.md` / §3, §5, §7 ve QA-001.

Bağımlılık yorumu:

- `B-WS-001` ve sürümlü WebSocket erişim sözleşmesi Wave 02'de QA kapalı olmalıdır.
- `A-FND-001`, `A-FND-002` ve `A-A11Y-001` Wave 03'te QA kapalı olmalıdır; client state ayrımı mevcut tema/state standardını tüketir.
- `B-API-002` ve `B-DB-001` Wave 04'te QA kapalı olmalıdır; recovery/presence health ve migration kapıları bunları tüketir.
- `B-MM-001`, `B-MM-002`, `B-MM-003`, `A-MATCH-001/002/003` sonraki wave'lerin otoritesidir. Wave 05 bunların `searchId`, scope/country veya offer karar protokolünü erkenden kurmaz.
- `B-MSG-001` Wave 10'un kalıcı mesaj idempotency otoritesidir. Wave 05 yalnız recovery sırasında belirsiz komutu otomatik tekrar etmeyerek duplicate üretmez.

## 3. Wave sonucu

Wave 05 sonunda:

- Authenticated reconnect sonrasında server; queue, pending offer, anonim room ve unread gerçeğini tek, sürümlü recovery snapshot ile açıklayacak.
- Kısa ve kontrollü bağlantı kopmasında aynı connection lease içindeki geçici state güvenle geri bağlanabilecek; grace süresi aşılırsa state açık bir reset reason ile kapanacak.
- Server restart veya state kaybı, client'ta hayalet queue/offer/chat bırakmayacak ve korunmayan arama otomatik devam ediyor gibi gösterilmeyecek.
- Eski socket/connection eventleri yeni bağlantının state'ini değiştiremeyecek.
- Pending offer zamanı client saatiyle yeniden hesaplanmayacak; server `autoAcceptAt` ve `serverNow` otorite olacak.
- Arkadaş ve sistem unread sayıları kalıcı kaynaktan reconcile edilecek; reconnect duplicate read/join/message üretmeyecek.
- Presence yalnız authenticated, süresi dolmamış server lease'lerinden üretilecek ve bir kullanıcının bütün cihazları birlikte değerlendirilecek.
- Son aktif lease kapandığında veya süresi dolduğunda `last_seen_at` güvenilir server zamanı ile güncellenecek.
- Arkadaş listesi ve arkadaş sohbeti header'ı `online / offline / unknown-stale` durumunu dürüstçe gösterecek; bilinmeyen durum Online veya Offline diye uydurulmayacak.
- Search, offer, anonymous room, friend room, system room ve media state'leri ayrı sahiplikte olacak; yanlış ekrana event veya mesaj sızmayacak.
- `eşleş → konuş → arkadaşlığa taşı` yolculuğu mod ve ilişki sınırlarını koruyacak; arkadaşlık anonim geçmişi geriye dönük kalıcılaştırmayacak.
- Wave 06 ve sonrasına ait country, partition queue, search lifecycle ve pending-match karar özellikleri başlamayacak.

## 4. Doğrulanmış başlangıç fotoğrafı

### 4.1 Backend connection ve transient state gerçeği

- `chatapp-backend/index.js` her WebSocket için yeni UUID `clientId` üretiyor; connection nesnesi `activeClients` process-memory map'ine authenticated `hello_ack` sonrasında ekleniyor.
- `waitingQueue`, `rooms`, `userRoomMap`, `pendingMatches` ve `userPendingMatchMap` yalnız process memory'de tutuluyor ve çoğunlukla socket `clientId` ile anahtarlanıyor.
- Client reconnect sırasında önceki connection'ı kanıtlayan recovery token/lease taşımıyor.
- `welcome` yalnız nickname ve dil döndürüyor; active state, unread, server epoch veya recovery sonucu taşımıyor.
- Socket `close` olduğunda pending offer iptal ediliyor, queue entry siliniyor ve anonim room hemen `disconnect` reason ile kapatılıyor.
- Server restart process-memory queue/offer/room state'lerini kaybediyor; bunu client'a açıklayan boot epoch veya reset snapshot yok.
- Queue `queued` event'i bugün `searchId`, `queuedAt` veya state revision taşımıyor; bunlar Wave 07'nin canonical otoritesidir.
- Pending offer event'i `matchId`, `autoAcceptAt` ve `timeoutMs` taşıyor; client buna rağmen `autoAcceptAt` değerini server alanından değil `Date.now() + timeoutMs` ile yeniden hesaplıyor.

### 4.2 Frontend reconnect ve state gerçeği

- `chatapp-frontend/src/App.jsx` jitter'lı retry ve online/focus/resume tetikleyicileriyle socket'i yeniden açabiliyor.
- Eski socket callback'leri `ws.current !== socket` guard'ıyla kısmen filtreleniyor; server event envelope'ında connection instance veya state revision bulunmuyor.
- `welcome` geldiğinde socket authenticated sayılıyor ve outbox hemen flush ediliyor; önce active-state reconciliation yapılmıyor.
- Reconnect sonrası client server snapshot istemiyor; ekranda kalan `status`, `roomId`, `pendingMatchOffer`, peer ve mesaj state'leri tahmine dayanabiliyor.
- `screen`, `status`, `messages`, `roomId`, `chatMode`, `activeFriend`, pending offer ve media state'i aynı üst component içinde bağımsız `useState` alanlarıyla tutuluyor.
- Aynı `messages` dizisi anonymous ve friend chat için kullanılıyor; manuel temizleme sırası state karışmasını engellemeye çalışıyor.
- Logout geniş bir temizlik yapıyor fakat back/cancel/reconnect yollarının tamamı aynı idempotent reducer/cleanup sözleşmesini tüketmiyor.
- Friend direct-message outbox'ı `clientMsgId` kullanıyor; anonymous mesaj için belirsiz gönderim retry/idempotency sözleşmesi yok.

### 4.3 Presence ve QA-001 gerçeği

- `activeClients` birden çok socket'i aynı `dbUserId` ile taşıyabiliyor; `req.isUserOnline` herhangi bir process-local kayıt varsa `true` dönüyor.
- `/friends/list` response'u `is_online` üretiyor fakat `last_seen_at`, freshness/observed time veya unknown state taşımıyor.
- `users.last_seen_at` kolonu ve indeksi mevcut; authenticated WebSocket connect/close yaşam döngüsü bu alanı güncellemiyor.
- `users_anon.last_seen_at` başka legacy akışta güncelleniyor; QA-001 authenticated friend presence için bu kaynak değildir.
- Socket close bir kullanıcının başka cihaz/socket'larının açık olup olmadığını değerlendirerek last seen yazmıyor.
- Process restart sonrasında map boşalıyor; başka instance varsa process-local map bütün servis presence'ını temsil etmiyor.
- Arkadaşlara yönelik `presence_update` event'i veya reconnect presence snapshot'ı yok.
- `FriendsScreen` `is_online` ile yalnız görsel nokta gösteriyor; `ChatScreen` friend verisi almadan sohbet bitmediyse sabit `common.online` metni yazıyor.
- QA-001 açık bulgusu gerçek offline, unknown, reconnect ve çoklu cihaz senaryolarının otomatik/manuel kanıtını istiyor.

### 4.4 Repo ve doğrulama yüzeyi

- Kök, backend ve frontend ayrı Git bağlamları taşıyor; kullanıcıya ait mevcut değişiklikler korunmalıdır.
- Backend'de yalnız `test_auth_flow.js` adlı sınırlı bir test dosyası görünür; realtime için hazır iki-client test harness'i doğrulanmadı.
- Frontend test altyapısı Wave 03 kapanışında yeniden doğrulanmalıdır; Wave 05 planı var olmayan test komutunu olmuş gibi kabul etmez.
- Android davranışı aynı React/WebSocket akışını tüketir fakat Android sync/version/signing Wave 18'in otoritesidir.

## 5. Kilitli Wave 05 sözleşmeleri

### 5.1 Kimlik ve otorite katmanları

Aşağıdaki kimlikler birbirinin yerine kullanılamaz:

| Kimlik | Üreten | Yaşam süresi | Kullanım | Kullanılamayacağı yer |
|---|---|---|---|---|
| `userId` | Auth/DB | Hesap | Presence aggregation, friendship yetkisi | Tek socket veya tek cihaz kimliği |
| `sessionId` | Auth katmanı | Login session | Recovery yetkilendirme sınırı | Client'a token hash açmak |
| `deviceId` | Doğrulanmış client metadata | Cihaz kurulumu | Multi-device görünürlük ve rate guard | Tek başına auth/recovery kanıtı |
| `connectionId` | Server | Bir authenticated socket | Event envelope ve stale callback guard | Reconnect sonrası kalıcı state kimliği |
| `recoveryToken` | Server | Kısa grace lease'i | Aynı tab/connection intent'ini güvenli geri bağlama | localStorage'da kalıcı kullanıcı takibi |
| `serverEpoch` | Server process/release | Boot/deploy süresi | Restart/state-loss tespiti | DB migration veya release kimliği yerine |
| `stateRevision` | Server active-state owner | Recovery state değiştikçe artar | Snapshot/event sıralaması | Global event sırası |

Kurallar:

- `recoveryToken` rastgele, tahmin edilemez, kullanıcı/session/device ile server-side bağlı ve kısa TTL'li olur; log, analytics veya URL'ye yazılmaz.
- Web client tab izolasyonu için tokenı yalnız memory/sessionStorage düzeyinde tutar; logout/account switch tokenı siler.
- Auth tamamlanmadan recovery uygulanmaz; token tek başına kullanıcı kimliği vermez.
- Her başarılı reconnect yeni `connectionId` üretir ve recovery lease'i atomik olarak yeni socket'e bağlar.
- Aynı lease'e yarışan iki socket için yalnız en yeni generation aktif kabul edilir; eski socket `superseded` reason ile kapanır.
- Event envelope en az `type`, `connectionId`, `serverEpoch`, `stateRevision` ve ilgili entity kimliğini taşır.

### 5.2 Recovery snapshot sözleşmesi

Authenticated `welcome` sonrasında ve outbox flush edilmeden önce server tek `recovery_snapshot` gönderir:

```json
{
  "type": "recovery_snapshot",
  "schemaVersion": 1,
  "connectionId": "server-connection-id",
  "serverEpoch": "boot-epoch",
  "serverNow": "2026-09-12T12:00:00.000Z",
  "result": "fresh | resumed | reset",
  "reason": "none | grace_expired | server_restart | state_missing | invalid_token | superseded",
  "recoveryGraceMs": 0,
  "stateRevision": 0,
  "active": { "kind": "idle" },
  "unread": {
    "friends": [],
    "system": 0,
    "revision": 0
  }
}
```

`active.kind` discriminated union'dır:

- `idle`: korunmuş queue/offer/anon room yoktur.
- `queue`: Wave 05'in mevcut queue kaydına geri bağlandığını söyler; Wave 07 gelene kadar yeni `searchId` veya gelişmiş lifecycle alanı icat etmez.
- `offer`: `matchId`, peer allowlist alanları, decision state, `autoAcceptAt` ve `timeoutMs` taşır.
- `anonymous_room`: `roomId`, peer allowlist alanları ve peer connection state taşır; anonim mesaj geçmişi uydurmaz.

Snapshot kuralları:

- Snapshot birden çok aktif transient kind taşımaz; queue, offer ve anonymous room birbirini dışlar.
- `fresh`, yeni authenticated bağlantıdır; client yalnız local hayalet transient state'i temizler.
- `resumed`, aynı recovery lease'i grace içinde atomik geri bağlamıştır.
- `reset`, önceki state'in korunmadığını açık reason ile söyler; client otomatik yeni queue başlatmaz.
- Snapshot DB'den friend/system unread değerlerini authoritative olarak reconcile eder; local artış yalnız teslim edilmemiş geçici tahmindir.
- Snapshot uygulanmadan realtime event buffer'ı/outbox flush başlamaz.
- Client yalnız current `connectionId` ve beklenen/higher `stateRevision` eventlerini işler; eski/düşük revision eventini drop edip ölçer.
- Bilinmeyen `schemaVersion`, güvenli `idle + unknown` durumuna düşer ve reconnect loop üretmez.

### 5.3 Reconnect grace ve transient state politikası

- Grace süresi merkezi, bounded server config'idir; source-of-truth response içinde `recoveryGraceMs` ile açıklanır.
- Network close anında transient state hemen yok edilmez; lease `detached` olur ve tek expiry timer/cleanup owner'ı tarafından tutulur.
- Aynı token/session/user ile grace içinde geri dönüş queue sırasını, offer'ı veya anonim room'u yeni socket'e atomik taşır.
- Grace aşılırsa cleanup yalnız bir kez çalışır: queue çıkarılır, pending offer canonical reason ile kapanır, room peer'e güvenli `peer_left` sonucu verir.
- Queue korunmadıysa snapshot `reset`; client “aramaya devam ediliyor” göstermez ve kendiliğinden `joinQueue` göndermez.
- Offer deadline disconnect nedeniyle client tarafında durmaz veya yeniden başlamaz; `serverNow` ve absolute `autoAcceptAt` esas alınır.
- Deadline reconnect'ten önce geçtiyse server timer/decision sonucunu önce finalize eder, sonra güncel snapshot üretir.
- Anonymous room'da peer detached iken teslim garantisi olmayan yeni anonim mesaj kabul edilmez; açık retryable/non-delivered error döner.
- Server restart yeni `serverEpoch` üretir. Process-memory transient state kayıpsa sonuç `reset/server_restart` olur; hayalet resume yapılmaz.
- Cleanup komutları idempotenttir. Duplicate cancel/leave/reconnect callback aynı stateRevision üzerinde ikinci peer sonucu veya ikinci analytics üretmez.
### 5.4 Presence source-of-truth sözleşmesi

Online tanımı:

> Kullanıcı, en az bir authenticated connection lease'i server zamanına göre süresi dolmamışsa `online`; güvenilir lease bulunmuyor ve veri kaynağı okunabiliyorsa `offline`; source okunamıyor veya freshness kanıtlanamıyorsa `unknown` kabul edilir.

Kilitli veri yaklaşımı:

- Process-local `activeClients` hızlı socket yönlendirmesi için kalabilir fakat ürün presence'ının tek otoritesi olamaz.
- Wave 04 migration zinciri üzerinden kısa ömürlü PostgreSQL connection lease registry'si kurulur; ad-hoc startup DDL kullanılmaz.
- Registry en az `connection_id`, `user_id`, server-side session bağını, hashed/opaque device bağını, `instance_id`, `connected_at`, `last_heartbeat_at`, `expires_at` ve generation bilgisini taşır.
- Raw session token, recovery token, IP veya kullanıcıya gereksiz hassas cihaz verisi presence tablosuna yazılmaz.
- Authenticated welcome lease'i açar; bounded heartbeat lease'i yeniler; clean close ilgili lease'i kapatır.
- Abrupt close veya process ölümü `expires_at` ile kendiliğinden stale olur. Cleanup worker idempotent ve tek sahipli/lock'lı çalışır.
- Kullanıcı bazında son geçerli lease kapanınca/expire olunca `users.last_seen_at`, son güvenilir server activity zamanı ile atomik güncellenir.
- Başka geçerli lease varken bir cihazın kapanması kullanıcıyı offline yapmaz ve `last_seen_at` offline anı gibi ileri yazılmaz.
- Friends list tek set-based query ile `is_online`, `last_seen_at`, `presence_state` ve `presence_observed_at` üretir; kullanıcı başına N+1 query yapılmaz.
- Gerekli indeksler query planı ve gerçek friend-list cardinality kanıtıyla migration üzerinden eklenir.

Instance/fan-out kuralı:

- Wave başlangıcında gerçek Render instance/topology bilgisi read-only doğrulanır.
- Tek instance varsayımı kod içine gizlenmez. Birden çok instance mümkünse presence değişimi PostgreSQL `LISTEN/NOTIFY` veya mevcut doğrulanmış ortak event bus üzerinden diğer instance'lara yayılır.
- Notify best-effort'tur; kayıp notify arkadaş listesi/snapshot reconciliation ile düzeltilir.
- Shared lease store erişilemezse process-local map `online` gerçeği diye sunulmaz; response/event `unknown` olur.

Presence event'i:

```json
{
  "type": "presence_update",
  "connectionId": "recipient-current-connection",
  "stateRevision": 42,
  "userId": "friend-user-id",
  "presence": "online | offline | unknown",
  "lastSeenAt": "2026-09-12T12:00:00.000Z",
  "observedAt": "2026-09-12T12:00:01.000Z"
}
```

- Event yalnız authenticated kullanıcının kabul edilmiş arkadaşlarına gider.
- Block/unfriend sonucu erişim kaybolduğunda presence subscription/fan-out hemen kapanır.
- `lastSeenAt`, online durumda gerekli değilse `null`; offline durumda geçerli ISO server timestamp; unknown durumda güvenilmez değer taşınmaz.
- Aynı kullanıcı için düşük revision/older `observedAt` update client tarafından reddedilir.
- Presence heartbeat ve update frekansı rate/batch/debounce sınırına sahiptir; her ping friend fan-out üretmez, yalnız görünür state geçişi event üretir.

### 5.5 Client state domain ve reducer sözleşmesi

Client state tek bir gevşek `status/messages/roomId` kümesi olarak yönetilmez. Wave 03'te oluşturulan state/module sınırları içinde şu sahiplikler ayrılır:

| Domain | Sahip olduğu state | İşleyebildiği event | Temizleme sınırı |
|---|---|---|---|
| Connection | ws phase, connectionId, serverEpoch, recovery phase/error | welcome, recovery snapshot, close/error | Logout/account switch'te tam |
| Anonymous match | queue/offer/anon room, peer, anonymous messages | queued/offer/matched/message/ended + recovery active | Cancel/leave/reset'te yalnız anon |
| Friend chat | selected friend id, history/outbox projection | direct message/ack/history/read | Chat exit selected view'i kapatır; kalıcı unread/store korunur |
| System chat | system thread/inbox/read state | system notice/message/read | Normal peer actionları açılmaz |
| Presence | friendId keyed state/revision/freshness | friends snapshot/presence update | Unfriend/block/logout |
| Media viewer | owner mode/entity/media id/status | image data/error | Owner room değişince veya logout |
| Navigation | görünür screen ve geri davranışı | kullanıcı intent'i + reconciled domain sonucu | Domain state'i tahmin ederek değiştirmez |

Reducer/command kuralları:

- Önce server recovery snapshot atomik uygulanır, sonra buffered current-connection eventleri sırayla reduce edilir.
- Navigation, backend state yaratmaz. Örneğin matching ekranının açık olması queue'nun var olduğu anlamına gelmez.
- Anonymous, friend ve system mesaj koleksiyonları birbirine yazamaz; her event owner kind + entity id ile doğrulanır.
- `activeFriend` kopya obje olarak stale kalmaz; selected friend id güncel friend/presence store'dan türetilir.
- Offer event'i current `matchId`; room event'i current `roomId`; direct message current `friendId/conversationId`; media current owner ile eşleşmeden state değiştiremez.
- Back/cancel/leave tek command intent üretir. Pending command varken ikinci tıklama yeni socket komutu göndermez.
- Server sonucu veya timeout sonrası cleanup tek reducer action ile geçici state'i temizler; birbirinden bağımsız `setState` sırası beklenmez.
- Reconnect raw kullanıcı komutlarını otomatik replay etmez. Friend outbox yalnız mevcut `clientMsgId` sözleşmesini tüketir; anonymous gönderim belirsizse otomatik tekrar yapılmaz.
- Logout/account switch tüm connection, recovery token, active domain, timers, buffered events, outbox ve media state'ini yeni hesaba sızmayacak biçimde temizler.

### 5.6 QA-001 UI ve metin sözleşmesi

Arkadaş sohbeti header'ı:

- Friend mode'da başlık altı presence store'dan türetilir; `ChatScreen` sabit `common.online` yazmaz.
- `online`: ikon + yerelleştirilmiş `Online`; mevcut TalkX success rengi destekleyici olabilir fakat tek işaret değildir.
- `offline` + valid timestamp: TR/EN yerelleştirilmiş göreli `Son görülme ... / Last seen ...` metni.
- `offline` + timestamp yok: dürüst genel `Çevrimdışı / Offline`; tarih uydurulmaz.
- `unknown` veya stale: `Durum bilinmiyor / Status unavailable`; online/offline rengi kullanılmaz.
- Kullanıcının kendi socket'i reconnect olurken son doğrulanmış peer state otomatik `online` yapılmaz. Freshness sınırı aşılmışsa unknown gösterilir; snapshot geldiğinde atomik güncellenir.
- Relative-time metni merkezi formatter'dan gelir, future/invalid timestamp güvenli fallback'e düşer ve görünür ekran için bounded timer ile güncellenir.
- Accessible name durum metnini içerir; renk, animasyon veya yalnız nokta presence'ın tek taşıyıcısı değildir.

Arkadaş listesi:

- Her satır aynı presence store'u tüketir; header ve liste birbirinden farklı gerçek göstermez.
- Online nokta yanında screen-reader metni bulunur; unknown, offline gibi sessizce çizilmez.
- Presence update list item'ı refresh gerektirmeden günceller; selected friend header aynı revision'ı görür.
- Büyük metin, dar telefon, keyboard focus ve reduced-motion mevcut Wave 03 state/token standardını korur.
- Bu wave mevcut TalkX glass/neon tema dilini değiştirmez; yalnız durum bilgisini doğru kaynağa bağlar.

### 5.7 Anonimden arkadaşlığa ürün geçişi

- `anonymous_search`, `pending_offer`, `anonymous_chat`, `friend_chat` ve `system_chat` kullanıcıya aynı mod gibi sunulmaz.
- Recovery banner/status yalnız gerçek connection/recovery state'ini açıklar; uzun bekleme, peer offline ve network offline aynı metni paylaşmaz.
- Anonymous room recovery anonim mesaj geçmişi varmış gibi restore etmez; yalnız oda/peer bağlantı durumunu doğrular.
- Anonymous sohbetten arkadaş isteği gönderilmesi mevcut geçici sohbeti kalıcı friend history'ye taşımaz.
- Arkadaşlık kabulü sonraki kalıcı friend conversation'ı açabilir; önceki anonim mesajlar history API'ye eklenmez.
- Ayrılma/yeni eşleşme, friend chat'e geçiş, report ve block sonuçları farklı domain cleanup üretir.
- Aynı peer ile hızlı rematch cooldown mevcut backend kuralını korur; Wave 05 yeni matchmaking policy'si icat etmez.
- Wave 09 offer UI'si gelene kadar mevcut teklif görünümü görsel olarak yeniden tasarlanmaz; yalnız server-time recovery doğruluğu sağlanır.

### 5.8 Fallback ve hata davranışı

| Durum | Server sonucu | Client davranışı | Yasak davranış |
|---|---|---|---|
| Recovery token yok | `fresh/idle` | Local transient ghost state'i temizle | Eski queue/room'u sürdür |
| Token invalid/başka session | `reset/invalid_token` + rotation | Güvenli idle, gerekirse auth feedback | Tokenı logla veya auth kabul et |
| Grace dolmuş | `reset/grace_expired` | Nedenli reset; kullanıcı isterse yeniden başlatır | Otomatik `joinQueue` |
| Server restart | Yeni epoch + `reset/server_restart` | Anon transient state'i kapat, persistent unread/history reconcile et | Ghost room/offer |
| Presence store unavailable | `unknown` | Nötr status ve son güncelleme bilgisi | Process map'ten sahte Online |
| Unread query unavailable | Snapshot `partial`/hata alanı | Mevcut sayımı doğrulanmamış olarak işaretle veya güvenli refresh | `0` ile sessizce sil |
| Offer deadline geçmiş | Final server state | Güncel snapshot'a geç | Countdown'u sıfırdan başlat |
| Eski event gelir | Current connection/revision ile uyuşmaz | Drop + metric | UI state değiştir |
| Duplicate close/cancel | Aynı idempotent sonuç | Tek cleanup | İkinci peer-left/requeue |
| Friend silinmiş/bloklu | Presence/history yetkisi yok | Friend state'i kapat ve listeyi yenile | Presence sızdır |

### 5.9 Privacy, güvenlik ve telemetry sınırı

- Recovery token, session token/hash, message body, IP, raw device identifier ve friend graph log/analytics payload'ına yazılmaz.
- Recovery/presence endpoint veya eventleri auth, account status, legal gate ve friendship/block yetkisini yeniden doğrular.
- Snapshot yalnız kullanıcının kendi active transient state'ini ve yetkili unread özetini taşır; başka kullanıcı internal connection bilgisi açılmaz.
- Peer'e yalnız ürün için gerekli `connected/reconnecting/left` sonucu verilir; device/instance/reason ayrıntısı verilmez.
- Recovery istekleri connection/user bazında rate limit ve payload limit taşır.
- Metrikler: reconnect attempt/outcome/reason/duration, resumed/reset kind, stale event drop, cleanup idempotency, presence lease count/expiry lag, snapshot latency/failure ve unknown presence sayısı.
- Label'lar bounded allowlist'tir; `userId`, `roomId`, `matchId`, recovery token veya high-cardinality connectionId metric label olmaz.
- Structured log correlation için request/connection correlation kullanılabilir fakat hassas kimlikler redacted/hash policy'sine uyar.
- Behavior eventleri product analytics'i şişirmemek için reconnect attempt değil canonical state sonucu bazında dedupe edilir.

## 6. Uygulama paketleri

### Paket 05A — Contract, topology ve başlangıç kanıtı

**Plan refs:** `B-WS-002`, `B-PRES-001`.

1. Root/backend/frontend Git status, branch, remote ve commit snapshot'ını ayrı kaydet.
2. Wave 02–04 QA kapanışlarını ve ilgili API/WS/migration/health sözleşmelerini doğrula.
3. Gerçek Render instance sayısı, restart modeli, WebSocket affinity ve DB bağlantı sınırlarını read-only doğrula.
4. Mevcut socket event envanteri, queue/offer/room cleanup sırası ve friends query planını çıkar.
5. `recovery_snapshot`, presence event ve error/reason schema fixture'larını test-first kilitle.
6. Grace/freshness/heartbeat/expiry config alanlarını merkezi ve bounded tanımla; secret olmayan varsayılanları environment contract'a bağla.
7. Canlı değişiklik gerektiren adımları ayrı onay kapısında tut.

**Çıkış:** Uygulanacak contract ve topology varsayımı kanıtlı; kod henüz state tahmin etmiyor.

### Paket 05B — Server recovery lease ve snapshot

**Plan ref:** `B-WS-002`.

1. Authenticated socket için connection identity, server epoch, recovery lease ve generation owner'ını ayrıştır.
2. `hello_ack/welcome` akışını recovery token sunumu/rotation ve snapshot sırasıyla sürümle.
3. Queue, pending offer ve room kayıtlarını raw socket yerine atomik rebind edilebilir participant handle'a bağla.
4. Close anında detached/grace state'i; expiry sonunda tek idempotent cleanup uygula.
5. Snapshot builder'ı current active kind, server time/revision, reason ve persistent unread provider ile kur.
6. Server restart/state-missing davranışını açık reset olarak üret.
7. Eski connection komutlarını/revision'larını reddet; superseded socket'i güvenli kapat.
8. Snapshot tamamlanmadan replay/outbox/normal protected command kabulünü sınırla.

**Çıkış:** İki client için resume/reset sonucu server otoriteli ve tekrar üretilebilir.

### Paket 05C — Multi-device presence backend'i

**Plan ref:** `B-PRES-001`.

1. Wave 04 migration runner ile connection lease registry ve gerekli indeks migrationını ekle.
2. Authenticated connect/heartbeat/clean close/abrupt expiry akışlarını registry'ye bağla.
3. Final live lease kapanışında user-scoped transaction/lock ile `last_seen_at` güncelle.
4. Friends list query'sini set-based `presence_state/is_online/last_seen_at/observed_at` response'una genişlet.
5. Presence transition'ı yalnız accepted friends'e ve block/unfriend filtresiyle yayınla.
6. Multi-instance ise shared fan-out'u; tek instance ise explicit topology guard'ını uygula.
7. Expired lease cleanup, restart recovery, DB unavailable unknown ve query-performance testlerini ekle.

**Çıkış:** Online/last seen tek process varsayımından çıkmış ve çoklu cihazda doğru.

### Paket 05D — Client recovery reducer ve state izolasyonu

**Plan ref:** `A-MATCH-004`.

1. Connection, anonymous match, friend, system, presence, media ve navigation state sahipliklerini Wave 03 modüllerine yerleştir.
2. `recovery_snapshot` için validating parser ve tek atomik reducer action kur.
3. Snapshot öncesi current-connection event buffer; sonrası revision/entity guard uygula.
4. Anonymous/friend/system mesaj ve aktif entity state'lerini ayrı store/reducer alanlarına taşı.
5. Back/cancel/leave/logout/account-switch cleanup'larını idempotent command + reducer sonucuna bağla.
6. Friend outbox'ı reconciliation sonrasına bırak; anonymous belirsiz komutu replay etme.
7. Media viewer'ı owner mode/entity değişiminde temizle.
8. Eski socket callback/event ve duplicate command testlerini ekle.

**Çıkış:** Recovery yanlış ekran, ghost room veya çapraz mesaj state'i üretmiyor.

### Paket 05E — QA-001 friend UI ve ürün geçişi

**Plan refs:** `A-FRIEND-001`, `A-PRD-002`.

1. Friend store'a server presence snapshot/update alanlarını ve revision/freshness reducer'ını bağla.
2. `activeFriend` görünümünü selected id + güncel friend store'dan türet.
3. `ChatScreen` friend header'ına tri-state presence prop/view-model ekle; anonymous status ile ayır.
4. Friends list indicator ve accessible text'i aynı view-model ile güncelle.
5. TR/EN online/offline/unknown/last-seen/reconnecting/reset metinlerini merkezi i18n kaynaklarına ekle.
6. Relative-time formatter'ı invalid/future/stale testleriyle kur.
7. Anonymous → friend geçişinde geçici mesajların kalıcı history'ye sızmadığını kanıtla.
8. Mevcut TalkX tema, 44 px hedef, focus, screen reader, reduced motion ve dar mobil düzeni koru.

**Çıkış:** QA-001 dürüst ve erişilebilir; ürün modları birbirine karışmıyor.

### Paket 05F — Entegrasyon, iki-client QA ve kapanış

**Plan refs:** Wave 05'in beş stable ID'si.

1. Focused backend/client testlerini ve iki-client recovery harness'ini çalıştır.
2. Multi-device, abrupt disconnect, grace expiry, restart ve stale event matrisini otomatik kanıtla.
3. Friends list query planı, snapshot latency ve presence lease cleanup ölçümlerini kaydet.
4. Desktop web, dar mobil viewport ve mevcut Android build üzerinde background/foreground manuel QA yap.
5. Full lint/test/build/encoding ve Wave 02–04 regresyon kapılarını çalıştır.
6. Gerçek değişen dosyalar, config/migration ve kanıt yollarını sonuç alanına yaz.
7. Kullanıcı manuel QA onayı gelmeden canonical checkbox/durum kapatma.
8. Wave 06'yı bu wave'in parçası olarak aktive etme veya uygulama.

**Çıkış:** Wave 05 kanıtlı kapanışa hazır; ardıl wave başlamadı.
## 7. Dosya ve servis etki sınırı

Bu liste planlanan etki yüzeyidir; Wave başlatıldığında repo yeniden doğrulanmadan dosya değişikliği yapılmaz.

### Backend olası etki

- `chatapp-backend/index.js` — WebSocket handshake, lifecycle, event envelope ve mevcut transient state entegrasyonu
- Recovery/connection state için ayrıştırılacak yeni backend service/modülleri
- Presence lease, last-seen transition ve fan-out için ayrıştırılacak service/modülleri
- `chatapp-backend/routes/friends.js` — set-based presence/last-seen response
- Wave 04'te kurulmuş migration dizini/runner — yalnız sürümlü presence schema değişikliği
- Merkezi config/env validation — grace, heartbeat, expiry ve instance kimliği
- Focused backend unit/integration/two-client testleri ve fixture'ları

### Frontend olası etki

- `chatapp-frontend/src/App.jsx` — yalnız orchestration sınırı; yeni domain logic burada yığılmaz
- Wave 03'te doğrulanmış connection/recovery ve state reducer/hook modülleri
- Anonymous/friend/system/presence/media state modülleri
- `chatapp-frontend/src/screens/ChatScreen.jsx` — friend presence view-model tüketimi
- `chatapp-frontend/src/screens/FriendsScreen.jsx` — accessible presence state
- `chatapp-frontend/src/components/Friends.jsx` — gerçekten aktif consumer ise aynı contract; kullanılmıyorsa sırf kapsamda diye değiştirilmez
- `chatapp-frontend/src/i18n/messages.tr.js` ve `messages.en.js`
- Mevcut token/CSS kaynağı — yalnız gerekli state/accessibility selector'ları
- Focused reducer/parser/component testleri ve fixture'ları

### Dokümantasyon ve operasyon etkisi

- İlgili API/WebSocket contract belgesi veya mevcut docs kaynağı
- Config/runbook kaynağında recovery/presence ayarları
- Wave 05 test/QA kanıt kaydı
- Canonical Plan A/B checkbox ve durumları yalnız gerçek kapanışta
- Master QA-001 durumu yalnız kullanıcı onayından sonra
- Wave Map ve `waves/README.md` yalnız kanıtlı durum değişikliğinde

### Değişiklik öncesi zorunlu kontrol

- Üç Git bağlamında path/status/branch/remote/commit
- Dosyanın tracked/untracked ve kullanıcı değişikliği durumu
- Wave 03 module/test gerçekliği
- Wave 04 migration/health/runbook gerçekliği
- Runtime instance ve DB topology
- İlgili dosyada BOM, line ending ve encoding biçimi

## 8. Açık kapsam dışı

- Wave 06 `B-DATA-001/002`, `C-COMP-002`, `B-DATA-003`, `C-TRUST-002`
- Global / Kendi Ülkem selector, canonical country veya hesap silme/retention uygulaması
- Wave 07 `B-MM-001` search lifecycle ve `A-MATCH-001` QA-014 ekranı
- Wave 08 Global/Country partition queue ve selector
- Wave 09 `B-MM-003` pending-match karar protokolü ve QA-003 görsel yeniden tasarımı
- Wave 10 `B-MSG-001` genel mesaj idempotency/outbox genişletmesi
- Wave 11 media/moderasyon/header action redesign
- Wave 12 auth/session/legal ekranları
- Admin dashboard, analytics UI veya release-health geliştirmesi
- Android version bump, Capacitor sync, signing, bundle veya store işlemleri
- Canlı DB migrationı, Render/Neon config değişikliği, restart/redeploy veya production smoke
- Framework rewrite, yeni state kütüphanesi veya gerekçesiz büyük `App.jsx` yeniden yazımı
- Presence bilgisini kabul edilmiş arkadaşlar dışına açmak
- Anonymous mesajları kalıcılaştırmak veya reconnect için message history icat etmek
- Wave 06 aktivasyonu veya uygulaması

## 9. Otomatik doğrulama planı

### 9.1 Contract/schema testleri

- Recovery snapshot'in required/optional alanları, enumları ve `schemaVersion` fixture ile doğrulanır.
- `active.kind` union aynı anda birden çok transient state kabul etmez.
- Event envelope current connection/revision/entity guard'ından geçmeden reducer'a ulaşmaz.
- Unknown field geriye uyumlu ignore edilir; unknown version güvenli reset/upgrade-required sonucu verir.
- Presence response `online/offline/unknown`, `lastSeenAt` ve `observedAt` kombinasyonlarını doğrular.
- Error/reason alanları allowlist dışı internal bilgi veya secret taşımaz.

### 9.2 Backend recovery state test matrisi

| Senaryo | Beklenen kanıt |
|---|---|
| İlk authenticated connect | `fresh/idle`, current connection/epoch ve authoritative unread |
| Queue iken grace içinde reconnect | Aynı queue participant handle, tek entry, `resumed` |
| Queue grace aşımı | Tek cleanup, `reset/grace_expired`, otomatik requeue yok |
| Offer iken reconnect | Aynı `matchId`, absolute deadline ve doğru remaining time |
| Offer deadline reconnect sırasında geçer | Önce canonical finalization, sonra güncel snapshot |
| Anonymous room grace içinde reconnect | Socket atomik rebind, peer'e tek recovery sonucu |
| Anonymous room grace aşımı | Tek end/peer-left; ghost room yok |
| Server restart | Yeni epoch, `reset/server_restart`, stale transient state yok |
| Aynı tokenla iki socket yarışı | Tek latest generation, eski socket superseded |
| Eski socket komutu/eventi | State değişmez, stale-drop metriği artar |
| Duplicate close/cancel/leave | Tek cleanup ve tek peer/requeue sonucu |
| Snapshot/unread DB hatası | Açık partial/unknown; sahte sıfır yok |

### 9.3 Presence ve DB test matrisi

- İlk authenticated lease online transition üretir.
- Auth öncesi socket kullanıcıyı online yapmaz.
- İki cihazdan biri kapanınca user online kalır ve offline last seen yazılmaz.
- Son cihaz clean close yaptığında last seen server zamanı ile bir kez güncellenir.
- Abrupt termination heartbeat expiry sonrası offline/last seen üretir.
- Expired lease cleanup tekrar çalıştırıldığında idempotenttir.
- Server restart stale lease'i sonsuza kadar online bırakmaz.
- İki instance eşzamanlı close/open yarışında user-scoped lock doğru final state'i üretir.
- DB/event-bus unavailable `unknown` üretir; process map'ten sahte online dönmez.
- Friends list tek query/bounded query set'i kullanır ve gerekli indeks planını kanıtlar.
- Unfriend/block sonrasında presence event erişimi kesilir.
- Presence notify kaçırılırsa reconnect/list snapshot doğru state'i geri getirir.

### 9.4 Client reducer/component test matrisi

- Recovery snapshot bütün ilgili state'i tek render transaction/reducer action ile uygular.
- Eski offer yeni connection/queue state'inde açılmaz.
- Friend direct message anonymous message listesine düşmez.
- Anonymous message friend/system state'ine düşmez.
- System chat cevap alanı/peer action state'i açmaz.
- Cancel/back double click tek leave intent üretir.
- Reset anonymous state'i temizlerken friend unread/outbox'ı silmez.
- Friend history load geç dönerse başka selected friend'a yazılmaz.
- Media response owner room/chat değişmişse viewer'ı açmaz.
- Reconnect öncesi belirsiz anonymous send otomatik replay edilmez.
- Friend outbox snapshot/reconciliation öncesi flush edilmez.
- Logout/account switch bütün token/timer/buffer/state'i temizler.
- Header online/offline/last seen/unknown/reconnecting state'lerini doğru metin ve accessible name ile render eder.
- Invalid/future/stale timestamp güvenli fallback'e düşer.
- Friends list ve active header aynı presence revision'ını tüketir.

### 9.5 Komut ve kalite kapıları

Mevcut repo bugün yalnız şu doğrulanmış komutları sağlar:

```powershell
npm.cmd run check:text-encoding
npm.cmd --prefix chatapp-frontend run lint
npm.cmd --prefix chatapp-frontend run build
node --check chatapp-backend/index.js
node --check chatapp-backend/routes/friends.js
```

- Root `npm test` bilerek başarısız placeholder'dır; başarı kanıtı diye çalıştırılmaz.
- Backend package'ında test script'i, frontend package'ında test script'i bugün yoktur.
- Wave 03 kapanışında oluşmuş gerçek test runner/komutları başlangıçta yeniden okunur.
- Wave 05'in gerekli backend/client focused testleri mevcut runner'a eklenir; runner yoksa dependency etkisi raporlanıp en küçük test altyapısı açık kapsamla kurulur.
- `node --check` yeni/etkilenen bütün CommonJS backend dosyalarına uygulanır.
- Lint/build warning ile test failure ayrılır; warning gizlenmez.
- Flaky timer/reconnect testi önce fake timer ve tek-worker/focused tekrar ile ayrıştırılır; ürün kodu kanıtsız değiştirilmez.
- Full komutların stdout/exit code/çalışma zamanı kapanış kanıtında saklanır.

## 10. Manuel ve iki-client QA planı

### 10.1 Desktop iki-client recovery

1. İki ayrı browser profile/incognito context ile iki farklı authenticated hesap aç.
2. DevTools Network/WS frame ve gerekli server correlation kaydını hazırla; token/mesaj body kaydetme.
3. Queue, offer ve anonymous room aşamalarında bir client'ın networkünü kısa süre kesip grace içinde aç.
4. Aynı entity'nin geri bağlandığını, duplicate queue/offer/room oluşmadığını ve peer mesajının dürüst olduğunu doğrula.
5. Grace süresini aşan kopmada reset/peer-left ve manuel yeniden başlatma davranışını doğrula.
6. Eski socket frame/eventini kontrollü geciktirerek yeni state'i değiştirmediğini kanıtla.
7. Server restart staging senaryosunda yeni epoch/reset ve ghost state yokluğunu kontrol et.

### 10.2 Multi-device presence

1. Hesap A'yı iki ayrı cihaz/profile'da; arkadaş B'yi üçüncü context'te aç.
2. A'nın ilk authenticated bağlantısında B listesinin/header'ının online olduğunu doğrula.
3. A cihazlarından yalnız birini kapat; B'de A online kalmalı.
4. Son A cihazını clean close et; B'de offline/last seen refreshsiz görünmeli.
5. A'yı abrupt network loss ile kes; expiry sonrası last seen ve tek offline transition doğrulanmalı.
6. B reconnect olurken header'ın sahte Online'a dönmediğini; snapshot sonrası doğru state'e geldiğini kontrol et.
7. A-B friendship silme/block sonrasında presence update sızıntısı olmadığını doğrula.

### 10.3 Friend/anonymous/system state izolasyonu

- Anonymous chat açıkken friend direct message gönder; yalnız friend unread/notification güncellensin.
- Friend history requestini yavaşlatıp başka friend seç; geç response yeni sohbete yazılmasın.
- Image viewer açıkken room/friend değiştir; eski medya yeni context'te görünmesin.
- Cancel/leave'e hızlı çift bas; peer yalnız tek sonuç alsın.
- Logout ardından başka hesapla giriş yap; önceki friend, unread, recovery ve media state'i görünmesin.
- System notice normal friend/anonymous message alanına düşmesin ve cevap alanı açmasın.
- Anonymous sohbetten arkadaş isteği kabulünden sonra friend history'de eski anonymous mesajların bulunmadığını doğrula.

### 10.4 UX, accessibility ve platform

- Friend header ve listede online/offline/unknown/last-seen metnini TR ve EN'de kontrol et.
- Renk körlüğü simülasyonu, screen reader, keyboard-only, focus görünürlüğü ve 200% text ile doğrula.
- Dar telefon viewport, safe-area, keyboard açık/kapalı ve reduced-motion senaryolarını kontrol et.
- Mevcut Android build'i background/foreground, kısa/uzun kopma ve resume için test et; sync/version/signing yapma.
- TalkX glass/neon temasının header/list state ekleriyle bozulmadığını ekran görüntüsüyle doğrula.

## 11. Kanıt ve kabul eşlemesi

| Plan ref | Gerekli kanıt | Kapanış şartı |
|---|---|---|
| B-WS-002 | Snapshot contract, grace/restart/rebind, stale-event ve duplicate cleanup iki-client sonuçları | Altı canonical kabul kriteri kanıtlı |
| B-PRES-001 | Multi-device lease, final close/expiry last seen, restart/unknown ve list performance sonuçları | Beş canonical kabul kriteri kanıtlı |
| A-MATCH-004 | Domain reducer, stale entity/event, cancel cleanup, message/outbox ve recovery sonuçları | Altı canonical kabul kriteri kanıtlı |
| A-FRIEND-001 | Friend response/event, header/list tri-state, TR/EN relative time ve accessibility kanıtı | Beş canonical kabul kriteri kanıtlı |
| A-PRD-002 | Mod/transition matrisi, anon history izolasyonu, leave/report/block ve backend-authority kanıtı | Beş canonical kabul kriteri kanıtlı |

Checkbox yalnız ilgili canonical kriter gerçek kod, otomatik test, manuel QA ve gereken yerde runtime kanıtıyla kapandığında işaretlenir. Kısmi altyapı, taslak schema veya yalnız screenshot stable ID'yi kapatmaz.

## 12. Riskler ve rollback

| Risk | Koruma | Rollback/durma davranışı |
|---|---|---|
| Grace ghost queue/room üretir | Tek lease owner, revision ve expiry testleri | Grace resume feature flag'ini kapat; güvenli reset'e dön |
| Aynı token iki socket'i sahiplenir | Generation compare-and-swap | Eski generation'ı kapat; state mutasyonunu durdur |
| Offer timer reconnect ile iki kez finalize olur | Server deadline + idempotent finalizer | Offer'ı canonical closed state'e al, duplicate room yaratma |
| Detached room mesaj kaybeder | Peer-detached send guard | Gönderimi non-delivered olarak reddet |
| Server restart client ghost state bırakır | serverEpoch + reset snapshot | Bütün anon transient state'i güvenli kapat |
| Snapshot ile realtime event yarışı | Buffer + revision ordering | Resync iste; tahminle event uygulama |
| Outbox reconciliation öncesi flush duplicate üretir | Snapshot gate + mevcut clientMsgId | Flush'ı durdur; item'ı pending/unknown bırak |
| Shared presence store yavaşlar | TTL/index/query plan/rate sınırı | Presence'ı unknown yap; request path'i çökertme |
| Lease expiry yanlış offline üretir | Heartbeat jitter budget + multi-device aggregation | Freshness'i unknown'a genişlet; sahte offline yazma |
| Last seen her cihaz kapanışında ileri gider | Final-lease transaction/lock | Yazımı durdur, önceki güvenilir timestamp'i koru |
| LISTEN/NOTIFY event kaybı | Snapshot/list reconciliation | Event'e güvenme; authoritative refresh yap |
| Friends query N+1/perf regresyonu | Set-based query + EXPLAIN evidence | Yeni projection'ı feature flag ile kapat |
| Presence privacy sızıntısı | Friendship/block auth filter | Fan-out'u durdur ve erişimi revoke et |
| Header reconnect'te flicker yapar | Tri-state freshness view-model | Unknown göster; Online varsayma |
| State extraction kullanıcı işini örter | Dirty snapshot ve küçük paketler | Yalnız Wave 05 farkını geri al |
| Yeni test altyapısı kapsamı büyütür | Başlangıçta runner doğrulaması | Dependency eklemeden dur ve etkiyi raporla |

## 13. Rollout, feature flag ve rollback sırası

1. Contract/parser/test fixture'ları davranış değiştirmeden eklenir.
2. Presence migration yalnız local/izole DB'de uygulanır ve Wave 04 migration kapılarından geçer.
3. Server recovery/presence üretimi default-off capability/feature flag arkasında staging'e çıkar.
4. Client capability görmüyorsa mevcut reconnect/global akışı çalışır; yeni UI yanlış presence göstermez ve selector/sonraki-wave özelliği açılmaz.
5. Staging'de tek instance, sonra doğrulanmış multi-instance/topology senaryosu test edilir.
6. Client parsing/reducer ve friend UI capability ile açılır; server eski client compatibility'si kanıtlanır.
7. İki-client/multi-device/Android foreground QA sonrası kullanıcı onayı alınır.
8. Production config/migration/deploy ancak ayrıca açık yetkiyle ve Wave 04 runbook'uyla yapılır.
9. Rollback önce client capability'yi, sonra event fan-out'u, sonra recovery resume'u kapatır; DB additive schema destructive biçimde geri alınmaz.
10. Rollback sırasında transient state güvenli `reset` olur; sahte resume veya veri silme yapılmaz.

## 14. Başlangıç kapısı

Bu kutular plan hazırlanırken işaretlenmez; yalnız Wave 05 gerçekten başlatılırken güncel kanıtla kapatılır:

- [ ] Wave 01–04 QA kapanışları ve kullanıcı onayı doğrulandı.
- [ ] Kullanıcı açıkça “Wave 05'i başlat” talimatı verdi.
- [ ] Root, backend ve frontend Git status/remote/branch/commit snapshot'ı alındı.
- [ ] Wave 02 WebSocket/auth contractı güncel kodda yeniden doğrulandı.
- [ ] Wave 03 client module/state/test standardı güncel repoda doğrulandı.
- [ ] Wave 04 migration/health/config/runbook kapıları doğrulandı.
- [ ] Runtime instance, WebSocket affinity ve shared DB/event topology read-only belirlendi.
- [ ] Mevcut queue/offer/room/unread/presence state ve close/reconnect event haritası güncellendi.
- [ ] Presence migrationı, indeks/query planı ve retention/cleanup etkisi incelendi.
- [ ] Recovery grace/freshness/heartbeat config sözleşmesi ve capability rollout'u kilitlendi.
- [ ] Canlı DB/config/restart/deploy işlemleri ayrı onay kapısına bağlandı.
- [ ] Wave 06 ve Wave 07–10 scope'larına taşma olmadığı doğrulandı.

## 15. Sonuç alanı

Wave 05 yürütülürse kapanış kaydı en az şunları içerir:

- Başlangıç/bitiş zamanı, Plan refs ve gerçek değişen dosyalar
- Üç Git bağlamının önce/sonra status/commit farkı
- Recovery/presence contract schema ve compatibility sonucu
- Queue/offer/room grace, restart, stale event ve idempotent cleanup iki-client kanıtı
- Presence migrationı, query planı, lease/expiry, multi-device ve last-seen sonuçları
- Client domain reducer, entity/revision guard, outbox ve media cleanup sonuçları
- QA-001 online/offline/unknown/last-seen TR/EN ve accessibility kanıtı
- Anonymous → friend history/mod geçişi izolasyon kanıtı
- Lint/build/encoding/backend syntax/focused/full test komutları ve exit code'ları
- Staging/Android mevcut build manuel QA sonucu; varsa ayrı onaylı canlı işlem kaydı
- Canonical checkbox ve Master QA-001 durum değişiklikleri
- Kullanıcı onayı, son Wave durumu ve Wave 06'nın başlatılmadığına dair açık kayıt

## 16. Durma kuralı

Wave 04 QA kapanışı ve kullanıcının açık Wave 05 başlatma talimatı birlikte gelene kadar:

- Wave 05 için kod, test, dependency, migration, DB, config, Android veya deploy değişikliği yapılmaz.
- Render/Neon/canlı servis üzerinde hiçbir state değişikliği yapılmaz.
- Wave 05 `Aktif` işaretlenmez; bu belge yalnız `Hazır — aktif değil` durumunda kalır.
- Wave 06 yalnız ayrı açık planlama talimatıyla belgelenebilir; aktive edilmez veya uygulanmaz.