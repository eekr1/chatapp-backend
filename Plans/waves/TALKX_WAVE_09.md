# TalkX Wave 09 Plan — QA-003 Pending Match Teklif Protokolü ve Karar Yüzeyi

> Bu belge yalnız Wave 09 için hazırlanmış uygulama planıdır.
> Canonical ayrıntı Plan B `B-MM-003`, Plan A `A-MATCH-002` ve Master QA-003'tedir.
> Plan hazırdır. Wave 09 aktif değildir, Wave 01–08 kapanmamıştır ve uygulama başlamamıştır. Wave 10 mesaj idempotency/outbox kapsamı bu belge içinde uygulanmaz; hazırlanmış Wave 10 planı aktif edilmez.

## 1. Durum ve yürütme sınırı

- **Wave:** 09
- **Wave adı:** QA-003 pending match teklif protokolü
- **Plan katılımı:** Plan B + Plan A
- **Canonical sıra:** `B-MM-003 → A-MATCH-002`
- **Plan durumu:** Hazır
- **Wave durumu:** Bekliyor
- **Uygulama durumu:** Başlamadı
- **Uygulama yetkisi:** Verilmedi
- **Giriş kapısı:** Wave 08 `QA kapalı` ve kullanıcıdan açık “Wave 09'u başlat” talimatı
- **Mevcut blokaj:** Wave 01–08 uygulanıp kapanmadı; Wave 09 uygulanamaz
- **Önceki wave:** Wave 08 — planı hazır, aktif değil
- **Sonraki wave:** Wave 10 — planı hazır, aktif değil ve başlatılmadı

Bu dosyanın hazırlanması Wave 09 aktivasyonu, kod/test/dependency değişikliği, migration, canlı queue/socket/conversation işlemi, feature flag, deploy veya Wave 10 uygulaması için yetki değildir.

## 2. Canonical referanslar ve öncelik

1. `B-MM-003` — matchId/searchId bağlı pending-match state machine, iki participant kararı, auto-accept, finalize ve requeue
2. `A-MATCH-002` — QA-003 teklif/kabul ekranı, countdown, CTA hiyerarşisi ve bütün durumların kullanıcı geri bildirimi
3. Master Backlog `QA-003` — onaylı tasarım yönü, davranış eşlemesi ve on maddelik kabul listesi
4. `B-MM-001` / `A-MATCH-001` — Wave 07 server-time/search lifecycle, mood/prompt ve offer geçişi
5. `B-MM-002` / `A-MATCH-003` — Wave 08 effective scope, country bütünlüğü, fallback ve same-scope requeue
6. `B-WS-002` / `A-MATCH-004` — Wave 05 connection recovery, epoch/revision ve stale state koruması
7. Onaylı görsel yön: `../assets/manual-qa/qa-003-approved-design-direction.png`
8. Baseline kanıt: `../assets/manual-qa/qa-003-current-match-offer.png`

Çelişki çözümü:

- Match ve karar gerçeği yalnız server state machine'indedir; client countdown sıfırında room veya acceptance uydurmaz.
- `Sohbete Başla` yalnız bu teklifi kabul eder; `Geç` yalnız bu peer teklifini reddeder; `Eşleşmeyi iptal et` bütün search journey'yi kapatır.
- Wave 08 effective scope requeue boyunca korunur; Wave 09 Global'e düşürmez veya scope UI eklemez.
- Wave 07 mood/prompt sakin ikincil içerik olarak korunur; otomatik gönderilmez.
- Görsel referans piksel kopyası değildir; kompozisyon, hiyerarşi, cyan/pembe neon dili, progress ve aksiyon seviyeleri otoritedir.
- Master/Plan ile mevcut kod çatışırsa canonical sözleşme kazanır.

## 3. Wave sonucu

Wave 09 sonunda:

- Her pending offer tek `matchId` ve iki katılımcının current `searchId`/effective scope kimliğiyle izlenecek.
- Offer; `offered → waiting/finalizing → completed` veya açık terminal `closed` geçişlerinden yalnız birini yaşayacak.
- Manual accept, auto-accept, reject/pass, cancel, timeout, disconnect ve retry aynı serialized/idempotent state machine'de çözülecek.
- Manual/auto accept yarışı en fazla bir conversation ve bir room üretecek.
- Stale matchId/searchId/revision kararı state'i değiştirmeyecek.
- Conversation DB hatası ghost room, yarım mapping veya delivered-like başarı üretmeyecek; iki taraf belirlenmiş aynı-scope requeue sonucunu görecek.
- Server absolute `offeredAt`, `autoAcceptAt` ve `serverNow` döndürecek; client countdown/progress'i bu zamanlardan hesaplayacak.
- Teklif anı merkez neon/glass kart, tek kimlik, net başlık/alt metin, progress ve üç seviyeli CTA ile güçlü ama sakin sunulacak.
- “Sohbete Başla” ana, “Geç” ikincil, “Eşleşmeyi iptal et” üçüncül olacak; bütün hedefler en az 44×44 px.
- Kullanıcı kabul ettikten sonra duplicate karar engellenecek ve `waitingPeer` açıkça gösterilecek.
- Peer accepted hint, reject, timeout, cancel, peer leave, reconnect ve server error ayrı kullanıcı durumları olacak.
- Generic anonim görsel kullanılacak; güvenilir presence sözleşmesi yoksa dekoratif online noktası olmayacak.
- 320 px, uzun kimlik/TR-EN metni, büyük font, WebView, klavye, screen reader ve reduced-motion doğrulanacak.
- QA-014/QA-017 davranışları ve offer öncesi geçiş bozulmayacak.
- Wave 10 başlamayacak.

## 4. Doğrulanmış başlangıç fotoğrafı

### 4.1 Backend pending gerçeği

- `pendingMatches` process-memory Map; user→match için ayrı map var.
- Pending kaydı iki participant, local decision, `autoAcceptAt`, timeout timer ve `finalized` boolean taşıyor.
- Offer `matchId`, peer alanları, autoAcceptAt ve timeoutMs taşıyor; searchId/scope/revision/command identity yok.
- Accept decision doğrudan participant'ı accepted yapıyor; duplicate/conflicting command için açık ack/idempotency sonucu yok.
- Timeout tüm pending participantları accepted yapıp finalize çağırıyor.
- Reject pair cooldown kurup pending'i kapatıyor ve iki tarafı yeniden queue'ya sokuyor.
- Requeue parametresiz join kullandığı için Wave 08 uygulanmadan effective scope korunmuyor.
- Conversation oluşturulduktan sonra room process state'i kuruluyor; crash/retry ve aynı match için persistent uniqueness ayrıca kanıtlı değil.
- Disconnect/recovery semantiği mevcut kodda pending state machine envelope'una bağlı değil.

### 4.2 Client teklif gerçeği

- `MatchScreen.jsx` search ve offer görünümünü aynı componentte koşullu render ediyor.
- Offer kartı username'i subtitle ve `@username` alanında tekrar edebiliyor; nickname ek bir satır açabiliyor.
- Countdown interval ile güncellense de `App.jsx` server `autoAcceptAt` değerini tüketmek yerine `Date.now() + timeoutMs` üretebiliyor.
- Reject ve accept yatay, birbirine yakın ağırlıkta; cancel kart dışındaki kırmızı outline düğme.
- Kalan saniye metni var fakat süreye bağlı görsel progress yok.
- Waiting/peerAccepted'in bazı eventleri var; reject/timeout/cancel/disconnect/reconnect için bütünlüklü görünüm modeli yok.
- Dekoratif online noktası mevcut kodda görünmüyor; yeni tasarım bunu güvenilir presence olmadan eklememeli.

### 4.3 Görsel ve repo kanıtı

- Current ve approved-direction PNG dosyaları repo dokümanında kayıtlıdır; uygulama başında render ölçüleriyle yeniden açılıp baseline alınır.
- Görsel dosyayı bu planlama oturumunda doğrudan görüntüleme aracı Windows sandbox hatası nedeniyle açamadı; canonical Master açıklaması ve asset varlığı doğrulandı. Uygulama başlangıç kapısında görsel inspection zorunludur.
- Root/backend/frontend kullanıcı değişiklikleri korunur; üç Git bağlamı ayrı snapshot edilir.

## 5. Pending match domain modeli

### 5.1 Kimlikler

- `matchId`: bir teklif çiftinin değişmez kimliği.
- Her participant için `searchId`, `queueAttempt`, effective scope ve gerekiyorsa canonical country code snapshot'ı.
- `commandId`: accept/pass/cancel retry idempotency anahtarı.
- `stateRevision` ve `serverEpoch`: event sırası ve restart koruması.
- Conversation/room kurulumu `matchId` ile idempotent bağ taşır.

Peer'e internal user id, country source veya hassas profil verisi gönderilmez. Public identity yalnız ürünün mevcut görünür username/nickname politikasından minimize edilir.

### 5.2 Match state

Önerilen server status:

- `offered` — iki karar pending
- `waiting` — en az bir participant accepted, diğer sonuç bekleniyor
- `finalizing` — iki taraf accepted; conversation/room tek kez kuruluyor
- `completed` — tek conversation/room sonucu üretildi
- `closed` — reason ile terminal, room yok

Participant decision:

- `pending`
- `accepted_manual`
- `accepted_auto`
- `rejected`
- `cancelled`
- `disconnected` yalnız recovery grace sonunda terminal policy sonucuysa

Karar kaydı decisionAt, commandId, actor ve safe source (`manual|deadline|recovery`) taşır.

### 5.3 İzinli geçişler

- offered → waiting: ilk manual accept
- offered/waiting → finalizing: iki decision accepted olduğunda
- offered/waiting → closed(rejected): bir participant Geç
- offered/waiting → closed(cancelled): bir participant bütün search'i iptal eder
- offered/waiting → closed(peer_left/disconnected): recovery policy grace sonrası
- offered/waiting → finalizing: deadline kalan pending kararları auto kabul eder
- finalizing → completed: conversation+room commit
- finalizing → closed(server_error): güvenli rollback/cleanup ve requeue policy
- Terminal completed/closed yeniden açılmaz.

Aynı command replay aynı ack/state snapshot döndürür. Aynı participant accepted olduktan sonra gelen farklı reject conflict olur ve state mutate etmez. Deadline/manual karar aynı user lock/match lock altında tek transition olarak çözülür.

## 6. Server time ve countdown

- Server `offeredAt`, `autoAcceptAt`, `serverNow` ve timeout policy version üretir.
- Client `serverNow` offset'iyle `remaining = autoAcceptAt - correctedNow` hesaplar.
- Progress `clamp(remaining / (autoAcceptAt - offeredAt))` üzerinden deterministiktir; interval yalnız render tetikler.
- Background/foreground veya reconnect sonrası snapshot'tan düzelir; local tick sayısına dayanmaz.
- Client server `autoAcceptAt` değerini yeniden üretmez.
- Sıfırda client kendi başına accepted/matched demez; `finalizing`/“Bağlantı kuruluyor” durumunda server sonucunu bekler.
- Server deadline timer gecikse bile karar absolute deadline altında serialized değerlendirilir.
- Çok geç/stale offer hiç gösterilmez; server current snapshot istenir.
- Saat alanı bozuksa primary karar güvenliği korunur, countdown “hesaplanıyor” fallback'i gösterir ve telemetry contract error üretir.

## 7. Realtime komut ve event sözleşmesi

### 7.1 Client karar komutu

```json
{
  "type": "matchDecision",
  "protocolVersion": 1,
  "matchId": "uuid",
  "searchId": "uuid",
  "commandId": "uuid",
  "decision": "ACCEPT"
}
```

`decision` yalnız `ACCEPT | PASS`. Bütün search'i kapatmak `leaveQueue/cancelMatchSearch` ailesinde matchId+searchId ile ayrı komuttur. Legacy accept/reject eventleri capability adapter üzerinden yeni state machine'e yönlenebilir.

### 7.2 Match offer

```json
{
  "type": "match_offer",
  "protocolVersion": 1,
  "matchId": "uuid",
  "searchId": "uuid",
  "queueAttempt": 1,
  "effectiveScope": "GLOBAL",
  "offeredAt": "server-time",
  "autoAcceptAt": "server-time",
  "serverNow": "server-time",
  "stateRevision": 42,
  "peer": { "publicLabel": "@example" }
}
```

COUNTRY scope bütünlük için canonical code taşıyabilir fakat QA-003 UI bunu göstermez. Mood/prompt client search snapshot'ından bağlanır; peer'e gönderilmez.

### 7.3 Server sonuçları

- `match_offer_state`: matchId, participant public decision state, waiting/finalizing status, deadline ve revision
- `match_offer_peer_accepted`: yalnız current match hint veya state snapshot'ının türevi
- `match_offer_closed`: matchId/searchId, controlled reason, actor result, requeue outcome ve revision
- `matched`: matchId/searchId, conversationId/roomId, peer public identity ve completed revision
- `match_decision_ack`: commandId, accepted/replayed/conflict sonucu ve current state
- Wave 05 recovery snapshot: pending match'in tamamını server otoritesiyle yeniden kurar

Controlled close reasonları en az `self_passed`, `peer_rejected`, `self_cancelled`, `peer_cancelled`, `timeout_result`, `peer_left`, `recovery_expired`, `server_error`, `stale_match` sınıflarını ayırır. Teknik kodlar locale metne çevrilir.

## 8. Backend uygulama paketi — B-MM-003

### 8.1 Tek mutation otoritesi

Pending match üzerindeki accept/pass/cancel/deadline/disconnect/finalize işlemleri tek servis ve match-level serialization üzerinden geçer. WebSocket switch dalları doğrudan Map alanı değiştirmez.

Servis her mutationda:

1. Actor authentication ve participant membership'i doğrular.
2. matchId/searchId/epoch/revision freshness kontrolü yapar.
3. commandId replay sonucunu arar.
4. Deadline ile manual action yarışını aynı server zamanına göre çözer.
5. İzinli state transition uygular.
6. Event/analytics ve requeue sonucunu aynı domain sonucu üzerinden üretir.
7. Client'a ack + authoritative snapshot yollar.

### 8.2 Idempotency ve race kuralları

- Aynı accept iki kez yalnız tek decision yazar.
- Accept ile auto-accept aynı anda gelirse ilk serialized transition kazanır; iki finalize yoktur.
- İki taraf aynı anda accept ederse finalizing lock yalnız bir conversation creation başlatır.
- Pass ile peer accept yarışında pass accepted before finalizing ise match closed; finalizing başladıysa deterministic conflict/current state döner.
- Cancel ile pass farklıdır: pass actor'u same-scope requeue eder; cancel actor search journey'yi terminal kapatır.
- Stale matchId veya eski searchId hiçbir current pending state'i kapatamaz.
- Disconnect kısa recovery grace içinde state'i bozmaz; grace sonunda policy peer'e açık reason/requeue verir.
- Server restart sonrası pending restore kanıtı yoksa client fake waiting sürdürmez; explicit reset/closed snapshot alır.

### 8.3 Requeue matrisi

| Terminal olay | Actor | Peer | Search/scope |
|---|---|---|---|
| Actor `PASS` | Requeue | Requeue | İkisinin kendi journey/effective scope'u |
| Peer reject | Requeue | Reject actor da requeue | Same-scope, pair cooldown |
| Tüm search cancel | Requeue yok, terminal | Requeue | Peer kendi effective scope |
| Peer cancel | Cancel actor yok | Requeue | Peer kendi effective scope |
| Recovery grace expired | Disconnected actor auto queue yok | Connected peer requeue | Peer scope korunur |
| Conversation error | İki connected participant requeue | İki connected participant requeue | Kendi scope/search policy |
| Successful room | Queue yok | Queue yok | Search journey completed |

Requeue current search journey sürüyorsa Wave 07 searchId politikası ve artan queueAttempt'i; Wave 08 effective scope/country snapshot'ını kullanır. Yeni search gerektiren terminal durumda yeni id açıkça üretilir. Parametresiz `joinQueue` fallback'i kabul edilmez.

### 8.4 Conversation ve room atomikliği

- Pending `finalizing` yapılmadan conversation creation başlamaz.
- Aynı match için conversation oluşturma idempotency anahtarı `matchId` olur.
- Mevcut şemada source match uniqueness yoksa Wave 04 migration kurallarıyla additive unique alan/tablo veya eşdeğer transaction ledger tasarlanır; production migration ayrıca onay ister.
- Conversation commit başarısızsa room/userRoomMap kurulmaz.
- DB commit başarılı ama process response kesilirse retry aynı conversation sonucunu bulur; ikinci conversation üretmez.
- Room map yalnız durable conversation sonucu alındıktan sonra kurulur.
- İki participant'a `matched` aynı completed state'ten gönderilir; tek taraflı ghost success recovery snapshotla düzeltilebilir.
- Cleanup timer/map/user mapping işlemleri terminal state sonucu üzerinden idempotent yapılır.

### 8.5 Cooldown, abuse ve privacy

- Pass/reject pair cooldown mevcut ürün politikasını korur; duplicate karar cooldown'u çoğaltmaz.
- Ban/block/shadow-ban sonucu pending aşamasında değişirse güvenli close reason ve requeue policy uygulanır.
- Analytics peer raw user ID, prompt metni veya country kaynağı taşımaz; gerekli match correlation erişim/retention politikasına bağlıdır.
- Internal state/loglar karar komut gövdesini gereksiz PII ile yazmaz.
- Public offer identity yalnız gereken label/avatar contractıdır.

## 9. Recovery ve lifecycle entegrasyonu

- Recovery snapshot `active.kind=pending_match` ile matchId, current searchId, status, own decision, peer-accepted hint, offeredAt, autoAcceptAt, effective scope ve revision döndürür.
- Reconnectte local offer değil snapshot kazanır.
- Kullanıcı önceden accepted ise CTA yeniden aktifleşmez; waitingPeer/finalizing durumu geri kurulur.
- Offer deadline geçtiyse client geçmiş süreli kartı açmaz; server current state ister.
- Pending preserved değilse controlled close/reset görünür ve policy'ye göre search/retry ekranına dönülür.
- App backgroundda server deadline işlemeye devam eder; foreground countdown yeniden hesaplanır.
- Eski socketten event, eski epoch veya düşük revision no-op olur.
- Matched sonucu gelmişse pending ekranı geri açılmaz.
- Browser/Android back tuşu tüm-search cancel semanticsini açık confirmation gerektirmeden yanlışlıkla tetiklemez; navigation policy başlangıçta kilitlenir.

## 10. Client görünüm modeli — A-MATCH-002

Teklif componenti socket eventlerini doğrudan yorumlamaz. Selector/reducer sonucu:

- `matchId`, `searchId`, `offerStatus`
- `ownDecision`, `peerDecisionHint`
- `offeredAt`, `autoAcceptAt`, serverClockOffset
- `decisionCommandId`, `decisionPending`
- `closeReason`, `requeueOutcome`, retryability
- Tek `peerPublicLabel` ve generic visual seed
- Wave 07 mood/prompt suggestion snapshot
- Wave 08 effective scope yalnız integrity/state; UI badge değildir

Karar submit edildiğinde ilgili CTA hemen pending/disabled olur; result gelmeden başarı varsayılmaz. Ack kaybında aynı commandId retry edilir.

## 11. Teklif ekranı bilgi mimarisi

Yukarıdan aşağı kompozisyon:

1. Ürün bağlamı içinde kısa `Eşleşme bulundu` başlığı
2. Merkez generic anonim eşleşme görseli / iki parçacığın final durumu
3. Tek, okunaklı peer public identity
4. Kısa açıklama ve remaining saniye
5. Süreye bağlı gerçek progress
6. Birincil `Sohbete Başla`
7. İkincil `Geç`
8. Üçüncül `Eşleşmeyi iptal et`
9. Gerektiğinde sakin mood/prompt suggestion ve state feedback

Aynı username subtitle + başlık + handle olarak tekrarlanmaz. Server tek public label üretir veya client canonical seçim kuralıyla yalnız bir primary identity gösterir. Nickname/username ikisi zorunlu değilse ek satırla yinelenmez.

Scope selector, country badge, flag, fallback kartı veya online dot teklif yüzeyine taşınmaz.

## 12. Görsel sistem

- Merkez kart mevcut dark glass yüzey ve cyan/mor-pembe neon tokenlarını kullanır.
- Approved direction'daki enerji korunur; yeni bağımsız gradient/glow ailesi oluşturulmaz.
- Kart ana odaktır; çevredeki efektler metin ve CTA kontrastını düşürmez.
- Generic anonim görsel gerçek avatar yokken profil fotoğrafı iddiası taşımaz.
- Gerçek avatar contractı sonradan varsa privacy ve fallback kararı olmadan bu Wave'de açılmaz.
- Güvenilir presence yoksa yeşil online noktası kullanılmaz.
- Progress dekoratif değildir; server deadline oranını gösterir ve kalan saniye metniyle desteklenir.
- `prefers-reduced-motion` hareketi kaldırır/kısaltır; countdown anlamı ve progress korunur.
- Transform/opacity/SVG/CSS tercih edilir; ağır bitmap, sürekli blur repaint veya WebView'i yoran filtre zinciri zorunlu değildir.
- 320 px ile geniş desktop arasında bounded card width ve safe-area kullanılır.
- Uzun public label ellipsis/wrap policy ile kartı bozmaz; accessible full label bulunur.
- Büyük sistem fontunda CTA sırası ve görünürlüğü korunur; gerektiğinde butonlar dikeyleşir.

## 13. CTA ve kullanıcı durumları

### 13.1 Sohbete Başla

- Tek ana CTA.
- Current match/search için ACCEPT komutu gönderir.
- İlk tıklamada pending/disabled ve progress indicator olur.
- Ack sonrası own accepted + waitingPeer görünür; tekrar tetiklenmez.
- İki taraf kabul/finalize olunca server `matched` ile chat'e geçirir.
- Client kendi başına room oluşturmaz.

### 13.2 Geç

- Yalnız mevcut peer teklifini PASS/reject eder.
- Pair cooldown uygulanır.
- Actor ve connected peer canonical policy ile aynı effective scope'ta requeue olur.
- Bütün search preference/journey iptal edilmiş gibi gösterilmez.
- Double pass tek sonuç üretir.

### 13.3 Eşleşmeyi iptal et

- Üçüncül ve sakin destructive eylemdir; karttan kopuk alarm butonu değildir.
- Actor'un bütün search journey'sini kapatır; actor auto-requeue olmaz.
- Peer doğru reason ile same-scope requeue edilir.
- Current pending + queue cleanup tek idempotent sonuçtur.
- Text ve konum `Geç` ile farkı açıklar; color tek ayırıcı değildir.

### 13.4 Durum metinleri

- offered: karar için kalan süre
- decision pending: “Kararın gönderiliyor...”
- own accepted: “Kabul ettin, karşı taraf bekleniyor.”
- peer accepted hint: “Eşleşmen hazır; kararını bekliyor.”
- finalizing: “Sohbet hazırlanıyor...”
- self passed/requeued: “Yeni bir eşleşme aranıyor.”
- peer rejected/left: nötr sonuç + aynı scope arama devamı
- timeout/auto-accept: server sonucuna göre sohbet hazırlanıyor veya requeue
- cancelled: arama kapandı
- reconnecting: karar vermeyi/geri sayımı local varsayımla finalize etmez
- server error: ghost success yok; güvenli retry/requeue sonucu

Metinler TR/EN merkezi katalogdadır; teknik state/reason kodu gösterilmez.

## 14. Mood/prompt ve scope koruması

- Wave 07 selected mood/prompt kartın ana kimlik/karar bilgisini bastırmadan sakin ikincil suggestion olabilir.
- Prompt otomatik composer'a yazılmaz veya gönderilmez.
- Pass/peer reject/timeout requeue aynı journey'de selection'ı korur.
- Cancel journey'yi bitirir ve Wave 07 cleanup policy'sini uygular.
- Wave 08 effective scope pending kaydında integrity için taşınır; UI'da gösterilmez.
- Requeue hiçbir zaman parametre kaybedip Global'e düşmez.
- Offer geldiğinde görünür fallback kapanır; geri dönüşte server snapshot'ına göre yeniden kurulur.

## 15. Erişilebilirlik ve responsive davranış

- Focus sırası başlık/kimlik açıklamasından sonra primary → secondary → tertiary eylemdir.
- Bütün hedefler minimum 44×44 px; focus-visible belirgindir.
- Button accessible names görünen metinle tutarlıdır; loading state `aria-busy` ve disabled semantics taşır.
- Countdown saniye başına aria-live spam yapmaz; meaningful state değişimleri polite duyurulur.
- Progressbar gerçek `aria-valuemin/max/now` veya kalan süre açıklaması taşır.
- Red/green tek anlam kaynağı değildir; label, hiyerarşi ve state metni vardır.
- 320 px, kısa ekran, landscape, safe-area, keyboard, %200 zoom/büyük font ve uzun TR/EN label test edilir.
- Reduced motion ile final particle/card giriş hareketi bekleme veya karar gecikmesi yaratmaz.
- Screen reader duplicate username okumaz; tek public identity vardır.

## 16. Telemetry

En az:

- `match_offer_received`
- `match_offer_rendered`
- `match_decision_submitted`
- `match_decision_result`
- `match_peer_accepted_seen`
- `match_auto_accept_applied`
- `match_offer_closed`
- `match_finalization_started/result`
- `chat_started`

Ortak envelope matchId/searchId, effective scope, own decision source, safe close reason, deadline/decision latency, app/platform/protocol version taşır. Full prompt, peer country, raw public label, IP veya message content taşımaz. Render olmayan offer impression sayılmaz. Replay/duplicate komut ikinci karar eventini üretmez.

## 17. Dosya ve servis etki haritası

Uygulama başlangıcında güncel keşifle daraltılacak beklenen yüzey:

- `chatapp-backend/index.js` veya Wave 07/08'de ayrıştırılmış matchmaking/pending service
- Pending serializer, state transition, idempotency, deadline ve finalize yardımcıları
- Conversation repository/migration yalnız matchId uniqueness eksikse
- Backend contract/state/fault-injection testleri
- `chatapp-frontend/src/App.jsx` veya domain reducer/store
- `chatapp-frontend/src/screens/MatchScreen.jsx` ve ayrıştırılmış Offer componenti
- Progress, generic identity visual ve state feedback yardımcıları
- `chatapp-frontend/src/i18n/messages.tr.js`, `messages.en.js` veya güncel locale kaynağı
- QA-003 current/approved assetleri ve yeni before/after kanıtları
- Web/Android E2E ve manuel QA sonuç dosyası

Mesaj outbox, kalıcı friend messaging, genel ChatScreen redesignı, country selector veya admin UI bu Wave'in dosya kapsamı değildir.

## 18. Uygulama sırası

1. Wave 08 kapanışı, Wave 05/07/08 realtime sözleşmeleri ve üç Git bağlamını doğrula.
2. Current/approved QA-003 görsellerini gerçek render ile incele; ölçü/kompozisyon baseline kaydet.
3. Master QA-003 ve iki stable ID kabulünü test/evidence kimliklerine bağla.
4. Pending match state machine, transition table, close/requeue matrix ve event schema'yı kilitle.
5. Match-level serialization, command idempotency ve absolute deadline testlerini önce yaz.
6. Backend accept/pass/cancel/auto/disconnect yollarını tek mutation service'ine taşı.
7. Conversation creation için matchId idempotency/transaction ve ghost-room cleanup'ı kur.
8. Recovery snapshot ve same-scope requeue entegrasyonunu tamamla.
9. Client offer reducer'ını server time/revision/command ack ile bağla.
10. Approved direction'a göre merkez card, tek identity, progress ve CTA hiyerarşisini uygula.
11. Bütün feedback, a11y, responsive, reduced-motion ve i18n durumlarını tamamla.
12. QA-014/QA-017 regresyonu ve iki-client fault matrisini çalıştır.
13. Web/Android manuel QA ve before/after kanıtı al.
14. Checkbox/durumları yalnız kanıt + kullanıcı onayıyla kapat; Wave 10'u başlatmadan dur.

## 19. Otomatik test planı

### 19.1 Backend state/contract

- İki participant için offer envelope, current search/scope ve aynı deadline.
- Aynı ACCEPT command replay → tek decision/ack.
- ACCEPT ardından PASS → deterministic conflict, state değişmez.
- İki taraf eşzamanlı accept → tek finalization.
- Manual accept ile deadline auto-accept yarışı → tek participant decision.
- İki deadline callback/retry → tek finalize.
- PASS ile peer accept yarışı → transition tablosuna göre tek terminal sonuç.
- Cancel ile pass ayrımı ve actor requeue farkı.
- Stale matchId/searchId/revision/epoch no-op.
- Peer accepted hint yalnız doğru participant/current match.
- Pair cooldown duplicate yazılmaz.
- Disconnect grace preserved ve expired sonuçları.
- Reject/timeout/error requeue kendi effective scope/country'sini korur.
- Conversation DB failure → room/maps yok, açık close/requeue.
- DB commit sonrası response kaybı/retry → aynı conversation, ikinci room yok.
- Matched/closed terminal state tekrar açılamaz.
- Legacy accept/reject capability adapter parity.

### 19.2 Client reducer/component

- Server autoAcceptAt aynen tüketilir; local yeniden üretim yok.
- Countdown/progress boundary, clock skew ve background dönüşü.
- Sıfırda local matched yok; finalizing görünümü.
- Tek public identity, duplicate username yok.
- Generic visual ve online-dot yokluğu.
- Primary/secondary/tertiary CTA doğru command türüne bağlanır.
- Decision pending double click'i önler.
- Own accepted waitingPeer'i recovery sonrası korur.
- Peer accepted/reject/timeout/cancel/leave/disconnect/error ayrı feedback.
- Stale offer render edilmez.
- Mood/prompt ikincil, no auto-send.
- Scope badge/control yok; requeue effective scope korunur.
- 320 px, long label, TR/EN, large font ve short viewport.
- Keyboard/focus/SR/progress semantics/reduced motion.

### 19.3 Entegrasyon/E2E

- İki client manual accept/manual accept.
- Bir manual, bir auto accept.
- İki auto accept.
- Accept/pass, pass/pass ve accept/cancel yarışları.
- Peer accepted hint ve waiting recovery.
- Offer sırasında kısa reconnect ve grace expiry.
- App background deadline geçişi.
- Peer reject/timeout sonrası same-scope search.
- Country search offer'da scope UI görünmemesi.
- Conversation error injection ve retry uniqueness.
- Duplicate/reordered/stale event injection.
- Web Chromium ve Android WebView kritik akışları.

## 20. Manuel QA matrisi

| Grup | Senaryo | Beklenen |
|---|---|---|
| Kompozisyon | Current vs approved direction | Merkez güçlü kart, tek identity, net hiyerarşi |
| Kabul | Sohbete Başla | Tek ACCEPT, waiting/finalizing ve chat |
| Geç | Mevcut peer reddi | Search sürer, same-scope requeue |
| İptal | Tüm eşleşmeyi iptal | Actor search terminal, peer requeue |
| Countdown | İlk an/orta/0 | Server-time progress ve doğru saniye |
| Auto | Tek/iki taraf pending | Tek finalize ve chat |
| Waiting | Actor kabul etti | CTA kilitli, peer bekleniyor |
| Hint | Peer kabul etti | Açık fakat baskısız hint |
| Close | Peer reject/leave/cancel | Doğru reason ve sonraki adım |
| Recovery | Reconnect/background | Snapshot kazanır, duplicate karar yok |
| Error | Conversation/server error | Ghost success yok, güvenli requeue |
| Identity | Username/nickname/anon/uzun | Tek okunaklı label, taşma yok |
| Presence | Güvenilir veri yok | Online dot yok |
| Regression | QA-014 mood/prompt | Korunur, otomatik gönderilmez |
| Regression | QA-017 country/global | Same-scope requeue, offer scope UI'siz |
| Mobil | 320 px/kısa/landscape/safe-area | Bütün kararlar erişilebilir |
| A11y | Keyboard/SR/focus/44 px/contrast | Bağımsız tamamlanabilir |
| Motion | Reduced/low-power | Anlam ve karar gecikmez |
| Locale | TR/EN/uzun metin | Hiyerarşi ve progress bozulmaz |

## 21. Canonical kabul eşlemesi

### 21.1 B-MM-003 — 7 kriter

- [ ] Aynı karar iki kez finalize etmiyor.
- [ ] Stale matchId kararı işlenmiyor.
- [ ] Auto/manual accept yarışı tek room oluşturuyor.
- [ ] Reject iki tarafa doğru reason/state veriyor.
- [ ] Conversation DB hatası ghost room bırakmıyor.
- [ ] Requeue actor/peer policy'si aynı scope'u taşıyor.
- [ ] QA-003 countdown alanları server time ile dönüyor.

### 21.2 A-MATCH-002 — 7 kriter

- [ ] Master QA-003 kabul kriterleri tamam.
- [ ] CTA'lar doğru mevcut davranışlara bağlanıyor.
- [ ] Çift accept/reject gönderimi yok.
- [ ] Stale offer gösterilmiyor.
- [ ] 320 px ve uzun metin/username taşmıyor.
- [ ] Countdown server zamanı ile uyumlu.
- [ ] Gerçek presence yoksa dekoratif online noktası yok.

### 21.3 Master QA-003 — 10 kriter

| # | Canonical kabul | Zorunlu kanıt |
|---:|---|---|
| 1 | Başlık, alt metin ve kimlik tekrarsız/TR-EN uygun | Component snapshots + content review |
| 2 | Countdown autoAcceptAt progress ve saniyeyle senkron | Server-clock boundary/reconnect test |
| 3 | Anonimliği bozmayan avatar/generic görsel | Visual/privacy review |
| 4 | Online noktası yalnız gerçek presence ile | Presence-off regression |
| 5 | Peer hint, waiting, reject, timeout, cancel, leave ve disconnect ayrı | State matrix/E2E |
| 6 | Primary/secondary/tertiary aksiyonlar ve 44 px | Visual/a11y test |
| 7 | Keyboard, focus, screen reader, contrast, reduced motion | Automated + manual accessibility |
| 8 | 320 px–desktop, uzun kimlik ve TR/EN taşmaz | Responsive screenshot matrix |
| 9 | Efektler düşük cihazda akıcı ve token tabanlı | Android/performance/reduced-motion |
| 10 | Kabul, geç, auto, iptal, peer accepted, timeout regresyonsuz | Two-client web/Android E2E |

Hiçbir kriter yalnız screenshot, yalnız backend testi veya yalnız “tasarım uygulandı” notuyla kapanmaz.

## 22. Kapsam dışı ve successor guard

- Wave 10 mesaj idempotency, outbox, delivery/ordering veya friend message işi
- Global/Country selector, fallback veya country badge'i teklif kartına taşımak
- QA-014 arama yüzeyini yeniden tasarlamak
- ChatScreen, friend chat, profile veya Home genel redesignı
- Gerçek avatar/presence contractı icat etmek
- Yeni sosyal filtre, monetization veya gamification
- Admin analytics/dashboard
- Wave 10 uygulaması

## 23. Risk ve rollback

| Risk | Koruma | Rollback/durma |
|---|---|---|
| Double accept iki room açar | Match lock + matchId DB uniqueness | Finalize flag/feature kapat, recovery snapshot |
| Auto/manual yarışır | Absolute deadline + serialized transition | Tek authoritative decision replay |
| Pass cancel gibi davranır | Ayrı command/state policy | Requeue sonucunu fail-closed durdur |
| Cancel actor'u tekrar queue'ya sokar | Explicit requeue matrix | Actor search terminal |
| Stale offer açılır | matchId/searchId/revision guard | Event no-op + snapshot |
| Client süreyi yeniden üretir | Server time contract | Countdown gizle, decision güvenli kalsın |
| DB başarılı, room cevabı kayıp | Idempotent matchId lookup | Aynı conversation recovery |
| DB hata ghost room üretir | Commit-before-room + cleanup | Maps temizle, same-scope requeue |
| Disconnect yanlış auto kabul | Recovery grace policy | Pending close/reset |
| Requeue scope kaybeder | Explicit effective scope snapshot | Requeue bloke |
| Identity tekrar/taşma | Tek public label contract | Generic anonymous fallback |
| Fake online algısı | Presence olmadan dot yok | Göstergeden vazgeç |
| Progress performansı bozar | CSS transform + corrected clock | Statik countdown |
| QA-003 visual scope ile kalabalıklaşır | Wave 08 successor guard | Scope UI farkını geri al |
| Dirty repo işi örter | Üç Git snapshot'ı | Yalnız Wave 09 farkını geri al |

Rollback completed conversationı silmeye dayanmaz. Capability kapatılırken current pending matchler explicit closed/reset veya mevcut güvenli legacy adapter sonucuyla tamamlanır; kararlar sessizce değiştirilmez.

## 24. Rollout ve canlı sınır

1. State/contract/idempotency testleri capability-off tamamlanır.
2. Conversation uniqueness migrationı gerekiyorsa izole test DB ve Wave 04 runbookuyla doğrulanır.
3. Staging iki-client race/fault matrisi çalışır.
4. Internal cohort'ta yeni server state machine, legacy UI ile gözlenir.
5. Yeni offer UI ayrı client flag ile açılır.
6. Web ardından Android responsive/a11y/reconnect/background QA tamamlanır.
7. Decision, finalize, close reason, duplicate ve ghost-room metricleri izlenir.
8. Rollback provası active pending matchler varken yapılır.
9. Canonical checkbox ve durum yalnız kullanıcı QA onayıyla kapatılır.

Production migration, gerçek queue/conversation sorgusu, feature flag, deployment/restart veya kullanıcı pending state müdahalesi ayrıca exact target/impact onayı ister.

## 25. Başlangıç kapısı

- [ ] Wave 01–08 QA kapanışları ve kullanıcı onayı doğrulandı.
- [ ] Kullanıcı açıkça “Wave 09'u başlat” dedi.
- [ ] Root/backend/frontend Git snapshot'ı alındı.
- [ ] Wave 05 recovery/epoch/revision gerçek kodda doğrulandı.
- [ ] Wave 07 searchId/timer/mood-prompt lifecycle gerçek kodda doğrulandı.
- [ ] Wave 08 effective scope/requeue/country bütünlüğü gerçek kodda doğrulandı.
- [ ] Current pending/decision/deadline/disconnect/conversation yolları yeniden envanterlendi.
- [ ] Approved QA-003 image gerçek araçla görsel olarak incelendi ve baseline ile karşılaştırıldı.
- [ ] Match state, participant decision, command idempotency ve deadline kuralları kilitlendi.
- [ ] Conversation matchId uniqueness ve transaction stratejisi kanıtlandı.
- [ ] Close/requeue/recovery matrisi product owner tarafından onaylandı.
- [ ] TR/EN/a11y/Web/Android manuel QA cihaz matrisi hazırlandı.
- [ ] Wave 10 kapsamına taşma olmadığı doğrulandı.

## 26. Sonuç alanı

- Başlangıç/bitiş, refs ve gerçek değişen dosyalar
- Üç Git bağlamının önce/sonra farkı
- Final state transition, event ve close/requeue matrisi
- Idempotency, deadline ve race test sonuçları
- Conversation uniqueness/transaction/ghost-room kanıtı
- Recovery, disconnect ve stale-event sonuçları
- Server-time countdown/progress kanıtı
- Approved-direction before/after desktop/mobile görselleri
- CTA davranışı ve bütün UI state sonuçları
- QA-014 mood/prompt ve QA-017 same-scope regresyonu
- A11y, responsive, reduced-motion ve Android kanıtı
- Syntax/lint/build/encoding/focused/full test exit code'ları
- B-MM-003, A-MATCH-002 ve Master QA-003 kabul tablosu
- Kullanıcı manuel QA onayı
- Wave 10'un başlatılmadığı açık durma kaydı

## 27. Durma kuralı

Wave 08 QA kapanışı ve kullanıcının açık Wave 09 başlatma talimatı birlikte gelene kadar:

- Wave 09 için kod, test, dependency, migration, config, canlı veri, feature flag veya deploy değişikliği yapılmaz.
- Wave 09 `Aktif` işaretlenmez; belge yalnız `Hazır — aktif değil` kalır.
- Canonical `[ ]` maddeler kanıtsız kapatılmaz.
- Wave 10 uygulanmaz; hazırlanmış plan aktif edilmez.
