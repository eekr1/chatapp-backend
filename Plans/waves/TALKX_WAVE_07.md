# TalkX Wave 07 Plan — QA-014 Gerçek Arama Yaşam Döngüsü

> Bu belge yalnız Wave 07 için hazırlanmış uygulama planıdır.
> Canonical ayrıntı Plan B `B-MM-001`, Plan A `A-MATCH-001` ve Master QA-014'tedir; burada Wave 08 Global/Country seçimi veya Wave 09 QA-003 teklif yeniden tasarımı üretilmez.
> Plan hazırdır. Wave 07 aktif değildir, Wave 01–06 kapanmamıştır ve uygulama başlamamıştır.

## 1. Durum ve yürütme sınırı

- **Wave:** 07
- **Wave adı:** QA-014 gerçek arama yaşam döngüsü
- **Plan katılımı:** Plan B + Plan A
- **Canonical sıra:** `B-MM-001 → A-MATCH-001`
- **Plan durumu:** Hazır
- **Wave durumu:** Bekliyor
- **Uygulama durumu:** Başlamadı
- **Uygulama yetkisi:** Verilmedi
- **Giriş kapısı:** Wave 06 **AUTO-VERIFIED / COMMITTED** ve kullanıcıdan açık “Wave 07'yi başlat” talimatı
- **Mevcut blokaj:** Wave 06 henüz committed değil; Wave 07 uygulanamaz
- **Önceki wave:** Wave 06 — planı hazır, aktif değil
- **Sonraki wave:** Wave 08 — planı hazır, aktif değil ve başlatılmadı

Bu dosyanın hazırlanması Wave 07 aktivasyonu, kod/test/dependency değişikliği, migration, dış servis, canlı veri, deploy veya Wave 08 uygulaması için yetki değildir.

## 1.1 Sale Release override — TAM / ÇEKİRDEK

- **Satış öncesi uygulanır:** Server-otoriteli join/search/cancel/requeue modeli, gerçek searchId/state, client'ın yalnız server phase'ini göstermesi ve double/stale queue temizliği.
- **Post-acquisition Roadmap / Deferred:** Yeni matchmaking özellikleri, yeni filtreler veya scope genişletmesi.
- **Kapanış:** Search lifecycle ve iki-client otomatik senaryoları geçer, tek Wave 07 commit'i alınır ve **DUR**. Web/Android manuel akış Checkpoint B/Wave 19'a gider.
- Wave 08 Global/Country scope'u bu wave'e çekilmez.

## 2. Canonical referanslar ve öncelik

1. `B-MM-001` — server-otoriteli search lifecycle, search kimliği, queue zamanı, cancel ve reconnect
2. `A-MATCH-001` — QA-014 canlı ve dürüst arama yüzeyi
3. Master Backlog `QA-014` — ürün kilitleri, metin katmanları, animasyon, mood/prompt, erişilebilirlik, telemetry ve manuel matris
4. `B-WS-002` — Wave 05 connection/recovery snapshot sözleşmesi; Wave 07 bunu tüketir, yeniden icat etmez
5. `A-MATCH-002`, `A-I18N-001`, `A-A11Y-001` — görsel hareket, yerelleştirme ve erişilebilirlik sınırları

Yürütme kaynağı: `../TALKX_WAVE_MAP.md` / Wave 07. Ayrıntı kaynakları: Plan B, Plan A ve Master Backlog / QA-014.

Çelişki çözümü:

- Backend gerçeği ile UI varsayımı çatışırsa backend'in sürümlü sözleşmesi kazanır; UI tahmin üretmez.
- Wave 05 recovery modeliyle çelişen otomatik yeniden-join yapılmaz. Queue kaybolduysa kullanıcı açık retry yapmadan yeni arama açılmaz.
- Wave 08'in `scope`, canonical country, havuz sayısı ve fallback kararları bu Wave'e çekilmez.
- Wave 09'un offer CTA, accept/reject/timeout ve QA-003 görsel hiyerarşisi değiştirilmez.
- Mood veya prompt hiçbir biçimde eşleşme filtresi, preference match ya da daha iyi eşleşme vaadi değildir.

## 3. Wave sonucu

Wave 07 sonunda:

- Her arama yolculuğu tek `searchId` ile tanınacak; eski event yeni aramayı bozamayacak.
- Arama ekranı yalnız `preparing`, `queued`, `extended`, `reconnecting`, `offline`, `cancelled` ve `offer` durumlarından birini gösterecek.
- Timer yalnız server queue onayından sonra, server `queuedAt` zamanına göre başlayacak; fake yüzde, sıra, ETA veya kullanıcı sayısı olmayacak.
- Cancel tek aktif aramayı idempotent kapatacak; çift tıklama, gecikmiş join ve geç offer yarışı güvenli olacak.
- Wave 05 recovery snapshot aynı aramanın korunup korunmadığını açıkça söyleyecek; korunmayan arama sessizce yeniden başlamayacak.
- Mevcut radar/anahtar animasyonu iki soyut TalkX parçacığına dönüşecek; gerçek offer gelmeden birleşme veya başarı sinyali vermeyecek.
- Mood ve manuel prompt yalnız konuşma başlangıç desteği olacak, arama havuzunu bölmeyecek ve otomatik mesaj göndermeyecek.
- Prompt kimliği TR/EN arasında stabil kalacak; otomatik sekiz saniyelik soru rotasyonu kaldırılacak.
- Arama yüzeyi 320 px, kısa ekran, safe-area, Android WebView, reduced-motion ve screen-reader koşullarında çalışacak.
- Gerçek `match_offer` geldiğinde süre hemen duracak; en fazla 300–600 ms görsel geçiş QA-003 sayaç/auto-accept süresini geciktirmeyecek.
- Davranış eventleri aynı search journey'ye bağlanacak; prompt metni veya yanıltıcı preference telemetry yazılmayacak.
- Wave 08 ve Wave 09 başlamayacak.

## 4. Doğrulanmış başlangıç fotoğrafı

### 4.1 Client gerçeği

- `MatchScreen.jsx` bugün `status`, `offer`, accept/reject/cancel callback'leriyle hem arama hem teklif görünümünü taşıyor.
- Arama görünümünde cyan anahtar/radar, sürekli scan/ping ve beş soruyu sekiz saniyede bir değiştiren local timer bulunuyor.
- Arama phase modeli, server `queuedAt`, elapsed timer, mood chip'leri, manuel “Başka soru” ve search identity yok.
- `App.jsx`, `joinQueue` gönderdikten hemen sonra matching ekranını açıyor; server `queued` onayı beklenmiyor.
- `queued` ve `match_offer` eventlerinde `searchId` yok. Client offer zamanını server değerinden tüketmek yerine yerelde yeniden üretebiliyor.
- Eski socket callback'ini reddeden socket-instance guard yararlı fakat aynı socket içindeki eski arama eventi için yeterli değil.

### 4.2 Backend gerçeği

- `waitingQueue` girdileri client/socket/kimlik taşıyor; `searchId`, `queuedAt`, attempt ve lifecycle phase taşımıyor.
- `joinQueue` bare `queued` gönderebiliyor veya uygun peer varsa doğrudan pending match oluşturabiliyor.
- `match_offer` match kimliği ve auto-accept zamanı taşıyor fakat katılımcının search kimliğini taşımıyor.
- `leaveQueue` queue/pending state'i temizliyor fakat idempotent command ack, hedef search guard ve `queue_left` sonucu yok.
- Reject/timeout sonrası requeue clientId üzerinden yapılıyor; aynı journey ile yeni queue attempt ayrımı tanımlı değil.
- Shadow-ban yolu da bare `queued` kullanıyor; yeni lifecycle privacy kararını açığa çıkarmadan aynı sözleşmeyi korumalı.

### 4.3 Bağımlılık ve repo gerçeği

- Wave 05 tamamlanmadan connection identity, recovery snapshot ve state revision varmış gibi kabul edilmez.
- Wave 06 tamamlanmadan canonical country hazır sayılmaz; Wave 07 hiçbir country/scope alanını queue kararına sokmaz.
- Root, backend ve frontend çalışma ağaçları kullanıcıya ait geniş/değişken durum taşıyabilir. Başlangıçta üç bağlam ayrı snapshot edilir; yalnız Wave 07 farkı sahiplenilir.

## 5. Kilitli ürün ve mimari kararları

### 5.1 Tek arama kimliği

- Client kullanıcı intentinde UUID biçimli `searchId` üretir ve `joinQueue` ile yollar.
- Server bu kimliği doğrular; kabul ettiği andan itibaren arama phase ve geçişlerinin tek otoritesidir.
- `preparing`, henüz server tarafından queue kabul edilmemiş local intent durumudur; timer yoktur.
- Aynı kullanıcı ve aynı `searchId` ile tekrar gelen join idempotent replay'dir; yeni queue kaydı oluşturmaz.
- Aynı kullanıcı için farklı bir aktif `searchId` varken yeni join sessizce eski aramayı değiştirmez; sürümlü conflict sonucu döner.
- Search journey cancel, başarılı chat kuruluşu veya açık terminal server sonucu ile kapanır.
- Peer reject/timeout sonrası aynı kullanıcı intenti sürüyorsa `searchId` korunur; her yeniden kuyruğa girişte `queueAttempt` artar ve yeni `queuedAt` verilir.
- Gelecekteki scope değişimi yeni search yaratacak olsa bile mood/prompt client-session selection katmanında taşınabilir; bu Wave scope üretmez.

### 5.2 Phase ve gösterim katmanı

| Phase | Kaynak | UI gerçeği | Timer | İzinli eylem |
|---|---|---|---|---|
| `preparing` | Client intent + gönderilmiş join | İstek hazırlanıyor/onay bekleniyor | Yok | Durdur |
| `queued` | Server ack/snapshot | Aktif queue | `queuedAt` bazlı | Durdur, mood/prompt |
| `extended` | Server timing policy/snapshot | Arama sürüyor; hata değil | Aynı attempt | Durdur, mood/prompt |
| `reconnecting` | Wave 05 gerçek socket/recovery | Bağlantı geri kuruluyor | Sonuç netleşene dek dondur/gizle | Bekle |
| `offline` | Wave 05 terminal/offline sonucu | Devam edilemiyor | Durur | Tekrar dene, kapat |
| `cancelled` | Server cancel ack | Arama kapandı | Durur | Ekrandan çıkış |
| `offer` | Gerçek current-search `match_offer` | Teklif alındı | Derhal durur | Mevcut QA-003 akışı |

`queued` bilgilendirme katmanları `initial`, `continuing`, `quiet`, `long` olur. Eşikler tek merkezi policy'den gelir; client server `queuedAt`, `serverNow` ve eşikleri kullanarak deterministik görünüm üretir. `extended`, server policy'deki uzun-wait eşiğinin geçildiği phase'dir; local rastgele timeout değildir. Recovery snapshot geçerli phase'i yeniden kurar.

### 5.3 Zaman modeli

- Timestamp'ler tek sürümlü UTC formatında taşınır.
- `queuedAt` mevcut queue attempt'in kabul anı; `searchStartedAt` journey'nin ilk kabul anıdır.
- `serverNow` ile client offset hesaplar; elapsed `correctedNow - queuedAt` olur ve negatif değer sıfıra clamp edilir.
- Interval yalnız render tetikler; doğruluk interval sayısına dayanmaz. Background dönüşünde zaman timestamp'ten yeniden hesaplanır.
- Requeue olursa attempt artar ve timer yeni `queuedAt` ile başlar; analytics aynı search journey altında kalır.
- Offer, cancel, offline veya terminal error timerı durdurur.
- Yüzde, ETA, sıra numarası, “yakında kesin” veya kanıtsız havuz yoğunluğu gösterilmez.

## 6. Realtime sözleşmesi

### 6.1 Capability ve sürümleme

- Welcome/capability sözleşmesi `matchSearchLifecycleV1` desteğini ilan eder.
- Yeni client capability yoksa lifecycle UI'yi açmaz; eski davranışa güvenli uyumluluk veya minimum-version politikası release kararında kilitlenir.
- Server geçişte legacy `joinQueue` için search kimliği üretebilir; yeni client her zaman `searchId` yollar.
- Ek alanlar eski client tarafından ignore edilebilir olmalı; anlamı değişen alan için capability zorunludur.

### 6.2 Client → server komutları

```json
{ "type": "joinQueue", "protocolVersion": 1, "searchId": "uuid", "commandId": "uuid" }
```

```json
{ "type": "leaveQueue", "protocolVersion": 1, "searchId": "uuid", "commandId": "uuid", "reason": "user_cancelled" }
```

- `commandId` retry/idempotency; `searchId` domain hedefidir.
- Wave 07 komutunda `scope`, country, mood, prompt veya havuz alanı yoktur.
- Mood/prompt matchmaking server'ına gönderilmez.

### 6.3 Server → client eventleri

- `queued`: protocolVersion, searchId, queueAttempt, searchStartedAt, queuedAt, serverNow, phase, timingPolicyVersion, tierThresholdsMs ve Wave 05 revision envelope'u.
- `search_phase`: searchId, queueAttempt, phase, effectiveAt, serverNow, reasonCode ve revision.
- `queue_left`: searchId ve commandId ile idempotent terminal ack; duplicate leave aynı sonucu replay eder, ikinci product event üretmez.
- `match_offer`: mevcut QA-003 alanlarına ek current searchId, queueAttempt, server autoAcceptAt, revision ve protocol version.
- Hata envelope'u stable code, searchId, commandId, retryable ve güvenli locale key taşır; teknik ayrıntı son kullanıcıya sızmaz.

### 6.4 Sıralama ve atomiklik

- Server current search state'ini queue mutationıyla aynı serialized kritik bölümde kurar.
- Immediate peer bulunsa bile client kabul edilmiş state'i offer'dan önce edinir; ordered `queued → match_offer` veya atomik snapshot+offer kullanılır.
- Pairing iki entry'yi atomik çıkarır, pending kaydında iki kullanıcının kendi search kimliğini tutar.
- Search mutationları user/participant anahtarında serialize edilir. Gecikmiş async join, sonradan gelen cancel tombstone'unu aşamaz.
- Cancel kabul edilince queue ve o search'e bağlı pending invalidate edilir; late offer server/client tarafından reddedilir.
- Düşük revision, farklı epoch veya current olmayan search kimliği reducer'da no-op olur.

### 6.5 Reconnect ve recovery

- Socket kesildiğinde UI yalnız gerçek connection state ile `reconnecting` olur; uzun bekleme reconnect gibi gösterilmez.
- Wave 05 snapshot `active.kind=queue`, current search/attempt/queuedAt/phase ve `queuePreserved=true` döndürürse aynı arama sürer.
- Queue korunmadıysa snapshot açık reset/idle reason döndürür; otomatik join yoktur, retry/close sunulur.
- Retry yeni searchId üretir; eski id eventleri tombstone/revision guard ile yok sayılır.
- Server restart/epoch değişimi preserved varsayılmaz.
- İkinci cihaz farklı search açarsa implicit takeover yoktur; Wave 05 politikasıyla conflict/snapshot döner.

### 6.6 Shadow-ban ve gizlilik

- Shadow-ban kullanıcıya moderation durumunu açmaz; aynı public lifecycle şemasını tüketir.
- Sistem sahte peer, offer, sıra veya preference match üretmez.
- Uzun bekleme metni nötrdür; kullanıcı sayısı, ülke veya ban sebebi çıkarımı yaptırmaz.

## 7. Backend uygulama paketi — B-MM-001

### 7.1 Domain kaydı ve invariantlar

Runtime search kaydı en az şunları taşır:

- `searchId`, authenticated participant/user key ve owning recovery handle
- `phase`, `searchStartedAt`, `queueAttempt`, `queuedAt`
- `createdAt`, `updatedAt`, terminal reason ve son revision
- Active queue entry/pending match ilişkisi
- Join/cancel command idempotency sonucu ve bounded tombstone

Mood, prompt text, country veya scope bu kayda Wave 07'de eklenmez. Kalıcı DB migrationı ancak somut gereksinim ve owner kararıyla açılır; lifecycle varsayılan olarak geçicidir.

Temel invariantlar:

1. Kullanıcı başına en fazla bir aktif search bulunur.
2. Queue entry ve pending participant her zaman searchId/attempt ile ilişkilidir.
3. Terminal search yeniden canlandırılmaz.
4. Bir event kendi search/revision sınırını aşamaz.
5. Queue kabul edilmeden elapsed timer gerçeği oluşmaz.
6. Cancel ack sonrası aynı search için yeni offer üretilemez.
7. Requeue yeni attempt'tir; yeni journey değildir.
8. Mood/prompt hiçbir queue predicate'ına girmez.

### 7.2 İzinli state geçişleri

- Client idle → preparing yalnız kullanıcı intentiyle
- Server idle → queued/extended kabul edilmiş join ile
- queued ↔ extended yalnız server timing policy/recovery ile
- queued/extended → reconnecting yalnız client connection görünümünde; server search state ayrıca korunur
- reconnecting → queued/extended yalnız preserved snapshot ile
- reconnecting → offline yalnız reset/terminal recovery sonucuyla
- queued/extended → cancelled yalnız current-search leave ile
- queued/extended → offer yalnız current-search real pairing ile
- offer → queued/extended mevcut reject/timeout requeue politikasında yeni attempt ile
- offer → terminal/chat mevcut QA-003 başarı akışıyla

Bunun dışındaki geçiş contract violation olarak loglanır ve state mutate etmez.

### 7.3 Cancel yarışları

- Client ilk tıklamada düğmeyi pending/disabled yapar ve tek `commandId` kullanır.
- Server duplicate komutu aynı ack ile cevaplar.
- Cancel join doğrulamasından önce gelirse search tombstone edilir; gecikmiş join queue'ya yazamaz.
- Pairing ile cancel aynı anda gelirse serialized işlem tek kazanan belirler. Cancel kazanırsa offer yok; offer kazanırsa current state/conflict açıkça döner.
- Ack networkte kaybolursa aynı commandId retry güvenlidir.
- Stale search leave current search'i kapatamaz.

### 7.4 Existing flow adaptasyonu

- `waitingQueue` düz array erişimi search identity'li tek lifecycle API'si arkasına alınır.
- `joinQueue`, `createPendingMatch`, `queueClientForRematch`, `cancelPendingMatchById`, disconnect cleanup ve shadow path aynı invariantları kullanır.
- Event üretimi tek serializer/validator üzerinden geçer; hiçbir dal bare `queued` göndermez.
- Eski `clientId` transport handle olabilir, domain search identity yerine geçmez.
- Offer kapanışı/requeue sırasında aynı journey ile yeni queue attempt ayrımı açık tutulur.
- Davranış eventleri mutation transaction/sonucuyla hizalanır; retry duplicate event üretmez.

## 8. Client uygulama paketi — A-MATCH-001

### 8.1 State sahipliği

Arama state'i ekran-local timer ve dağınık `status` stringlerinden çıkarılıp Wave 05 domain reducer/store'una bağlanır:

- `searchId`, `phase`, `queueAttempt`, `queuedAt`, `serverClockOffset`
- timing policy version, tier eşikleri ve computed display tier
- cancel command, pending ve terminal/error reason
- `moodId`, `promptId`, recent prompt ring
- current offer envelope ve visual transition deadline

Reducer bütün eventlerde epoch/revision/searchId/attempt guard uygular. React ekranı yalnız selector sonucu render eder; socket paketini yorumlamaz. Offer alt görünümü ayrıştırılabilir fakat davranışı Wave 09 öncesi değiştirilmez.

### 8.2 Ekran yerleşimi

Yukarıdan aşağı tek ritim:

1. İki parçacıklı ambient alan
2. Status başlığı, kısa açıklama ve yalnız uygun phase'de elapsed timer
3. `Random`, `Fun`, `Casual`, `Deep` erişilebilir mood chip'leri
4. Kompakt prompt kartı ve `Başka soru` eylemi
5. İkincil `Aramayı durdur` eylemi

Tek ana panel hissi korunur; iç içe cam kart/glow yığını oluşturulmaz. TalkX koyu zemin, cyan ve mor/pembe neon dili devam eder. Desktop'ta bounded max-width; mobilde safe-area ve `100dvh`. Kısa ekranda önce animasyon küçülür, eylem erişimi korunur; normal hedefte scroll yoktur.

### 8.3 Parçacık animasyonu

- Anahtar/radar yerine biri cyan, biri mor/pembe iki soyut parçacık kullanılır.
- Farklı orbitlerde yaklaşır/uzaklaşır ve hafif iz bırakırlar; yaklaşık 6–8 saniyelik ambient ritim başarı iddiası değildir.
- Gerçek offer gelmeden tam birleşme, checkmark, yüzde dolumu veya final pulse yoktur.
- `reconnecting` sırasında hareket yavaşlar ve iz kesintili olur; `offline` statikleşir.
- Offer'da yalnız görsel final yaklaşma ve cyan/pembe dalga yapılır.
- CSS/SVG transform/opacity tercih edilir; ağır canvas, sürekli blur repaint veya WebView'i zorlayan filter zinciri yoktur.
- `prefers-reduced-motion` için statik parçacıklar ve çok hafif opacity; offer geçişi beklemez.

### 8.4 Dürüst status metinleri

Metinler i18n anahtarlarından ve tek state/tier tablosundan gelir:

- preparing: istek hazırlanıyor/onay bekleniyor; “eşleşme aranıyor” iddiası yok
- initial (~0–8 sn): arama başladı
- continuing (~8–20 sn): arama sürüyor
- quiet (~20–45 sn): biraz sürebileceğini nötr söyler
- long (45+ sn / extended): arama sürüyor ve durdurulabilir; hata değildir
- reconnecting: bağlantı geri kuruluyor
- restored: aynı arama devam ediyor
- reset/offline: arama devam edemedi; retry/close seçenekleri

Teknik WebSocket/queue terimi, exact kullanıcı sayısı, ülke, preference veya kesin süre yazılmaz. Aria-live yalnız anlamlı phase değişiminde polite announcement yapar; saniye sayacı canlı bölgeye alınmaz.

### 8.5 Mood ve prompt katalogu

- Stable category ID'leri: `random`, `fun`, `casual`, `deep`.
- Her gerçek kategori için locale başına 8–10 güvenli prompt; Random dengeli seçimdir.
- Prompt ID locale'den bağımsızdır; TR/EN aynı ID setini taşır.
- Promptlar PII istemez; cinsel, saldırgan, tetikleyici veya dar kültürel varsayım içermez.
- Mobilde yaklaşık üç satırı aşmayacak editoryal limit uygulanır.
- Otomatik rotasyon kaldırılır. Yalnız mood seçimi veya `Başka soru` prompt'u değiştirir.
- Bounded recent ring anlık tekrarı önler; RNG testte seed edilebilir.
- Dil değişiminde promptId korunur; eksik çeviri mixed-language üretmez.
- Aynı search ve reject/timeout requeue boyunca seçim korunur.
- Cancel/close journey'yi bitirir; yeni search `random` ve yeni/nonrecent prompt ile açılır.

### 8.6 Offer ve chat devri

- Current-search offer gelir gelmez phase `offer` olur ve elapsed timer durur.
- Mood/prompt snapshot offer state'ine taşınır; matchmaking sonucu gibi sunulmaz.
- Görsel final geçiş 300–600 ms hedefindedir. Server `autoAcceptAt` hemen işlemeye devam eder; animation callback karar mantığını bloke etmez.
- Remaining süre güvenli bütçeden azsa geçiş kısalır/atlanır; reduced-motion'da bekleme yoktur.
- Mevcut offer CTA görünümü ve accept/reject davranışı korunur.
- Chat'te prompt yalnız kullanıcı dokunursa composer'a alınabilen suggestion'dır; otomatik gönderilmez.

### 8.7 Erişilebilirlik ve responsive sınır

- Mood chip'leri button/radio semantics, görünür focus ve seçili state taşır.
- Prompt değiştirme, stop, retry ve close klavye/screen-reader ile erişilebilir olur.
- Status hiyerarşisi heading/description/timer olarak semantiktir.
- Renk tek bilgi taşıyıcısı değildir; reconnect/offline/cancel metin ve shape ile ayrılır.
- Minimum dokunma hedefi, safe-area inset, font scaling ve 320 px width doğrulanır.
- Kısa Android WebView'de CTA ekran dışına itilmez; önce ambient alan küçülür.

## 9. Telemetry ve privacy

Allowlist eventleri:

- `match_search_started`
- `match_queue_confirmed`
- `match_status_tier_seen`
- `match_mood_selected`
- `match_prompt_changed`
- `match_search_cancelled`
- `match_reconnect_started`
- `match_reconnect_result`
- `match_offer_received`

Ortak envelope mümkün olduğunda searchId, queueAttempt, phase/tier, timing policy version, reason code, app version ve privacy-safe latency taşır. Prompt için yalnız promptId/category yazılır; tam metin yazılmaz. Mood/prompt eventleri `preference_match` veya filtre etkisi adlandırması kullanmaz. Replay duplicate product event üretmez. Wave 14 dashboard işi bu Wave'e çekilmez.

## 10. Dosya etki haritası

Uygulama başladığında kesin liste güncel keşifle daraltılır. Beklenen yüzey:

- `chatapp-backend/index.js` ve gerekirse ayrıştırılmış matchmaking lifecycle/serializer modülü
- Backend contract/state-machine testleri
- `chatapp-frontend/src/App.jsx` veya Wave 05 domain state katmanı
- `chatapp-frontend/src/screens/MatchScreen.jsx`
- Küçük SearchAmbient/prompt catalog/reducer yardımcıları
- `chatapp-frontend/src/i18n.jsx` veya mevcut locale katalogları
- `ChatScreen.jsx` içinde yalnız suggestion devri gerekiyorsa küçük tüketim
- Component/unit/integration/E2E testleri ve QA kanıtı

DB schema, country resolver, Home selector, offer yeniden tasarımı, admin ekranı ve deployment config varsayılan kapsam dışıdır.

## 11. Uygulama sırası

1. Wave 06 kapanışı, üç repo snapshot'ı ve gerçek Wave 05 recovery sözleşmesini doğrula.
2. QA-014 maddelerini test/kanıt kimliklerine eşleştir; baseline ekran ve iki-client davranışını kaydet.
3. Search state machine, invariant, event schema, idempotency ve revision validator'larını test-first kilitle.
4. Backend queue/pending/requeue/cancel yollarını search-aware tek lifecycle API'sine geçir.
5. Recovery snapshot'a preserved search alanlarını ekle ve restart/reset davranışını doğrula.
6. Capability/legacy adapter ile server contractını feature-off yayımlanabilir yap.
7. Client reducer/store'u server-otoriteli phase ve clock-corrected timer ile bağla.
8. Mood/prompt katalogunu, i18n completeness validator'ını ve preservation kurallarını ekle.
9. Search yüzeyini yeni yerleşim ve parçacık animasyonuyla değiştir; offer subview'ını koru.
10. Cancel/reconnect/offline/retry/offer transition yarışlarını otomatik test et.
11. Web + Android manuel QA, accessibility ve performans kanıtını tamamla.
12. Stable ID/checklist'leri yalnız kanıt ve kullanıcı onayıyla kapat; Wave 08'i başlatmadan dur.

## 12. Otomatik test planı

### 12.1 Backend contract/state testleri

- Geçerli join → tam `queued` envelope ve server zamanı
- Aynı search/command duplicate join → tek queue entry, replayed result
- Farklı active search → deterministic conflict, implicit replacement yok
- Immediate peer → accepted state offer'dan önce veya atomik reducer sırası
- Pairing → iki kullanıcıya kendi searchId'siyle offer
- Rapid/double cancel → tek mutation ve tek product event
- Async delayed join + cancel → tombstone kazanır, late queue/offer yok
- Old search cancel/offer/phase → current search'i etkilemez
- Requeue → aynı journey, artan attempt, yeni queuedAt
- Preserved reconnect → aynı search/timer; reset → otomatik join yok
- Server epoch/revision gerilemesi → event reddi
- Clock skew/background → doğru elapsed/tier
- Shadow path → aynı schema, moderation disclosure yok
- Disconnect/room/pending cleanup invariantları

### 12.2 Client reducer/component testleri

- Preparing'de timer yok; queued ack ile başlar
- Her phase yalnız izinli control/metni gösterir
- Tier eşikleri boundary değerlerinde deterministik
- Cancel pending çift tıklamayı engeller; ack sonrası cleanup
- Stale searchId/attempt/revision event no-op
- Reconnecting ile extended birbirine karışmaz
- Reset/offline retry yeni searchId üretir
- Mood/prompt filtre payload'ına girmez
- Prompt yalnız explicit action ile değişir; locale switch ID'yi korur
- Reject/timeout requeue selection'ı korur; cancel/new journey resetler
- Offer timerı anında durdurur ve server autoAcceptAt'ı korur
- Reduced-motion transition beklemez
- Aria-live saniyelik spam üretmez
- 320 px/kısa viewport/safe-area layout taşmaz

### 12.3 Veri ve i18n doğrulaması

- TR/EN prompt ID set parity
- Kategori başına 8–10 prompt
- Duplicate/boş/çok uzun prompt ve eksik çeviri reddi
- Analytics allowlist ve full-prompt sızıntı testi
- User-facing metinde teknik queue/WS, fake ETA/position/count ifadesi scan'i

### 12.4 Entegrasyon ve E2E

- İki gerçek client queue → offer; iki tarafta doğru search identity
- Dört bekleme zaman katmanı
- Delayed queue ack
- Preserved ve reset reconnect
- Permanent offline retry/close
- Rapid cancel ve late offer
- Old search event injection
- Reject, timeout, auto-accept ve başarılı chat devri
- Web Chromium ve Android WebView kritik senaryoları

Test komutları mevcut package scriptlerine göre başlangıçta netleştirilir; yeni dependency sırf plan varsayımıyla eklenmez. Flaky test product code değişikliğiyle maskelenmez; izole yeniden çalıştırma ve kanıt kaydı gerekir.

## 13. Manuel QA havuzu — Checkpoint B / Wave 19 (commit kapısı değil)

| Alan | Senaryo | Beklenen |
|---|---|---|
| Başlangıç | join ack gecikiyor | Preparing görünür, timer yok |
| Zaman | 0–8 / 8–20 / 20–45 / 45+ | Doğru, dürüst tier; fake progress yok |
| Reconnect | Queue preserved | Aynı searchId ve doğru elapsed ile devam |
| Reconnect | Queue reset | Offline/reset mesajı; otomatik join yok |
| Cancel | Hızlı çift tık | Tek leave, tek ack/analytics, offer yok |
| Stale | Eski queued/offer enjekte | Yeni arama değişmez |
| Mood | Dört chip + Random | Erişilebilir; queue davranışı değişmez |
| Prompt | Başka soru/dil değişimi | Manuel, tekrar kontrolü, aynı stable ID |
| Offer | Gerçek offer | Timer hemen durur; geçiş countdown'u geciktirmez |
| Requeue | Reject/timeout | Yeni attempt; mood/prompt korunur |
| Chat | Prompt suggestion | Otomatik gönderilmez |
| Motion | Reduced motion | Statik/hafif güvenli görünüm |
| Mobil | 320 px, kısa ekran, safe area | Eylemler görünür; taşma yok |
| Android | WebView/background/foreground | Phase ve süre snapshot'tan düzelir |
| A11y | Klavye, focus, screen reader, font scale | Operasyon tamamlanabilir; live spam yok |

Her kritik state için web ve Android ekran/video kanıtı alınır; yalnız screenshot otomatik contract testlerinin yerine geçmez.

## 14. Canonical kabul eşlemesi

### 14.1 B-MM-001

- [ ] Master QA-014 backend maddeleri eksiksiz uygulandı.
- [ ] Timer yalnız server queue ack'inden sonra başlıyor.
- [ ] Cancel sonrası late offer oluşmuyor/işlenmiyor.
- [ ] Preserved ve reset reconnect semantics otomatik ve manuel kanıtlı.
- [ ] `match_offer` yalnız current search için kabul ediliyor.
- [ ] Server/client clock skew timerı bozmuyor.
- [ ] Behavior eventleri aynı search journey'ye bağlanıyor.

### 14.2 A-MATCH-001

- [ ] Master QA-014 UI/UX maddeleri korunup kanıtlandı.
- [ ] UI backend phase'i tahmin etmiyor.
- [ ] Animasyon gerçek offer öncesi başarı/merge göstermiyor.
- [ ] 100dvh, kısa telefon ve Android WebView doğrulandı.
- [ ] Reconnect ile uzun bekleme görsel/metinsel ayrıldı.
- [ ] Stale event yeni search state'ini bozamıyor.
- [ ] Mood/prompt aynı journey ve gelecekteki scope değişimi sınırında korunabilir.
- [ ] Offer geçişi QA-003 countdown/autoAcceptAt'ı geciktirmiyor.

### 14.3 Master QA-014 kapanış matrisi

| # | Canonical kabul | Zorunlu kanıt |
|---|---|---|
| 1 | Yalnız gerçek lifecycle phase | Reducer/contract test + state screenshots |
| 2 | Timer queue ack ile başlar | Delayed-ack ve clock-skew test |
| 3 | Dürüst katmanlı metin | Boundary test + TR/EN review |
| 4 | İki TalkX parçacığı | Web/Android görsel kanıt |
| 5 | Offer öncesi fake merge yok | Animation state testi |
| 6 | Reduced motion güvenli | Media-query test + manuel QA |
| 7 | Dört mood ve Random | A11y/component testi |
| 8 | Mood queue'yu bölmez | Payload/server predicate testi |
| 9 | 8–10 güvenli prompt/kategori/locale | Catalog validator + içerik review |
| 10 | Prompt yalnız manuel değişir | Timer/interaction testi |
| 11 | Stable promptId ve seçim devri | Locale/requeue/offer testi |
| 12 | Prompt otomatik gönderilmez | Chat integration testi |
| 13 | Stop ikincil ve idempotent | Rapid cancel E2E |
| 14 | Reconnect/extended/offline ayrımı | Fault-injection matrisi |
| 15 | Stale search eventi etkisiz | Old-event injection testi |
| 16 | Responsive/a11y/safe-area | 320 px, kısa Android, SR/keyboard |
| 17 | Privacy-safe journey telemetry | Event schema ve payload scan |

Checkbox yalnız gerçek kod, otomatik test, gerekli manuel cihaz kanıtı ve kullanıcı QA onayıyla kapanır.

## 15. Kapsam dışı ve successor guard

Bu Wave'de yapılmayacaklar:

- Global / My Country selector, scope snapshot veya scope değiştirme
- Country queue partition, canonical country resolve, pool count ve 15/45 saniye fallback
- Country unavailable/insufficient UX ve scope telemetry dashboard'u
- QA-003 teklif kartı/CTA/hiyerarşi yeniden tasarımı
- Match success screen, chat shell genel redesign veya profil kartı
- Admin panel, moderation policy, retention/deletion veya release automation
- Wave 08 uygulaması ya da Wave 09 planı/uygulaması

Wave 07'nin generic searchId, attempt, revision ve honest phase altyapısı Wave 08 tarafından tüketilebilir; bu genişleyebilirlik scope davranışını erkenden ekleme gerekçesi değildir.

## 16. Riskler ve rollback

| Risk | Koruma | Rollback/durma davranışı |
|---|---|---|
| Client fake timer başlatır | Ack-gated reducer | Lifecycle flag kapat |
| Cancel ile async join yarışır | Serialized mutation + tombstone | Search'i fail-closed terminal yap |
| Late offer yeni search'i bozar | searchId/attempt/revision guard | Event no-op + metric |
| Immediate match queued sırasını atlar | Tek serializer/ordered transition | Offer emit'i durdur, state replay |
| Clock skew yanlış tier gösterir | serverNow offset + snapshot | Timerı gizle, phase metnini koru |
| Reconnect duplicate queue açar | Wave 05 snapshot, no auto-join | Reset ekranı ve manual retry |
| Multi-device iki search açar | User-level uniqueness/conflict | İkinci join reddi |
| Shadow behavior banı açar | Aynı public schema/metin | Ayrı reason'ı kaldır |
| Prompt filtre sanılır | Açık microcopy + payload exclusion | Mood/prompt flag kapat |
| Prompt locale eksik/mixed olur | Stable ID parity validator | Release bloke |
| Animation fake offer üretir | Merge yalnız real offer | Final motion kapat |
| Animation WebView'i yorar | CSS/SVG budget | Statik fallback |
| Transition countdown'u yer | Server autoAcceptAt + clamp | Transition'ı sıfırla |
| Küçük ekranda stop kaybolur | 100dvh/safe-area test | Ambient alanı küçült |
| Analytics prompt sızdırır | ID-only allowlist test | Eventi kapat/redact |
| Legacy client kırılır | Capability + adapter | Capability'yi kapat |
| Dirty repo işi örter | Üç bağlam snapshot | Yalnız Wave 07 farkını geri al |

Rollback queue'nun kendiliğinden canlandırılmasına dayanmaz. Capability kapatıldığında server active search'i kontrollü terminal/reset sonucuyla kapatır; sessiz duplicate join üretmez.

## 17. Rollout kapıları

1. Contract/state testleri ve legacy fixture'lar yeşil olmadan capability ilan edilmez.
2. Backend yeni alanları önce compatibility modunda üretir; client flag kapalıdır.
3. Staging iki-client ve cancel/reconnect fault injection tamamlanır.
4. Client flag küçük test cohort'unda açılır; stale-event, duplicate-search, cancel latency ve crash metricleri izlenir.
5. Web ardından Android WebView/background/reduced-motion kanıtı alınır.
6. Prompt/i18n içerik incelemesi ve accessibility manuel QA tamamlanır.
7. Rollback provası capability/flag üzerinden yapılır; open search'ler deterministic reset görür.
8. Checkbox ve Wave durumu yalnız gerçek kanıt + kullanıcı QA onayıyla güncellenir.

Canlı deploy, flag değişimi, gerçek kullanıcı telemetry sorgusu veya production socket/queue müdahalesi bu planla yetkilendirilmez.

## 18. Başlangıç kapısı

Bu kutular plan hazırlanırken işaretlenmez; yalnız Wave 07 gerçekten başlatılırken güncel kanıtla kapatılır:

- [ ] Wave 01–06 QA kapanışları ve kullanıcı onayı doğrulandı.
- [ ] Kullanıcı açıkça “Wave 07'yi başlat” talimatı verdi.
- [ ] Root, backend ve frontend Git status/remote/branch/commit snapshot'ı alındı.
- [ ] Wave 05 connection identity, recovery snapshot, server epoch ve state revision gerçek kodda doğrulandı.
- [ ] Wave 06'nın bu Wave için scope/country davranışı açmadığı doğrulandı.
- [ ] Current queue/pending/requeue/disconnect/shadow-ban yolları yeniden envanterlendi.
- [ ] Existing MatchScreen/App/i18n/ChatScreen baseline test ve screenshot kanıtı alındı.
- [ ] Search state machine, timestamp formatı, idempotency ve immediate-match sırası kilitlendi.
- [ ] Legacy client/capability/rollback politikası owner tarafından onaylandı.
- [ ] Mood/prompt TR/EN içerik seti ve güvenlik inceleme sahibi belirlendi.
- [ ] Web/Android/reduced-motion/a11y manuel QA cihaz matrisi hazırlandı.
- [ ] Wave 08 Global/Country ve Wave 09 QA-003 offer sınırlarına taşma olmadığı doğrulandı.

## 19. Sonuç alanı

Wave 07 yürütülürse kapanış kaydı en az şunları içerir:

- Başlangıç/bitiş zamanı, Plan refs ve gerçek değişen dosyalar
- Üç Git bağlamının önce/sonra status/commit farkı
- Final protocol/capability/state-transition sözleşmesi
- Search identity, queue timing, cancel/idempotency ve stale-event kanıtları
- Preserved/reset reconnect ve server restart sonuçları
- Immediate match, reject/timeout requeue ve multi-device sonuçları
- Prompt catalog parity/content validator ve no-filter/no-auto-send kanıtı
- Web/Android responsive, safe-area, reduced-motion, keyboard ve screen-reader kanıtı
- Syntax/lint/build/encoding/focused/full test komutları ve exit code'ları
- Rollout/rollback provası ve ilgili metric özeti
- B-MM-001, A-MATCH-001 ve Master QA-014 kabul tablosu
- Checkpoint B / Wave 19'a aktarılmış manuel QA kaydı
- Wave 08'in başlatılmadığına dair açık durma kaydı

## 20. Durma kuralı

Wave 06 QA kapanışı ve kullanıcının açık Wave 07 başlatma talimatı birlikte gelene kadar:

- Wave 07 için kod, test, dependency, migration, config, data scan veya deploy değişikliği yapılmaz.
- Wave 07 `Aktif` işaretlenmez; bu belge yalnız `Hazır — aktif değil` durumunda kalır.
- Canonical `[ ]` kabul maddeleri kanıtsız işaretlenmez.
- Wave 08 uygulanmaz; hazırlanmış plan aktif edilmez.
