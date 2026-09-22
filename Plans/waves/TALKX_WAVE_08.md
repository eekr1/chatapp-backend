# TalkX Wave 08 Plan — QA-017 Global / Kendi Ülkem Dikey Dilimi

> Bu belge yalnız Wave 08 için hazırlanmış uygulama planıdır.
> Canonical ayrıntı Plan B `B-MM-002`, Plan A `A-MATCH-003`, Plan C `C-ANL-002`, Plan A `A-HOME-001` ve Master QA-017'dedir.
> Plan hazırdır. Wave 08 aktif değildir, Wave 01–07 kapanmamıştır ve uygulama başlamamıştır. Wave 09 QA-003 teklif protokolü bu belge içinde uygulanmaz; hazırlanmış Wave 09 planı aktif edilmez.

## 1. Durum ve yürütme sınırı

- **Wave:** 08
- **Wave adı:** QA-017 Global / Kendi Ülkem dikey dilimi
- **Plan katılımı:** Plan B + Plan A + Plan C
- **Canonical sıra:** `B-MM-002 → A-MATCH-003 → C-ANL-002 → A-HOME-001`
- **Plan durumu:** Hazır
- **Wave durumu:** Bekliyor
- **Uygulama durumu:** Başlamadı
- **Uygulama yetkisi:** Verilmedi
- **Giriş kapısı:** Wave 07 **AUTO-VERIFIED / COMMITTED** ve kullanıcıdan açık “Wave 08'i başlat” talimatı
- **Mevcut blokaj:** Wave 07 henüz committed değil; Wave 08 uygulanamaz
- **Önceki wave:** Wave 07 — planı hazır, aktif değil
- **Sonraki wave:** Wave 09 — planı hazır, aktif değil ve başlatılmadı

Bu dosyanın hazırlanması Wave 08 aktivasyonu, kod/test/dependency değişikliği, migration, gerçek geo/IP sorgusu, canlı veri, admin telemetry sorgusu, feature flag, deploy veya Wave 09 uygulaması için yetki değildir.

## 1.1 Sale Release override — TAM / ÇEKİRDEK

- **Satış öncesi uygulanır:** Ayrı Global/Kendi Ülkem queue-scope davranışı, kesin country filtresi, sessiz Global fallback'in kaldırılması, doğru UI scope durumu ve temel telemetry.
- **Post-acquisition Roadmap / Deferred:** Yeni segmentler, deney/rollout altyapısı, manuel ülke seçimi ve gelişmiş matching analytics.
- **Kapanış:** Scope izolasyonu/fallback otomatik testleri geçer, tek Wave 08 commit'i alınır ve **DUR**. Gerçek iki-client Web/Android QA'sı Checkpoint B/Wave 19'a gider.
- Telemetry yalnız işlevi doğrulayacak minimum düzeyde tutulur.

## 2. Canonical referanslar ve bağımlılık sırası

1. `B-MM-002` — Global/Country queue partitionı, scope/search bütünlüğü, atomik değişim ve fallback otoritesi
2. `A-MATCH-003` — Home ve QA-014 içindeki ortak scope kontrolü, switching ve fallback UX
3. `C-ANL-002` — privacy-safe scope/country ölçümü ve Jarvis özeti
4. `A-HOME-001` — selector'ın arama öncesi mevcut anonim eşleşme kartına yerleşmesi ve Home hiyerarşisi
5. `B-DATA-002` — Wave 06 canonical matchmaking country; Wave 08 bunu tüketir, geo gerçeğini yeniden üretmez
6. `B-MM-001` ve `A-MATCH-001` — Wave 07 searchId, phase, timer, mood/prompt, reconnect ve stale-event sözleşmesi
7. `B-MM-003` ve `A-MATCH-002` — Wave 09 QA-003 otoritesi; yalnız regresyon sınırı olarak okunur

Çelişki çözümü:

- Kullanıcının seçimi `preferredMatchScope`, aktif aramanın gerçeği server onaylı `effectiveMatchScope` olur.
- Client ülke kodu veya display name'i matchmaking otoritesi yapamaz; Wave 06 canonical country kazanır.
- COUNTRY hiçbir koşulda sessizce GLOBAL ile karışmaz. Global'e geçiş yalnız açık kullanıcı aksiyonudur.
- Scope, QA-014 `searchPhase` değildir; iki eksen bağımsız birleşir.
- Wave 09 teklif UI'sine bayrak, badge, selector, CTA veya yeni bilgi katmanı eklenmez.
- Plan ayrıntısıyla Master QA-017 çatışırsa Master'ın kilitli ürün kararı kazanır.

## 3. Wave sonucu

Wave 08 sonunda:

- Yeni/seçimsiz kullanıcı Global varsayılanını görecek; geçerli son açık tercih hesap güvenliğiyle hatırlanabilecek.
- Kullanıcı yalnız `GLOBAL` veya server'ın hesabı için uygun bulduğu tek `COUNTRY` kapsamını seçebilecek.
- Ülke biliniyorsa “My Country” yerine locale'e göre gerçek ülke adı gösterilecek.
- Aynı kompakt segmented control Home anonim eşleşme kartında CTA üstünde ve QA-014 arama ekranında parçacıkların üstünde ortak state'i tüketecek.
- Queue `match:global` ve `match:country:<ISO>` mantıksal partitionlarına ayrılacak; GLOBAL yalnız GLOBAL, COUNTRY yalnız aynı ISO COUNTRY ile eşleşecek.
- Kullanıcı/hesap başına tek aktif search invariantı partition, reconnect, requeue, scope change ve ikinci cihaz yarışında korunacak.
- Aktif aramada scope değişimi eski search'i invalidate edip yeni searchId/queuedAt üreten atomik server işlemi olacak.
- Country araması uzadığında merkezi server-time eşiğiyle tek, kompakt Global önerisi gösterilecek; arama durmayacak ve otomatik geçiş olmayacak.
- Peer reject, timeout veya conversation retry requeue son onaylanmış effective scope'u koruyacak.
- QA-014 mood/prompt, parçacık animasyonu ve gerçek phase modeli scope eklenince bozulmayacak.
- QA-003 teklif ekranı görünüm, CTA ve countdown bakımından değişmeyecek; scope yalnız bütünlük kontrolü için eventte taşınabilecek.
- Telemetry tam IP/GPS/şehir/peer ülke veya serbest country string taşımadan requested/effective scope ve funnel sonucunu ölçecek.
- Admin özeti kaynak, zaman penceresi, tazelik, birim ve minimum cohort ile Global/Country sonuçlarını dürüstçe karşılaştıracak.
- Web, Android, TR/EN, 320 px, kısa ekran, keyboard, screen reader ve reduced-motion kanıtlanacak.
- Wave 09 başlamayacak.

## 4. Doğrulanmış başlangıç fotoğrafı

### 4.1 Mevcut queue ve search

- Backend bugün tek process-memory `waitingQueue` kullanıyor; entry scope veya country taşımıyor.
- `joinQueue` client scope/search alanı kabul etmiyor; `queueClientForRematch` parametresiz yeniden join çağırıyor.
- GLOBAL/COUNTRY partition, `changeMatchScope`, fallback eligibility ve country-aware pending match bulunmuyor.
- Wave 07 uygulanmış sayılmaz. Başlangıçta gerçek koddan searchId/revision/idempotency sözleşmesi yeniden doğrulanmadan bu Wave ilerlemez.

### 4.2 Mevcut country gerçeği

- `legal_acceptances.location_country` serbest metin tarihsel kabul snapshot'ıdır ve doğrudan queue anahtarı olamaz.
- Wave 06 planı canonical ISO alpha-2 code, source/status/freshness/policy version ve privacy yaşam döngüsünü sahiplenir.
- Wave 06 canonical country çekirdeği **AUTO-VERIFIED / COMMITTED** olmadan geçerli `COUNTRY` capability açılamaz.
- Tam IP, GPS, şehir veya adres queue/pending/telemetry kaydına kopyalanmaz.

### 4.3 Mevcut client yüzeyi

- Home anonim eşleşme kartı bugün doğrudan anon mode başlatma aksiyonuna gider; ortak scope selector/state yoktur.
- Match ekranında Wave 07 planındaki lifecycle ve ambient yüzey henüz uygulanmış değildir.
- Preferred/effective scope, switching, fallback ve server country availability state'i görünmüyor.
- İki yüzeyin ayrı local state tutması kabul edilmez.

### 4.4 Mevcut analytics/admin

- QA-017 event family, metric denominatorları, country cohort masking ve kaynak/zaman/tazelikli Jarvis özeti canonical uygulamada yoktur.
- Düşük hacimli ülke sonuçlarının kullanıcı veya tekil davranış açığa çıkarmaması gerekir.
- Wave 14 genel davranış dashboard'u bu Wave'e çekilmez; C-ANL-002 yalnız QA-017'nin bounded özetidir.

### 4.5 Repo ve operasyon sınırı

- Root/backend/frontend çalışma ağaçlarında geniş kullanıcı değişiklikleri bulunabilir; üç Git bağlamı ayrı snapshot edilir.
- Production ülke verisi, IP, queue, analytics veya admin kayıtları plan hazırlanırken sorgulanmaz.
- Çoklu backend instance gerçeği başlangıçta doğrulanır; process-memory queue ile çoklu instance birlikte kullanılıyorsa Wave kapatılamaz.

## 5. Kilitli ürün ve state modeli

### 5.1 Ürün cümlesi

> Global varsayılan eşleşme kapsamıdır. Kullanıcı kendi doğrulanmış ülkesini kesin filtre olarak seçebilir; düşük bulunabilirlikte Global yalnızca önerilir, hiçbir zaman sessizce uygulanmaz.

İlk sürüm yalnız Global ve kullanıcının tek gerçek ülkesidir. Manuel başka ülke, birden fazla ülke, dil/yaş/cinsiyet/ilgi/saat dilimi filtresi, ücretli öncelik ve canlı havuz sayısı yoktur.

### 5.2 İki bağımsız state ekseni

Search ekseni Wave 07'den değişmeden gelir:

- `preparing | queued | extended | reconnecting | offline | cancelled | offer`

Scope ekseni:

- `preferredMatchScope: GLOBAL | COUNTRY`
- `effectiveMatchScope: GLOBAL | COUNTRY | null`
- `effectiveCountry: { code, displayName, status, version } | null`
- `scopeChangeStatus: idle | switching | failed`
- `fallbackStatus: hidden | eligible | visible | declined | accepted`
- `searchId` ve `queueAttempt`

Geçerli birleşimler arasında `COUNTRY + reconnecting`, `GLOBAL + extended` ve `COUNTRY + offer` bulunabilir. `extended` otomatik Global demek değildir. UI aktif aramada server onayı gelmeden preferred seçimi effective gibi çizmez.

### 5.3 Tercih ve effective gerçek

- İlk kullanım `GLOBAL`.
- Yalnız server tarafından başarıyla onaylanmış açık kullanıcı tercihi kalıcı tercih olabilir.
- Tercih authenticated account kapsamındadır; logout/hesap değişiminde başka kullanıcıya sızmaz.
- Server preference otorite, local cache yalnız hızlı ilk çizimdir.
- Kayıtlı COUNTRY fakat country unavailable/stale ise COUNTRY join yoktur; selector açıklamalı disabled olur ve Global alternatif olarak sunulur.
- Bu durumda Global arama da kullanıcı başlatma CTA'sına basmadan otomatik başlamaz.
- Country refresh/seyahat/VPN sinyali aktif search'i sessizce değiştirmez.

## 6. Canonical country tüketim sözleşmesi

Wave 08 country üretmez; Wave 06'nın server-owned sonucunu tüketir. Kullanıcıya açılan minimum response:

- canonical ISO 3166-1 alpha-2 `code`
- locale-safe `displayName`
- `availability: available | unavailable | stale`
- `countryVersion` veya policy/version kimliği
- kullanıcıya uygun, teknik olmayan reason key

Kurallar:

- Client COUNTRY isteğinde countryCode göndermese tercih edilir; gönderirse server ignore/validate eder ve asla otorite kabul etmez.
- Queue key yalnız server'ın current authenticated-user canonical code'undan üretilir.
- Display name eşleşme anahtarı değildir.
- `inferred` gibi status'ların eligibility kararı Wave 06 policy'sinden gelir; Wave 08 yeni doğrulama standardı uydurmaz.
- Country unavailable/stale hatası açık, retryable sınıf ve güvenli Global CTA bilgisi döndürür; backend kendiliğinden Global join yapmaz.
- Peer country veya geo source client'a açılmaz.

## 7. Matchmaking partition ve invariantlar

Mantıksal anahtarlar:

```text
match:global
match:country:TR
match:country:DE
match:country:BR
```

Teknoloji `Map<queueKey, QueueEntry[]>`, indeks veya shared atomic queue olabilir; semantik sabittir.

Queue entry en az participant/user identity, connection routing, searchId, queueAttempt, scope, canonical countryCode veya null, queuedAt, trigger ve revision taşır.

Invariantlar:

1. Kullanıcı/hesap başına bütün partitionlar toplamında en fazla bir aktif entry.
2. GLOBAL yalnız GLOBAL ile eşleşir.
3. COUNTRY yalnız aynı ISO country key'iyle eşleşir.
4. Block, ban, shadow-ban, cooldown ve FIFO/fairness partition içinde korunur.
5. Invalid/disconnected entry cleanup bütün partitionları kapsar.
6. Pending match her iki participant'ın searchId, scope ve country bütünlüğünü taşır.
7. Requeue effective scope/country'yi açıkça devralır; default parametreyle Global'e düşmez.
8. Çoklu instance varsa tek process memory global otorite sayılamaz; shared atomic queue/lock gerekir veya deployment tek instance olarak kanıtlanıp guard edilir.
9. Country kuyruğunun boş olması error/connection failure değildir.

## 8. Realtime ve atomik scope değişimi

### 8.1 Capability

Welcome/config cevabı sürümlü yapı taşır:

```json
{
  "matchScopes": {
    "version": 1,
    "enabled": true,
    "supported": ["GLOBAL", "COUNTRY"],
    "countryAvailable": true
  }
}
```

- Capability yoksa selector tamamen gizlenir ve mevcut Global akış çalışır.
- Backend yalnız GLOBAL destekliyorsa client COUNTRY isteğinde ısrar etmez.
- Eski client yeni backend'e legacy join ile Global girebilir.
- Yeni eventler eski client'ı bozmamalı; anlamı değişen davranış feature gate arkasındadır.
- Feature kapatılırsa aktif COUNTRY search sessizce Global'e taşınmaz; runbook kontrollü terminal/reset veya kullanıcı önerisi üretir.

### 8.2 Arama başlatma

1. Kullanıcı Home'da tercihini seçer ve mevcut başlat CTA'sına basar.
2. Client yeni searchId/commandId ve yalnız `scope` intentini yollar.
3. COUNTRY için server authenticated kullanıcının canonical ülkesini çözer.
4. UI `preparing`; timer yok.
5. Server tek-active-search guardı içinde queue key'i kurup entry'yi yazar.
6. `queued` effective scope, country sunum bilgisi, queuedAt ve fallback zamanını onaylar.
7. Yalnız ack sonrası effective görünüm ve timer başlar.
8. Country uygun değilse error döner; Global otomatik join olmaz.

Örnek komut:

```json
{
  "type": "joinQueue",
  "protocolVersion": 1,
  "searchId": "uuid",
  "commandId": "uuid",
  "scope": "COUNTRY"
}
```

Örnek onay:

```json
{
  "type": "queued",
  "searchId": "uuid",
  "queueAttempt": 1,
  "scope": "COUNTRY",
  "country": { "code": "TR", "displayName": "Türkiye", "version": 3 },
  "queuedAt": "server-time",
  "fallbackEligibleAt": "server-time"
}
```

### 8.3 Aktif aramada değişim

Tercih edilen tek atomik komut:

```json
{
  "type": "changeMatchScope",
  "protocolVersion": 1,
  "fromSearchId": "old-uuid",
  "searchId": "new-uuid",
  "commandId": "uuid",
  "scope": "GLOBAL"
}
```

Server kullanıcı anahtarındaki serialized işlemde:

1. `fromSearchId` current mı doğrular.
2. Yeni scope/country eligibility'yi doğrular.
3. Eski queue/pending search'i invalidate eder.
4. Yeni search'i tek doğru partitiona yazar.
5. Tek revision artışıyla yeni `queued` snapshot döndürür.
6. Eski search için late queued/fallback/offer'ı reddeder veya güvenli kapatır.

Ayrı leave+join kullanımı ancak server tek transaction/state-machine ile atomiklik sağlıyorsa kabul edilir; iki client mesajının sırası garanti sayılmaz. Hata sonucu sıfır veya iki entry bırakmaz. Response authoritative active-search snapshot taşır; UI failed state'i ve güvenli retry'ı buradan kurar.

Hızlı segment tıklamalarında bir switching komutu uçuşta olur. Son intent coalesce edilebilir, fakat her tıklama queue oluşturmaz. Double action aynı commandId ile idempotenttir.

### 8.4 Event ailesi

- `joinQueue`
- `queued`
- `changeMatchScope`
- `match_scope_change_failed`
- `country_fallback_available` veya queued içindeki server-time eligibility
- `leaveQueue`
- `queue_left`
- `match_offer`
- `match_offer_closed`
- Wave 05 recovery snapshot

Kontrollü kodlar:

- `MATCH_COUNTRY_UNAVAILABLE`
- `MATCH_COUNTRY_STALE`
- `MATCH_SCOPE_INVALID`
- `MATCH_SCOPE_CHANGE_FAILED`
- `MATCH_SEARCH_STALE`

Bütün queue/offer/fallback eventleri searchId/revision taşır. COUNTRY eventinde canonical ISO code bulunur; displayName yalnız sunumdur. Teknik kod UI'da doğrudan gösterilmez.

## 9. Reconnect, requeue ve yarış matrisi

- Preserved reconnect aynı searchId, effective scope, country, queuedAt ve fallback state ile sürer.
- Queue korunmadıysa Wave 07 gibi otomatik join yok; açık restart sonucu ve kullanıcı aksiyonu gerekir. Restart yeni searchId üretirken son geçerli tercih kullanılabilir.
- Peer reject, offer timeout veya conversation retry requeue aynı effective scope/country ile yeni queueAttempt oluşturur.
- Scope change ile eski offer yarışırsa yalnız server current revision/search kazanır; stale QA-003 kartı açılmaz.
- Scope change sırasında disconnect olursa recovery snapshot tek authoritative sonucu verir; client iki komut üretmez.
- Fallback görünürken offer gelirse offer kazanır, fallback kapanır.
- Fallback accept ile old country offer yarışında atomik scope-change sonucu kazanır; stale offer reddedilir.
- İkinci cihaz farklı scope açamaz. Wave 07/Wave 05 politikası implicit takeover yerine deterministic conflict/snapshot uygular.
- Background/foreground client local segment görüntüsüne değil active-search snapshot'a göre toparlanır.
- Server restart queue'yu düşürürse UI sonsuz reconnect göstermez.
- Country policy/version aktif arama ortasında değişirse mevcut snapshot sessizce mutasyona uğramaz; terminal/restart kararı açık reason taşır.

## 10. Country fallback

### 10.1 Eligibility

- İlk ürün varsayımı yaklaşık 30 saniyedir; gerçek eşik merkezi, sürümlü server config'indedir.
- Server `fallbackEligibleAt` veya tek `country_fallback_available` eventi üretir.
- Client içine 30 saniye dağınık hard-code edilmez.
- Eligibility yalnız COUNTRY current search içindir ve server timestamp/revision ile doğrulanır.
- Reconnect snapshot görünmüş/declined fallback durumunu taşır; duplicate öneri üretmez.

### 10.2 UI davranışı

Kompakt inline alan QA-014 içeriğini itmeden şunu söyler:

> Türkiye'de eşleşme bulmak biraz daha uzun sürüyor.

Eylemler:

- `Global'e geç` — normal atomik scope-change; yeni searchId/queuedAt/timer
- `Burada aramaya devam et` — aynı country search devam eder
- Kapatma — aynı session'da tekrar rahatsız etmez

Fallback görünmesi aramayı durdurmaz. “Kimse yok”, “son kişi”, kesin süre veya uydurma yoğunluk yoktur. Accept dışındaki aksiyonlar scope'u değiştirmez.

### 10.3 Fallback state invariantları

- Search başına en fazla bir shown impression.
- `declined` ve `continued` kullanıcı aksiyonu olarak, hiç görmeme durumundan ayrılır.
- New scope/new search fallback state'i yeniden kurabilir.
- Requeue aynı journey'de server policy'nin belirlediği davranışı taşır; duplicate modal/kart yoktur.
- Global search fallback göstermez.
- Feature/config kapanışı sessiz fallback değildir.

## 11. Client UI/UX paketi — A-MATCH-003

### 11.1 Ortak segmented control

Aynı component ve store selector iki yerde kullanılır:

1. Home anonim eşleşme kartında ana CTA'nın hemen üstü
2. QA-014 MatchScreen'de ambient parçacıkların hemen üstü

Kontrol yeni ekran, modal veya bağımsız büyük kart değildir. Home ve Match ayrı local scope state tutmaz. Home preferred seçimi; active Match server effective state ve switching sonucunu birlikte gösterir.

### 11.2 Görsel dil

- Koyu zemin, mevcut glass yüzey, cyan/mor-pembe tokenları korunur.
- Seçili segment hafif glow ve dengeli kontrast; unselected okunur fakat ikincildir.
- İkinci dış çerçeve, kalın glow, yeni gradient ailesi veya badge yoktur.
- Label `Global | Türkiye/Germany/Brazil`; ülke biliniyorken “My Country” gösterilmez.
- Bayrak opsiyonel destek işaretidir, tek anlam kaynağı değildir. Emoji platform farkı bozarsa text-only veya kontrollü asset kullanılır.
- Uzun ülke adı tek satır, kontrollü ellipsis; accessible name tamdır.
- Her hedef en az 44×44 px; focus-visible, Tab ve ok tuşu davranışı vardır.
- 320 px ve kısa telefonda tek satır kalır; önce animasyon boşluğu küçülür.

Semantik `radiogroup` ve radio/segmented option davranışıdır. Screen reader seçili durum ve 1/2 konumunu duyurur. Switching `aria-busy`/polite status ile söylenir; segmentler çift submit'i engeller.

### 11.3 Preferred/effective görünümü

- Search yokken seçili görünüm preferred state'tir.
- Active search'te effective scope ana gerçektir.
- Kullanıcı diğer segmente basınca hedef preference intent olarak görünür fakat success glow/arama metni yeni queued gelmeden değişmez.
- Switching sırasında sayaç durur; “Arama kapsamı değiştiriliyor...” gösterilir.
- Başarıda yeni effective scope ve timer sıfırdan kurulur.
- Hata authoritative snapshot'a rollback/reconcile olur; keyfi local scope bırakılmaz.

### 11.4 Country unavailable/stale

- Segment disabled veya açıklamalı unavailable state olur.
- Non-technical metin: “Bu hesap için ülke eşleşmesi henüz kullanılamıyor.”
- Keyfi country code gönderilmez.
- Global açık alternatif olarak görünür; otomatik başlatılmaz.
- Retry yalnız Wave 06 country refresh policy izin veriyorsa sunulur; client geo/IP tahmini yapmaz.

### 11.5 QA-014 korunması

- Scope control ambient parçacıkların üstündedir; animasyonun odağını çalmaz.
- Search phase/timer server otoritesi aynı kalır.
- Mood/prompt scope change sırasında korunur.
- Country/Global metinleri phase+tier tablosuyla compose edilir; mixed state stringleri dağınık if bloklarında kurulmaz.
- Fallback inline alan prompt/stop aksiyonunu ekran dışına itmez.
- Reduced motion yalnız animasyonu etkiler, scope anlamını değiştirmez.

## 12. Home paketi — A-HOME-001

Wave 08, A-HOME-001'in bütün kabulünü kapatabilmek için yalnız gerekli bounded Home düzenini yapar:

- Anonim eşleşme kartı birincil ürün akışı olmaya devam eder.
- Arkadaşlar/istekler/unread ikincil ama görünür kalır; selector bunları örtmez.
- Scope join öncesi seçilir ve ana CTA'nın hemen üstündedir.
- Selector için ara ekran/modal açılmaz.
- Güvenilir realtime online sayı kaynağı yoksa sayı gösterilmez; Wave'e sahte count eklenmez.
- Loading, capability-off, country-unavailable, offline ve reconnect state'leri layout kırmadan ele alınır.
- Mobil/klavye sırası: açıklama → scope → start CTA → ikincil arkadaş yüzeyi.
- Home genel redesignı, yeni navigasyon veya kart ailesi bu stable ID'yi kapatma bahanesiyle yapılmaz.

## 13. QA-003 regresyon koruması

Gerçek offer geldiğinde:

- Offer current searchId/effective scope ve COUNTRY ise canonical code ile bütünlük kontrolünden geçer.
- Scope selector interaktif teklif kontrolü olmaz.
- QA-003 kartına bayrak, Country badge, yeni CTA veya ayrı açıklama eklenmez.
- Kimlik, countdown/progress, `Sohbete Başla`, `Geç` ve `Eşleşmeyi iptal et` hiyerarşisi aynen kalır.
- Mood/prompt devri sürer; scope bunların önüne geçmez.
- `Geç` yalnız peer'i reddeder; scope korunur.
- Tüm aramayı iptal et active queue'yu kapatır; sonraki başlangıç tercihi policy'ye göre saklanabilir.
- Scope bütünlük alanı eventte bulunabilir fakat peer konumu olarak kullanıcıya açılmaz.

## 14. Analytics ve Jarvis özeti — C-ANL-002

### 14.1 Event sözleşmesi

- `match_scope_selector_seen`
- `match_scope_selected`
- `match_search_started` — requested scope
- `match_queue_confirmed` — effective scope
- `match_scope_change_started`
- `match_scope_change_result`
- `match_country_fallback_shown`
- `match_country_fallback_action`
- `match_offer_received` — effective scope
- `match_search_cancelled` — effective scope ve elapsed bucket
- Accept/reject/chat start mevcut eventlerinin search journey/scope bağı

Ortak alanlar eventVersion, occurredAt, searchId veya privacy-safe journeyId, requested/effective scope, ISO country yalnız izinli kendi-user boyutunda, queueAttempt, result/reason code, app/platform version ve server policy version olur.

Yasak alanlar: tam IP, GPS, şehir/adres, peer country, serbest country adı, prompt metni ve raw socket payload.

### 14.2 Metric birimleri ve denominatorlar

| Metric | Birim | Denominator / not |
|---|---|---|
| Selector seen | Unique eligible screen impression | Capability açık ve kontrol gerçekten görünür |
| Scope selected | Explicit selection action | Programmatic default selection sayılmaz |
| Queue confirmed | Search attempt | Server effective ack |
| Wait median/P95 | Confirmed queue attempt | queuedAt → current offer/cancel; sonuç türü ayrılır |
| Offer rate | Search attempt | Fair, aynı pencere ve eligibility |
| Accept/reject/cancel | Offer veya search, metric'e göre | Birim kartta açık yazılır |
| Fallback shown | Eligible country search | Kartı görmeyen decline değildir |
| Fallback accepted/continued | Shown fallback | Kapatma/continue ayrı reason |
| Chat start | Confirmed search journey | Scope-change child searchleri journey bağıyla dedupe edilebilir |

Global ve Country kıyaslaması aynı release/cohort/time window ve eligibility kuralında yapılır. Scope change yeni search'tir fakat güvenli pseudonymous journey bağı korunur. Az örnekten ürün sonucu çıkarılmaz.

### 14.3 Cohort ve privacy

- Minimum cohort eşiği deterministic config ve version taşır.
- Alt eşikte country breakdown gizlenir veya `other/suppressed` bucket'a alınır; exact count/user drill-down yoktur.
- Admin kullanıcı listesine gizli country tracking kolonu eklenmez.
- Country code yalnız ürünün kendi canonical kullanıcı verisi ve policy izin verdiği aggregation katmanında işlenir.
- Retention/erasure C-COMP/B-DATA policy registry'sine bağlanır.
- Event payload allowlist ve redaction testleri release kapısıdır.

### 14.4 Jarvis kartı

Özet varsayılanında:

1. Durum: Global/Country median bekleme ve fallback kabul özeti
2. Etki: uygun search/cohort ve dönem
3. Aksiyon: örnek yeterliyse config/product review; değilse “veri yetersiz”
4. Kanıt: source event version, time window, generatedAt, freshness ve metric definition

Kart ülke ülke ham kullanıcı tablosu değildir. Örnek metin yalnız gerçek veriden üretilir; veri yoksa rakam uydurulmaz. Stale/partial/ingestion-error ayrı durumdur.

## 15. Dosya ve servis etki haritası

Uygulama başında gerçek repo keşfiyle daraltılacak beklenen yüzey:

- `chatapp-backend/index.js` veya Wave 07 matchmaking lifecycle modülü
- Wave 06 canonical country repository/service'i
- Queue partition, scope serializer/validator, fallback policy ve recovery snapshot
- Backend contract/state/fault-injection testleri
- `chatapp-frontend/src/App.jsx` veya Wave 05/07 domain reducer/store
- `chatapp-frontend/src/screens/HomeScreen.jsx`
- `chatapp-frontend/src/screens/MatchScreen.jsx`
- Ortak `MatchScopeControl` ve küçük fallback componenti
- `chatapp-frontend/src/i18n.jsx` veya locale katalogları
- C-ANL-002 bounded admin analytics endpoint/query/card ve testleri
- Web/Android E2E, screenshots ve QA kanıt dosyası

Wave 06 canonical country migrationı zaten kapanmış olmalıdır; Wave 08 aynı migrationı yeniden yazmaz. Yeni dependency, shared queue teknolojisi veya production config ancak gerçek deployment ihtiyacı ve ayrıca onayla seçilir.

## 16. Uygulama sırası

1. Wave 07 kapanışını, Wave 06 country contractını, üç repo snapshot'ını ve deployment instance topolojisini doğrula.
2. Master QA-017'nin 25 kabul maddesini kanıt/test ID'lerine bağla.
3. Capability, scope enum, event schema, queue key ve atomic transition contractını kilitle.
4. Tek-active-search invariantını partitionlar ve instance sınırında test-first kur.
5. Join, pairing, cancel, requeue, reconnect ve pending offer yollarını effective scope-aware yap.
6. Server-time fallback eligibility ve exactly-once search state'ini ekle.
7. Ortak preferred/effective scope reducer'ı ve account-scoped preference hydration'ı kur.
8. Ortak segmented controlü Home CTA üstü ve QA-014 ambient üstünde entegre et.
9. Country unavailable, switching, failure reconciliation ve inline fallback UX'i tamamla.
10. QA-014 mood/prompt/phase ve QA-003 offer regresyonlarını çalıştır.
11. Privacy-safe event/aggregation/C-ANL-002 Jarvis kartını source/time/cohort ile bağla.
12. Web/Android/a11y/i18n/fault-injection kanıtını tamamla.
13. Stable ID ve Master checkbox'larını yalnız kullanıcı QA onayıyla kapat; Wave 09'u başlatmadan dur.

## 17. Otomatik test planı

### 17.1 Backend ve queue

- GLOBAL/GLOBAL eşleşir; GLOBAL/COUNTRY eşleşmez.
- Aynı ISO COUNTRY eşleşir; farklı ISO COUNTRY eşleşmez.
- Client sahte countryCode gönderir; server canonical değeri kullanır/reddeder.
- Unavailable/stale country COUNTRY queue açmaz ve Global otomatik başlamaz.
- Bütün partitionlarda tek-user tek-active-search.
- Scope change atomik başarı; eski entry yok, yeni tek entry var.
- Scope change hata/timeout; sıfır veya iki entry yok, authoritative snapshot var.
- Rapid change/double command idempotent.
- Old queued/fallback/offer stale olur.
- Pairing search/scope/country bütünlüğünü iki participant için taşır.
- Block/ban/shadow/cooldown/fairness partition içinde korunur.
- Requeue effective scope/country'yi korur.
- Preserved reconnect scope/timer/fallback state'i korur.
- Reset/restart sessiz Global üretmez.
- Multi-device conflict ve multi-instance atomicity/deployment guard.
- Capability-off ve legacy Global client.

### 17.2 Client/component

- İlk kullanım Global; account-scoped preference hydration.
- İki selector aynı store/state'i tüketir.
- Search öncesi preferred ve active effective görünüm ayrılır.
- Country gerçek localized name; unavailable/stale güvenli state.
- Switching double submit'i kapatır; timer yeni queued öncesi başlamaz.
- Failure authoritative state'e reconcile olur.
- Fallback eşikten önce yok, sonra bir kez; search sürer.
- Go Global yeni search/timer; continue/close aynı country search.
- Reconnect duplicate fallback göstermez.
- Mood/prompt scope değişiminde korunur.
- Offer selector/fallback'i kapatır; QA-003 UI değişmez.
- 44 px, radiogroup, focus, arrows, screen reader ve aria-busy.
- 320 px, uzun ülke, büyük font, safe-area, kısa ekran, reduced-motion.

### 17.3 Analytics/admin

- Event allowlist ve yasak geo/raw payload scan'i.
- Shown/selected/default ve accepted/continued ayrımı.
- Search vs journey dedupe.
- Median/P95 fixture doğruluğu ve aynı pencere kıyası.
- Minimum cohort altı suppression.
- Empty/stale/partial/error Jarvis durumları.
- Source/time window/generatedAt/freshness ve denominator görünürlüğü.
- Kullanıcı listesinde country tracking drill-down bulunmaması.

## 18. Manuel QA havuzu — Checkpoint B / Wave 19 (commit kapısı değil)

| Grup | Senaryo | Beklenen |
|---|---|---|
| Varsayılan | Yeni kullanıcı | Global seçili, otomatik search yok |
| Tercih | Dönen Global/COUNTRY | Son geçerli hesap tercihi, başka hesaba sızma yok |
| Country | TR/TR | Aynı COUNTRY partitionda offer |
| İzolasyon | TR/DE ve GLOBAL/COUNTRY | Eşleşme yok |
| Veri | null/free-text/invalid/stale | COUNTRY join yok, açıklamalı alternatif |
| Saldırı | Sahte client country | Başka ülke queue'suna giriş yok |
| Scope | Global→Country / Country→Global | Atomik yeni search, yeni timer |
| Yarış | Hızlı tıklama/old queued/old offer | Tek entry, stale UI yok |
| Recovery | Refresh/background/reconnect | Server effective state kazanır |
| Requeue | reject/timeout/error | Aynı effective scope |
| Fallback | eşik öncesi/sonrası | Önce yok; sonra bir kez ve search sürer |
| Fallback | Global'e geç/continue/close | Yalnız açık accept scope değiştirir |
| Offer | Fallback ile aynı an | Current offer kazanır, QA-003 temiz |
| UI | Home ve Match | Aynı kontrol/state, tema bozulmaz |
| Mobil | 320 px/kısa/uzun ülke/büyük font | Tek satır, eylemler görünür |
| A11y | Klavye/SR/focus/44 px | Seçim ve durum anlaşılır |
| Platform | Web + Android WebView/back/background | Davranış eşliği |
| Analytics | low cohort/stale/partial | Maskeli veya veri yetersiz; raw kullanıcı yok |

## 19. Canonical kabul eşlemesi

### 19.1 B-MM-002 — 9 kriter

- [ ] Master QA-017 backend/data kriterleri tamam.
- [ ] Farklı country partitionları eşleşmiyor.
- [ ] GLOBAL ve COUNTRY karışmıyor.
- [ ] Sahte client country code etkisiz/reddedilmiş.
- [ ] Tek active search instance sınırında korunuyor.
- [ ] Scope race ve stale offer testli.
- [ ] Requeue aynı effective scope'u koruyor.
- [ ] Capability eski client'ı bozmuyor.
- [ ] Çoklu instance için shared/atomic otorite veya açık tek-instance guard kanıtlı.

### 19.2 A-MATCH-003 — 9 kriter

- [ ] Master QA-017 client kriterleri tamam.
- [ ] İki selector aynı state'i tüketiyor.
- [ ] User seçimi server onayı gelmeden effective görünmüyor.
- [ ] Country unavailable iken keyfi kod gönderilmiyor.
- [ ] Scope değişiminde timer yeni queued ile sıfırlanıyor.
- [ ] Fallback search'i durdurmuyor ve otomatik Global yapmıyor.
- [ ] Bayrak/renk tek anlam kaynağı değil.
- [ ] 44 px, radiogroup ve screen-reader tamam.
- [ ] Capability yoksa selector gizli ve Global akış sağlam.

### 19.3 C-ANL-002 — 6 kriter

- [ ] Master QA-017 analytics/privacy kriterleri tamam.
- [ ] Metric birimleri tanımlı.
- [ ] Source/time window/tazelik görünür.
- [ ] Minimum cohort eşiği deterministik.
- [ ] Global ve Country bekleme adil pencereyle kıyaslanıyor.
- [ ] Kullanıcı listesine gizli country tracking key açılmıyor.

### 19.4 A-HOME-001 — 5 kriter

- [ ] Anonim eşleşme birincil ürün akışı olarak belirgin.
- [ ] Arkadaşlar ikincil fakat görünür.
- [ ] Scope join öncesinde seçilebiliyor.
- [ ] Selector ayrı ara ekran/modal oluşturmuyor.
- [ ] Güvenilir olmayan online sayı gösterilmiyor.

### 19.5 Master QA-017 — 25 kriter

| # | Canonical kabul | Zorunlu kanıt |
|---:|---|---|
| 1 | Global ilk kullanım ve ana kapsam | New-user preference/store testi |
| 2 | Scope arama öncesi, modal olmadan seçilir | Home interaction ve ekran kanıtı |
| 3 | Home ve Match aynı control/state'i kullanır | Component/store integration testi |
| 4 | Gerçek yerelleştirilmiş ülke adı | ISO/locale fixture ve uzun-ad QA |
| 5 | Unavailable/stale COUNTRY queue açmaz | Backend negatif test + client alternatif |
| 6 | Tema, contrast, focus, 44 px ve screen reader | A11y otomasyonu + manuel QA |
| 7 | Scope ve searchPhase bağımsız eksenlerdir | Reducer transition matrix |
| 8 | Timer yalnız yeni queued ack ile başlar | Delayed-ack/clock testi |
| 9 | Scope change atomik ve idempotenttir | Race/fault-injection testi |
| 10 | Stale search eventi yeni scope/offer'ı bozamaz | Old-event injection |
| 11 | COUNTRY yalnız aynı canonical ISO ile eşleşir | İki-client positive/negative matrix |
| 12 | GLOBAL ve COUNTRY sessizce karışmaz | Cross-partition negatif test |
| 13 | Global yalnız açık fallback aksiyonudur | UI + server mutation testi |
| 14 | Fallback merkezi server time ve tek gösterimdir | Threshold/reconnect/dedupe testi |
| 15 | Reject/timeout/requeue effective scope'u korur | Offer/requeue integration |
| 16 | QA-003 hiyerarşisi/countdown değişmez | Visual + behavior regression |
| 17 | QA-014 mood/prompt/particle korunur | Search UI regression |
| 18 | Legal acceptance country queue key değildir | Data-flow/static contract kanıtı |
| 19 | Canonical ISO/source/status/time modeli kullanılır | Wave 06 contract integration |
| 20 | Client sahte country ile yönlendiremez | Forged payload security testi |
| 21 | Queue/telemetry hassas geo veya peer country taşımaz | Schema/payload privacy scan |
| 22 | Capability eski frontend/backend'i bozmaz | Compatibility matrix |
| 23 | Scope funnel tanımlı eventlerle ölçülür | Event/metric fixture |
| 24 | TR/EN, uzun ad, 320 px, WebView ve a11y geçer | Platform manuel/otomatik QA |
| 25 | Scope izolasyonu iki-client ve Web/Android ile kanıtlanır | E2E + kullanıcı QA onayı |

Hiçbir kriter yalnız ekran görüntüsü, yalnız backend testi veya yalnız analytics sorgusuyla kapanmaz.

## 20. Kapsam dışı ve successor guard

- Manuel başka ülke veya birden fazla ülke
- Dil, yaş, cinsiyet, ilgi veya saat dilimi filtresi
- Canlı/estimated pool veya online count
- Sessiz COUNTRY→GLOBAL genişletmesi
- GPS/hassas konum toplama
- Country'yi ücretli sıra/öncelik sinyali yapma
- QA-003 kartına scope kontrolü, flag, badge, CTA veya yeni bilgi bloğu
- Wave 09 pending-offer protokolünü uygulama
- Wave 14 genel analytics dashboard'u
- Yeni genel Home/Match redesignı

## 21. Risk ve rollback

| Risk | Koruma | Rollback/durma |
|---|---|---|
| Havuzlar karışır | Queue-key invariant + iki-client negatif test | Scope capability kapat |
| Sahte country kabul edilir | Server canonical lookup | COUNTRY join reddet |
| Scope change iki entry bırakır | User lock + atomik transition | Fail-closed snapshot |
| Old offer açılır | searchId/scope/revision guard | Offer no-op/close |
| Requeue Global'e düşer | Explicit effective scope parametresi | Requeue durdur |
| Fallback sessiz geçiş yapar | Yalnız explicit action | COUNTRY devam/terminal |
| Reconnect kartı çoğaltır | Search-level shown state | Duplicate ignore |
| Country stale iken seçilir | Wave 06 eligibility | Segment unavailable |
| İkinci cihaz partition deler | User-level uniqueness | Conflict/snapshot |
| Multi-instance process queue ayrışır | Shared atomic backend veya deployment guard | Rollout bloke |
| Düşük cohort kullanıcı açar | Deterministic suppression | Breakdown gizle |
| Metric yanlış kıyaslanır | Birim/window/eligibility | Özet “veri yetersiz” |
| Selector temayı boğar | Ortak kompakt control | Capability ile gizle |
| Uzun ülke taşar | Ellipsis + full accessible name | Text-only compact |
| QA-003 değişir | Snapshot/visual regression | Scope UI farkını geri al |
| Dirty repo işi örter | Üç Git snapshot'ı | Yalnız Wave 08 farkı geri al |

Rollback aktif COUNTRY kullanıcılarını sessizce Global'e taşımaz. Capability kapatıldığında server kontrollü terminal/reset sonucu veya açık Global önerisi verir.

## 22. Rollout ve canlı sınır

1. Wave 06/07 contract ve QA kapanışları doğrulanır.
2. Server capability-off iken partition/contract testleri tamamlanır.
3. Staging synthetic countries ve iki-client matrix çalışır.
4. Internal cohort'ta selector + COUNTRY açılır; isolation/stale/cancel/reconnect metricleri izlenir.
5. Fallback ayrı flag/config ile açılır; exactly-once ve explicit accept doğrulanır.
6. C-ANL-002 summary minimum cohort üstü sentetik/staging veriyle kanıtlanır.
7. Web ardından Android ve accessibility QA tamamlanır.
8. Rollback provası active COUNTRY davranışıyla yapılır.
9. Canonical checkbox/durum yalnız kullanıcı QA onayıyla kapatılır.

Production DB/geo/IP/analytics sorgusu, migration, shared queue servisi, feature flag, config, deploy/restart veya gerçek kullanıcı state değişikliği ayrıca exact target/impact onayı ister.

## 23. Başlangıç kapısı

- [ ] Wave 01–07 QA kapanışları ve kullanıcı onayı doğrulandı.
- [ ] Kullanıcı açıkça “Wave 08'i başlat” dedi.
- [ ] Root/backend/frontend Git snapshot'ı alındı.
- [ ] Wave 06 canonical country schema/service/policy/retention gerçek kodda doğrulandı.
- [ ] Wave 07 lifecycle/searchId/timer/idempotency/recovery gerçek kodda doğrulandı.
- [ ] Backend instance topolojisi ve queue otoritesi kanıtlandı.
- [ ] Legacy client/capability/rollback kararı kilitlendi.
- [ ] Scope state, event şeması, queue key ve atomic transition invariantları onaylandı.
- [ ] Fallback threshold/config owner'ı ve kullanıcı metni onaylandı.
- [ ] Analytics unit/denominator/cohort/retention kararları kilitlendi.
- [ ] Sentetik country ve iki-client test fixture'ları hazırlandı.
- [ ] Web/Android/TR-EN/a11y cihaz matrisi hazırlandı.
- [ ] Wave 09 QA-003 kapsamına taşma olmadığı doğrulandı.

## 24. Sonuç alanı

Wave yürütülürse kapanış kaydı en az şunları içerir:

- Başlangıç/bitiş, stable refs ve gerçek değişen dosyalar
- Üç Git bağlamının önce/sonra farkı
- Final capability/event/state/queue-key sözleşmesi
- Canonical country eligibility ve forged-country kanıtı
- Partition isolation, fairness, block/cooldown ve single-search kanıtı
- Scope-change atomiklik/idempotency/stale-offer sonuçları
- Reconnect/requeue/multi-device/instance sonuçları
- Fallback threshold/exactly-once/accept/continue sonuçları
- Ortak selector Home/Match, responsive/a11y/i18n kanıtı
- QA-014 mood/prompt/phase ve QA-003 görsel/işlev regresyonu
- Analytics payload/privacy/cohort/metric/Jarvis kanıtı
- Syntax/lint/build/encoding/focused/full test exit code'ları
- Checkpoint B / Wave 19'a aktarılmış manuel QA kaydı
- Wave 09'un başlatılmadığı açık durma kaydı

## 25. Durma kuralı

Wave 07 QA kapanışı ve kullanıcının açık Wave 08 başlatma talimatı birlikte gelene kadar:

- Wave 08 için kod, test, dependency, migration, config, geo/data sorgusu, feature flag veya deploy değişikliği yapılmaz.
- Wave 08 `Aktif` işaretlenmez; belge yalnız `Hazır — aktif değil` kalır.
- Canonical `[ ]` maddeler kanıtsız kapatılmaz.
- Wave 09 uygulanmaz; hazırlanmış plan aktif edilmez.
