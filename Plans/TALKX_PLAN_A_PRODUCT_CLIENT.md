# TalkX Plan A — Product & Client Experience

> TalkX kullanıcı ürününün, Web frontend'in ve Android WebView deneyiminin canonical uygulama planı.
> Kaynak envanter: `docs/TALKX_MASTER_BACKLOG.md`.
> Bu plan hazırdır; hiçbir uygulama wave'i başlamamıştır.

## 1. Belge rolü ve otorite

Bu belge kullanıcının gördüğü, okuduğu ve etkileşim kurduğu TalkX deneyiminin uygulama otoritesidir. Master backlog ham bulgu, kilitli ürün kararı ve QA kanıtını korur; bu plan o kaynağı stable uygulama maddelerine dönüştürür.

Bir wave bu plandaki ayrıntıyı yeniden anlatmaz. Yalnız ilgili ID'lere, alt başlıklara ve kabul kriterlerine yönlendirir.

Otorite sırası:

1. `TALKX_MASTER_BACKLOG.md` içindeki kilitli ürün kararları ve QA kanıtları
2. Bu belgedeki Plan A ürün/client sözleşmeleri
3. `TALKX_WAVE_MAP.md` sırası
4. `TALKX_WAVE_MAP.md` ve hazırlanmış `waves/TALKX_WAVE_NN.md` dosyaları; plan dosyasının varlığı aktivasyon değildir
5. Kod ve test kanıtı

Çelişki varsa wave yeni karar üretmez; önce canonical plan düzeltilir.

## 2. Plan durumu ve sınırı

- **Plan durumu:** Hazır
- **Uygulama durumu:** Başlamadı
- **Wave Map durumu:** Hazır
- **Hazırlanmış Wave Planları:** Wave 01 — `waves/TALKX_WAVE_01.md`; Wave 02 — `waves/TALKX_WAVE_02.md`; Wave 03 — `waves/TALKX_WAVE_03.md`; Wave 04 — `waves/TALKX_WAVE_04.md`; Wave 05 — `waves/TALKX_WAVE_05.md`; Wave 06 — `waves/TALKX_WAVE_06.md`; Wave 07 — `waves/TALKX_WAVE_07.md`; Wave 08 — `waves/TALKX_WAVE_08.md`; Wave 09 — `waves/TALKX_WAVE_09.md`; Wave 10 — `waves/TALKX_WAVE_10.md`; Wave 11 — `waves/TALKX_WAVE_11.md`; Wave 12 — `waves/TALKX_WAVE_12.md`; Wave 13 — `waves/TALKX_WAVE_13.md`; Wave 14 — `waves/TALKX_WAVE_14.md`; Wave 15 — `waves/TALKX_WAVE_15.md`; Wave 16 — `waves/TALKX_WAVE_16.md`; Wave 17 — `waves/TALKX_WAVE_17.md`; Wave 18 — `waves/TALKX_WAVE_18.md`; Wave 19 — `waves/TALKX_WAVE_19.md` — on dokuz plan da hazır, aktif değil
- **Uygulama wave'i:** Başlamadı
- **Birincil alan:** Product / UI-UX / Web frontend / Android WebView kullanıcı akışları
- **Ana repo alanı:** `chatapp-frontend/`
- **Bağlı planlar:** Plan B — Platform, Realtime & Data; Plan C — Admin, Trust & Release

Bu plan:

- Kullanıcıya görünen bilgi hiyerarşisini,
- Client state ve ekran davranışını,
- UI bileşenleri ve içerik sözleşmesini,
- Responsive/accessibility/i18n kurallarını,
- Frontend test ve manuel QA kapılarını

tanımlar.

Bu plan backend eventinin iç uygulamasını, DB migration'ını, admin ekranını, release pipeline'ını veya mağaza politikasını sahiplenmez. Bunlara stable Plan B/C ID'leri üzerinden bağlanır.

## 3. Bağlayıcı ürün ilkeleri

- TalkX global bir anonim sohbet ürünüdür.
- Rastgele birebir anonim eşleşme çekirdek deneyimdir.
- Global anonim eşleşme ilk kullanım varsayılanıdır.
- Kendi ülkem seçimi kesin filtredir; kullanıcı onayı olmadan Global'e genişletilmez.
- Kullanıcıya teknik socket/queue dili değil gerçek durum, sonuç ve sonraki aksiyon gösterilir.
- Anonim eşleşme, arkadaşlığa geçiş ve kalıcı arkadaş sohbeti aynı ürün hikâyesinin parçalarıdır.
- Kullanıcılar arası anonimlik ile servis düzeyindeki veri sahipliği birbirine karıştırılmaz.
- E-posta toplamama ve hesap kurtarma sunmama kararı değişmedikçe client bunu dürüstçe açıklar.
- İlk sürüm filtre çöplüğüne dönüşmez; manuel ülke, dil, yaş, cinsiyet ve ilgi filtresi Plan A kapsamında değildir.
- TalkX tema dili koyu zemin, kontrollü cyan/mor-pembe neon, glass yüzey ve sakin bilgi hiyerarşisidir.
- Jarvis ilkesi: durum/özet → etki/bağlam → aksiyon → isteğe bağlı kanıt.
- Renk, ikon, bayrak veya animasyon tek başına anlam taşımaz.
- 320 px mobil, kısa ekran, safe-area, büyük yazı, klavye ve ekran okuyucu sonradan eklenen QA değil tasarım girdisidir.
- Web ve Android kullanıcı davranışı gereksiz yere ayrışmaz.
- Ayrı talimat olmadan bu planın sonraki maddesine veya gelecekteki wave'e geçilmez.

## 4. Stable ID ve wave referans kuralı

Plan A kimlik alanları:

- `A-PRD-*`: ürün tanımı ve kullanıcı vaadi
- `A-FND-*`: frontend mimarisi ve görsel temel
- `A-AUTH-*`: auth, session ve legal client
- `A-HOME-*`: Home, navigasyon ve destek
- `A-MATCH-*`: anonim eşleşme
- `A-FRIEND-*`: arkadaşlık ve kalıcı sohbet
- `A-SYS-*`: TalkX Sistem kullanıcı deneyimi
- `A-I18N-*`: içerik ve yerelleştirme
- `A-A11Y-*`: accessibility/responsive
- `A-MOB-*`: Android WebView client davranışı
- `A-QA-*`: client kalite kapıları

Bir wave referansı örneği:

    Plan refs:
    - A-MATCH-003 / Kabul kriterleri 1–12
    - B-MM-002 / Event ve queue sözleşmesi
    - C-ANL-002 / Scope telemetry özeti

Plan haritasındaki `Birincil bağımlılık` sütunu yalnız wave sıralamasında önce kapanması gereken ID'leri gösterir. `Çapraz plan sözleşmeleri` tablosundaki sağlayıcı/tüketici ilişkileri bağımlılık değildir; bağlı ID'ler aynı wave'de veya ardışık wave'lerde birlikte doğrulanabilir.

## 5. Plan haritası

| ID | Sonuç | Master/QA kaynağı | Birincil bağımlılık | Durum |
|---|---|---|---|---|
| A-PRD-001 | Tek ürün vaadi ve anonimlik dili | Master §3, §5 | — | [ ] |
| A-PRD-002 | Anonimden arkadaşlığa tutarlı ürün hikâyesi | Master §3, §5 | A-FRIEND-001 | [ ] |
| A-FND-001 | Test altında ayrıştırılmış frontend kabuğu | Master §7 | B-API-001 | [ ] |
| A-FND-002 | Ortak tasarım tokenı ve ekran state standardı | Master §7 | A-FND-001 | [ ] |
| A-AUTH-001 | Dürüst auth ve hesap-kurtarma açıklaması | Master §1, §13 | B-AUTH-001 | [ ] |
| A-AUTH-002 | Legal reaccept ve session recovery client akışı | Master §7, §13 | B-AUTH-002, C-LEGAL-001 | [ ] |
| A-HOME-001 | Home bilgi hiyerarşisi ve mod seçimi | Master §13 | A-MATCH-003 | [ ] |
| A-HOME-002 | Ayarlar, destek ve hesap silme kullanıcı akışı | Master §13 | B-DATA-003, C-TRUST-002 | [ ] |
| A-MATCH-001 | QA-014 canlı ve dürüst arama yüzeyi | QA-014 | B-MM-001 | [ ] |
| A-MATCH-002 | QA-003 eşleşme teklif/kabul yüzeyi | QA-003 | B-MM-003 | [ ] |
| A-MATCH-003 | QA-017 Global/kendi ülkem selector ve fallback UI | QA-017 | B-MM-002, B-DATA-002 | [ ] |
| A-MATCH-004 | Search/offer/chat client state izolasyonu | Master §7, QA-003/014/017 | B-WS-002 | [ ] |
| A-FRIEND-001 | QA-001 gerçek presence ve son görülme | QA-001 | B-PRES-001 | [ ] |
| A-FRIEND-002 | QA-002 anlaşılır sohbet header aksiyonları | QA-002 | C-TRUST-001 | [ ] |
| A-FRIEND-003 | Kalıcı mesaj, outbox ve medya kullanıcı deneyimi | Master §7, §13 | B-MSG-001/002 | [ ] |
| A-SYS-001 | QA-015 doğrulanmış TalkX Sistem sohbeti | QA-015 | B-SYS-001, C-SYS-001 | [ ] |
| A-I18N-001 | TR/EN ve güvenli fallback içerik modeli | Master §7, QA-010/014/015/017 | B-I18N-001 | [ ] |
| A-A11Y-001 | Ortak accessibility ve responsive sözleşmesi | Master §7, §11, §13 | A-FND-002 | [ ] |
| A-MOB-001 | Web/Android WebView davranış eşliği | Master §13, §15 | C-MOB-001 | [ ] |
| A-QA-001 | Frontend component/E2E ve manuel client kapıları | Master §11, §13, §15 | A-FND-001, A-FND-002 | [ ] |

## 6. A-PRD-001 — Tek ürün vaadi ve anonimlik dili

**Amaç:** Web, Android ve kullanıcı metinlerinde TalkX'in ne olduğu tek cümleyle anlaşılır olsun.

**Kaynak:** Master §3, §5; kilitli ürün kararları.

**Kapsam:**

- Global anonim birebir sohbet
- Hesap sahibi fakat karşı tarafa anonim kullanıcı modeli
- Sohbet sonrası arkadaşlığa ve kalıcı mesaja geçiş
- Kullanıcılar arası anonimlik ile servis veri işlemesinin ayrılması
- Anonim ve arkadaş modlarındaki saklama farkının açık anlatımı
- Web, Android ve mağaza açıklamalarında aynı çekirdek anlam

**Kapsam dışı:**

- 18+ yeniden konumlandırma
- E-posta ile hesap kurtarma
- Yeni sosyal ağ veya içerik üretim özelliği
- Pazarlama sloganı testleri

**Bağımlılıklar:**

- C-COMP-001 mağaza/yaş/uyum kararı
- B-DATA-003 veri yaşam döngüsü
- A-PRD-002 arkadaşlığa geçiş

**Kabul kriterleri:**

- [x] Beş saniyede ürünün anonim birebir eşleşme olduğu anlaşılıyor.
- [x] Hesap bulunması anonimlik iddiasıyla çelişkili anlatılmıyor.
- [x] Kullanıcılar arası görünmezlik ve servis veri sahipliği açık ayrılıyor.
- [x] Anonim ve arkadaş sohbeti saklama farkı doğru kaynağa dayanıyor.
- [x] Web/Android ana metinleri aynı anlamı taşıyor.
- [x] C-COMP-001 sonuçları ürünü sessizce 18+ veya bölgesel başka kimliğe dönüştürmüyor.

**Kanıt:** TR/EN metin karşılaştırması, privacy/data-flow incelemesi, Web/Android ekran görüntüsü.

## 7. A-PRD-002 — Anonimden arkadaşlığa ürün hikâyesi

**Amaç:** `eşleş → konuş → arkadaşlığa taşı` çekirdek döngüsünü kopuk ekranlar yerine tek ürün yolculuğu hâline getirmek.

**Kapsam:**

- Anonim eşleşmeden sohbet başlangıcına kesintisiz geçiş
- Rapor/engel/ayrılma aksiyonlarının doğru aşamada bulunması
- Arkadaş isteği ve kalıcı sohbet farkının anlaşılması
- Anonim sohbet bitince veri ve ilişki durumunun dürüst açıklanması
- Aynı peer ile istemsiz hızlı yeniden eşleşmenin kullanıcıya yansımaması

**Kabul kriterleri:**

- [ ] Her aşamada kullanıcı hangi modda olduğunu anlıyor.
- [ ] Arkadaş eklemek anonim sohbeti geriye dönük kalıcı mesaj geçmişine dönüştürmüyor.
- [ ] Ayrılma, yeni eşleşme ve arkadaşlığa geçiş aynı aksiyon gibi görünmüyor.
- [ ] Rapor ve engel akışı sohbet durumunu güvenli kapatıyor.
- [ ] Plan B state sözleşmesi client tarafından tahmin edilmiyor.

## 8. A-FND-001 — Frontend kabuğunu test altında ayrıştırma

**Amaç:** `App.jsx` içindeki auth, WebSocket, push, outbox, legal ve navigasyon sorumluluklarını davranış değişmeden kademeli ayırmak.

**Kapsam:**

- Önce mevcut state/event haritası
- Hook/service/state reducer sınırları
- Screen routing ve deep-link sahipliği
- Authenticated socket lifecycle
- Match, friend chat ve system chat state izolasyonu
- Her extraction öncesi regression testi
- Kullanılmayan state/import ve hook dependency temizliği

**Kapsam dışı:** Tek wave'de büyük yeniden yazım veya framework değişimi.

**Bağımlılıklar:** B-WS-001, B-API-001, A-QA-001.

**Kabul kriterleri:**

- [ ] Her ayrılan modülün tek sorumluluğu ve testi var.
- [ ] Match/friend/system chat state'leri birbirine karışmıyor.
- [ ] Refresh, geri, logout ve deep-link davranışı belgeli.
- [ ] Lint hata ve uyarıları sahiplik bazında kapanıyor.
- [ ] Extraction ürün davranışını izinsiz değiştirmiyor.

## 9. A-FND-002 — Tasarım tokenı ve ortak ekran state standardı

**Amaç:** Yeni QA ekranlarının mevcut TalkX temasını koruyarak tutarlı davranması.

**Kapsam:**

- Renk, surface, border, radius, glow, spacing ve typography tokenları
- Loading, empty, stale, partial error, offline, reconnect ve permission state'leri
- Ana/ikincil/tehlikeli aksiyon hiyerarşisi
- Modal, inline feedback, toast ve recovery kullanım sınırları
- 100dvh, safe-area ve kısa ekran davranışı
- Hafif CSS/SVG animasyon ve reduced motion standardı

**Kabul kriterleri:**

- [ ] QA-003/014/017 aynı görsel ailede.
- [ ] Admin teması buraya kopyalanmıyor; kullanıcı yüzeyi kendi sakin dilini koruyor.
- [ ] Teknik hata kodu ana ekranda gösterilmiyor.
- [ ] Yeni bileşenler kontrolsüz yeni renk/glow/spacing üretmiyor.
- [ ] Düşük güçlü WebView'da ana akış akıcı.

## 10. A-AUTH-001 — Auth ve hesap politikası client sözleşmesi

**Amaç:** Kayıt, giriş, şifre değiştirme ve hesap kurtarma olmayan modelin kullanıcıya dürüst sunulması.

**Kapsam:**

- Kayıttaki `Önemli Uyarı`
- Kullanıcı adı/şifre kuralları
- E-posta toplanmadığının açıklanması
- Şifre unutulduğunda kurtarma sunulmadığının açık sonucu
- localStorage session token risk kararının Plan B ile uyumu
- Çoklu cihaz/logout davranış metinleri

**Kabul kriterleri:**

- [ ] Olmayan şifre kurtarma seçeneği vaat edilmiyor.
- [ ] Uyarı kritik bilgiyi gizlemiyor fakat kayıt ekranını boğmuyor.
- [ ] Hata mesajları güvenli, yerelleştirilmiş ve eyleme dönük.
- [ ] Session sona ermesi veri kaybı veya hesap silme gibi anlatılmıyor.

## 11. A-AUTH-002 — Legal reaccept ve session recovery

**Amaç:** Legal sürüm değişikliği ile normal auth/reconnect sorununu ayırmak.

**Kapsam:**

- Eski/yeni hesap reaccept
- Kabul öncesi engellenen akış
- TR/EN legal içerik
- Backend required/accepted version state'i
- Offline, timeout ve stale legal config
- Başarılı kabul sonrası güvenli dönüş

**Kabul kriterleri:**

- [ ] Reaccept nedeni ve sonraki adım anlaşılır.
- [ ] Başarısız kabul başarılı görünmüyor.
- [ ] Aynı kabul tekrar tekrar gönderilmiyor.
- [ ] Web/Android aynı legal sürümü gösteriyor.
- [ ] C-LEGAL-001 yayın sözleşmesiyle çelişmiyor.

## 12. A-HOME-001 — Home ve mod seçimi

**Amaç:** Kullanıcının anonim eşleşme ile arkadaş sohbeti arasında ne yapacağını ilk bakışta anlaması.

**Kapsam:**

- Anonim eşleşme ana girişi
- Arkadaşlar/istekler/unread durumu
- Global/Country scope selector'ın arama öncesi yerleşimi
- Online sayının yalnız güvenilir kaynaktan gösterimi
- Loading/offline/reconnect durumları
- Mobil ve klavye akışı

**Kabul kriterleri:**

- [ ] Anonim eşleşme birincil ürün akışı olarak belirgin.
- [ ] Arkadaşlar ikincil fakat görünür.
- [ ] Scope `joinQueue` öncesinde seçilebiliyor.
- [ ] Selector ayrı ara ekran/modal oluşturmuyor.
- [ ] Güvenilir olmayan online sayı gösterilmiyor.

## 13. A-HOME-002 — Ayarlar, destek ve hesap silme

**Amaç:** Hesap ve destek aksiyonlarını güvenli, anlaşılır ve erişilebilir kılmak.

**Kapsam:**

- Profil/görünen isim
- Şifre ve dil
- Push/medya izin onboarding'i
- Destek metni, email alanı, medya ve boyut limitleri
- Hesap silme talebi
- Bekleme, başarı, hata ve tekrar davranışları
- Geri dönüş ve deep-link

**Kabul kriterleri:**

- [ ] Destructive hesap silme normal ayarla aynı ağırlıkta görünmüyor.
- [ ] Gönderim sonucu ve sonraki adım açık.
- [ ] Aynı destek kaydı retry ile duplicate olmuyor.
- [ ] İzin reddi uygulamayı kilitlemiyor.
- [ ] Tamamlanan hesap silme client state'ini temizliyor.

## 14. A-MATCH-001 — QA-014 anonim eşleşme arama yüzeyi

**Amaç:** Aramayı canlı, dürüst ve işlevsel hâle getirmek.

**Canonical kaynak:** Master QA-014. Backend phase otoritesi B-MM-001'dir.

**Kilitli davranışlar:**

- Anahtar/radar yerine iki anonim TalkX parçacığı
- Gerçek offer gelmeden birleşmeyen ambient animasyon
- `preparing / queued / extended / reconnecting / offline / cancelled / offer`
- Sayaç yalnız server `queued` onayıyla
- Sahte yüzde, kalan süre veya sıra yok
- Mood havuzu bölmez
- Prompt kullanıcı aksiyonuyla değişir; otomatik dönmez
- Mood/prompt teklif ve sohbet önerisine taşınır, otomatik gönderilmez
- `Aramayı durdur` ikincil aksiyondur
- QA-003'e gerçek `match_offer` ile kesintisiz geçiş

**Bağımlılıklar:** B-MM-001, B-WS-002, A-MATCH-002/003, A-I18N-001, A-A11Y-001.

**Kabul kriterleri:**

- [ ] Master QA-014 kabul kriterlerinin tamamı korunuyor.
- [ ] Ekran gerçek backend phase'ini tahmin etmiyor.
- [ ] Animasyon offer öncesi sahte başarı anlatmıyor.
- [ ] Kısa telefon ve Android WebView'da 100dvh içine sığıyor.
- [ ] Reconnect ve uzun bekleme farklı anlatılıyor.
- [ ] Eski search eventi yeni aramayı bozamıyor.
- [ ] Mood/prompt scope değişiminde kaybolmuyor.
- [ ] QA-003 countdown süresi geçiş animasyonuyla gecikmiyor.

**Kanıt:** Master QA-014 manuel matrisi, iki istemcili test, Web/Android ekran görüntüsü.

## 15. A-MATCH-002 — QA-003 teklif ve kabul yüzeyi

**Amaç:** Eşleşme bulundu anını güçlü fakat net bir karar ekranına dönüştürmek.

**Canonical kaynak:** Master QA-003. Pending match otoritesi B-MM-003'tür.

**Kapsam:**

- Merkez neon/glass kart
- Tekrarsız kimlik ve açıklama
- `autoAcceptAt` ile senkron progress/saniye
- `Sohbete Başla` ana CTA
- `Geç` ikincil CTA
- `Eşleşmeyi iptal et` üçüncül CTA
- waiting peer, peer accepted, reject, timeout, cancel, disconnect
- QA-014 mood/prompt'un sakin ikincil gösterimi

**QA-017 koruması:**

- Scope selector interaktif kalmaz.
- İlk sürümde country badge/bayrak/yeni CTA eklenmez.
- Teklif aktif `searchId` ve scope doğrulamasından sonra gösterilir.
- Reject/timeout sonrası aynı scope requeue görünümü korunur.

**Kabul kriterleri:**

- [ ] Master QA-003 kabul kriterleri tamam.
- [ ] CTA'lar doğru mevcut davranışlara bağlanıyor.
- [ ] Çift accept/reject gönderimi yok.
- [ ] Stale offer gösterilmiyor.
- [ ] 320 px ve uzun metin/username taşmıyor.
- [ ] Countdown server zamanı ile uyumlu.
- [ ] Gerçek presence yoksa dekoratif online noktası yok.

## 16. A-MATCH-003 — QA-017 Global/kendi ülkem UI

**Amaç:** Global ve kendi ülkem kapsamını TalkX temasını bozmadan mevcut akışa yedirmek.

**Canonical kaynaklar:**

- UI ve ürün ayrıntısı: Master QA-017
- Queue/event/country otoritesi: B-MM-002 ve B-DATA-002
- Analitik özeti: C-ANL-002

**Kapsam:**

- Home anonim eşleşme kartında CTA üstü segmented control
- QA-014 yüzeyinde parçacık animasyonu üstünde aynı kontrol
- İlk kullanım Global
- Gerçek yerelleştirilmiş ülke adı
- Country unavailable/stale client durumu
- Aktif aramada `switching` ve atomik yeniden arama geri bildirimi
- Yaklaşık 30 sn merkezi eşik sonrası kullanıcı onaylı Global önerisi
- `Global'e geç` / `Burada aramaya devam et`
- QA-003'e scope kontrolü taşımama

**Kapsam dışı:** Manuel ülke, dil/yaş/cinsiyet/ilgi filtresi, online count, otomatik fallback.

**State:**

- `preferredMatchScope`
- `effectiveMatchScope`
- `effectiveCountry`
- `scopeChangeStatus`
- `fallbackStatus`
- `searchId`
- QA-014 `searchPhase` ile bağımsız birleşim

**Kabul kriterleri:**

- [ ] Master QA-017 §17 kabul kriterlerinin client maddeleri tamam.
- [ ] İki selector aynı state'i tüketiyor.
- [ ] User seçimi server onayı gelmeden effective görünmüyor.
- [ ] Country unavailable iken keyfi kod gönderilmiyor.
- [ ] Scope değişiminde sayaç yeni `queued` ile sıfırlanıyor.
- [ ] Fallback aramayı durdurmuyor ve otomatik Global yapmıyor.
- [ ] Bayrak/renk tek anlam kaynağı değil.
- [ ] 44 px, radiogroup ve screen-reader davranışı tamam.
- [ ] Feature capability yoksa mevcut Global akış bozulmadan selector gizleniyor.

## 17. A-MATCH-004 — Client state izolasyonu ve recovery

**Amaç:** Search, pending offer, anonymous room, friend room ve system room state'lerinin birbirine karışmasını engellemek.

**Kapsam:**

- Aktif mode/screen/room/search kimlikleri
- Stale WebSocket event filtreleme
- Refresh/background/foreground
- Back/cancel/logout
- Peer reject/leave/timeout
- Offline ve reconnect recovery
- Aynı hesabın ikinci cihaz davranışı
- Image viewer ve geçici medya state temizliği

**Kabul kriterleri:**

- [ ] Eski offer yeni search üzerinde açılmıyor.
- [ ] Friend chat mesajı anon room'a düşmüyor.
- [ ] System chat normal peer gibi cevap alanı açmıyor.
- [ ] Cancel tek leave üretip geçici state'i temizliyor.
- [ ] Belirsiz gönderim sonucu duplicate mesaja yol açmıyor.
- [ ] Recovery backend snapshot'ını otorite kabul ediyor.

## 18. A-FRIEND-001 — QA-001 presence

**Amaç:** Arkadaş sohbeti header'ında sahte `Online` yerine gerçek presence veya son görülme göstermek.

**Kaynak:** Master QA-001. Backend otoritesi B-PRES-001.

**Kapsam:**

- `is_online` ve `last_seen_at`
- Active friend state aktarımı
- Authenticated WebSocket bağlanma/kopma
- Unknown/stale presence
- TR/EN göreli zaman
- Çoklu cihaz

**Kabul kriterleri:**

- [ ] Gerçek offline kullanıcı Online görünmüyor.
- [ ] Unknown durum offline diye uydurulmuyor.
- [ ] Son görülme kaynağı ve zaman formatı tutarlı.
- [ ] Reconnect'te header flicker/sahte online üretmiyor.
- [ ] Renk tek başına presence anlatmıyor.

## 19. A-FRIEND-002 — QA-002 sohbet header aksiyonları

**Amaç:** Rapor ve çıkış aksiyonlarını anlaşılır, dengeli ve güvenli hâle getirmek.

**Kapsam:**

- Gerçek ikon/etiket
- Tooltip ve aria-label
- 44 px dokunma
- Focus/hover/pressed
- Mobil taşma/overflow
- Rapor ile sohbetten çıkışın farklı sonuçları
- Destructive confirmation gerektiği yer

**Kabul kriterleri:**

- [ ] İkonlar noktalama veya belirsiz sembol değil.
- [ ] Rapor ve çıkış aynı eylem gibi görünmüyor.
- [ ] Klavye ve ekran okuyucu çalışıyor.
- [ ] Dar telefonda aksiyonlar taşmıyor.
- [ ] Plan C moderasyon sonucu doğru client feedback'e dönüyor.

## 20. A-FRIEND-003 — Kalıcı mesaj, outbox ve medya UX

**Amaç:** Arkadaş sohbetini reconnect ve medya sınırlarında güvenilir hissettirmek.

**Kapsam:**

- Normal/uzun/hızlı/emoji mesaj
- Optimistic state yalnız server sözleşmesi izin veriyorsa
- Pending/sent/failed/duplicate görünümü
- Outbox retry ve `client_msg_id`
- Typing ve çoklu cihaz
- Tek kullanımlık fotoğraf gönderme/açma/expire
- İzin reddi, boyut, upload/fetch timeout
- Peer silme/engelleme

**Kabul kriterleri:**

- [ ] Belirsiz gönderim durumu dürüst gösteriliyor.
- [ ] Retry duplicate mesaj üretmiyor.
- [ ] Anon ve friend mesaj state'i ayrık.
- [ ] Expired medya tekrar açılabilir görünmüyor.
- [ ] Fotoğraf içeriği telemetry/log'a sızmıyor.
- [ ] Web/Android aynı sonuç semantiğini taşıyor.

## 21. A-SYS-001 — QA-015 TalkX Sistem kullanıcı sohbeti

**Amaç:** Kullanıcıya doğrulanmış TalkX Sistem göndericisinden kalıcı, tek yönlü ve güvenilir mesaj yüzeyi sunmak.

**Canonical kaynak:** Master QA-015. Teslim/inbox B-SYS-001; kampanya/admin C-SYS-001.

**Kapsam:**

- Arkadaşlar ekranında sabit ve doğrulanmış Sistem satırı
- Sahte user/friendship oluşturmama
- Kalıcı geçmiş/pagination
- Unread/read ve çoklu cihaz sync
- Tek yönlü composer davranışı
- Güvenli allowlist CTA
- WebSocket canlı ekleme
- Push'tan doğru Sistem sohbetine yönlenme
- TR/EN/fallback
- Offline açılış

**Kabul kriterleri:**

- [ ] Master QA-015 kullanıcı-client kriterleri tamam.
- [ ] Sistem mesajı normal arkadaş hesabı gibi davranmıyor.
- [ ] Reply alanı yanlış vaat üretmiyor.
- [ ] Push yalnız dikkat katmanı; mesaj inbox'ta kalıcı.
- [ ] CTA dış URL güvenli açılıyor.
- [ ] Duplicate campaign recipient client'ta çift mesaj olmuyor.
- [ ] Read state cihazlar arasında toparlanıyor.

## 22. A-I18N-001 — TR/EN ve güvenli fallback

**Amaç:** Bütün kullanıcı akışlarında locale tutarlılığını korumak.

**Kapsam:**

- Auth, Home, match, offer, chat, system, legal ve recovery
- Stabil message/prompt ID
- Ülke display name kataloğu
- Eksik çeviri kontrolü
- Aynı ekranda karışık dil engeli
- Uzun metin ve çoğul/zaman biçimleri
- Backend error code → güvenli client metni

**Kabul kriterleri:**

- [ ] TR/EN aynı feature sürümünde teslim.
- [ ] Teknik error code son kullanıcıya dökülmüyor.
- [ ] Eksik locale güvenli ve tek dilli fallback kullanıyor.
- [ ] Country code ile display name karıştırılmıyor.
- [ ] Uzun metin responsive düzeni bozmuyor.
- [ ] Prompt ID analitikte tam kullanıcı metni taşımıyor.

## 23. A-A11Y-001 — Accessibility ve responsive

**Amaç:** Accessibility'yi ekran sonu düzeltmesi değil kabul kapısı yapmak.

**Kapsam:**

- Semantic landmark ve heading
- Form label/error ilişkilendirme
- Focus order/focus visible/focus restore
- Screen reader live-region gürültü kontrolü
- 44x44 dokunma
- Contrast ve renk dışı anlam
- Reduced motion
- 320 px, kısa telefon, büyük yazı ve safe-area
- Klavye açıldığında composer/CTA
- Android back davranışı

**Kabul kriterleri:**

- [ ] Accessibility lint ve klavye smoke temiz.
- [ ] Sayaç her saniye ekran okuyucuya okunmuyor.
- [ ] Modal/offer açıldığında focus güvenli taşınıyor.
- [ ] Kapanışta focus anlamlı yere dönüyor.
- [ ] Yatay scroll veya kesilmiş ana CTA yok.
- [ ] Görsel animasyon kapalıyken durum anlaşılır.

## 24. A-MOB-001 — Web/Android WebView eşliği

**Amaç:** Aynı React uygulamasının Web ve Capacitor içinde farklı ve kırılgan davranmasını engellemek.

**Kapsam:**

- Native/no-origin config
- Safe-area ve 100dvh
- Android back
- App background/foreground
- Network değişimi
- Push deep-link
- Medya/camera izinleri
- WebView sürümü
- Eski bundle/canlı backend uyumu

**Kabul kriterleri:**

- [ ] Aynı release'te Web ve Android ana akışları eşdeğer.
- [ ] Back tuşu aktif sohbet/offer/search state'ini güvenli kapatıyor.
- [ ] Background dönüşü stale UI göstermiyor.
- [ ] İzin reddi kontrollü fallback veriyor.
- [ ] C-MOB-001 release/version sonucu kullanıcı yüzeyiyle eşleşiyor.

## 25. A-QA-001 — Client kalite ve kanıt kapıları

**Amaç:** Plan A maddesini yalnız görsel olarak değil davranış ve veri doğruluğuyla kapatmak.

**Otomatik kapılar:**

- Lint
- Production build
- Component test
- Kritik E2E
- İki istemcili match/chat senaryoları
- Accessibility kontrolleri
- TR/EN missing-key kontrolü
- Stale/reconnect/duplicate testleri
- Android asset/version uyumu ilgili wave kapsamındaysa

**Manuel kapılar:**

- Master §13 frontend listesi
- Master §15 Android listesi içindeki kullanıcı akışları
- İlgili QA kaydının manuel matrisi
- Desktop + 320 px + kısa telefon + Android WebView
- Önce/sonra ekran görüntüsü
- Kullanıcı onayı gereken tasarım sonucu

**Kapanış kuralı:**

- [ ] Plan ID kabul kriterleri kanıtla işaretli.
- [ ] Bağlı Plan B/C sözleşmeleri tamam veya açıkça kapsam dışı.
- [ ] Test sonucu tarih/komut/sayı ile kayıtlı.
- [ ] Manuel QA sonucu ve cihaz/browser kayıtlı.
- [ ] Bilinen hata saklanmıyor.
- [ ] Sonraki wave başlatılmıyor.

## 26. Çapraz plan sözleşmeleri

| Plan A tüketicisi | Canonical sağlayıcı | Kural |
|---|---|---|
| A-AUTH-001/002 | B-AUTH-001/002 | Session ve legal sonucu client tahmin etmez |
| A-MATCH-001 | B-MM-001 | Search phase yalnız server sözleşmesinden |
| A-MATCH-002 | B-MM-003 | Offer/countdown/pending state server otoriteli |
| A-MATCH-003 | B-MM-002, B-DATA-002 | Scope ve ülke client tarafından uydurulmaz |
| A-FRIEND-001 | B-PRES-001 | Presence/last seen backend otoriteli |
| A-FRIEND-003 | B-MSG-001/002 | Idempotency ve medya yaşam döngüsü backend'de |
| A-SYS-001 | B-SYS-001, C-SYS-001 | Inbox/delivery ve campaign farklı sahiplik |
| A-I18N-001 | B-I18N-001, C-NOTIFY-001 | Locale kaynağı ve içerik varyantı sözleşmeli |
| A-MOB-001 | C-MOB-001, C-REL-001 | Release/build/deploy kimliği operasyon otoriteli |

## 27. Master backlog kaynak kapsama indeksi

Plan A'nın birincil aldığı kaynaklar:

- Master §3 — kullanıcı ürün döngüsü
- Master §5 — ürün ve konumlandırma
- Master §7 — frontend teknik backlog
- Master §13 — manuel frontend inceleme listesi
- Master §15 — kullanıcıya dönük Android inceleme maddeleri
- QA-001, QA-002, QA-003, QA-014
- QA-015 kullanıcı uygulaması dilimi
- QA-016 client instrumentation/recovery dilimi
- QA-017 ürün ve UI/client dilimi

Plan A'nın referans verdiği fakat sahiplenmediği kaynaklar:

- Master §6 → Plan C
- Master §8 ve §10 → Plan B
- Master §9 ve §12 → Plan C
- Master §11 → alanına göre Plan A/B/C
- Master §14 → Plan C
- Master §17 Fikir Parkı → master'da kalır, planlara otomatik taşınmaz

## 28. Plan A tamamlanma tanımı

Plan A bütünü ancak:

- Bütün stable ID'ler tamamlanmış veya açık gerekçeyle kapsam dışı,
- Bağlı Plan B/C sözleşmeleriyle çelişki kalmamış,
- Kullanıcı ana döngüsü Web ve Android'de uçtan uca çalışmış,
- QA-001/002/003/014/015-client/016-client/017-client kapanmış,
- Lint/build/component/E2E ve accessibility kapıları geçmiş,
- TR/EN ve responsive manuel QA tamamlanmış,
- Kanıtlar ilgili wave sonuçlarında bulunabilir

olduğunda tamamlanır.

Planın hazır olması uygulamanın başladığı veya herhangi bir QA'nın kapandığı anlamına gelmez.
