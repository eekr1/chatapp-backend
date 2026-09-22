# TalkX Wave 03 Plan — Test Edilebilir Client Kabuğu ve Dürüst Auth UX

> Bu belge yalnız Wave 03 için hazırlanmış uygulama planıdır.
> Canonical ayrıntı Plan A stable ID maddelerindedir; burada yeni ürün özelliği veya sonraki-wave ekranı üretilmez.
> Plan hazırdır. Wave 03 aktif değildir, Wave 01–02 kapanmamıştır ve uygulama başlamamıştır.

## 1. Durum ve yürütme sınırı

- **Wave:** 03
- **Wave adı:** Test edilebilir client kabuğu, tema/state temeli ve dürüst auth UX
- **Plan durumu:** Hazır
- **Wave durumu:** Bekliyor
- **Uygulama durumu:** Başlamadı
- **Uygulama yetkisi:** Verilmedi
- **Giriş kapısı:** Wave 02 **AUTO-VERIFIED / COMMITTED** ve kullanıcıdan açık “Wave 03'ü başlat” talimatı
- **Mevcut blokaj:** Wave 02 henüz committed değil; Wave 03 uygulanamaz
- **Önceki wave:** Wave 02 — planı hazır, aktif değil
- **Sonraki wave:** Wave 04 — planı ayrı talimatla hazırlandı; aktif değil ve uygulanmadı

Bu dosyanın hazırlanması Wave 03 aktivasyonu, frontend kodu/CSS'i, dependency veya test altyapısı değişikliği, Android sync, deploy ya da Wave 04 aktivasyonu/uygulaması için yetki değildir.

## 1.1 Sale Release override — KÜÇÜLTÜLMÜŞ

- **Satış öncesi uygulanır:** Yalnız riskli match/friend/system state ayrımı, gerekli küçük extraction'lar, auth hata/recovery UX'i ve kritik mobile/responsive/accessibility düzeltmeleri.
- **Post-acquisition Roadmap / Deferred:** App.jsx'in komple parçalanması, tam design-system/semantic-token migration'ı, geniş component standardizasyonu ve kozmetik yeniden tasarım.
- **Koruma:** Mevcut TalkX görünümü ve çalışan akışlar değişmez; refactor kendi başına amaç değildir.
- **Kapanış:** Focused test + lint/build geçer, tek Wave 03 commit'i alınır ve **DUR**. Manuel görsel/a11y doğrulama Checkpoint A/Wave 19'a gider.

## 2. Canonical referanslar

Uygulama sırası değişmez:

1. `A-FND-001` — Plan A / frontend kabuğunu test altında ayrıştırma / bütün kabul kriterleri
2. `A-FND-002` — Plan A / tasarım tokenı ve ortak ekran state standardı / bütün kabul kriterleri
3. `A-A11Y-001` — Plan A / accessibility ve responsive / bütün kabul kriterleri
4. `A-AUTH-001` — Plan A / auth ve hesap politikası client sözleşmesi / bütün kabul kriterleri

Yürütme kaynağı: `../TALKX_WAVE_MAP.md` / Wave 03.
Canonical ayrıntı kaynağı: `../TALKX_PLAN_A_PRODUCT_CLIENT.md`.
Kilitli karar ve kanıt kaynağı: `../TALKX_MASTER_BACKLOG.md` / §1, §3, §5, §7, §13, §15 ve ilgili QA kayıtları.

Bağımlılık yorumu:

- `B-API-001` ve `B-WS-001` Wave 02 Sale Release scope'unda otomatik doğrulanmış ve committed olmalıdır; client server state'ini veya hata anlamını tahmin etmez.
- `A-QA-001` Wave 17'nin bütünleşik kalite programıdır. Wave 03, extraction güvenliği için focused test altyapısı ve kanıt üretir fakat `A-QA-001` maddesini kapatmaz.
- A-A11Y-001 bu wave içinde bütün yeni/ayrılan client temelinin kabul kapısıdır; sonradan uygulanacak kozmetik kontrol değildir.

## 3. Wave sonucu

Wave 03 sonunda:

- `App.jsx` içindeki auth, screen navigation, WebSocket lifecycle, push, legal, outbox ve chat domainleri davranış değiştirmeden sahipliği belirli modüllere ayrılmaya başlayacak.
- Match, friend chat ve system chat state'leri birbirine karışmayacak; ortak app shell yalnız orkestrasyon ve screen composition taşıyacak.
- Refresh, browser back, Android back, logout ve desteklenen deep-link davranışı tek navigation/state sözleşmesiyle belgeli olacak.
- Mevcut TalkX koyu neon/glass görünümü korunarak renk, surface, border, radius, glow, spacing ve typography semantic tokenları merkezileştirilecek.
- Loading, empty, stale, partial error, offline, reconnecting ve permission durumları ortak anlam/aksiyon hiyerarşisine sahip olacak.
- Teknik hata kodu ana kullanıcı arayüzüne dökülmeyecek; durum metni ve recovery aksiyonu yerelleştirilmiş olacak.
- Semantic landmark, heading, label/error ilişkisi, focus order/restore, 44x44 hedef, contrast, reduced motion, 320 px, kısa ekran, büyük yazı, safe-area ve klavye davranışı temel kabul kapısı olacak.
- Auth ekranı e-posta toplanmadığını, kurtarma olmadığını ve session sona ermesinin hesap/veri silinmesi olmadığını açık fakat sakin biçimde anlatacak.
- QA-014 arama, QA-003 teklif ve QA-017 scope ekranları yeniden tasarlanmayacak; yalnız gelecekte aynı temel/token/state ailesini tüketebilecek güvenli zemin kurulacak.

## 4. Doğrulanmış başlangıç fotoğrafı

### 4.1 Repo ve değişiklik güvenliği

- Repo kökünde kullanıcıya ait geniş ve önceden var olan dirty/untracked durum bulunuyor.
- Güncel `chatapp-frontend/` ve `docs/` ağaçları Git görünümünde untracked.
- Wave 03 mevcut kullanıcı değişikliklerini sahiplenmez, geri almaz, taşımadan önce hash almadan dosya bölmez veya toplu formatlamaz.
- Uygulama başlangıcında hedef JSX/CSS/package dosyalarının hash/status ve ekran davranışı fotoğrafı alınır.

### 4.2 A-FND-001 mevcut gerçek

- Client React 19 + Vite kullanıyor; routing framework'ü bulunmuyor ve ekran geçişleri büyük ölçüde `screen` state'iyle yönetiliyor.
- `App.jsx` yaklaşık 83 KB; auth kontrolü, screen state, WebSocket, reconnect, match, friend/system chat, push, legal, permission, outbox, toast ve modal davranışlarını aynı bileşende topluyor.
- `App.jsx` içinde çok sayıda `useState`, `useEffect`, `useCallback` ve mutable ref bulunuyor; domain sınırları kod seviyesinde açık değil.
- Mevcut ayrı parçalar `api.js`, `nativeBridge.js`, `Auth`, `Friends`, `Profile` ve `GlassCard`; extraction için kullanılabilir başlangıç sınırları var.
- Match/friend/system mesaj state'leri aynı app orkestrasyonunda yan yana duruyor; yanlış reset veya stale event riski var.
- Browser history/deep-link sahipliği açık bir router/reducer sözleşmesine bağlı görünmüyor.
- Android back listener native bridge'de mevcut; screen transition ve modal önceliği tek testli state machine olarak görünür değil.
- Frontend `package.json` yalnız dev/build/lint/preview scriptleri taşıyor; component/unit test komutu yok.

### 4.3 A-FND-002 mevcut gerçek

- `index.css` içinde `--bg-deep`, `--primary`, `--accent`, text, glass, glow, font ve safe-area değişkenleri bulunuyor.
- `index.css` yaklaşık 35 KB, `App.css` yaklaşık 9 KB; iki dosyada da çok sayıda component kuralı ve tekrarlanan hard-coded hex/rgba değeri var.
- Bazı yüzeyler token tüketirken bazıları doğrudan renk, shadow, radius ve spacing yazıyor.
- Auth bileşeninde kart, uyarı, CTA ve switch alanlarında geniş inline style kullanımı var.
- Mevcut CSS `100vh` + `100dvh`, safe-area ve keyboard offset desteğini bazı yüzeylerde taşıyor; bütün screen/modal/CTA'lar aynı standardı tüketmiyor.
- Loading, empty, offline, reconnect, stale, permission ve partial error durumları ortak component/state modeli yerine ekranlara dağılmış.
- Client toast sınıflarında `admin-toast-*` adı kullanılması kullanıcı/admin tasarım sahipliğini bulanıklaştırıyor.
- QA-003/014/017 için mevcut stiller var; Wave 03 bunların görünümünü yeniden tasarlamaz.

### 4.4 A-A11Y-001 mevcut gerçek

- Bazı dialog, status ve `aria-live` kullanımları mevcut; legal/permission kartları `role="dialog"` taşıyor.
- Auth inputları görünür `<label>` veya `aria-label` yerine placeholder'a dayanıyor; hata alanı inputlarla programatik bağlı değil.
- Login/register geçişi tıklanabilir `<span>` ile yapılıyor; doğal klavye/role davranışı yok.
- Bazı close kontrolleri görsel `x` metni kullanıyor; isim verilse de ikon ve touch target standardı ortak değil.
- `focus-visible` kuralları bazı bileşenlerde var; bütün interaktif elemanlar için tek odak standardı görünmüyor.
- Modal açılış focus'u, trap/containment ve kapanış focus restore davranışı sistematik test altında değil.
- Global `overflow-x: hidden` olası taşmayı gizleyebilir; 320 px/büyük yazı testinin yerine geçmez.
- Kod taramasında ortak `prefers-reduced-motion` standardı görünmedi.
- Screen reader live-region gürültüsü ve saniyelik sayaç duyuruları için merkezi policy yok.

### 4.5 A-AUTH-001 mevcut gerçek

- Auth login/register modlarını aynı formda sunuyor ve register sırasında legal kabul checkbox'ı bulunuyor.
- `Önemli Uyarı` ve e-posta/kurtarma olmadığı bilgisi mevcut; inline danger kutusunda gösteriliyor.
- Kullanıcı adı ve parola inputları browser/autocomplete/label/error yardım metni açısından eksik.
- Hata metni doğrudan `err.response?.data?.error` okuyabiliyor; Wave 02 canonical error code sözleşmesine tam bağlı değil.
- Token `localStorage` içinde saklanıyor; bu risk kararı Web/Android/session policy ile belgeli değil.
- Login/register geçişi semantik button değil; form error focus/live-region davranışı yok.
- Loading submit'i disable ediyor; duplicate submit koruması var fakat durum açıklaması ve recovery standardı ortak değil.
- Auth kartı inline `minHeight: 100vh`, sabit 40 px padding ve 400 px max width kullanıyor; kısa ekran, keyboard ve 320 px davranışı açık kanıtlı değil.
- Session sona ermesi uygulamada token temizliği/splash dönüşü üretebiliyor; kullanıcı metni hesap silinmesi veya veri kaybı anlamına gelmemeli.

## 5. Kilitli Wave 03 sözleşmeleri

### 5.1 Extraction ve sahiplik kuralı

- Önce mevcut screen/state/event haritası ve characterization testleri yazılır; sonra tek sorumluluklu extraction yapılır.
- Tek PR/adımda büyük `App.jsx` yeniden yazımı, framework değişimi veya router zorunluluğu yoktur.
- Her extraction tek davranış kümesini taşır ve öncesi/sonrası test ile doğrulanır.
- App shell yalnız bootstrap, domain composition ve üst seviye navigation sahipliği taşır.
- Auth/session, realtime connection, match, friend chat, system chat, legal, push/permission, outbox ve notification state'leri ayrı sahiplik sınırına kavuşur.
- Domainler birbirinin mutable state'ini doğrudan değiştirmez; açık action/event/selector arayüzü kullanır.
- Socket event parse/routing tek yerde yapılır; domain reducer/controller yalnız kendi eventini tüketir.
- Refresh, logout ve session-expired reset matrisi hangi state'in korunacağını/silineceğini açıkça tanımlar.
- Deep-link ve Android back geçişleri aynı navigation policy'sini tüketir; iki ayrı gerçek üretmez.
- Kullanılmayan state/import ve hook dependency temizliği yalnız extraction kapsamındaki kanıtla yapılır.

### 5.2 Client state alanları

| Alan | Sahip olduğu durum | Sahip olmadığı durum |
|---|---|---|
| App shell/navigation | Aktif screen, modal önceliği, back/deep-link intenti | Mesaj listesi, match sonucu, session doğrulama |
| Auth/session | Auth bootstrap, user, session phase, logout/session-expired sonucu | Match veya friend chat içeriği |
| Realtime connection | Socket phase, capability, reconnect sinyali, event dispatch | Screen metni veya ürün kararı |
| Match | Search/offer/anonymous room state | Friend/system message state |
| Friend chat | Active friend, persistent messages, outbox/unread | Anonymous room state |
| System chat | Sistem conversation ve delivery state | Friend/anonymous chat state |
| Legal | Legal config/reaccept state | Genel auth hatası veya matchmaking country |
| Push/permission | Native permission ve delivery intenti | Navigation state'i doğrudan keyfi değiştirme |

Bu tablo yeni ürün akışı değildir; mevcut sorumlulukların test edilebilir sahiplik ayrımıdır.

### 5.3 Tasarım token katmanları

- Mevcut TalkX renk değerleri korunur; tokenlaştırma rebrand değildir.
- Primitive değerler ile semantic kullanım ayrılır: canvas/surface/elevated, text primary/secondary, border subtle/active, action primary/secondary/danger, status success/warning/error/info.
- Radius, spacing, typography, elevation/glow, motion duration/easing ve touch target tokenları merkezi olur.
- Component-specific token yalnız semantic token yetmediğinde ve tekrar kanıtlandığında eklenir.
- Yeni component doğrudan rastgele hex/rgba, shadow, radius veya spacing üretmez.
- Inline style yalnız gerçekten runtime değeri için kullanılır; sabit görsel karar CSS class/tokena taşınır.
- Admin tokenları client'a kopyalanmaz; kullanıcı yüzeyi sakin neon/glass dilini korur.
- Token migration küçük dilimler hâlinde, screenshot/contrast karşılaştırmasıyla yapılır.
### 5.4 Ortak ekran state sözleşmesi

Her ekran yalnız gerçekten anlamlı alt kümeyi kullanır:

- `loading`: İlk güvenilir veri bekleniyor; sahte empty/error gösterilmez.
- `ready`: Güncel ve kullanılabilir veri/aksiyon var.
- `empty`: İstek başarılı fakat gerçek kayıt yok; neden ve birincil aksiyon açık.
- `stale`: Önceki veri görünür fakat güncelliği kesin değil; zaman ve yenile aksiyonu var.
- `partial_error`: Kullanılabilir veri korunur, başarısız alt bölüm ve retry ayrılır.
- `offline`: Bağlantı yok; mümkün olan yerel içerik ve tekrar davranışı dürüstçe gösterilir.
- `reconnecting`: Bağlantı geri kazanılıyor; offline veya başarılı gibi anlatılmaz.
- `permission_required/denied`: İzin nedeni, etkisi ve güvenli alternatif görünür.
- `forbidden`: Yetki/policy sonucu; teknik backend metni veya sahte retry yok.

Öncelik kuralı:

1. Güvenlik/legal olarak engelleyici durum
2. Offline/reconnecting
3. İlk loading
4. Partial error/stale
5. Empty/ready

State componenti yalnız sunum yapar; server phase'i, session sonucu veya veri varlığını tahmin etmez.

### 5.5 Aksiyon ve feedback hiyerarşisi

- Ekranda tek birincil aksiyon bulunur; ikincil ve destructive aksiyon aynı ağırlıkta görünmez.
- Modal kritik karar veya focus containment gerektiğinde; inline feedback yerel form/state için; toast geçici, geri döndürülebilir sonuç için kullanılır.
- Kalıcı hata yalnız toast ile kaybolmaz; kullanıcı geri döndüğünde durum bulunabilir.
- Teknik error code ana metinde gösterilmez; request/reference ID ancak detay/destek katmanında bulunur.
- Loading butonu sonucu taklit etmez; duplicate submit engellenir ve progress metinle anlaşılır.
- Renk/ikon/animasyon tek başına başarı, hata veya seçim anlamı taşımaz.

### 5.6 Accessibility ve responsive sözleşmesi

- Her screen anlamlı landmark ve tek mantıksal `h1` sahibi olur; heading seviyeleri atlamaz.
- Her form kontrolünün görünür label'ı, gerektiğinde description ve `aria-describedby` ile bağlı hata alanı vardır.
- Form hatası submit sonrası özetlenir; focus ilk hatalı alana veya anlaşılır hata özetine güvenli taşınır.
- Modal açılışında başlangıç focus'u, Tab containment, Escape/back davranışı ve kapanış focus restore hedefi tanımlıdır.
- Status/live-region yalnız anlamlı phase değişiminde duyurur; timer/progress her saniye okutulmaz.
- Bütün interaktif hedefler en az 44x44 CSS px veya eşdeğer güvenli hit area taşır.
- `:focus-visible` görünür, yüksek contrastlı ve glow altında kaybolmayan tek standardı tüketir.
- Metin/ikon/şekil renk dışı anlam taşır; normal, hover, focus, disabled ve error contrastı ölçülür.
- `prefers-reduced-motion: reduce` durumunda ambient/dekoratif motion kapanır; durum ve CTA aynı anlamı korur.
- 320 px genişlik, kısa telefon yüksekliği, %200 metin, landscape, safe-area ve açılan keyboard ayrı kabul senaryolarıdır.
- `overflow-x: hidden` taşma hatasını başarılı test saydırmaz; DOM ölçümü ve gerçek viewport kontrolü yapılır.
- Android back önceliği: açık modal/menu → geçici screen → ana screen → güvenli app exit policy.

### 5.7 Auth ve hesap politikası sözleşmesi

- Login/register tek form ailesinde kalabilir fakat mode başlığı, submit label'ı ve geçiş kontrolü semantik/erişilebilirdir.
- Kullanıcı adı ve parola görünür label, autocomplete, inputMode/constraint ve güvenli yardım metni taşır.
- Register'daki `Önemli Uyarı`, e-posta toplanmadığını ve parola unutulursa kurtarma sunulmadığını submit öncesinde açıkça gösterir.
- Uyarı ana formu boğmaz; danger/destructive olay varmış gibi panik üretmeden yüksek önemde sunulur.
- Olmayan şifre sıfırlama linki, “yakında” vaadi veya destek üzerinden gizli kurtarma beklentisi oluşturulmaz.
- Hata metni Wave 02 `errorCode` sözleşmesinden locale anahtarına çevrilir; ham backend İngilizce mesajı ana kaynak değildir.
- Session expired/revoked durumu “oturumun sona erdi” diye anlatılır; hesap silindi veya mesajlar kayboldu iddiası üretmez.
- Current/all-device logout metni Wave 02 policy'siyle birebir uyumludur.
- `localStorage` token kullanımı threat/risk kararı olmadan sessizce başka yere taşınmaz; Web/Android güven modeli belgelenir.
- Mode değişiminde error, password visibility ve legal checkbox kontrollü resetlenir; username kaybı açık UX kararı olmadan yapılmaz.
- Submit sırasında duplicate çağrı engellenir; başarı yalnız gerçek backend sonucu sonrası gösterilir.

## 6. Uygulama paketleri

### Paket 03A — Davranış envanteri ve focused test zemini

Muhtemel hedefler:

- `chatapp-frontend/package.json`
- Yeni test config/setup ve focused fixture dosyaları
- `chatapp-frontend/src/App.jsx`, `api.js`, `utils/nativeBridge.js` için characterization testleri
- Ekran/state/event sahiplik matrisi belgesi veya test fixture'ı

İş sırası:

1. Mevcut screen, modal, session, socket ve domain state envanterini çıkar.
2. Splash/auth/home/friends/matching/chat/legal/permission render geçişlerini fixture ile dondur.
3. Refresh, logout, session-expired, browser back, Android back ve deep-link davranışlarını kaydet.
4. Match/friend/system eventlerinin hangi state'i değiştirdiğini characterization testleriyle kanıtla.
5. React 19 ile uyumlu minimum component/unit test zemini kur; bütünleşik Wave 17 CI programına taşma.
6. Mevcut lint/build ve bilinen baseline sorunlarını Wave 03 değişikliğinden ayır.

### Paket 03B — A-FND-001 client kabuğu ayrıştırması

Muhtemel hedefler:

- `chatapp-frontend/src/App.jsx`
- Yeni `app/`, `state/`, `hooks/` veya `services/` altında sahipliği açık küçük modüller
- `chatapp-frontend/src/api.js`
- `chatapp-frontend/src/utils/nativeBridge.js`

İş sırası:

1. Saf normalize/selector/reducer fonksiyonlarını side-effect kodundan ayır.
2. Auth/session bootstrap ve logout reset sahipliğini çıkar.
3. WebSocket lifecycle/event router'ı domain state'lerinden ayır.
4. Match, friend chat ve system chat reducer/controller sınırlarını ayrı kur.
5. Legal, push/permission, outbox ve toast sahipliğini küçük adımlarla çıkar.
6. Navigation/back/deep-link transition tablosunu tek policy'de birleştir.
7. Her extraction sonrası focused test + lint + build çalıştır; başarısız adımda yalnız o dilimi geri al.
8. App shell'i screen composition seviyesine indir; satır sayısını hedef metrik yapıp davranışı feda etme.

### Paket 03C — A-FND-002 semantic token ve ortak state temeli

Muhtemel hedefler:

- `chatapp-frontend/src/index.css`
- `chatapp-frontend/src/App.css`
- Yeni theme/token CSS katmanı
- Ortak client UI/state componentleri
- `GlassCard.jsx` ve yalnız foundation tüketen mevcut bileşenler

İş sırası:

1. Kullanılan renk/surface/border/glow/radius/spacing/type/motion değerlerini envanterle.
2. Mevcut görsel değerleri primitive → semantic token eşlemesine taşı.
3. Primary/secondary/danger action ve disabled/focus state standardını kur.
4. Loading/empty/stale/partial-error/offline/reconnecting/permission component contractını oluştur.
5. Sabit inline stilleri küçük dilimlerle class/tokena taşı.
6. `admin-toast-*` gibi client sahipliğini bozan sınıf adlarını davranış ve screenshot altında temizle.
7. 100dvh, safe-area, keyboard offset ve kısa ekran layout primitive'lerini merkezileştir.
8. QA-003/014/017 görünümünü değiştirmeden yeni token aliases ile aynı renderı koru.

### Paket 03D — A-A11Y-001 erişilebilirlik ve responsive temel kapısı

Muhtemel hedefler:

- App shell, modal, toast ve ortak state componentleri
- `Auth.jsx`, `Friends.jsx`, `Profile.jsx`, `GlassCard.jsx`
- `index.css`, `App.css`
- Focus/viewport/accessibility focused testleri

İş sırası:

1. Landmark/heading ve interaktif element envanterini çıkar.
2. Button olmayan tıklanabilir span/div kontrollerini semantik elemente geçir.
3. Form label/description/error bağlarını ve live-region politikasını uygula.
4. Modal focus entry/trap/restore ve Escape/Android back davranışını ortaklaştır.
5. 44x44 hit area, focus-visible ve contrast açıklarını kapat.
6. Reduced-motion standardını dekoratif/ambient animasyonlara uygula.
7. 320 px, kısa ekran, %200 text, landscape, safe-area ve keyboard testlerini kur.
8. Global overflow gizlemesine güvenmeden yatay taşma ve kesilmiş CTA olmadığını kanıtla.

### Paket 03E — A-AUTH-001 dürüst auth UX

Muhtemel hedefler:

- `chatapp-frontend/src/components/Auth.jsx`
- `chatapp-frontend/src/api.js`
- `chatapp-frontend/src/i18n/messages.tr.js`
- `chatapp-frontend/src/i18n/messages.en.js`
- Auth styles ve focused component testleri

İş sırası:

1. Login/register mode, validation, loading, success ve error state'lerini açık modelle.
2. Visible label, autocomplete, help/error association ve focus davranışını kur.
3. Login/register geçişini gerçek button yap; form submit ile çakışmasını engelle.
4. Önemli Uyarı'yı inline style'dan semantic component/token standardına geçir.
5. E-posta/kurtarma politikasını TR/EN aynı anlamla, vaat üretmeden doğrula.
6. Backend error message okumayı Wave 02 code → locale adapterına bağla.
7. Session expired ve logout sonuç metinlerini Wave 02 policy'siyle eşle.
8. localStorage risk kararını Web/Android bağlamıyla kaydet; yetkisiz storage mimarisi değiştirme.
9. Short-screen/keyboard/320 px/large-text ve ekran okuyucu akışını testle.

## 7. Dosya ve servis etki sınırı

### Birincil client alanı

- `chatapp-frontend/package.json` ve yalnız focused test config'i
- `chatapp-frontend/src/App.jsx`
- `chatapp-frontend/src/api.js`
- `chatapp-frontend/src/index.css`
- `chatapp-frontend/src/App.css`
- `chatapp-frontend/src/components/`
- `chatapp-frontend/src/i18n/`
- `chatapp-frontend/src/utils/nativeBridge.js`
- Yalnız Wave 03 sahiplik/test/theme/state modülleri

### Read-only sözleşme tüketimi

- Wave 02 API/error/session/socket capability sözleşmeleri
- Capacitor back/safe-area mevcut davranışı
- QA-003/014/017 mevcut ekran baseline'ı

### Varsayılan olarak değişmeyecek alanlar

- Backend API/WebSocket davranışı
- Admin paneli
- Android Gradle/version/signing ve native release zinciri
- Matchmaking queue, scope veya offer protokolü
- Veritabanı ve migrationlar

## 8. Açık kapsam dışı

- `A-HOME-001/002` Home, ayarlar, destek ve hesap silme özellik çalışması
- `A-MATCH-001/002/003/004` QA-014, QA-003, QA-017 ve reconnect görsel/işlev değişikliği
- `A-FRIEND-001/002/003` presence, güven aksiyonları ve persistent messaging özellikleri
- `A-AUTH-002` legal reaccept ve session recovery ürün akışı
- `A-I18N-001` bütün ürünün içerik/locale konsolidasyonu
- `A-MOB-001` Web/Android davranış eşliği programı
- `A-QA-001` bütünleşik client kalite kapısının kapatılması
- React/Vite değişimi, yeni UI framework veya zorunlu router migrationı
- TalkX rebrand, yeni tema, yeni neon paleti veya admin tasarım dilinin client'a taşınması
- QA-003/014/017 ekranlarının yeniden tasarımı
- Backend, DB, admin, Render, production config veya deploy
- Android sync/build/version/signing/store işlemleri
- Wave 04 aktivasyonu veya uygulaması

## 9. Otomatik doğrulama planı

### Mevcut kapılar

- `npm --prefix chatapp-frontend run lint`
- `npm --prefix chatapp-frontend run build`
- `npm run check:text-encoding`
- Değişen saf JS modülleri için syntax/import doğrulaması

### Focused test zemini

Wave 03 uygulamasında minimum tekrar üretilebilir component/unit test komutu kurulur. Bu, Wave 17 `A-QA-001` bütünleşik kalite programını erkenden kapatmaz.

Test grupları:

- App bootstrap ve screen transition
- Auth/session bootstrap, logout ve session-expired reset
- Socket event router → doğru domain reducer
- Match/friend/system state izolasyonu
- Refresh, browser back, Android back ve deep-link policy
- Legal/push/permission/outbox sahiplik sınırları
- Ortak screen-state render ve aksiyon önceliği
- Token/class regression ve kontrolsüz yeni görsel değer taraması

### A-FND-001 characterization matrisi

- Mevcut desteklenen splash → auth/home sırası
- Home → friends → friend chat → back
- Home → matching → offer/chat → leave
- System message/deep-link açılışı
- Refresh sırasında korunacak/silinecek state
- Current/all-device logout sonrası state temizliği
- Session expired sırasında auth dönüşü
- Stale socket eventinin yanlış domain state'ini değiştirmemesi
- Extraction öncesi ve sonrası event/render eşliği

### A-FND-002 görsel/state matrisi

- Primitive ve semantic token inventory snapshotı
- Yeni hard-coded color/glow/radius/spacing eklenmemesi
- Primary/secondary/danger/disabled/focus karşılaştırması
- Loading, empty, stale, partial error, offline, reconnecting ve permission renderları
- Teknik error code'un ana kullanıcı metnine sızmaması
- 100dvh/safe-area/keyboard layout primitive testleri
- QA-003/014/017 baseline screenshot farkının yalnız izinli foundation etkisi olması
- Düşük güçlü WebView için motion ve render yükü kontrolü

### A-A11Y-001 matrisi

- Accessibility lint ve component semantic sorguları
- Landmark/heading düzeni
- Label, description, error association
- Keyboard-only Tab/Shift+Tab/Enter/Space/Escape
- Modal başlangıç focus'u, containment ve restore
- Live-region duyuru sayısı; timer'ın saniyelik spam üretmemesi
- 44x44 touch target ölçümü
- Focus-visible ve contrast kontrolü
- Reduced-motion altında aynı durum/aksiyon anlamı
- 320 px, kısa viewport, %200 text ve landscape yatay taşma kontrolü
- Safe-area ve keyboard açıkken ana CTA/composer erişimi

### A-AUTH-001 matrisi

- Login/register semantik mode değişimi
- Kullanıcı adı/parola visible label ve autocomplete
- Legal checkbox label/link davranışı
- Önemli Uyarı'nın submit öncesi görünürlüğü
- E-posta/kurtarma politikasının TR/EN eş anlamı
- INVALID_INPUT, BAD_CREDENTIALS, RATE_LIMITED, SESSION_EXPIRED ve generic fallback
- Duplicate submit koruması
- Hata sonrası focus ve `aria-describedby`
- Loading/başarı/hata state'leri
- Session sona ermesinin hesap silinmesi gibi anlatılmaması

## 10. Manuel QA havuzu — Checkpoint A / Wave 19 (commit kapısı değil)

### Davranış regresyonu

- Desteklenen masaüstü browserda splash/auth/home/friends/matching/chat/system akışları
- Refresh, browser back, logout ve session-expired
- İki client ile anonymous ve friend/system state'lerinin karışmaması
- Push/deep-link ile doğru screen/modal önceliği
- Extraction öncesi/sonrası kullanıcı davranışı eşliği

### Tema ve ortak durumlar

- Koyu TalkX neon/glass kimliğinin korunması
- Renk, glow, radius, spacing ve typography'nin ekranlar arasında tutarlı görünmesi
- Primary/secondary/danger aksiyonların beş saniyede ayrılması
- Loading/empty/stale/partial error/offline/reconnecting/permission durumlarında durum → etki → aksiyon sırası
- Teknik hata kodu, stack veya ham payload görünmemesi
- Reduced motion açık/kapalı karşılaştırması
- Düşük güçlü Android WebView'da temel geçiş akıcılığı

### Accessibility ve responsive

- Klavye ile bütün auth ve temel navigation akışı
- Screen reader ile heading/label/error/status/dialog isimleri
- Modal açılış, Escape/back kapanış ve focus restore
- 320 px genişlik, kısa telefon, landscape ve %200 text
- Notch/safe-area üst-alt boşlukları
- Keyboard açıkken auth submit ve temel CTA erişimi
- Yatay scroll, kesilmiş CTA veya erişilemeyen close kontrolü olmaması
- Renk algısı olmadan hata/seçim/durumun anlaşılması

### Auth TR/EN

- Login ve register başlık/CTA/geçiş anlamı
- Kullanıcı adı/şifre kuralları ve güvenli hata metni
- Register öncesi e-posta/kurtarma uyarısı
- Olmayan “şifremi unuttum” veya gizli kurtarma vaadi bulunmaması
- Legal linklerin klavye ve ekran okuyucu davranışı
- Current/all-device logout metninin Wave 02 policy'siyle uyumu
- Session expired sonucunun veri veya hesap silinmesi gibi anlatılmaması

Android native davranış eşliği ve store/release kanıtı Wave 18'e aittir; burada yalnız mevcut WebView'da foundation regresyon smoke'u yapılır.

## 11. Kanıt ve kabul eşlemesi

| Plan ref | Gerekli kanıt | Kapanış şartı |
|---|---|---|
| A-FND-001 | State/event haritası, extraction diffleri, focused testler, refresh/back/logout/deep-link kayıtları | Beş canonical kabul kriteri kanıtlı |
| A-FND-002 | Token inventory/diff, ortak state örnekleri, QA-003/014/017 screenshot karşılaştırması, WebView performans smoke'u | Beş canonical kabul kriteri kanıtlı |
| A-A11Y-001 | A11y lint/semantic test, keyboard/screen-reader/focus, 320 px/large-text/reduced-motion kanıtı | Altı canonical kabul kriteri kanıtlı |
| A-AUTH-001 | TR/EN auth screenshotları, form semantic testleri, error/session policy matrisi | Dört canonical kabul kriteri kanıtlı |

Checkbox yalnız ilgili canonical kabul kriteri gerçek kanıtla kapandığında işaretlenir. Focused Wave 03 testlerinin tamamlanması `A-QA-001` Wave 17 maddesini otomatik kapatmaz.

## 12. Riskler ve rollback

| Risk | Koruma | Rollback/durma davranışı |
|---|---|---|
| App extraction gizli davranışı değiştirir | Önce characterization, tek sorumluluklu küçük dilim | Yalnız son extraction dilimini geri al |
| Hook dependency değişikliği reconnect/notification döngüsü üretir | Effect/closure testleri ve render ölçümü | İlgili hook extractionını geri al; semantiği yamama |
| Domain state ayrımı mesajı yanlış ekrana taşır | Event router ve stale-event negatif testleri | Yeni reducer/router dilimini geri al |
| Router/framework ekleme kapsamı büyütür | Mevcut screen modelini önce saf transition policy'ye al | Framework migrationını durdur |
| Token migrationı görünümü değiştirir | Mevcut değerleri alias ile semantic tokena bağla | Son token dilimini geri al; yeni palet üretme |
| Global CSS başka ekranı bozar | Selector inventory ve baseline screenshot | Değişikliği lokalize et veya geri al |
| A11y düzeltmesi layoutu taşırır | 320 px, %200 text ve short viewport testi | Boyut küçültmek yerine layoutu güvenli geri al |
| Live-region kullanıcıyı spamler | Phase bazlı duyuru testi | İlgili regionı sessize al; kritik metni görünür koru |
| Focus trap kullanıcıyı kilitler | Keyboard/Escape/back/focus restore matrisi | Modal focus katmanını geri al; bypass üretme |
| Auth metni kurtarma vaadi yaratır | Kilitli ürün kararı ve TR/EN karşılaştırması | Son doğrulanmış metne dön |
| localStorage değişimi sessionı kırar | Wave 02 policy + threat decision gate | Storage değişikliğini yapmadan dur |
| Test altyapısı Wave 17'ye taşar | Yalnız Wave 03 focused testleri | Genel CI/refactor işini Wave 17'ye bırak |
| Dirty repo kullanıcı işini örter | Başlangıç hash/status ve hedef listesi | Yalnız Wave 03 farkını geri al |

## 13. Dependency, canlı işlem ve build sınırı

Wave 03 frontend foundation planıdır. Aşağıdakiler ayrıca açık yetki veya ilgili sonraki wave'i ister:

- Yeni npm dependency kurulumu veya lockfile değişikliği, Wave 03 açıkça başlatıldıktan sonra yalnız gerekli focused test ihtiyacıyla yapılabilir.
- Android asset sync, Gradle build, version bump, signing veya store işlemi bu wave'in doğal parçası değildir.
- Backend API/session/socket sözleşmesi değiştirilmez; Wave 02 sağlayıcısında eksik bulunursa uygulama durur.
- Production deploy, Render config veya canlı feature flag işlemi ayrıca açık yetki ister.
- Tasarım sonucu mevcut görünümden materyal biçimde ayrışırsa kullanıcı görsel onayı olmadan devam edilmez.
- Yeni route/framework kararı extraction için zorunlu görünürse etki açıklanır ve ayrıca karar alınır.

## 14. Başlangıç kapısı

Wave 03 uygulamasına geçmeden önce:

- [ ] Wave 01 ve Wave 02 **AUTO-VERIFIED / COMMITTED**; açık canonical/manual maddeler checkpoint havuzunda.
- [ ] Kullanıcı açıkça “Wave 03'ü başlat” dedi.
- [ ] Dirty repo başlangıç fotoğrafı hedef JSX/CSS/package dosyaları için kaydedildi.
- [ ] Wave 02 API/error/session/socket capability sözleşmeleri güncel kodda yeniden doğrulandı.
- [ ] Desteklenen browser ve Android WebView baseline'ı kaydedildi.
- [ ] QA-003/014/017 mevcut ekran screenshot baseline'ları alındı.
- [ ] Screen/state/event ve back/deep-link mevcut davranış matrisi çıkarıldı.
- [ ] Minimum focused test yaklaşımı ve olası dependency etkisi görünür hâle getirildi.
- [ ] localStorage token risk kararının bu wave içinde sessiz mimari değişiklik üretmeyeceği kabul edildi.
- [ ] Wave 04 kapsamına taşma olmadığı tekrar kontrol edildi.

Bu kutular plan hazırlanırken işaretlenmez.

## 15. Sonuç alanı

- **Başlangıç zamanı:** —
- **Tamamlanan Plan refs:** —
- **Değişen dosyalar:** —
- **Extraction adımları:** —
- **Otomatik kanıt:** —
- **Accessibility kanıtı:** —
- **Web/Android smoke:** —
- **Manuel QA:** Checkpoint A / Wave 19'a ertelendi
- **Kullanıcı görsel onayı:** —
- **Wave durumu:** Bekliyor
- **Sonraki wave:** Başlatılmadı

## 16. Durma kuralı

Bu belge hazırlandıktan sonra durulur. Wave 02 **AUTO-VERIFIED / COMMITTED** olmadan ve kullanıcı açıkça Wave 03'ü başlatmadan:

- Frontend kodu, CSS, dependency, lockfile veya test config'i değiştirilmez.
- App extraction, token migration veya auth UI değişikliği yapılmaz.
- Android sync/build veya deploy yapılmaz.
- Wave Map'te Wave 03 `Aktif` yapılmaz.
- Wave 04 yalnız ayrı açık planlama talimatıyla belgelenebilir; aktive edilmez veya uygulanmaz.
